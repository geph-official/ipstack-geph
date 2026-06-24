use tokio::time::{sleep_until, Instant as TokioInstant, Sleep};

use crate::packet::TcpHeaderWrapper;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    time::Duration,
};

const MAX_UNACK: u32 = 1024 * 16; // 16KB
const MAX_INFLIGHT_SEGMENTS: usize = 16;
const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB
const RTO: Duration = Duration::from_millis(100);
// tokio has no "never" timer, so we use a deadline far enough in the future to
// stand in for one without overflowing the instant arithmetic.
const FAR_FUTURE: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

#[derive(Debug, PartialEq)]
pub enum TcpState {
    SynReceived(bool), // bool means if syn/ack is sent
    Established,
    FinWait1(bool),
    FinWait2(bool), // bool means waiting for ack
    Closed,
}

#[derive(Debug, PartialEq)]
pub(super) enum PacketStatus {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
    KeepAlive,
}

#[derive(Debug)]
pub(super) struct Tcb {
    seq: u32,
    pub(super) retransmission: Option<u32>,
    ack: u32,
    last_ack: u32,
    pub(super) timeout: Pin<Box<Sleep>>,
    tcp_timeout: Duration,
    recv_window: u16,
    send_window: u16,
    state: TcpState,
    avg_send_window: (u64, u64), // (avg, count)
    pub(super) inflight_packets: Vec<InflightPacket>,
    unordered_packets: BTreeMap<u32, UnorderedPacket>,

    // Very simple RTO (Retransmission TimeOut) timer. Whenever there is at
    // at least one un-acknowledged packet in `inflight_packets` we arm this
    // timer for a fixed 100 ms. When the timer fires the oldest un-
    // acknowledged packet should be retransmitted and the timer re-armed if
    // there are still packets in flight. This is an extremely rudimentary
    // implementation that does not try to follow RFC 6298.
    rto_timer: Pin<Box<Sleep>>,
}

impl Tcb {
    pub(super) fn new(ack: u32, tcp_timeout: Duration) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::random::<u32>();
        let deadline = TokioInstant::now() + tcp_timeout;
        Tcb {
            seq,
            retransmission: None,
            ack,
            last_ack: seq,
            tcp_timeout,
            timeout: Box::pin(sleep_until(deadline)),
            send_window: u16::MAX,
            recv_window: 0,
            state: TcpState::SynReceived(false),
            avg_send_window: (1, 1),
            inflight_packets: Vec::new(),
            unordered_packets: BTreeMap::new(),

            rto_timer: Box::pin(sleep_until(TokioInstant::now() + FAR_FUTURE)),
        }
    }
    pub(super) fn add_inflight_packet(&mut self, seq: u32, buf: Vec<u8>) {
        let was_empty = self.inflight_packets.is_empty();
        let buf_len = buf.len() as u32;
        self.inflight_packets.push(InflightPacket::new(seq, buf));
        self.seq = self.seq.wrapping_add(buf_len);
        if was_empty && buf_len > 0 {
            self.arm_rto();
        }
    }
    pub(super) fn add_unordered_packet(&mut self, seq: u32, buf: Vec<u8>) {
        if seq_before(seq, self.ack) {
            return;
        }
        self.unordered_packets
            .insert(seq, UnorderedPacket::new(buf));
    }
    pub(super) fn get_available_read_buffer_size(&self) -> usize {
        READ_BUFFER_SIZE.saturating_sub(
            self.unordered_packets
                .iter()
                .fold(0, |acc, (_, p)| acc + p.payload.len()),
        )
    }
    pub(super) fn get_unordered_packets(&mut self) -> Option<Vec<u8>> {
        // dbg!(self.ack);
        // for (seq,_) in self.unordered_packets.iter() {
        //     dbg!(seq);
        // }
        self.unordered_packets.remove(&self.ack).map(|p| p.payload)
    }
    pub(super) fn add_seq_one(&mut self) {
        self.seq = self.seq.wrapping_add(1);
    }
    pub(super) fn get_seq(&self) -> u32 {
        self.seq
    }
    pub(super) fn add_ack(&mut self, add: u32) {
        self.ack = self.ack.wrapping_add(add);
    }
    pub(super) fn get_ack(&self) -> u32 {
        self.ack
    }
    pub(super) fn get_last_ack(&self) -> u32 {
        self.last_ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> &TcpState {
        &self.state
    }
    pub(super) fn change_send_window(&mut self, window: u16) {
        let avg_send_window = ((self.avg_send_window.0 * self.avg_send_window.1) + window as u64)
            / (self.avg_send_window.1 + 1);
        self.avg_send_window.0 = avg_send_window;
        self.avg_send_window.1 += 1;
        self.send_window = window;
    }
    pub(super) fn get_send_window(&self) -> u16 {
        self.send_window
    }
    pub(super) fn get_avg_send_window(&self) -> u64 {
        self.avg_send_window.0
    }
    pub(super) fn change_recv_window(&mut self, window: u16) {
        self.recv_window = window;
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.recv_window
    }
    // #[inline(always)]
    // pub(super) fn buffer_size(&self, payload_len: u16) -> u16 {
    //     match MAX_UNACK - self.inflight_packets.len() as u32 {
    //         // b if b.saturating_sub(payload_len as u32 + 64) != 0 => payload_len,
    //         // b if b < 128 && b >= 4 => (b / 2) as u16,
    //         // b if b < 4 => b as u16,
    //         // b => (b - 64) as u16,
    //         b if b >= payload_len as u32 * 2 && b > 0 => payload_len,
    //         b if b < 4 => b as u16,
    //         b => (b / 2) as u16,
    //     }
    // }

    pub(super) fn check_pkt_type(&self, header: &TcpHeaderWrapper, p: &[u8]) -> PacketStatus {
        let tcp_header = header.inner();
        let packet_ack = tcp_header.acknowledgment_number;

        if seq_before(packet_ack, self.last_ack) || seq_after(packet_ack, self.seq) {
            PacketStatus::Invalid
        } else if self.last_ack == packet_ack {
            if !p.is_empty() {
                PacketStatus::NewPacket
            } else if self.send_window == tcp_header.window_size && self.seq != self.last_ack {
                PacketStatus::RetransmissionRequest
            } else if self.ack.wrapping_sub(1) == tcp_header.sequence_number {
                PacketStatus::KeepAlive
            } else {
                PacketStatus::WindowUpdate
            }
        } else if seq_after(packet_ack, self.last_ack) {
            if !p.is_empty() {
                PacketStatus::NewPacket
            } else {
                PacketStatus::Ack
            }
        } else {
            PacketStatus::Invalid
        }
    }
    pub(super) fn change_last_ack(&mut self, ack: u32) {
        if seq_before(ack, self.last_ack) || seq_after(ack, self.seq) {
            return;
        }
        self.last_ack = ack;

        if self.state == TcpState::Established {
            if let Some(i) = self.inflight_packets.iter().position(|p| p.contains(ack)) {
                let mut inflight_packet = self.inflight_packets.remove(i);
                tracing::trace!("packet {} is acked", inflight_packet.seq);
                let distance = ack.wrapping_sub(inflight_packet.seq) as usize;
                if distance < inflight_packet.payload.len() {
                    inflight_packet.payload.drain(0..distance);
                    inflight_packet.seq = ack;
                    self.inflight_packets.push(inflight_packet);
                }
            }
            self.inflight_packets.retain(|p| {
                let last_byte = p.seq.wrapping_add(p.payload.len() as u32);
                seq_after(last_byte, self.last_ack)
            });
            if self.inflight_packets.is_empty() {
                self.disarm_rto();
            } else {
                self.arm_rto();
            }
        }
    }
    pub fn is_send_buffer_full(&self) -> bool {
        self.inflight_packets.len() >= MAX_INFLIGHT_SEGMENTS
            || self.seq.wrapping_sub(self.last_ack) >= MAX_UNACK
    }

    //==================== RTO helpers ====================

    // Poll the RTO timer. Returns true if it has fired.
    pub(crate) fn poll_rto(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        if Pin::new(&mut self.rto_timer).poll(cx).is_ready() {
            if self.inflight_packets.is_empty() {
                self.disarm_rto();
            } else {
                self.arm_rto();
            }
            true
        } else {
            false
        }
    }

    pub(crate) fn reset_timeout(&mut self) {
        let deadline = TokioInstant::now() + self.tcp_timeout;
        self.timeout.as_mut().reset(deadline);
    }

    fn arm_rto(&mut self) {
        self.rto_timer
            .as_mut()
            .reset(TokioInstant::now() + RTO);
    }

    fn disarm_rto(&mut self) {
        self.rto_timer
            .as_mut()
            .reset(TokioInstant::now() + FAR_FUTURE);
    }
}

#[derive(Debug)]
pub struct InflightPacket {
    pub seq: u32,
    pub payload: Vec<u8>,
    // pub send_time: SystemTime, // todo
}

impl InflightPacket {
    fn new(seq: u32, payload: Vec<u8>) -> Self {
        Self {
            seq,
            payload,
            // send_time: SystemTime::now(), // todo
        }
    }
    pub(crate) fn contains(&self, seq: u32) -> bool {
        seq_after(seq, self.seq) && seq_lte(seq, self.seq.wrapping_add(self.payload.len() as u32))
    }
}

#[derive(Debug)]
struct UnorderedPacket {
    payload: Vec<u8>,
    // pub recv_time: SystemTime, // todo
}

impl UnorderedPacket {
    pub(crate) fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            // recv_time: SystemTime::now(), // todo
        }
    }
}

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_after(a: u32, b: u32) -> bool {
    seq_before(b, a)
}

fn seq_lte(a: u32, b: u32) -> bool {
    a == b || seq_before(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_comparisons_wrap() {
        assert!(seq_after(2, u32::MAX - 2));
        assert!(seq_before(u32::MAX - 2, 2));
        assert!(seq_lte(2, 2));
    }

    #[tokio::test]
    async fn partial_ack_across_wrap_keeps_remaining_payload() {
        let mut tcb = Tcb::new(0, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        tcb.seq = u32::MAX - 2;
        tcb.last_ack = u32::MAX - 2;

        tcb.add_inflight_packet(u32::MAX - 2, vec![0; 10]);
        assert_eq!(tcb.seq, 7);

        tcb.change_last_ack(2);
        assert_eq!(tcb.last_ack, 2);
        assert_eq!(tcb.inflight_packets.len(), 1);
        assert_eq!(tcb.inflight_packets[0].seq, 2);
        assert_eq!(tcb.inflight_packets[0].payload.len(), 5);
    }
}
