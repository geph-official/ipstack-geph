use tokio::time::{sleep_until, Instant as TokioInstant, Sleep};

use crate::packet::tcp_flags::{ACK, PSH};
use std::{collections::BTreeMap, future::Future, pin::Pin, time::Duration};

const MAX_UNACK: u32 = 1024 * 16; // 16KB
const MAX_INFLIGHT_SEGMENTS: usize = 16;
pub(super) const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB
const RTO: Duration = Duration::from_millis(100);
// Exponential backoff for the RTO timer. Without backoff, a peer that never
// ACKs (e.g. its socket vanished and the RST never reached us) is retransmitted
// to every 100 ms for the whole tcp_timeout — potentially hours of 10 pkt/s
// garbage per dead flow. Back off to RTO_MAX and give up entirely after
// MAX_RETRANSMITS consecutive unanswered retransmissions (~35 s), resetting the
// connection like a real TCP stack would.
const RTO_MAX: Duration = Duration::from_millis(3200);
const MAX_RETRANSMITS: u32 = 15;
// tokio has no "never" timer, so we use a deadline far enough in the future to
// stand in for one without overflowing the instant arithmetic.
const FAR_FUTURE: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

#[derive(Debug, PartialEq)]
pub enum TcpState {
    SynReceived(bool), // bool means if syn/ack is sent
    Established,
    Closed,
}

#[derive(Debug)]
pub(super) struct Tcb {
    seq: u32,
    ack: u32,
    last_ack: u32,
    pub(super) timeout: Pin<Box<Sleep>>,
    tcp_timeout: Duration,
    send_window: u16,
    state: TcpState,
    pub(super) inflight_packets: Vec<InflightPacket>,
    unordered_packets: BTreeMap<u32, UnorderedPacket>,
    pending_fin: Option<u32>,

    // Very simple RTO (Retransmission TimeOut) timer. Whenever there is at
    // at least one un-acknowledged packet in `inflight_packets` we arm this
    // timer, starting at 100 ms and doubling per unanswered retransmission up
    // to RTO_MAX. When the timer fires the oldest un-acknowledged packet
    // should be retransmitted and the timer re-armed if there are still
    // packets in flight. This does not try to follow RFC 6298 beyond the
    // backoff-and-give-up shape.
    rto_timer: Pin<Box<Sleep>>,
    rto_current: Duration,
    rto_strikes: u32,
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
            ack,
            last_ack: seq,
            tcp_timeout,
            timeout: Box::pin(sleep_until(deadline)),
            send_window: u16::MAX,
            state: TcpState::SynReceived(false),
            inflight_packets: Vec::new(),
            unordered_packets: BTreeMap::new(),
            pending_fin: None,

            rto_timer: Box::pin(sleep_until(TokioInstant::now() + FAR_FUTURE)),
            rto_current: RTO,
            rto_strikes: 0,
        }
    }
    pub(super) fn add_inflight_packet(&mut self, seq: u32, buf: Vec<u8>) {
        self.track_segment(InflightPacket {
            seq,
            flags: PSH | ACK,
            payload: buf,
        });
    }

    pub(super) fn add_control(&mut self, flags: u8) {
        self.track_segment(InflightPacket {
            seq: self.seq,
            flags,
            payload: Vec::new(),
        });
    }

    fn track_segment(&mut self, segment: InflightPacket) {
        let was_empty = self.inflight_packets.is_empty();
        self.seq = self.seq.wrapping_add(segment.sequence_len());
        self.inflight_packets.push(segment);
        if was_empty {
            self.reset_rto_backoff();
            self.arm_rto();
        }
    }

    pub(super) fn add_unordered_packet(&mut self, mut seq: u32, mut buf: Vec<u8>) {
        if seq_before(seq, self.ack) {
            let consumed = self.ack.wrapping_sub(seq) as usize;
            if consumed >= buf.len() {
                return;
            }
            buf.drain(..consumed);
            seq = self.ack;
        }
        let start = seq.wrapping_sub(self.ack) as usize;
        buf.truncate(READ_BUFFER_SIZE.saturating_sub(start));
        if buf.is_empty() {
            return;
        }
        let end = start + buf.len();
        let ack = self.ack;

        // Keep stored ranges disjoint. When a segment overlaps a buffered
        // segment, retain the portions of the old segment outside the new one.
        let mut ends = Vec::new();
        self.unordered_packets.retain(|&old_seq, old| {
            let old_start = old_seq.wrapping_sub(ack) as usize;
            let old_end = old_start + old.payload.len();
            if old_end <= start || end <= old_start {
                return true;
            }
            if old_end > end {
                ends.push((
                    ack.wrapping_add(end as u32),
                    old.payload.split_off(end - old_start),
                ));
            }
            if old_start < start {
                old.payload.truncate(start - old_start);
                return true;
            }
            false
        });
        self.unordered_packets.extend(
            ends.into_iter()
                .map(|(seq, payload)| (seq, UnorderedPacket::new(payload))),
        );
        self.unordered_packets
            .insert(seq, UnorderedPacket::new(buf));
    }
    pub(super) fn get_unordered_packets(&mut self) -> Option<Vec<u8>> {
        self.unordered_packets.remove(&self.ack).map(|p| p.payload)
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
        self.send_window = window;
    }
    pub(super) fn get_available_send_window(&self) -> u16 {
        let bytes_in_flight = self.seq.wrapping_sub(self.last_ack);
        self.send_window
            .saturating_sub(bytes_in_flight.min(u16::MAX as u32) as u16)
    }
    pub(super) fn is_old_ack(&self, ack: u32) -> bool {
        seq_before(ack, self.last_ack)
    }

    pub(super) fn valid_ack(&self, ack: u32) -> bool {
        seq_lte(self.last_ack, ack) && seq_lte(ack, self.seq)
    }

    pub(super) fn change_last_ack(&mut self, ack: u32) {
        if !seq_after(ack, self.last_ack) || seq_after(ack, self.seq) {
            return;
        }
        self.last_ack = ack;

        self.inflight_packets.retain_mut(|segment| {
            let end = segment.seq.wrapping_add(segment.sequence_len());
            if !seq_after(end, ack) {
                return false;
            }
            if seq_before(segment.seq, ack) {
                segment
                    .payload
                    .drain(..ack.wrapping_sub(segment.seq) as usize);
                segment.seq = ack;
            }
            true
        });
        if self.inflight_packets.is_empty() {
            self.disarm_rto();
        } else {
            self.reset_rto_backoff();
            self.arm_rto();
        }
    }
    pub fn is_send_buffer_full(&self) -> bool {
        self.inflight_packets.len() >= MAX_INFLIGHT_SEGMENTS
            || self.seq.wrapping_sub(self.last_ack) >= MAX_UNACK
    }

    pub(super) fn record_fin(&mut self, sequence_number: u32) {
        if sequence_number.wrapping_sub(self.ack) as usize <= READ_BUFFER_SIZE {
            self.pending_fin = Some(sequence_number);
        }
    }

    pub(super) fn consume_pending_fin(&mut self) -> bool {
        if self.pending_fin == Some(self.ack) {
            self.pending_fin = None;
            self.add_ack(1);
            true
        } else {
            false
        }
    }

    //==================== RTO helpers ====================

    // Poll the RTO timer. Returns true if it has fired. Each firing counts as
    // a strike and doubles the next timeout (capped at RTO_MAX); the caller
    // should check `rto_exhausted` and reset the connection once the strikes
    // run out.
    pub(crate) fn poll_rto(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        if Pin::new(&mut self.rto_timer).poll(cx).is_ready() {
            if self.inflight_packets.is_empty() {
                self.disarm_rto();
            } else {
                self.rto_strikes += 1;
                self.rto_current = (self.rto_current * 2).min(RTO_MAX);
                self.arm_rto();
            }
            true
        } else {
            false
        }
    }

    // Whether retransmission has gone unanswered for so long that the
    // connection should be considered dead.
    pub(crate) fn rto_exhausted(&self) -> bool {
        self.rto_strikes > MAX_RETRANSMITS
    }

    pub(crate) fn rto_strikes(&self) -> u32 {
        self.rto_strikes
    }

    fn reset_rto_backoff(&mut self) {
        self.rto_current = RTO;
        self.rto_strikes = 0;
    }

    pub(crate) fn reset_timeout(&mut self) {
        let deadline = TokioInstant::now() + self.tcp_timeout;
        self.timeout.as_mut().reset(deadline);
    }

    fn arm_rto(&mut self) {
        self.rto_timer
            .as_mut()
            .reset(TokioInstant::now() + self.rto_current);
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
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl InflightPacket {
    fn sequence_len(&self) -> u32 {
        if self.payload.is_empty() {
            1
        } else {
            self.payload.len() as u32
        }
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

    #[tokio::test(start_paused = true)]
    async fn rto_gives_up_after_max_unanswered_retransmissions() {
        let mut tcb = Tcb::new(0, Duration::from_secs(3600));
        tcb.change_state(TcpState::Established);
        tcb.seq = 100;
        tcb.last_ack = 100;
        tcb.add_inflight_packet(100, vec![0; 10]);

        let mut fired = 0u32;
        while !tcb.rto_exhausted() {
            std::future::poll_fn(|cx| {
                if tcb.poll_rto(cx) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            fired += 1;
            assert!(fired < 100, "give-up must trigger before 100 firings");
        }
        assert_eq!(fired, MAX_RETRANSMITS + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn ack_progress_resets_rto_backoff() {
        let mut tcb = Tcb::new(0, Duration::from_secs(3600));
        tcb.change_state(TcpState::Established);
        tcb.seq = 100;
        tcb.last_ack = 100;
        tcb.add_inflight_packet(100, vec![0; 10]);
        tcb.add_inflight_packet(110, vec![0; 10]);

        // Take a few strikes...
        for _ in 0..3 {
            std::future::poll_fn(|cx| {
                if tcb.poll_rto(cx) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
        }
        assert_eq!(tcb.rto_strikes(), 3);

        // ...then ACK the first packet: strikes reset, timer re-armed.
        tcb.change_last_ack(110);
        assert_eq!(tcb.rto_strikes(), 0);
        assert!(!tcb.inflight_packets.is_empty());
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

    #[tokio::test]
    async fn partial_ack_keeps_oldest_unacked_segment_first() {
        let mut tcb = Tcb::new(0, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        tcb.seq = 100;
        tcb.last_ack = 100;
        tcb.add_inflight_packet(100, vec![0; 100]);
        tcb.add_inflight_packet(200, vec![0; 100]);

        tcb.change_last_ack(150);

        assert_eq!(tcb.inflight_packets.len(), 2);
        assert_eq!(tcb.inflight_packets[0].seq, 150);
        assert_eq!(tcb.inflight_packets[0].payload.len(), 50);
        assert_eq!(tcb.inflight_packets[1].seq, 200);
    }

    #[tokio::test]
    async fn advertised_window_accounts_for_bytes_in_flight() {
        let mut tcb = Tcb::new(0, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        tcb.seq = 100;
        tcb.last_ack = 100;
        tcb.change_send_window(10);

        assert_eq!(tcb.get_available_send_window(), 10);
        tcb.add_inflight_packet(100, vec![0; 8]);
        assert_eq!(tcb.get_available_send_window(), 2);
        tcb.add_inflight_packet(108, vec![0; 2]);
        assert_eq!(tcb.get_available_send_window(), 0);
    }
}
