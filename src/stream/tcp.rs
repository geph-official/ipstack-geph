use crate::{
    packet::{
        tcp_flags::{ACK, FIN, NON, PSH, RST, SYN},
        IpHeader, IpStackPacketProtocol, NetworkPacket, TcpHeaderWrapper, TransportHeader,
    },
    stream::tcb::{PacketStatus, Tcb, TcpState},
    PacketReceiver, PacketSender, DROP_TTL, TTL,
};

use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpOptionElement};
use futures_lite::StreamExt;
use log::{error, trace, warn};
use std::{
    cmp,
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
enum Shutdown {
    Ready,
    Pending(Waker),
    None,
}

impl Shutdown {
    fn pending(&mut self, w: Waker) {
        *self = Shutdown::Pending(w);
    }
    fn ready(&mut self) {
        if let Shutdown::Pending(w) = self {
            w.wake_by_ref();
        }
        *self = Shutdown::Ready;
    }
}

#[derive(Debug)]
pub(crate) struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_receiver: Pin<Box<PacketReceiver>>,
    packet_sender: PacketSender,
    packet_to_send: Option<NetworkPacket>,
    tcb: Tcb,
    mtu: u16,
    peer_mss: u16,
    shutdown: Shutdown,
    write_notify: Option<Waker>,
    session_generation: u64,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeaderWrapper,
        packet_sender: PacketSender,
        stream_receiver: PacketReceiver,
        mtu: u16,
        tcp_timeout: Duration,
    ) -> anyhow::Result<IpStackTcpStream> {
        // RFC 9293 section 3.7.1: MSS limits TCP data, not the IP packet.
        // The virtual interface's MTU can exceed the peer's actual link MTU.
        let peer_mss = tcp
            .inner()
            .options_iterator()
            .find_map(|option| match option {
                Ok(TcpOptionElement::MaximumSegmentSize(mss)) => Some(mss),
                _ => None,
            })
            .unwrap_or(if src_addr.is_ipv4() { 536 } else { 1220 });
        anyhow::ensure!(peer_mss > 0, "TCP peer advertised a zero MSS");
        let stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb: Tcb::new(tcp.inner().sequence_number + 1, tcp_timeout),
            mtu,
            peer_mss,
            shutdown: Shutdown::None,
            write_notify: None,
            session_generation: 0,
        };
        if tcp.inner().syn {
            return Ok(stream);
        }
        if tcp.inner().rst {
            warn!("not responding RST with RST")
        } else {
            // A stray packet for a flow we know nothing about (e.g. a
            // connection that predates this IpStack instance). Reset it so
            // the peer's kernel tears the connection down promptly. The RST's
            // sequence number must be the stray packet's acknowledgment
            // number — that is exactly the peer's RCV.NXT, and per RFC 5961
            // anything else is answered with a challenge ACK instead of an
            // abort (a fresh Tcb's random sequence number would leave the
            // peer's connection alive and wedged indefinitely).
            let rst_seq = if tcp.inner().ack {
                tcp.inner().acknowledgment_number
            } else {
                0
            };
            let pkt = stream.create_rev_packet(RST | ACK, TTL, rst_seq, Vec::new())?;
            if let Err(err) = stream.packet_sender.try_send(pkt) {
                warn!("Error sending RST/ACK packet: {:?}", err);
            }
        }
        anyhow::bail!(
            "stray TCP packet src_addr={src_addr} dst_addr={dst_addr}, tcp={:?}",
            tcp
        )
    }

    pub(crate) fn with_session_generation(mut self, session_generation: u64) -> Self {
        self.session_generation = session_generation;
        self
    }

    fn calculate_payload_len(&self, ip_header_size: u16, tcp_header_size: u16) -> u16 {
        let fixed_ip_header_size = if self.src_addr.is_ipv4() { 20 } else { 40 };
        let option_size = ip_header_size.saturating_sub(fixed_ip_header_size)
            + tcp_header_size.saturating_sub(20);
        cmp::min(
            self.tcb.get_available_send_window(),
            cmp::min(
                self.mtu.saturating_sub(ip_header_size + tcp_header_size),
                self.peer_mss.saturating_sub(option_size),
            ),
        )
    }

    fn create_rev_packet(
        &self,
        flags: u8,
        ttl: u8,
        seq: impl Into<Option<u32>>,
        mut payload: Vec<u8>,
    ) -> anyhow::Result<NetworkPacket> {
        let mut tcp_header = etherparse::TcpHeader::new(
            self.dst_addr.port(),
            self.src_addr.port(),
            seq.into().unwrap_or(self.tcb.get_seq()),
            self.tcb.get_recv_window(),
        );

        tcp_header.acknowledgment_number = self.tcb.get_ack();
        if flags & SYN != 0 {
            tcp_header.syn = true;
        }
        if flags & ACK != 0 {
            tcp_header.ack = true;
        }
        if flags & RST != 0 {
            tcp_header.rst = true;
        }
        if flags & FIN != 0 {
            tcp_header.fin = true;
        }
        if flags & PSH != 0 {
            tcp_header.psh = true;
        }

        let ip_header = match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::TCP, dst.octets(), src.octets())?;
                let payload_len = self.calculate_payload_len(
                    ip_h.header_len() as u16,
                    tcp_header.header_len() as u16,
                );
                payload.truncate(payload_len as usize);
                ip_h.set_payload_len(payload.len() + tcp_header.header_len())?;
                ip_h.dont_fragment = true;
                IpHeader::Ipv4(ip_h)
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = etherparse::Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::TCP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let payload_len = self.calculate_payload_len(
                    ip_h.header_len() as u16,
                    tcp_header.header_len() as u16,
                );
                payload.truncate(payload_len as usize);
                let len = payload.len() + tcp_header.header_len();
                ip_h.set_payload_length(len)?;

                IpHeader::Ipv6(ip_h)
            }
            _ => unreachable!(),
        };

        match ip_header {
            IpHeader::Ipv4(ref ip_header) => {
                tcp_header.checksum = tcp_header.calc_checksum_ipv4(ip_header, &payload)?;
            }
            IpHeader::Ipv6(ref ip_header) => {
                tcp_header.checksum = tcp_header.calc_checksum_ipv6(ip_header, &payload)?;
            }
        }
        Ok(NetworkPacket {
            ip: ip_header,
            transport: TransportHeader::Tcp(tcp_header),
            payload,
            teardown_generation: (ttl == DROP_TTL).then_some(self.session_generation),
        })
    }

    /// Aborts a not-yet-established connection by sending a RST to the peer, so
    /// its `connect()` fails immediately with "connection refused" instead of
    /// hanging. Use this when the application actively refuses the connection
    /// (e.g. an upstream dial returned `ConnectionRefused`). For
    /// unreachable/timeout failures, simply drop the stream instead: that
    /// leaves the SYN unanswered so the peer's Happy Eyeballs can fall back to
    /// another address rather than treating the path as up-but-refused.
    pub fn reset(&mut self) {
        if let Ok(p) = self.create_rev_packet(RST | ACK, TTL, None, Vec::new()) {
            let _ = self.packet_sender.try_send(p);
        }
        self.close();
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.write_notify.take() {
            waker.wake();
        }
    }

    fn close(&mut self) {
        self.tcb.change_state(TcpState::Closed);
        self.shutdown.ready();
        self.wake_writer();
    }
}

impl IpStackTcpStream {
    fn poll_read_inner(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            // Check for RTO expiration and retransmit the oldest
            // unacknowledged packet if necessary. If retransmissions have gone
            // unanswered past the give-up point, reset the connection instead
            // of retransmitting into a dead flow for the rest of tcp_timeout.
            let poll_rto = !self.tcb.inflight_packets.is_empty();
            if poll_rto && self.tcb.poll_rto(cx) {
                if self.tcb.rto_exhausted() {
                    tracing::warn!(
                        strikes = self.tcb.rto_strikes(),
                        dst = display(self.src_addr),
                        "too many unanswered retransmissions, resetting connection"
                    );
                    let _ = self.packet_sender.try_send(
                        self.create_rev_packet(RST | ACK, TTL, None, Vec::new())
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                    );
                    self.close();
                    return Poll::Ready(Err(Error::from(ErrorKind::TimedOut)));
                }
                let pkt = self.tcb.inflight_packets.first().unwrap();
                if let Ok(rp) = self.create_rev_packet(PSH | ACK, TTL, pkt.seq, pkt.payload.clone())
                {
                    tracing::debug!(
                        seq = pkt.seq,
                        strikes = self.tcb.rto_strikes(),
                        "retransmitting unacknowledged packet"
                    );
                    let _ = self.packet_sender.try_send(rp);
                }
            }
            if let Some(packet) = self.packet_to_send.take() {
                if self.packet_sender.try_send(packet).is_err() {
                    self.close();
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
            }
            if *self.tcb.get_state() == TcpState::Closed {
                self.shutdown.ready();
                return Poll::Ready(Ok(0));
            }

            if *self.tcb.get_state() == TcpState::FinWait2(false) {
                self.packet_to_send = Some(
                    self.create_rev_packet(NON, DROP_TTL, None, Vec::new())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                );
                self.close();
                return Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted)));
            }

            let min = self.tcb.get_available_read_buffer_size() as u16;
            self.tcb.change_recv_window(min);

            if *self.tcb.get_state() == TcpState::SynReceived(false) {
                self.packet_to_send = Some(
                    self.create_rev_packet(SYN | ACK, TTL, None, Vec::new())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                );
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::SynReceived(true));
                continue;
            }

            if let Some(b) = self
                .tcb
                .get_unordered_packets()
                .filter(|_| matches!(self.shutdown, Shutdown::None))
            {
                let mut b = b;
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                self.tcb.add_ack(n as u32);
                if n < b.len() {
                    let remaining = b.split_off(n);
                    let next_seq = self.tcb.get_ack();
                    self.tcb.add_unordered_packet(next_seq, remaining);
                }

                if self.tcb.consume_pending_fin() {
                    self.tcb.change_state(TcpState::FinWait1(true));
                }

                self.packet_sender
                    .try_send(
                        self.create_rev_packet(ACK, TTL, None, Vec::new())
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                    )
                    .or(Err(ErrorKind::UnexpectedEof))?;
                return Poll::Ready(Ok(n));
            }
            if matches!(Pin::new(&mut self.tcb.timeout).poll(cx), Poll::Ready(_)) {
                trace!("timeout reached for {:?}", self.dst_addr);
                self.close();
                self.packet_sender
                    .try_send(
                        self.create_rev_packet(RST | ACK, TTL, None, Vec::new())
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                    )
                    .or(Err(ErrorKind::UnexpectedEof))?;
                return Poll::Ready(Err(Error::from(ErrorKind::TimedOut)));
            }
            if *self.tcb.get_state() == TcpState::FinWait1(true) {
                self.packet_to_send = Some(
                    self.create_rev_packet(FIN | ACK, TTL, None, Vec::new())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                );
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::FinWait2(true));
                continue;
            } else if matches!(self.shutdown, Shutdown::Pending(_))
                && *self.tcb.get_state() == TcpState::Established
                && self.tcb.get_last_ack() == self.tcb.get_seq()
            {
                self.packet_to_send = Some(
                    self.create_rev_packet(FIN | ACK, TTL, None, Vec::new())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                );
                self.tcb.add_seq_one();
                self.tcb.change_state(TcpState::FinWait1(false));
                continue;
            }
            match self.stream_receiver.poll_next(cx) {
                Poll::Ready(Some(p)) => {
                    let IpStackPacketProtocol::Tcp(t) = p.transport_protocol() else {
                        unreachable!()
                    };
                    if t.flags() & RST != 0 {
                        self.packet_to_send = Some(
                            self.create_rev_packet(NON, DROP_TTL, None, Vec::new())
                                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                        );
                        self.close();
                        return Poll::Ready(Err(Error::from(ErrorKind::ConnectionReset)));
                    }
                    let packet_status = self.tcb.check_pkt_type(&t, &p.payload);
                    if packet_status == PacketStatus::Invalid {
                        continue;
                    }
                    self.tcb.reset_timeout();

                    if *self.tcb.get_state() == TcpState::SynReceived(true) {
                        if t.inner().ack {
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);
                            self.tcb.change_send_window(t.inner().window_size);
                            self.tcb.change_state(TcpState::Established);
                            self.wake_writer();
                        }
                    } else if *self.tcb.get_state() == TcpState::Established {
                        let has_payload = !p.payload.is_empty();
                        let payload_len = p.payload.len() as u32;
                        let sequence_number = t.inner().sequence_number;

                        if t.inner().ack {
                            match packet_status {
                                PacketStatus::WindowUpdate => {
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.wake_writer();
                                }
                                PacketStatus::Invalid => continue,
                                PacketStatus::KeepAlive => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.packet_to_send = Some(
                                        self.create_rev_packet(ACK, TTL, None, Vec::new())
                                            .map_err(|e| {
                                                std::io::Error::new(ErrorKind::InvalidData, e)
                                            })?,
                                    );
                                    self.wake_writer();
                                }
                                PacketStatus::RetransmissionRequest => {
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.tcb.retransmission = Some(t.inner().acknowledgment_number);
                                    if matches!(self.as_mut().poll_flush_inner(cx), Poll::Pending) {
                                        return Poll::Pending;
                                    }
                                }
                                PacketStatus::NewPacket => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.wake_writer();
                                }
                                PacketStatus::Ack => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.wake_writer();
                                }
                            };
                        }

                        if has_payload {
                            self.tcb.add_unordered_packet(sequence_number, p.payload);
                        }

                        if t.inner().fin {
                            self.tcb
                                .record_fin(sequence_number.wrapping_add(payload_len));
                            if self.tcb.consume_pending_fin() {
                                self.packet_to_send = Some(
                                    self.create_rev_packet(ACK, TTL, None, Vec::new()).map_err(
                                        |e| std::io::Error::new(ErrorKind::InvalidData, e),
                                    )?,
                                );
                                self.tcb.change_state(TcpState::FinWait1(true));
                            }
                        }
                    } else if *self.tcb.get_state() == TcpState::FinWait1(false) {
                        if t.inner().fin && t.inner().ack {
                            self.tcb.add_ack(1);
                            self.packet_to_send = Some(
                                self.create_rev_packet(ACK, TTL, None, Vec::new())
                                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                            );
                            self.tcb.change_send_window(t.inner().window_size);
                            self.tcb.change_state(TcpState::FinWait2(true));
                            continue;
                        } else if t.inner().ack {
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);
                            self.tcb.add_ack(1);
                            self.tcb.change_state(TcpState::FinWait2(true));
                            continue;
                        }
                    } else if *self.tcb.get_state() == TcpState::FinWait2(true) {
                        if t.inner().fin && t.inner().ack {
                            self.packet_to_send = Some(
                                self.create_rev_packet(ACK, TTL, None, Vec::new())
                                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                            );
                            self.tcb.change_state(TcpState::FinWait2(false));
                        } else if t.inner().ack {
                            self.tcb.change_state(TcpState::FinWait2(false));
                        }
                    }
                }
                Poll::Ready(None) => {
                    self.close();
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl IpStackTcpStream {
    fn poll_write_inner(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if *self.tcb.get_state() != TcpState::Established {
            if matches!(self.tcb.get_state(), &TcpState::SynReceived(_)) {
                // The read side processes the handshake ACK or terminal error.
                self.write_notify = Some(cx.waker().clone());
                return Poll::Pending;
            }
            return Poll::Ready(Err(Error::from(ErrorKind::NotConnected)));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.tcb.get_available_send_window() == 0 || self.tcb.is_send_buffer_full() {
            self.write_notify = Some(cx.waker().clone());
            return Poll::Pending;
        }

        if self.tcb.retransmission.is_some() {
            self.write_notify = Some(cx.waker().clone());
            if matches!(self.as_mut().poll_flush_inner(cx), Poll::Pending) {
                return Poll::Pending;
            }
        }

        let packet = self
            .create_rev_packet(PSH | ACK, TTL, None, buf.to_vec())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        let seq = self.tcb.get_seq();
        let payload_len = packet.payload.len();
        if payload_len == 0 {
            self.write_notify = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let payload = packet.payload.clone();
        self.packet_sender
            .try_send(packet)
            .or(Err(ErrorKind::UnexpectedEof))?;
        self.tcb.add_inflight_packet(seq, payload);
        self.tcb.reset_timeout();

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush_inner(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if *self.tcb.get_state() != TcpState::Established {
            return Poll::Ready(Err(Error::from(ErrorKind::NotConnected)));
        }

        if let Some(s) = self.tcb.retransmission.take() {
            if let Some(packet) = self.tcb.inflight_packets.iter().find(|p| p.seq == s) {
                let rev_packet = self
                    .create_rev_packet(PSH | ACK, TTL, packet.seq, packet.payload.clone())
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

                self.packet_sender
                    .try_send(rev_packet)
                    .or(Err(ErrorKind::UnexpectedEof))?;
            } else {
                error!("Packet {} not found in inflight_packets", s);
                error!("seq: {}", self.tcb.get_seq());
                error!("last_ack: {}", self.tcb.get_last_ack());
                error!("ack: {}", self.tcb.get_ack());
                error!("inflight_packets:");
                for p in self.tcb.inflight_packets.iter() {
                    error!("seq: {}", p.seq);
                    error!("payload len: {}", p.payload.len());
                }
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionReset,
                    "requested retransmission is no longer in flight",
                )));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close_inner(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we never sent a SYN-ACK (the peer closed/dropped this stream before
        // ever reading from it — e.g. because an upstream dial failed), abandon
        // it silently. Driving the read state machine here would emit a SYN-ACK
        // and then a FIN, making a dead connection look like one that briefly
        // connected and immediately closed. That defeats a client's Happy
        // Eyeballs: a failed IPv6 dial on an IPv4-only path would appear to
        // connect (so the client commits to it) and then die, instead of
        // staying unresponsive so the IPv4 attempt can win.
        if matches!(self.tcb.get_state(), TcpState::SynReceived(false)) {
            self.close();
            return Poll::Ready(Ok(()));
        }
        if matches!(self.shutdown, Shutdown::Ready) {
            return Poll::Ready(Ok(()));
        } else if matches!(self.shutdown, Shutdown::None) {
            self.shutdown.pending(cx.waker().clone());
        }
        self.poll_read_inner(cx, &mut []).map(|x| x.map(|_| ()))
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match self.poll_read_inner(cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_write_inner(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_flush_inner(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_close_inner(cx)
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Ok(p) = self.create_rev_packet(NON, DROP_TTL, None, Vec::new()) {
            if let Err(err) = self.packet_sender.try_send(p) {
                trace!("Error sending NON packet: {:?}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::poll_once;
    use std::{
        future::poll_fn,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::Wake,
    };

    #[tokio::test]
    async fn writes_respect_peer_mss_and_local_limits() {
        // Keep the stack's large default MTU: the peer's SYN must prevent
        // oversized DF packets when this stream feeds a forwarded VPN path.
        for (ipv6, advertised, mtu, window, expected) in [
            (false, Some(1460), 16384, 65535, 1460),
            (true, Some(1440), 16384, 65535, 1440),
            (false, None, 16384, 65535, 536),
            (true, None, 16384, 65535, 1220),
            (false, Some(9000), 1500, 65535, 1460),
            (true, Some(9000), 1500, 65535, 1440),
            (false, Some(1460), 16384, 100, 100),
            (false, Some(1), 16384, 65535, 1),
        ] {
            let (packet_sender, packet_receiver) = async_channel::unbounded();
            let (_stream_sender, stream_receiver) = async_channel::unbounded();
            let (src, dst): (SocketAddr, SocketAddr) = if ipv6 {
                (
                    "[fd00::1]:1000".parse().unwrap(),
                    "[fd00::2]:2000".parse().unwrap(),
                )
            } else {
                (
                    "10.0.0.1:1000".parse().unwrap(),
                    "10.0.0.2:2000".parse().unwrap(),
                )
            };
            let mut syn = etherparse::TcpHeader::new(1000, 2000, 999, window);
            syn.syn = true;
            if let Some(mss) = advertised {
                syn.set_options(&[
                    etherparse::TcpOptionElement::Noop,
                    etherparse::TcpOptionElement::MaximumSegmentSize(mss),
                ])
                .unwrap();
            }
            let mut stream = Box::pin(
                IpStackTcpStream::new(
                    src,
                    dst,
                    (&syn).into(),
                    packet_sender,
                    stream_receiver,
                    mtu,
                    Duration::from_secs(60),
                )
                .unwrap(),
            );
            stream.tcb.change_state(TcpState::Established);
            stream.tcb.change_send_window(window);
            let bytes = vec![0xab; 8192];
            let written = poll_fn(|cx| stream.as_mut().poll_write_inner(cx, &bytes))
                .await
                .unwrap();
            assert_eq!(
                written, expected,
                "ipv6={ipv6}, MSS={advertised:?}, MTU={mtu}"
            );
            let packet = packet_receiver.recv().await.unwrap();
            assert_eq!(packet.payload, bytes[..expected]);
            // Retransmitting must preserve the same segmentation limit.
            let TransportHeader::Tcp(header) = packet.transport else {
                panic!("not TCP")
            };
            // Leave room in the window to isolate retransmission sizing
            // from the existing send-window accounting.
            stream.tcb.change_send_window(u16::MAX);
            stream.tcb.retransmission = Some(header.sequence_number);
            poll_fn(|cx| stream.as_mut().poll_flush_inner(cx))
                .await
                .unwrap();
            let retry = packet_receiver.recv().await.unwrap();
            assert_eq!(retry.payload, bytes[..expected]);
        }
    }

    #[tokio::test]
    async fn zero_mss_syn_is_rejected() {
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
        let (_stream_sender, stream_receiver) = async_channel::unbounded();
        let mut syn = etherparse::TcpHeader::new(1000, 2000, 999, u16::MAX);
        syn.syn = true;
        syn.set_options(&[TcpOptionElement::MaximumSegmentSize(0)])
            .unwrap();
        let result = IpStackTcpStream::new(
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
            (&syn).into(),
            packet_sender,
            stream_receiver,
            16384,
            Duration::from_secs(60),
        );
        assert!(result.unwrap_err().to_string().contains("zero MSS"));
    }

    #[tokio::test]
    async fn effective_mss_accounts_for_header_options() {
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
        let mut stream = unestablished_stream(packet_sender);
        stream.mtu = 16384;
        stream.peer_mss = 1460;
        assert_eq!(stream.calculate_payload_len(20, 32), 1448);
        assert_eq!(stream.calculate_payload_len(24, 32), 1444);
        stream.src_addr = "[fd00::1]:1000".parse().unwrap();
        stream.dst_addr = "[fd00::2]:2000".parse().unwrap();
        stream.peer_mss = 1440;
        assert_eq!(stream.calculate_payload_len(40, 32), 1428);
        assert_eq!(stream.calculate_payload_len(48, 32), 1420);
        stream.peer_mss = 1;
        assert_eq!(stream.calculate_payload_len(40, 32), 0);
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_handshake_wakes_writer_only_on_ack_reset_or_timeout() {
        for outcome in ["ack", "reset", "timeout"] {
            let (output, packets) = async_channel::unbounded();
            let (input, incoming) = async_channel::unbounded();
            let mut syn = etherparse::TcpHeader::new(1000, 2000, 999, u16::MAX);
            syn.syn = true;
            let timeout = Duration::from_secs(5);
            let mut stream = Box::pin(
                IpStackTcpStream::new(
                    "10.0.0.1:1000".parse().unwrap(),
                    "10.0.0.2:2000".parse().unwrap(),
                    (&syn).into(),
                    output,
                    incoming,
                    1500,
                    timeout,
                )
                .unwrap(),
            );
            let count = Arc::new(WakeCounter::default());
            let waker = Waker::from(count.clone());
            let mut writer = Context::from_waker(&waker);
            assert!(stream
                .as_mut()
                .poll_write_inner(&mut writer, b"hello")
                .is_pending());

            let read_waker = Waker::from(Arc::new(WakeCounter::default()));
            let mut reader = Context::from_waker(&read_waker);
            let mut buf = [0];
            assert!(stream
                .as_mut()
                .poll_read_inner(&mut reader, &mut buf)
                .is_pending());
            assert!(
                matches!(packets.try_recv().unwrap().transport, TransportHeader::Tcp(tcp) if tcp.syn && tcp.ack)
            );
            assert!(stream
                .as_mut()
                .poll_write_inner(&mut writer, b"hello")
                .is_pending());
            assert_eq!(count.0.load(Ordering::Relaxed), 0);

            if outcome == "timeout" {
                tokio::time::advance(timeout + Duration::from_millis(1)).await;
            } else {
                let mut reply = etherparse::TcpHeader::new(1000, 2000, 1000, u16::MAX);
                reply.ack = true;
                reply.rst = outcome == "reset";
                reply.acknowledgment_number = stream.tcb.get_seq();
                input
                    .try_send(NetworkPacket {
                        ip: IpHeader::Ipv4(
                            Ipv4Header::new(20, TTL, IpNumber::TCP, [10, 0, 0, 1], [10, 0, 0, 2])
                                .unwrap(),
                        ),
                        transport: TransportHeader::Tcp(reply),
                        payload: Vec::new(),
                        teardown_generation: None,
                    })
                    .unwrap();
            }
            let read = stream.as_mut().poll_read_inner(&mut reader, &mut buf);
            assert_eq!(count.0.load(Ordering::Relaxed), 1, "{outcome}");
            let write = stream.as_mut().poll_write_inner(&mut writer, b"hello");
            if outcome == "ack" {
                assert!(read.is_pending());
                assert!(matches!(write, Poll::Ready(Ok(5))));
            } else {
                assert!(matches!(read, Poll::Ready(Err(_))));
                assert!(
                    matches!(write, Poll::Ready(Err(e)) if e.kind() == ErrorKind::NotConnected)
                );
            }
        }
    }

    #[tokio::test]
    async fn partial_reads_keep_remaining_payload() {
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
        let (_stream_sender, stream_receiver) = async_channel::unbounded();
        let mut tcb = Tcb::new(1000, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        tcb.add_unordered_packet(1000, vec![1, 2, 3, 4, 5]);

        let mut stream = Box::pin(IpStackTcpStream {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            shutdown: Shutdown::None,
            write_notify: None,
            session_generation: 1,
        });

        let mut first = [0; 2];
        let n = poll_fn(|cx| stream.as_mut().poll_read_inner(cx, &mut first))
            .await
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(first, [1, 2]);

        let mut second = [0; 8];
        let n = poll_fn(|cx| stream.as_mut().poll_read_inner(cx, &mut second))
            .await
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(&second[..3], &[3, 4, 5]);
    }

    #[tokio::test]
    async fn psh_fin_ece_ack_preserves_payload_and_wakes_blocked_writer() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let (stream_sender, stream_receiver) = async_channel::unbounded();
        let mut tcb = Tcb::new(1000, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        let first_unacked_seq = tcb.get_seq();
        tcb.add_inflight_packet(first_unacked_seq, vec![0; 16]);
        let peer_ack = tcb.get_seq();

        let wake_counter = Arc::new(WakeCounter::default());
        let mut stream = Box::pin(IpStackTcpStream {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            shutdown: Shutdown::None,
            write_notify: Some(Waker::from(wake_counter.clone())),
            session_generation: 1,
        });

        let payload = vec![1];
        let ip = Ipv4Header::new(
            payload.len() as u16,
            TTL,
            IpNumber::TCP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        )
        .unwrap();
        let mut tcp = etherparse::TcpHeader::new(1000, 2000, 1000, u16::MAX);
        tcp.psh = true;
        tcp.fin = true;
        tcp.ece = true;
        tcp.ack = true;
        tcp.acknowledgment_number = peer_ack;
        stream_sender
            .try_send(NetworkPacket {
                ip: IpHeader::Ipv4(ip),
                transport: TransportHeader::Tcp(tcp),
                payload,
                teardown_generation: None,
            })
            .unwrap();

        let mut read_buf = [0];
        let read = poll_fn(|cx| stream.as_mut().poll_read_inner(cx, &mut read_buf))
            .await
            .unwrap();

        assert_eq!(read, 1);
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(stream.write_notify.is_none());
        assert_eq!(stream.tcb.get_last_ack(), peer_ack);
        assert!(stream.tcb.inflight_packets.is_empty());
        assert_eq!(*stream.tcb.get_state(), TcpState::FinWait1(true));

        let payload_ack = packet_receiver.recv().await.unwrap();
        let TransportHeader::Tcp(payload_ack) = payload_ack.transport else {
            panic!("expected TCP ACK");
        };
        assert_eq!(payload_ack.acknowledgment_number, 1002);

        let mut empty = [];
        assert!(poll_once(poll_fn(|cx| stream
            .as_mut()
            .poll_read_inner(cx, &mut empty)))
        .await
        .is_none());
        let our_fin = packet_receiver.recv().await.unwrap();
        let TransportHeader::Tcp(our_fin) = our_fin.transport else {
            panic!("expected TCP FIN");
        };
        assert!(our_fin.fin);
        assert_eq!(our_fin.acknowledgment_number, 1002);
    }

    #[tokio::test]
    async fn writes_use_only_the_remaining_advertised_window() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let (_stream_sender, stream_receiver) = async_channel::bounded(64);
        let mut tcb = Tcb::new(1000, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        tcb.change_send_window(60_000);
        tcb.change_send_window(10);
        let mut stream = Box::pin(IpStackTcpStream {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            shutdown: Shutdown::None,
            write_notify: None,
            session_generation: 1,
        });

        let first = poll_fn(|cx| stream.as_mut().poll_write_inner(cx, b"12345678"))
            .await
            .unwrap();
        let second = poll_fn(|cx| stream.as_mut().poll_write_inner(cx, b"abcdef"))
            .await
            .unwrap();

        assert_eq!(first, 8);
        assert_eq!(second, 2);
        assert_eq!(packet_receiver.recv().await.unwrap().payload.len(), 8);
        assert_eq!(packet_receiver.recv().await.unwrap().payload.len(), 2);
        assert_eq!(stream.tcb.get_available_send_window(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_packet_does_not_refresh_idle_timeout() {
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
        let (stream_sender, stream_receiver) = async_channel::bounded(64);
        let mut tcb = Tcb::new(1000, Duration::from_secs(5));
        tcb.change_state(TcpState::Established);
        let invalid_ack = tcb.get_seq().wrapping_add(100);
        let mut stream = Box::pin(IpStackTcpStream {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            shutdown: Shutdown::None,
            write_notify: None,
            session_generation: 1,
        });

        tokio::time::advance(Duration::from_secs(4)).await;
        let ip = Ipv4Header::new(0, TTL, IpNumber::TCP, [10, 0, 0, 1], [10, 0, 0, 2]).unwrap();
        let mut tcp = etherparse::TcpHeader::new(1000, 2000, 1000, u16::MAX);
        tcp.ack = true;
        tcp.acknowledgment_number = invalid_ack;
        stream_sender
            .try_send(NetworkPacket {
                ip: IpHeader::Ipv4(ip),
                transport: TransportHeader::Tcp(tcp),
                payload: Vec::new(),
                teardown_generation: None,
            })
            .unwrap();

        let mut empty = [];
        assert!(poll_once(poll_fn(|cx| stream
            .as_mut()
            .poll_read_inner(cx, &mut empty)))
        .await
        .is_none());
        tokio::time::advance(Duration::from_secs(2)).await;
        let error = poll_fn(|cx| stream.as_mut().poll_read_inner(cx, &mut empty))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    fn unestablished_stream(packet_sender: PacketSender) -> IpStackTcpStream {
        let (_stream_sender, stream_receiver) = async_channel::unbounded();
        // A fresh Tcb is in SynReceived(false): the SYN arrived but we have not
        // sent a SYN-ACK yet (i.e. the application never accepted/read it).
        let tcb = Tcb::new(1000, Duration::from_secs(60));
        assert_eq!(*tcb.get_state(), TcpState::SynReceived(false));
        IpStackTcpStream {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            shutdown: Shutdown::None,
            write_notify: None,
            session_generation: 1,
        }
    }

    fn tcp_flags_of(pkt: &crate::packet::NetworkPacket) -> (bool, bool, bool, bool) {
        match &pkt.transport {
            crate::packet::TransportHeader::Tcp(h) => (h.syn, h.ack, h.rst, h.fin),
            _ => panic!("expected a TCP packet"),
        }
    }

    // Closing a connection that was never accepted (no SYN-ACK ever sent) must
    // stay completely silent, so the peer's SYN goes unanswered and its Happy
    // Eyeballs can fall back. Previously this synthesized a SYN-ACK then a FIN,
    // making a dead path look like it briefly connected and then closed.
    #[tokio::test]
    async fn closing_unaccepted_stream_is_silent() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let mut stream = Box::pin(unestablished_stream(packet_sender));
        let res = poll_fn(|cx| stream.as_mut().poll_close_inner(cx)).await;
        assert!(res.is_ok());
        assert!(
            packet_receiver.try_recv().is_err(),
            "closing an unaccepted stream must not emit any packet (no SYN-ACK)"
        );
    }

    // A stray (non-SYN) packet for an unknown flow must be answered with a
    // RST whose sequence number equals the stray packet's acknowledgment
    // number (the peer's RCV.NXT). Anything else fails the peer kernel's
    // RFC 5961 in-window check, is answered with a challenge ACK, and leaves
    // the peer's connection alive-but-wedged indefinitely.
    #[tokio::test]
    async fn stray_packet_rst_echoes_acknowledgment_number() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let (_stream_sender, stream_receiver) = async_channel::unbounded();
        let mut header = etherparse::TcpHeader::new(1000, 2000, 123456, 64000);
        header.ack = true;
        header.acknowledgment_number = 987654;
        let res = IpStackTcpStream::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            (&header).into(),
            packet_sender,
            stream_receiver,
            1500,
            Duration::from_secs(60),
        );
        assert!(
            res.is_err(),
            "a stray non-SYN packet must not create a stream"
        );
        let pkt = packet_receiver
            .try_recv()
            .expect("stray packet must be answered with a RST");
        let crate::packet::TransportHeader::Tcp(tcp) = &pkt.transport else {
            panic!("expected a TCP packet");
        };
        assert!(tcp.rst);
        assert_eq!(
            tcp.sequence_number, 987654,
            "RST seq must echo the stray packet's ack number"
        );
    }

    // reset() on an unaccepted connection must send a RST (not complete the
    // handshake), so the peer's connect() fails fast with "connection refused".
    #[tokio::test]
    async fn reset_sends_rst_not_syn_ack() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let mut stream = unestablished_stream(packet_sender);
        stream.reset();
        let pkt = packet_receiver
            .try_recv()
            .expect("reset must emit a RST packet");
        let (syn, ack, rst, _fin) = tcp_flags_of(&pkt);
        assert!(rst, "reset must set RST");
        assert!(ack, "reset must set ACK");
        assert!(!syn, "reset must not complete the handshake");
    }
}
