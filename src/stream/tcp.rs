use crate::{
    packet::{
        tcp_flags::{ACK, FIN, NON, PSH, RST, SYN},
        IpHeader, IpStackPacketProtocol, NetworkPacket, TcpHeaderWrapper, TransportHeader,
    },
    stream::tcb::{PacketStatus, Tcb, TcpState},
    PacketReceiver, PacketSender, DROP_TTL, TTL,
};

use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel};
use futures_lite::StreamExt;
use log::{error, trace, warn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::{
    cmp,
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

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
    shutdown: Shutdown,
    write_notify: Option<Waker>,
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
        let stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            packet_to_send: None,
            tcb: Tcb::new(tcp.inner().sequence_number + 1, tcp_timeout),
            mtu,
            shutdown: Shutdown::None,
            write_notify: None,
        };
        if tcp.inner().syn {
            return Ok(stream);
        }
        if tcp.inner().rst {
            warn!("not responding RST with RST")
        } else {
            let pkt = stream.create_rev_packet(RST | ACK, TTL, None, Vec::new())?;
            if let Err(err) = stream.packet_sender.try_send(pkt) {
                warn!("Error sending RST/ACK packet: {:?}", err);
            }
        }
        anyhow::bail!(
            "stray TCP packet src_addr={src_addr} dst_addr={dst_addr}, tcp={:?}",
            tcp
        )
    }

    fn calculate_payload_len(&self, ip_header_size: u16, tcp_header_size: u16) -> u16 {
        cmp::min(
            self.tcb.get_send_window(),
            self.mtu.saturating_sub(ip_header_size + tcp_header_size),
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
        self.tcb.change_state(TcpState::Closed);
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
            // unacknowledged packet if necessary.
            let poll_rto = !self.tcb.inflight_packets.is_empty();
            if poll_rto && self.tcb.poll_rto(cx) {
                let pkt = self.tcb.inflight_packets.first().unwrap();
                if let Ok(rp) = self.create_rev_packet(PSH | ACK, TTL, pkt.seq, pkt.payload.clone())
                {
                    tracing::warn!(
                        "retransmitting {}; this is unusual unless buffers are full",
                        pkt.seq
                    );
                    let _ = self.packet_sender.try_send(rp);
                }
            }
            if let Some(packet) = self.packet_to_send.take() {
                self.packet_sender
                    .try_send(packet)
                    .or(Err(ErrorKind::UnexpectedEof))?;
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
                self.tcb.change_state(TcpState::Closed);
                self.shutdown.ready();
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
                self.packet_sender
                    .try_send(
                        self.create_rev_packet(RST | ACK, TTL, None, Vec::new())
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                    )
                    .or(Err(ErrorKind::UnexpectedEof))?;
                self.tcb.change_state(TcpState::Closed);
                self.shutdown.ready();
                return Poll::Ready(Err(Error::from(ErrorKind::TimedOut)));
            }
            if *self.tcb.get_state() == TcpState::FinWait1(true) {
                self.packet_to_send = Some(
                    self.create_rev_packet(FIN | ACK, TTL, None, Vec::new())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                );
                self.tcb.add_seq_one();
                self.tcb.add_ack(1);
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
                    self.tcb.reset_timeout();
                    let IpStackPacketProtocol::Tcp(t) = p.transport_protocol() else {
                        unreachable!()
                    };
                    if t.flags() & RST != 0 {
                        self.packet_to_send = Some(
                            self.create_rev_packet(NON, DROP_TTL, None, Vec::new())
                                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                        );
                        self.tcb.change_state(TcpState::Closed);
                        self.shutdown.ready();
                        return Poll::Ready(Err(Error::from(ErrorKind::ConnectionReset)));
                    }
                    if self.tcb.check_pkt_type(&t, &p.payload) == PacketStatus::Invalid {
                        continue;
                    }

                    if *self.tcb.get_state() == TcpState::SynReceived(true) {
                        if t.flags() == ACK {
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);
                            self.tcb.change_send_window(t.inner().window_size);
                            self.tcb.change_state(TcpState::Established);
                        }
                    } else if *self.tcb.get_state() == TcpState::Established {
                        if t.flags() == ACK {
                            match self.tcb.check_pkt_type(&t, &p.payload) {
                                PacketStatus::WindowUpdate => {
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.write_notify {
                                        n.wake_by_ref();
                                        self.write_notify = None;
                                    };
                                    continue;
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
                                    continue;
                                }
                                PacketStatus::RetransmissionRequest => {
                                    self.tcb.change_send_window(t.inner().window_size);
                                    self.tcb.retransmission = Some(t.inner().acknowledgment_number);
                                    if matches!(self.as_mut().poll_flush_inner(cx), Poll::Pending) {
                                        return Poll::Pending;
                                    }
                                    continue;
                                }
                                PacketStatus::NewPacket => {
                                    // if t.inner().sequence_number != self.tcb.get_ack() {
                                    //     dbg!(t.inner().sequence_number);
                                    //     self.packet_to_send = Some(self.create_rev_packet(
                                    //         ACK,
                                    //         TTL,
                                    //         None,
                                    //         Vec::new(),
                                    //     )?);
                                    //     continue;
                                    // }

                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb
                                        .add_unordered_packet(t.inner().sequence_number, p.payload);

                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.write_notify {
                                        n.wake_by_ref();
                                        self.write_notify = None;
                                    };
                                    continue;
                                }
                                PacketStatus::Ack => {
                                    self.tcb.change_last_ack(t.inner().acknowledgment_number);
                                    self.tcb.change_send_window(t.inner().window_size);
                                    if let Some(ref n) = self.write_notify {
                                        n.wake_by_ref();
                                        self.write_notify = None;
                                    };
                                    continue;
                                }
                            };
                        }
                        if t.flags() == (FIN | ACK) {
                            self.tcb.add_ack(1);
                            self.packet_to_send = Some(
                                self.create_rev_packet(ACK, TTL, None, Vec::new())
                                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                            );
                            self.tcb.change_state(TcpState::FinWait1(true));
                            continue;
                        }
                        if t.flags() == (PSH | ACK) {
                            if !matches!(
                                self.tcb.check_pkt_type(&t, &p.payload),
                                PacketStatus::NewPacket
                            ) {
                                continue;
                            }
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);

                            if p.payload.is_empty()
                                || self.tcb.get_ack() != t.inner().sequence_number
                            {
                                continue;
                            }

                            self.tcb.change_send_window(t.inner().window_size);

                            self.tcb
                                .add_unordered_packet(t.inner().sequence_number, p.payload);
                            continue;
                        }
                    } else if *self.tcb.get_state() == TcpState::FinWait1(false) {
                        if t.flags() == ACK {
                            self.tcb.change_last_ack(t.inner().acknowledgment_number);
                            self.tcb.add_ack(1);
                            self.tcb.change_state(TcpState::FinWait2(true));
                            continue;
                        } else if t.flags() == (FIN | ACK) {
                            self.tcb.add_ack(1);
                            self.packet_to_send = Some(
                                self.create_rev_packet(ACK, TTL, None, Vec::new())
                                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                            );
                            self.tcb.change_send_window(t.inner().window_size);
                            self.tcb.change_state(TcpState::FinWait2(true));
                            continue;
                        }
                    } else if *self.tcb.get_state() == TcpState::FinWait2(true) {
                        if t.flags() == ACK {
                            self.tcb.change_state(TcpState::FinWait2(false));
                        } else if t.flags() == (FIN | ACK) {
                            self.packet_to_send = Some(
                                self.create_rev_packet(ACK, TTL, None, Vec::new())
                                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                            );
                            self.tcb.change_state(TcpState::FinWait2(false));
                        }
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
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
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            return Poll::Ready(Err(Error::from(ErrorKind::NotConnected)));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.tcb.get_send_window() == 0
            || (self.tcb.get_send_window() as u64) < self.tcb.get_avg_send_window() / 2
            || self.tcb.is_send_buffer_full()
        {
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
            self.shutdown.ready();
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
    use std::{
        future::poll_fn,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

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
            shutdown: Shutdown::None,
            write_notify: None,
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

    fn unestablished_stream(
        packet_sender: PacketSender,
    ) -> IpStackTcpStream {
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
            shutdown: Shutdown::None,
            write_notify: None,
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
