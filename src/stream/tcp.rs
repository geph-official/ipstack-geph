use crate::{
    packet::{
        tcp_flags::{ACK, FIN, NON, PSH, RST, SYN},
        IpHeader, IpStackPacketProtocol, NetworkPacket, TcpHeaderWrapper, TransportHeader,
    },
    stream::tcb::{Tcb, TcpState, READ_BUFFER_SIZE},
    PacketReceiver, PacketSender, DROP_TTL, TTL,
};

use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpOptionElement};
use futures_lite::StreamExt;
use log::{trace, warn};
use parking_lot::Mutex;
use std::{
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{self, Sleep},
};

#[derive(Debug, Default)]
struct Waiters {
    read: Mutex<Option<Waker>>,
    write: Mutex<Option<Waker>>,
}

fn notify(waiter: &Mutex<Option<Waker>>) {
    let waker = waiter.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

impl Wake for Waiters {
    fn wake(self: Arc<Self>) {
        notify(&self.read);
        notify(&self.write);
    }
}

#[derive(Debug, Default)]
struct StreamIo {
    waiters: Arc<Waiters>,
    peer_finished: bool,
    fin_sent: bool,
    error: Option<ErrorKind>,
    persist: Option<Pin<Box<Sleep>>>,
}

#[derive(Debug)]
pub(crate) struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_receiver: Pin<Box<PacketReceiver>>,
    packet_sender: PacketSender,
    tcb: Tcb,
    mtu: u16,
    peer_mss: u16,
    io: StreamIo,
    session_generation: Option<u64>,
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
            tcb: Tcb::new(tcp.inner().sequence_number.wrapping_add(1), tcp_timeout),
            mtu,
            peer_mss,
            io: StreamIo::default(),
            session_generation: None,
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
            let pkt = stream.create_rev_packet(RST | ACK, TTL, rst_seq, &[])?;
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
        self.session_generation = Some(session_generation);
        self
    }

    fn local_mss(&self) -> u16 {
        self.mtu
            .saturating_sub(if self.src_addr.is_ipv4() { 40 } else { 60 })
    }

    fn create_rev_packet(
        &self,
        flags: u8,
        ttl: u8,
        seq: impl Into<Option<u32>>,
        payload: &[u8],
    ) -> anyhow::Result<NetworkPacket> {
        let mut tcp_header = etherparse::TcpHeader::new(
            self.dst_addr.port(),
            self.src_addr.port(),
            seq.into().unwrap_or(self.tcb.get_seq()),
            READ_BUFFER_SIZE as u16,
        );

        tcp_header.acknowledgment_number = self.tcb.get_ack();
        if flags & SYN != 0 {
            tcp_header.syn = true;
            tcp_header.set_options(&[TcpOptionElement::MaximumSegmentSize(
                self.local_mss().max(1),
            )])?;
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
                let len = payload.len() + tcp_header.header_len();
                ip_h.set_payload_length(len)?;

                IpHeader::Ipv6(ip_h)
            }
            _ => unreachable!(),
        };

        match ip_header {
            IpHeader::Ipv4(ref ip_header) => {
                tcp_header.checksum = tcp_header.calc_checksum_ipv4(ip_header, payload)?;
            }
            IpHeader::Ipv6(ref ip_header) => {
                tcp_header.checksum = tcp_header.calc_checksum_ipv6(ip_header, payload)?;
            }
        }
        Ok(NetworkPacket {
            ip: ip_header,
            transport: TransportHeader::Tcp(tcp_header),
            payload: payload.to_vec(),
            extensions: Vec::new(),
            session_generation: self.session_generation,
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
        if let Ok(p) = self.create_rev_packet(RST | ACK, TTL, None, &[]) {
            let _ = self.packet_sender.try_send(p);
        }
        self.close(Some(ErrorKind::ConnectionReset));
    }

    fn close(&mut self, error: Option<ErrorKind>) {
        self.tcb.change_state(TcpState::Closed);
        self.io.error = error;
        notify(&self.io.waiters.read);
        notify(&self.io.waiters.write);
    }

    fn send_segment(&self, flags: u8, seq: u32, data: &[u8]) -> std::io::Result<()> {
        let packet = self
            .create_rev_packet(flags, TTL, seq, data)
            .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
        match self.packet_sender.try_send(packet) {
            // Dropping a wire packet under load is visible to TCP loss recovery.
            Ok(()) | Err(async_channel::TrySendError::Full(_)) => Ok(()),
            Err(async_channel::TrySendError::Closed(_)) => Err(ErrorKind::BrokenPipe.into()),
        }
    }

    fn send_ack(&self) -> std::io::Result<()> {
        self.send_segment(ACK, self.tcb.get_seq(), &[])
    }

    fn process_peer_packet(&mut self, packet: NetworkPacket) -> std::io::Result<()> {
        let IpStackPacketProtocol::Tcp(header) = packet.transport_protocol() else {
            return Ok(());
        };
        let tcp = header.inner();
        if tcp.rst {
            return Err(ErrorKind::ConnectionReset.into());
        }

        if *self.tcb.get_state() == TcpState::SynReceived(true) {
            if tcp.syn && !tcp.ack && tcp.sequence_number.wrapping_add(1) == self.tcb.get_ack() {
                return self.send_segment(SYN | ACK, self.tcb.get_seq().wrapping_sub(1), &[]);
            }
            if !tcp.ack
                || tcp.syn
                || tcp.sequence_number != self.tcb.get_ack()
                || tcp.acknowledgment_number != self.tcb.get_seq()
            {
                return Ok(());
            }
            self.tcb.change_state(TcpState::Established);
        } else if !tcp.ack || tcp.syn {
            return Ok(());
        }

        let ack = tcp.acknowledgment_number;
        if self.tcb.valid_ack(ack) {
            let previous_ack = self.tcb.get_last_ack();
            let previous_window = self.tcb.get_available_send_window();
            self.tcb.change_last_ack(ack);
            self.tcb.change_send_window(tcp.window_size);
            self.tcb.reset_timeout();
            if previous_ack != ack || previous_window != self.tcb.get_available_send_window() {
                notify(&self.io.waiters.write);
            }
        } else if !self.tcb.is_old_ack(ack) {
            return Ok(());
        }

        let sequence = tcp.sequence_number;
        let length = packet.payload.len() as u32;
        if !self.io.peer_finished {
            self.tcb.add_unordered_packet(sequence, packet.payload);
            if tcp.fin {
                self.tcb.record_fin(sequence.wrapping_add(length));
            }
            if self.tcb.consume_pending_fin() {
                self.io.peer_finished = true;
                self.send_ack()?;
                notify(&self.io.waiters.read);
                return Ok(());
            }
            if sequence == self.tcb.get_ack() && length != 0 {
                notify(&self.io.waiters.read);
                return Ok(());
            }
        }

        // Repeat the cumulative ACK for duplicate data, a receive gap, or
        // a window probe. Pure in-sequence ACKs must not create ACK loops.
        if length != 0 || tcp.fin || sequence == self.tcb.get_ack().wrapping_sub(1) {
            self.send_ack()?;
        }
        Ok(())
    }

    // Reads, writes and shutdown can drive TCP. Timers and the packet channel use
    // one waker that notifies both halves even when they run in separate tasks.
    fn drive(&mut self) -> std::io::Result<()> {
        if *self.tcb.get_state() == TcpState::Closed {
            return self.io.error.map_or(Ok(()), |kind| Err(kind.into()));
        }
        let waker = Waker::from(self.io.waiters.clone());
        let mut cx = Context::from_waker(&waker);

        if self.stream_receiver.is_closed() {
            return Err(ErrorKind::NotConnected.into());
        }

        if *self.tcb.get_state() == TcpState::SynReceived(false) {
            self.send_segment(SYN | ACK, self.tcb.get_seq(), &[])?;
            self.tcb.add_control(SYN | ACK);
            self.tcb.change_state(TcpState::SynReceived(true));
        }

        // Always register the waker, including while the timer is disarmed.
        if self.tcb.poll_rto(&mut cx) {
            if self.tcb.rto_exhausted() {
                tracing::debug!(strikes = self.tcb.rto_strikes(), peer = %self.src_addr, "TCP retransmission limit reached");
                let _ = self.send_segment(RST | ACK, self.tcb.get_seq(), &[]);
                return Err(ErrorKind::TimedOut.into());
            }
            if let Some(segment) = self.tcb.inflight_packets.first() {
                self.send_segment(segment.flags, segment.seq, &segment.payload)?;
            }
        }
        if self.tcb.timeout.as_mut().poll(&mut cx).is_ready() {
            let _ = self.send_segment(RST | ACK, self.tcb.get_seq(), &[]);
            return Err(ErrorKind::TimedOut.into());
        }

        for _ in 0..64 {
            match self.stream_receiver.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(packet)) => self.process_peer_packet(packet)?,
                Poll::Ready(None) => return Err(ErrorKind::NotConnected.into()),
                Poll::Pending => return Ok(()),
            }
        }
        waker.wake();
        Ok(())
    }

    fn drive_or_close(&mut self) -> std::io::Result<()> {
        if let Err(error) = self.drive() {
            self.close(Some(error.kind()));
            return Err(error);
        }
        Ok(())
    }

    fn poll_read_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        *self.io.waiters.read.lock() = Some(cx.waker().clone());
        self.drive_or_close()?;

        if !buf.is_empty() {
            if let Some(data) = self.tcb.get_unordered_packets() {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                self.tcb.add_ack(n as u32);
                if n < data.len() {
                    let next = self.tcb.get_ack();
                    self.tcb.add_unordered_packet(next, data[n..].to_vec());
                }
                if self.tcb.consume_pending_fin() {
                    self.io.peer_finished = true;
                }
                self.send_ack()?;
                return Poll::Ready(Ok(n));
            }
        }
        if self.io.peer_finished || *self.tcb.get_state() == TcpState::Closed {
            return Poll::Ready(Ok(0));
        }
        Poll::Pending
    }

    fn poll_write_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        *self.io.waiters.write.lock() = Some(cx.waker().clone());
        self.drive_or_close()?;
        if *self.tcb.get_state() == TcpState::Closed || self.io.fin_sent {
            return Poll::Ready(Err(ErrorKind::NotConnected.into()));
        }
        if *self.tcb.get_state() != TcpState::Established {
            return Poll::Pending;
        }

        let limit = self
            .tcb
            .get_available_send_window()
            .min(self.local_mss())
            .min(self.peer_mss);
        if self.local_mss() == 0 {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "MTU cannot fit TCP data",
            )));
        }
        if limit == 0 && self.tcb.inflight_packets.is_empty() {
            let waker = Waker::from(self.io.waiters.clone());
            let timer = self
                .io
                .persist
                .get_or_insert_with(|| Box::pin(time::sleep(Duration::from_secs(1))));
            if timer
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
            {
                timer
                    .as_mut()
                    .reset(time::Instant::now() + Duration::from_secs(1));
                // A segment immediately before SND.UNA elicits a fresh ACK
                // and window advertisement without consuming sequence space.
                self.send_segment(ACK, self.tcb.get_last_ack().wrapping_sub(1), &[])?;
            }
        }
        if limit == 0 || self.tcb.is_send_buffer_full() {
            return Poll::Pending;
        }

        self.io.persist = None;
        let seq = self.tcb.get_seq();
        let data = &buf[..buf.len().min(limit as usize)];
        self.send_segment(PSH | ACK, seq, data)?;
        self.tcb.add_inflight_packet(seq, data.to_vec());
        self.tcb.reset_timeout();
        Poll::Ready(Ok(data.len()))
    }

    fn poll_close_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Dropping an unused stream (for example after a failed upstream dial)
        // must leave the original SYN unanswered.
        if *self.tcb.get_state() == TcpState::SynReceived(false) {
            self.close(None);
            return Poll::Ready(Ok(()));
        }
        *self.io.waiters.write.lock() = Some(cx.waker().clone());
        self.drive_or_close()?;
        if *self.tcb.get_state() == TcpState::Closed {
            return Poll::Ready(Ok(()));
        }
        if *self.tcb.get_state() != TcpState::Established || !self.tcb.inflight_packets.is_empty() {
            return Poll::Pending;
        }
        if !self.io.fin_sent {
            self.send_segment(FIN | ACK, self.tcb.get_seq(), &[])?;
            self.tcb.add_control(FIN | ACK);
            self.io.fin_sent = true;
        }
        if self.tcb.inflight_packets.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
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
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.io.error.map_or(Ok(()), |kind| Err(kind.into())))
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
        if let Ok(p) = self.create_rev_packet(NON, DROP_TTL, None, &[]) {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
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
            tokio::time::advance(Duration::from_millis(101)).await;
            let mut reader = Context::from_waker(Waker::noop());
            assert!(stream
                .as_mut()
                .poll_read_inner(&mut reader, &mut [])
                .is_pending());
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
    async fn pending_handshake_wakes_writer_on_ack_reset_or_timeout() {
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
                        extensions: Vec::new(),
                        session_generation: None,
                    })
                    .unwrap();
            }
            let read = stream.as_mut().poll_read_inner(&mut reader, &mut buf);
            assert!(count.0.load(Ordering::Relaxed) > 0, "{outcome}");
            let write = stream.as_mut().poll_write_inner(&mut writer, b"hello");
            if outcome == "ack" {
                assert!(read.is_pending());
                assert!(matches!(write, Poll::Ready(Ok(5))));
            } else {
                assert!(matches!(read, Poll::Ready(Err(_))));
                assert!(matches!(write, Poll::Ready(Err(_))));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_reader_wakes_for_first_retransmission_and_writer_probes_zero_window() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let (_input, stream_receiver) = async_channel::unbounded();
        let mut stream = Box::pin(IpStackTcpStream {
            src_addr: "127.0.0.1:1000".parse().unwrap(),
            dst_addr: "127.0.0.1:2000".parse().unwrap(),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            tcb: Tcb::new(1000, Duration::from_secs(60)),
            mtu: 1500,
            peer_mss: 1460,
            io: StreamIo::default(),
            session_generation: None,
        });
        stream.tcb.change_state(TcpState::Established);
        let read_count = Arc::new(WakeCounter::default());
        let write_count = Arc::new(WakeCounter::default());
        let read_waker = Waker::from(read_count.clone());
        let write_waker = Waker::from(write_count.clone());
        let mut reader = Context::from_waker(&read_waker);
        let mut writer = Context::from_waker(&write_waker);
        assert!(stream
            .as_mut()
            .poll_read_inner(&mut reader, &mut [0])
            .is_pending());
        assert!(matches!(
            stream.as_mut().poll_write_inner(&mut writer, b"data"),
            Poll::Ready(Ok(4))
        ));
        let original = packet_receiver.try_recv().unwrap();
        tokio::time::advance(Duration::from_millis(101)).await;
        tokio::task::yield_now().await;
        assert!(read_count.0.load(Ordering::Relaxed) > 0);
        assert!(stream
            .as_mut()
            .poll_read_inner(&mut reader, &mut [0])
            .is_pending());
        assert_eq!(
            packet_receiver.try_recv().unwrap().payload,
            original.payload
        );

        let seq = stream.tcb.get_seq();
        stream.tcb.change_last_ack(seq);
        stream.tcb.change_send_window(0);
        assert!(stream
            .as_mut()
            .poll_write_inner(&mut writer, b"more")
            .is_pending());
        tokio::time::advance(Duration::from_millis(1001)).await;
        assert!(stream
            .as_mut()
            .poll_write_inner(&mut writer, b"more")
            .is_pending());
        let probe = packet_receiver.try_recv().unwrap();
        let TransportHeader::Tcp(header) = probe.transport else {
            panic!("expected TCP probe")
        };
        assert!(header.ack);
        assert_eq!(header.sequence_number, seq.wrapping_sub(1));
        assert!(probe.payload.is_empty());
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
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            io: StreamIo::default(),
            session_generation: Some(1),
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
    async fn peer_fin_preserves_payload_and_allows_a_response() {
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let (stream_sender, stream_receiver) = async_channel::unbounded();
        let mut tcb = Tcb::new(1000, Duration::from_secs(60));
        tcb.change_state(TcpState::Established);
        let first_unacked_seq = tcb.get_seq();
        tcb.add_inflight_packet(first_unacked_seq, vec![0; 16]);
        let peer_ack = tcb.get_seq();

        let mut stream = Box::pin(IpStackTcpStream {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            stream_receiver: Box::pin(stream_receiver),
            packet_sender,
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            io: StreamIo::default(),
            session_generation: Some(1),
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
                extensions: Vec::new(),
                session_generation: None,
            })
            .unwrap();

        let mut read_buf = [0];
        let read = poll_fn(|cx| stream.as_mut().poll_read_inner(cx, &mut read_buf))
            .await
            .unwrap();

        assert_eq!(read, 1);

        assert_eq!(stream.tcb.get_last_ack(), peer_ack);
        assert!(stream.tcb.inflight_packets.is_empty());
        assert!(stream.io.peer_finished);

        let payload_ack = packet_receiver.recv().await.unwrap();
        let TransportHeader::Tcp(payload_ack) = payload_ack.transport else {
            panic!("expected TCP ACK");
        };
        assert_eq!(payload_ack.acknowledgment_number, 1002);

        assert_eq!(stream.as_mut().read(&mut [0]).await.unwrap(), 0);
        assert!(packet_receiver.is_empty());
        assert_eq!(stream.as_mut().write(b"response").await.unwrap(), 8);
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
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            io: StreamIo::default(),
            session_generation: Some(1),
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
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            io: StreamIo::default(),
            session_generation: Some(1),
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
                extensions: Vec::new(),
                session_generation: None,
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
            tcb,
            mtu: 1500,
            peer_mss: u16::MAX,
            io: StreamIo::default(),
            session_generation: Some(1),
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
