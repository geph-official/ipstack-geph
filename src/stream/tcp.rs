use crate::{
    packet::{
        tcp_flags::{ACK, FIN, NON, PSH, RST, SYN},
        IpHeader, IpStackPacketProtocol, NetworkPacket, TcpHeaderWrapper, TransportHeader,
    },
    stream::tcb::{PacketStatus, Tcb, TcpState},
    PacketReceiver, PacketSender, DROP_TTL, TTL,
};

use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel};
use futures_lite::{AsyncRead, AsyncWrite, StreamExt};
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
        let pkt = stream.create_rev_packet(RST | ACK, TTL, None, Vec::new())?;
        if let Err(err) = stream.packet_sender.try_send(pkt) {
            warn!("Error sending RST/ACK packet: {:?}", err);
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
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
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
            self.tcb.reset_timeout();

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
                self.tcb.add_ack(b.len() as u32);
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);

                self.packet_sender
                    .try_send(
                        self.create_rev_packet(ACK, TTL, None, Vec::new())
                            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?,
                    )
                    .or(Err(ErrorKind::UnexpectedEof))?;
                return Poll::Ready(Ok(n));
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
                                    if matches!(self.as_mut().poll_flush(cx), Poll::Pending) {
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

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(
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
        self.tcb.reset_timeout();

        if (self.tcb.get_send_window() as u64) < self.tcb.get_avg_send_window() / 2
            || self.tcb.is_send_buffer_full()
        {
            self.write_notify = Some(cx.waker().clone());
            return Poll::Pending;
        }

        if self.tcb.retransmission.is_some() {
            self.write_notify = Some(cx.waker().clone());
            if matches!(self.as_mut().poll_flush(cx), Poll::Pending) {
                return Poll::Pending;
            }
        }

        let packet = self
            .create_rev_packet(PSH | ACK, TTL, None, buf.to_vec())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        let seq = self.tcb.get_seq();
        let payload_len = packet.payload.len();
        let payload = packet.payload.clone();
        self.packet_sender
            .try_send(packet)
            .or(Err(ErrorKind::UnexpectedEof))?;
        self.tcb.add_inflight_packet(seq, payload);

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(
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
                panic!("Please report these values at: https://github.com/narrowlink/ipstack/");
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if matches!(self.shutdown, Shutdown::Ready) {
            return Poll::Ready(Ok(()));
        } else if matches!(self.shutdown, Shutdown::None) {
            self.shutdown.pending(cx.waker().clone());
        }
        self.poll_read(cx, &mut []).map(|x| x.map(|_| ()))
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
