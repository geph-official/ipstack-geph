use crate::{
    packet::{IpHeader, NetworkPacket, TransportHeader},
    PacketReceiver, PacketSender, TTL,
};
use anyhow::Context;

use bytes::Bytes;
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};

use parking_lot::Mutex;
use std::{net::SocketAddr, pin::Pin, time::Duration};
use tokio::time::{timeout_at, Instant};

#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Pin<Box<PacketReceiver>>,
    pkt_sender: PacketSender,

    udp_timeout: Duration,
    last_activity: Mutex<Instant>,
    session_generation: Option<u64>,
    mtu: u16,
}

impl IpStackUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,

        pkt_sender: PacketSender,
        mtu: u16,
        udp_timeout: Duration,
    ) -> Self {
        let (stream_sender, stream_receiver) = async_channel::bounded::<NetworkPacket>(10);

        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Box::pin(stream_receiver),
            pkt_sender,

            udp_timeout,
            last_activity: Mutex::new(Instant::now()),
            session_generation: None,
            mtu,
        }
    }

    pub(crate) fn with_session_generation(mut self, generation: u64) -> Self {
        self.session_generation = Some(generation);
        self
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        loop {
            anyhow::ensure!(!self.stream_receiver.is_closed(), "UDP session closed");
            let deadline = *self.last_activity.lock() + self.udp_timeout;
            match timeout_at(deadline, self.stream_receiver.recv()).await {
                Ok(packet) => {
                    let packet = packet?;
                    *self.last_activity.lock() = Instant::now();
                    return Ok(packet.payload.into());
                }
                Err(error) => {
                    if Instant::now() >= *self.last_activity.lock() + self.udp_timeout {
                        return Err(error).context("timeout");
                    }
                }
            }
        }
    }

    pub async fn send(&self, bts: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(!self.stream_receiver.is_closed(), "UDP session closed");
        let packet = self
            .create_rev_packet(TTL, bts.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.pkt_sender.send(packet).await?;
        *self.last_activity.lock() = Instant::now();
        Ok(())
    }

    pub(crate) fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    fn create_rev_packet(&self, ttl: u8, payload: Vec<u8>) -> anyhow::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, dst.octets(), src.octets())?;
                if self.mtu < (ip_h.header_len() + UHS) as u16 {
                    anyhow::bail!("message too large");
                }
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);
                if payload.len() > line_buffer as usize {
                    anyhow::bail!("message too large");
                }
                ip_h.set_payload_len(payload.len() + UHS)?;
                let udp_header = UdpHeader::with_ipv4_checksum(
                    self.dst_addr.port(),
                    self.src_addr.port(),
                    &ip_h,
                    &payload,
                )?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload,
                    extensions: Vec::new(),
                    session_generation: self.session_generation,
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                if self.mtu < (ip_h.header_len() + UHS) as u16 {
                    anyhow::bail!("message too large");
                }
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);

                if payload.len() > line_buffer as usize {
                    anyhow::bail!("message too large");
                }

                ip_h.payload_length = (payload.len() + UHS) as u16;
                let udp_header = UdpHeader::with_ipv6_checksum(
                    self.dst_addr.port(),
                    self.src_addr.port(),
                    &ip_h,
                    &payload,
                )?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload,
                    extensions: Vec::new(),
                    session_generation: self.session_generation,
                })
            }
            _ => unreachable!(),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    #[tokio::test(start_paused = true)]
    async fn receive_deadline_counts_outgoing_packets_as_activity() {
        let (sender, _receiver) = async_channel::unbounded();
        let stream = IpStackUdpStream::new(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:2345".parse().unwrap(),
            sender,
            1500,
            Duration::from_secs(5),
        );
        let mut receive = std::pin::pin!(stream.recv());
        assert!(futures_lite::future::poll_once(receive.as_mut())
            .await
            .is_none());
        tokio::time::advance(Duration::from_secs(4)).await;
        stream.send(b"still active").await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(futures_lite::future::poll_once(receive.as_mut())
            .await
            .is_none());
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(receive.await.is_err());
    }

    #[test]
    fn oversized_udp_datagram_returns_error() {
        let (sender, _receiver) = async_channel::unbounded();
        let stream = IpStackUdpStream::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2000),
            sender,
            28,
            Duration::from_secs(60),
        );

        assert!(stream.create_rev_packet(TTL, vec![1]).is_err());
        assert!(stream.create_rev_packet(TTL, Vec::new()).is_ok());
    }

    #[test]
    fn oversized_ipv6_udp_datagram_returns_error() {
        let (sender, _receiver) = async_channel::unbounded();
        let stream = IpStackUdpStream::new(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1000),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 2000),
            sender,
            48,
            Duration::from_secs(60),
        );

        assert!(stream.create_rev_packet(TTL, vec![1]).is_err());
        assert!(stream.create_rev_packet(TTL, Vec::new()).is_ok());
    }
}
