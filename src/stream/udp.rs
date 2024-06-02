use crate::{
    packet::{IpHeader, NetworkPacket, TransportHeader},
    PacketReceiver, PacketSender, TTL,
};
use anyhow::Context;

use bytes::Bytes;
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};

use smol_timeout::TimeoutExt;
use std::{net::SocketAddr, pin::Pin, time::Duration};

#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Pin<Box<PacketReceiver>>,
    pkt_sender: PacketSender,

    udp_timeout: Duration,
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
        let (stream_sender, stream_receiver) = async_channel::unbounded::<NetworkPacket>();

        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Box::pin(stream_receiver),
            pkt_sender,

            udp_timeout,
            mtu,
        }
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        Ok(self
            .stream_receiver
            .recv()
            .timeout(self.udp_timeout)
            .await
            .context("timeout")??
            .payload
            .into())
    }

    pub async fn send(&self, bts: &[u8]) -> anyhow::Result<()> {
        let packet = self
            .create_rev_packet(TTL, bts.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.pkt_sender.send(packet).await?;
        Ok(())
    }

    pub(crate) fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    fn create_rev_packet(&self, ttl: u8, mut payload: Vec<u8>) -> anyhow::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, dst.octets(), src.octets())?;
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);
                payload.truncate(line_buffer as usize);
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
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);

                payload.truncate(line_buffer as usize);

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
