use etherparse::{Ipv4Header, Ipv6Header, NetSlice, SlicedPacket, TcpHeader, UdpHeader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub struct NetworkTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: bool,
}
pub mod tcp_flags {
    pub const ACK: u8 = 0b00010000;
    pub const PSH: u8 = 0b00001000;
    pub const RST: u8 = 0b00000100;
    pub const SYN: u8 = 0b00000010;
    pub const FIN: u8 = 0b00000001;
    pub const NON: u8 = 0b00000000;
}

#[derive(Debug, Clone)]
pub(crate) enum IpStackPacketProtocol {
    Tcp(TcpHeaderWrapper),
    Unknown,
    Udp,
}

#[derive(Debug, Clone)]
pub(crate) enum IpHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

#[derive(Debug, Clone)]
pub(crate) enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Unknown {
        protocol: etherparse::IpNumber,
        fragmented: bool,
    },
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub(crate) ip: IpHeader,
    pub(crate) transport: TransportHeader,
    pub(crate) payload: Vec<u8>,
    pub(crate) extensions: Vec<u8>,
    // Only locally generated packets from accepted streams carry this identity.
    pub(crate) session_generation: Option<u64>,
}
impl NetworkPacket {
    pub fn parse(buf: &[u8]) -> anyhow::Result<Self> {
        let p = SlicedPacket::from_ip(buf).map_err(|_| anyhow::anyhow!("InvalidPacket"))?;
        let ip = p.net.ok_or_else(|| anyhow::anyhow!("InvalidPacket"))?;

        let (ip, ip_payload, extensions) = match ip {
            NetSlice::Ipv4(ip) => (
                IpHeader::Ipv4(ip.header().to_header()),
                ip.payload().clone(),
                ip.extensions()
                    .auth
                    .map_or_else(Vec::new, |auth| auth.slice().to_vec()),
            ),
            NetSlice::Ipv6(ip) => (
                IpHeader::Ipv6(ip.header().to_header()),
                ip.payload().clone(),
                ip.extensions().slice().to_vec(),
            ),
        };
        let (transport, payload) = match p.transport {
            Some(etherparse::TransportSlice::Tcp(h)) => {
                (TransportHeader::Tcp(h.to_header()), h.payload())
            }
            Some(etherparse::TransportSlice::Udp(u)) => {
                (TransportHeader::Udp(u.to_header()), u.payload())
            }
            _ => (
                TransportHeader::Unknown {
                    protocol: ip_payload.ip_number,
                    fragmented: ip_payload.fragmented,
                },
                ip_payload.payload,
            ),
        };
        let payload = payload.to_vec();

        Ok(NetworkPacket {
            ip,
            transport,
            payload,
            extensions,
            session_generation: None,
        })
    }
    pub(crate) fn transport_protocol(&self) -> IpStackPacketProtocol {
        match self.transport {
            TransportHeader::Udp(_) => IpStackPacketProtocol::Udp,
            TransportHeader::Tcp(ref h) => IpStackPacketProtocol::Tcp(h.into()),
            _ => IpStackPacketProtocol::Unknown,
        }
    }
    pub fn src_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.source_port,
            TransportHeader::Tcp(tcp) => tcp.source_port,
            _ => 0,
        };
        match &self.ip {
            IpHeader::Ipv4(ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.source)), port),
            IpHeader::Ipv6(ip) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.source)), port),
        }
    }
    pub fn dst_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.destination_port,
            TransportHeader::Tcp(tcp) => tcp.destination_port,
            _ => 0,
        };
        match &self.ip {
            IpHeader::Ipv4(ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.destination)), port),
            IpHeader::Ipv6(ip) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.destination)), port),
        }
    }
    pub fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.src_addr(),
            dst: self.dst_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn reverse_network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.dst_addr(),
            dst: self.src_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        match self.ip {
            IpHeader::Ipv4(ref ip) => ip.write(&mut buf)?,
            IpHeader::Ipv6(ref ip) => ip.write(&mut buf)?,
        }
        buf.extend_from_slice(&self.extensions);
        match self.transport {
            TransportHeader::Tcp(ref h) => h.write(&mut buf)?,
            TransportHeader::Udp(ref h) => h.write(&mut buf)?,
            _ => {}
        };
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }
    pub fn ttl(&self) -> u8 {
        match &self.ip {
            IpHeader::Ipv4(ip) => ip.time_to_live,
            IpHeader::Ipv6(ip) => ip.hop_limit,
        }
    }
}
#[derive(Debug, Clone)]
pub(super) struct TcpHeaderWrapper {
    header: TcpHeader,
}

impl TcpHeaderWrapper {
    pub fn inner(&self) -> &TcpHeader {
        &self.header
    }
}

impl From<&TcpHeader> for TcpHeaderWrapper {
    fn from(header: &TcpHeader) -> Self {
        TcpHeaderWrapper {
            header: header.clone(),
        }
    }
}

// pub struct UdpPacket {
//     header: UdpHeader,
// }

// impl UdpPacket {
//     pub fn inner(&self) -> &UdpHeader {
//         &self.header
//     }
// }

// impl From<&UdpHeader> for UdpPacket {
//     fn from(header: &UdpHeader) -> Self {
//         UdpPacket {
//             header: header.clone(),
//         }
//     }
// }

#[cfg(test)]
pub mod tests {
    use super::*;
    use criterion::{black_box, Criterion};
    use rand::random;
    use std::time::Duration;

    fn create_raw_packet(mtu: usize) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ipv4(random(), random(), random())
            .tcp(random(), random(), random(), random())
            .fin()
            .psh()
            .ack(random());

        let payload_len = mtu - builder.size(0);
        assert_eq!(mtu, builder.size(payload_len));
        let payload: Vec<u8> = (0..payload_len).map(|_| random()).collect();

        let mut buf = Vec::new();
        builder.write(&mut buf, &payload[..]).unwrap();
        assert_eq!(mtu, buf.len());
        buf
    }

    fn create_packet(mtu: usize) -> NetworkPacket {
        let packet = create_raw_packet(mtu);
        NetworkPacket::parse(packet.as_slice()).unwrap()
    }

    fn benchmarks(c: &mut Criterion) {
        for mtu in [64, 1500, 4096, 16384, 65515] {
            let buf = create_raw_packet(mtu);
            c.bench_function(format!("decode_mtu_{mtu}").as_str(), |b| {
                b.iter(|| {
                    let packet = black_box(&buf[..]);
                    let _packet = NetworkPacket::parse(packet).unwrap();
                })
            });
        }

        for mtu in [64, 1500, 4096, 16384, 65515] {
            let packet = create_packet(mtu);
            c.bench_function(format!("encode_mtu_{mtu}").as_str(), |b| {
                b.iter(|| {
                    let packet = black_box(&packet);
                    let _packet = packet.to_bytes();
                })
            });
        }
    }

    #[test]
    fn ipv6_extension_round_trips_and_preserves_the_inner_protocol() {
        let mut raw = vec![0u8; 40];
        raw[0] = 0x60;
        raw[4..6].copy_from_slice(&12u16.to_be_bytes());
        raw[6] = etherparse::IpNumber::IPV6_HEADER_HOP_BY_HOP.0;
        raw[7] = 64;
        raw.extend_from_slice(&[47, 0, 0, 0, 0, 0, 0, 0]);
        raw.extend_from_slice(&[1, 2, 3, 4]);
        let parsed = NetworkPacket::parse(&raw).unwrap();
        assert!(matches!(
            parsed.transport,
            TransportHeader::Unknown {
                protocol: etherparse::IpNumber(47),
                fragmented: false
            }
        ));
        assert_eq!(parsed.payload, [1, 2, 3, 4]);
        assert_eq!(parsed.to_bytes().unwrap(), raw);
    }

    #[test]
    fn bench() {
        // `cargo test --profile bench -j1 -- --nocapture bench -- <benchmark_filter>
        // This workaround allows benchmarking private interfaces with `criterion` in stable rust.
        let args: Vec<String> = std::env::args().collect();
        let filter = args
            .windows(3)
            .filter(|p| p.len() >= 2 && p[0].ends_with("bench") && p[1] == "--")
            .map(|s| s.get(2).unwrap_or(&"".to_string()).clone())
            .next();
        let filter = match filter {
            Some(f) => f,
            None => return,
        };
        let profile_time = args
            .windows(2)
            .filter(|p| p.len() == 2 && p[0] == "--profile-time")
            .map(|s| s[1].as_str())
            .next();

        let mut c = Criterion::default()
            .with_output_color(true)
            .without_plots()
            .with_filter(filter)
            .warm_up_time(Duration::from_secs_f32(0.5))
            .measurement_time(Duration::from_secs_f32(0.5))
            .profile_time(profile_time.map(|s| Duration::from_secs_f32(s.parse().unwrap())));

        benchmarks(&mut c);

        Criterion::default().final_summary();
    }
}
