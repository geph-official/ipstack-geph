use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport},
};
use async_channel::{Receiver, Sender};
use async_executor::Executor;
use bytes::Bytes;
use log::trace;
use moka::{sync::Cache, Expiry};
use packet::{NetworkPacket, NetworkTuple};
use parking_lot::Mutex;
use std::time::{Duration, Instant};

pub(crate) type PacketSender = Sender<NetworkPacket>;
pub(crate) type PacketReceiver = Receiver<NetworkPacket>;
pub(crate) type SessionCollection = Cache<NetworkTuple, PacketSender>;

mod packet;
pub mod stream;

const DROP_TTL: u8 = 0;

const TTL: u8 = 64;

pub struct IpStackConfig {
    pub mtu: u16,

    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: 16384,

            tcp_timeout: Duration::from_secs(3600),
            udp_timeout: Duration::from_secs(600),
        }
    }
}

pub struct IpStack {
    accept_receiver: Receiver<IpStackStream>,
    exec: Executor<'static>,
}

impl IpStack {
    pub fn new(
        config: IpStackConfig,
        recv_packet: Receiver<Bytes>,
        send_packet: Sender<Bytes>,
    ) -> IpStack {
        let (accept_sender, accept_receiver) = async_channel::unbounded();
        let exec = Executor::new();
        exec.spawn(run(config, recv_packet, send_packet, accept_sender))
            .detach();

        IpStack {
            accept_receiver,
            exec,
        }
    }

    pub async fn accept(&self) -> anyhow::Result<IpStackStream> {
        self.exec
            .run(async { Ok(self.accept_receiver.recv().await?) })
            .await
    }
}

async fn run(
    config: IpStackConfig,
    recv_packet: Receiver<Bytes>,
    send_packet: Sender<Bytes>,
    accept_sender: Sender<IpStackStream>,
) -> anyhow::Result<()> {
    let sessions: SessionCollection = Cache::builder()
        .expire_after(SessionExpiry {
            tcp_timeout: config.tcp_timeout,
            udp_timeout: config.udp_timeout,
        })
        .build();
    let sessions = Mutex::new(sessions);

    let (pkt_sender, pkt_receiver) = async_channel::unbounded::<NetworkPacket>();

    let accept_loop = async {
        loop {
            let packet = recv_packet.recv().await?;
            let mut sessions = sessions.lock();
            if let Some(stream) =
                process_device_read(&packet, &mut sessions, pkt_sender.clone(), &config)
            {
                let _ = accept_sender.try_send(stream);
            }
        }
    };

    let inject_loop = async {
        loop {
            let packet = pkt_receiver.recv().await?;
            let mut sessions = sessions.lock();
            process_upstream_recv(packet, &mut sessions, send_packet.clone())?;
        }
    };

    futures_lite::future::race(accept_loop, inject_loop).await
}

struct SessionExpiry {
    tcp_timeout: Duration,
    udp_timeout: Duration,
}

impl Expiry<NetworkTuple, PacketSender> for SessionExpiry {
    fn expire_after_create(
        &self,
        key: &NetworkTuple,
        _value: &PacketSender,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(if key.tcp {
            self.tcp_timeout
        } else {
            self.udp_timeout
        })
    }

    fn expire_after_read(
        &self,
        key: &NetworkTuple,
        _value: &PacketSender,
        _read_at: Instant,
        _duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        self.expire_after_create(key, _value, _read_at)
    }

    fn expire_after_update(
        &self,
        key: &NetworkTuple,
        _value: &PacketSender,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        self.expire_after_create(key, _value, _updated_at)
    }
}

fn process_device_read(
    data: &[u8],
    sessions: &mut SessionCollection,
    pkt_sender: PacketSender,
    config: &IpStackConfig,
) -> Option<IpStackStream> {
    let Ok(packet) = NetworkPacket::parse(data) else {
        return Some(IpStackStream::UnknownNetwork(data.to_owned()));
    };

    if let IpStackPacketProtocol::Unknown = packet.transport_protocol() {
        return Some(IpStackStream::UnknownTransport(
            IpStackUnknownTransport::new(
                packet.src_addr().ip(),
                packet.dst_addr().ip(),
                packet.payload,
                &packet.ip,
                config.mtu,
                pkt_sender,
            ),
        ));
    }

    if let Some(sender) = sessions.get(&packet.network_tuple()) {
        let _ = sender.try_send(packet);
        None
    } else {
        let (a, b) = create_stream(packet.clone(), config, pkt_sender)?;
        sessions.insert(packet.network_tuple(), a);
        Some(b)
    }
}

fn create_stream(
    packet: NetworkPacket,
    config: &IpStackConfig,
    pkt_sender: PacketSender,
) -> Option<(PacketSender, IpStackStream)> {
    match packet.transport_protocol() {
        IpStackPacketProtocol::Tcp(h) => {
            match IpStackTcpStream::new(
                packet.src_addr(),
                packet.dst_addr(),
                h,
                pkt_sender,
                config.mtu,
                config.tcp_timeout,
            ) {
                Ok(stream) => Some((stream.stream_sender(), IpStackStream::Tcp(stream))),
                Err(e) => {
                    log::debug!("IpStackTcpStream::new failed \"{}\"", e);

                    None
                }
            }
        }
        IpStackPacketProtocol::Udp => {
            let stream = IpStackUdpStream::new(
                packet.src_addr(),
                packet.dst_addr(),
                pkt_sender,
                config.mtu,
                config.udp_timeout,
            );
            let _ = stream.stream_sender().try_send(packet.clone());
            Some((stream.stream_sender(), IpStackStream::Udp(stream)))
        }
        IpStackPacketProtocol::Unknown => {
            unreachable!()
        }
    }
}

fn process_upstream_recv(
    packet: NetworkPacket,
    sessions: &mut SessionCollection,
    device: Sender<Bytes>,
) -> anyhow::Result<()> {
    if packet.ttl() == 0 {
        sessions.remove(&packet.reverse_network_tuple());
        return Ok(());
    }
    #[allow(unused_mut)]
    let Ok(mut packet_bytes) = packet.to_bytes() else {
        trace!("to_bytes error");
        return Ok(());
    };

    let _ = device.try_send(packet_bytes.into());
    // device.flush().await.unwrap();

    Ok(())
}

pub trait Device {
    fn read_packet(&self) -> Bytes;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{tcp_flags, IpHeader, TransportHeader};
    use etherparse::{IpNumber, Ipv4Header, TcpHeader};
    use futures_lite::{
        future::{poll_fn, poll_once},
        AsyncRead, AsyncWrite,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder =
            etherparse::PacketBuilder::ipv4(Ipv4Addr::LOCALHOST.octets(), [10, 0, 0, 2], 64)
                .udp(src_port, dst_port);
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    fn tcp_packet(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: Option<u32>,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut ip = Ipv4Header::new(
            0,
            64,
            IpNumber::TCP,
            Ipv4Addr::LOCALHOST.octets(),
            [10, 0, 0, 2],
        )
        .unwrap();
        let mut tcp = TcpHeader::new(src_port, dst_port, seq, u16::MAX);
        tcp.syn = flags & tcp_flags::SYN != 0;
        tcp.fin = flags & tcp_flags::FIN != 0;
        tcp.rst = flags & tcp_flags::RST != 0;
        tcp.psh = flags & tcp_flags::PSH != 0;
        tcp.ack = ack.is_some() || flags & tcp_flags::ACK != 0;
        tcp.acknowledgment_number = ack.unwrap_or(0);
        ip.set_payload_len(payload.len() + tcp.header_len())
            .unwrap();
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload).unwrap();

        NetworkPacket {
            ip: IpHeader::Ipv4(ip),
            transport: TransportHeader::Tcp(tcp),
            payload: payload.to_vec(),
        }
        .to_bytes()
        .unwrap()
    }

    fn packet_tcp_header(packet: &NetworkPacket) -> &TcpHeader {
        let TransportHeader::Tcp(tcp) = &packet.transport else {
            panic!("expected TCP packet");
        };
        tcp
    }

    #[test]
    fn session_expiry_uses_protocol_specific_configured_timeout() {
        let expiry = SessionExpiry {
            tcp_timeout: Duration::from_secs(11),
            udp_timeout: Duration::from_secs(7),
        };
        let (sender, _receiver) = async_channel::unbounded();
        let tcp_tuple = NetworkTuple {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1000)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2000)),
            tcp: true,
        };
        let udp_tuple = NetworkTuple {
            tcp: false,
            ..tcp_tuple
        };

        assert_eq!(
            expiry.expire_after_create(&tcp_tuple, &sender, Instant::now()),
            Some(Duration::from_secs(11))
        );
        assert_eq!(
            expiry.expire_after_create(&udp_tuple, &sender, Instant::now()),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn process_device_read_creates_udp_stream_and_routes_later_packets_to_it() {
        let config = IpStackConfig::default();
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
        let mut sessions = Cache::builder()
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .build();

        let first = udp_packet(1000, 2000, b"one");
        let Some(IpStackStream::Udp(stream)) =
            process_device_read(&first, &mut sessions, packet_sender.clone(), &config)
        else {
            panic!("expected first UDP packet to create stream");
        };

        let second = udp_packet(1000, 2000, b"two");
        assert!(process_device_read(&second, &mut sessions, packet_sender, &config).is_none());

        assert_eq!(&*pollster::block_on(stream.recv()).unwrap(), b"one");
        assert_eq!(&*pollster::block_on(stream.recv()).unwrap(), b"two");
    }

    #[test]
    fn process_upstream_recv_drop_ttl_removes_reverse_session() {
        let config = IpStackConfig::default();
        let mut sessions: SessionCollection = Cache::builder()
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .build();

        let raw = udp_packet(1000, 2000, b"payload");
        let packet = NetworkPacket::parse(&raw).unwrap();
        let (sender, _receiver) = async_channel::unbounded();
        let removed_tuple = packet.reverse_network_tuple();
        sessions.insert(removed_tuple, sender);
        assert!(sessions.get(&removed_tuple).is_some());

        let mut drop_packet = packet.clone();
        match &mut drop_packet.ip {
            packet::IpHeader::Ipv4(ip) => ip.time_to_live = DROP_TTL,
            packet::IpHeader::Ipv6(ip) => ip.hop_limit = DROP_TTL,
        }
        let (device_sender, _device_receiver) = async_channel::unbounded();

        process_upstream_recv(drop_packet, &mut sessions, device_sender).unwrap();
        assert!(sessions.get(&removed_tuple).is_none());
    }

    #[test]
    fn tcp_happy_path_handshake_write_ack_and_read_payload() {
        let config = IpStackConfig {
            mtu: 1500,
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(60),
        };
        let (packet_sender, packet_receiver) = async_channel::unbounded();
        let mut sessions = Cache::builder()
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .build();

        let syn = tcp_packet(1000, 2000, 1000, None, tcp_flags::SYN, &[]);
        let Some(IpStackStream::Tcp(stream)) =
            process_device_read(&syn, &mut sessions, packet_sender.clone(), &config)
        else {
            panic!("expected SYN to create TCP stream");
        };
        let mut stream = Box::pin(stream);

        let mut empty = [];
        let first_read = pollster::block_on(poll_once(poll_fn(|cx| {
            stream.as_mut().poll_read(cx, &mut empty)
        })));
        assert!(first_read.is_none());

        let syn_ack = packet_receiver.try_recv().unwrap();
        let syn_ack_tcp = packet_tcp_header(&syn_ack);
        assert!(syn_ack_tcp.syn);
        assert!(syn_ack_tcp.ack);
        assert_eq!(syn_ack_tcp.sequence_number, 100);
        assert_eq!(syn_ack_tcp.acknowledgment_number, 1001);

        let client_ack = tcp_packet(
            1000,
            2000,
            1001,
            Some(syn_ack_tcp.sequence_number + 1),
            tcp_flags::ACK,
            &[],
        );
        assert!(
            process_device_read(&client_ack, &mut sessions, packet_sender.clone(), &config)
                .is_none()
        );
        let establish = pollster::block_on(poll_once(poll_fn(|cx| {
            stream.as_mut().poll_read(cx, &mut empty)
        })));
        assert!(establish.is_none());

        let written =
            pollster::block_on(poll_fn(|cx| stream.as_mut().poll_write(cx, b"server-data")))
                .unwrap();
        assert_eq!(written, b"server-data".len());

        let outbound = packet_receiver.try_recv().unwrap();
        let outbound_tcp = packet_tcp_header(&outbound);
        assert!(outbound_tcp.psh);
        assert!(outbound_tcp.ack);
        assert_eq!(outbound.payload, b"server-data");

        let server_next_seq = outbound_tcp.sequence_number + outbound.payload.len() as u32;
        let ack_server_data =
            tcp_packet(1000, 2000, 1001, Some(server_next_seq), tcp_flags::ACK, &[]);
        assert!(process_device_read(
            &ack_server_data,
            &mut sessions,
            packet_sender.clone(),
            &config
        )
        .is_none());
        let ack_poll = pollster::block_on(poll_once(poll_fn(|cx| {
            stream.as_mut().poll_read(cx, &mut empty)
        })));
        assert!(ack_poll.is_none());

        let inbound = tcp_packet(
            1000,
            2000,
            1001,
            Some(server_next_seq),
            tcp_flags::PSH | tcp_flags::ACK,
            b"client-data",
        );
        assert!(process_device_read(&inbound, &mut sessions, packet_sender, &config).is_none());

        let mut read_buf = [0; 32];
        let read =
            pollster::block_on(poll_fn(|cx| stream.as_mut().poll_read(cx, &mut read_buf))).unwrap();
        assert_eq!(&read_buf[..read], b"client-data");

        let data_ack = packet_receiver.try_recv().unwrap();
        let data_ack_tcp = packet_tcp_header(&data_ack);
        assert!(data_ack_tcp.ack);
        assert_eq!(
            data_ack_tcp.acknowledgment_number,
            1001 + b"client-data".len() as u32
        );
    }
}
