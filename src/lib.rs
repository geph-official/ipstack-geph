use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport},
};
use async_channel::{Receiver, Sender, TrySendError};
use bytes::Bytes;
use log::trace;
use moka::{sync::Cache, Expiry};
use packet::{NetworkPacket, NetworkTuple};
use parking_lot::Mutex;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

pub(crate) type PacketSender = Sender<NetworkPacket>;
pub(crate) type PacketReceiver = Receiver<NetworkPacket>;

#[derive(Clone)]
pub(crate) struct SessionEntry {
    sender: PacketSender,
    generation: u64,
}

pub(crate) type SessionCollection = Cache<NetworkTuple, SessionEntry>;

mod packet;
pub mod stream;

const DROP_TTL: u8 = 0;

const TTL: u8 = 64;

const ACCEPT_QUEUE_CAPACITY: usize = 1024;
const MAX_SESSIONS: u64 = 65_536;
static NEXT_SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

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
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl IpStack {
    /// Creates a new `IpStack`. Must be called from within a tokio runtime, as
    /// the background processing loop is spawned onto it.
    pub fn new(
        config: IpStackConfig,
        recv_packet: Receiver<Bytes>,
        send_packet: Sender<Bytes>,
    ) -> IpStack {
        let (accept_sender, accept_receiver) = async_channel::bounded(ACCEPT_QUEUE_CAPACITY);
        let task = tokio::spawn(run(config, recv_packet, send_packet, accept_sender));

        IpStack {
            accept_receiver,
            task,
        }
    }

    pub async fn accept(&self) -> anyhow::Result<IpStackStream> {
        Ok(self.accept_receiver.recv().await?)
    }
}

impl Drop for IpStack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run(
    config: IpStackConfig,
    recv_packet: Receiver<Bytes>,
    send_packet: Sender<Bytes>,
    accept_sender: Sender<IpStackStream>,
) -> anyhow::Result<()> {
    let sessions: SessionCollection = Cache::builder()
        .max_capacity(MAX_SESSIONS)
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
                match accept_sender.try_send(stream) {
                    Ok(()) => {}
                    Err(TrySendError::Full(stream)) => {
                        remove_stream_session(&stream, &mut sessions);
                        trace!("dropping new stream because the accept queue is full");
                    }
                    Err(TrySendError::Closed(stream)) => {
                        remove_stream_session(&stream, &mut sessions);
                        anyhow::bail!("accept channel closed");
                    }
                }
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

impl Expiry<NetworkTuple, SessionEntry> for SessionExpiry {
    fn expire_after_create(
        &self,
        key: &NetworkTuple,
        _value: &SessionEntry,
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
        _value: &SessionEntry,
        _read_at: Instant,
        _duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        self.expire_after_create(key, _value, _read_at)
    }

    fn expire_after_update(
        &self,
        key: &NetworkTuple,
        _value: &SessionEntry,
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

    let tuple = packet.network_tuple();
    if let Some(session) = sessions.get(&tuple) {
        match session.sender.try_send(packet) {
            Ok(()) => return None,
            Err(TrySendError::Full(_packet)) => {
                trace!("dropping packet for congested session {tuple:?}");
                return None;
            }
            Err(TrySendError::Closed(packet)) => {
                trace!("replacing closed session {tuple:?}");
                sessions.remove(&tuple);
                return install_stream(packet, sessions, pkt_sender, config);
            }
        }
    }

    install_stream(packet, sessions, pkt_sender, config)
}

fn install_stream(
    packet: NetworkPacket,
    sessions: &mut SessionCollection,
    pkt_sender: PacketSender,
    config: &IpStackConfig,
) -> Option<IpStackStream> {
    let tuple = packet.network_tuple();
    let generation = NEXT_SESSION_GENERATION.fetch_add(1, Ordering::Relaxed);
    let (sender, stream) = create_stream(packet, config, pkt_sender, generation)?;
    sessions.insert(tuple, SessionEntry { sender, generation });
    Some(stream)
}

fn create_stream(
    packet: NetworkPacket,
    config: &IpStackConfig,
    pkt_sender: PacketSender,
    session_generation: u64,
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
                session_generation,
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
        let tuple = packet.reverse_network_tuple();
        if let (Some(generation), Some(session)) =
            (packet.teardown_generation, sessions.get(&tuple))
        {
            if session.generation == generation {
                sessions.remove(&tuple);
            }
        }
        return Ok(());
    }
    #[allow(unused_mut)]
    let Ok(mut packet_bytes) = packet.to_bytes() else {
        trace!("to_bytes error");
        return Ok(());
    };

    match device.try_send(packet_bytes.into()) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => trace!("dropping packet because the device queue is full"),
        Err(TrySendError::Closed(_)) => anyhow::bail!("device output channel closed"),
    }
    // device.flush().await.unwrap();

    Ok(())
}

fn remove_stream_session(stream: &IpStackStream, sessions: &mut SessionCollection) {
    let tuple = match stream {
        IpStackStream::Tcp(_) => Some(NetworkTuple {
            src: stream.local_addr(),
            dst: stream.peer_addr(),
            tcp: true,
        }),
        IpStackStream::Udp(_) => Some(NetworkTuple {
            src: stream.local_addr(),
            dst: stream.peer_addr(),
            tcp: false,
        }),
        IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => None,
    };
    if let Some(tuple) = tuple {
        sessions.remove(&tuple);
    }
}

pub trait Device {
    fn read_packet(&self) -> Bytes;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{tcp_flags, IpHeader, TransportHeader};
    use etherparse::{IpNumber, Ipv4Header, TcpHeader};
    use futures_lite::future::poll_once;
    use std::future::poll_fn;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    fn current_thread_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

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
            teardown_generation: None,
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
        let session = SessionEntry {
            sender,
            generation: 1,
        };
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
            expiry.expire_after_create(&tcp_tuple, &session, Instant::now()),
            Some(Duration::from_secs(11))
        );
        assert_eq!(
            expiry.expire_after_create(&udp_tuple, &session, Instant::now()),
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

        let rt = current_thread_rt();
        assert_eq!(&*rt.block_on(stream.recv()).unwrap(), b"one");
        assert_eq!(&*rt.block_on(stream.recv()).unwrap(), b"two");
    }

    #[test]
    fn process_device_read_replaces_closed_udp_session_and_replays_packet() {
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
        drop(stream);

        let second = udp_packet(1000, 2000, b"two");
        let Some(IpStackStream::Udp(replacement)) =
            process_device_read(&second, &mut sessions, packet_sender, &config)
        else {
            panic!("expected closed UDP session to be replaced");
        };

        let rt = current_thread_rt();
        assert_eq!(&*rt.block_on(replacement.recv()).unwrap(), b"two");
    }

    #[test]
    fn process_device_read_drops_udp_packet_when_live_session_queue_is_full() {
        let config = IpStackConfig::default();
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
        let mut sessions = Cache::builder()
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .build();

        let first = udp_packet(1000, 2000, b"0");
        let Some(IpStackStream::Udp(stream)) =
            process_device_read(&first, &mut sessions, packet_sender.clone(), &config)
        else {
            panic!("expected first UDP packet to create stream");
        };

        for payload in 1u8..10 {
            let packet = udp_packet(1000, 2000, &[payload]);
            assert!(
                process_device_read(&packet, &mut sessions, packet_sender.clone(), &config)
                    .is_none()
            );
        }

        let dropped = udp_packet(1000, 2000, b"dropped");
        assert!(
            process_device_read(&dropped, &mut sessions, packet_sender.clone(), &config).is_none()
        );

        let rt = current_thread_rt();
        for expected in 0u8..10 {
            let received = rt.block_on(stream.recv()).unwrap();
            if expected == 0 {
                assert_eq!(&*received, b"0");
            } else {
                assert_eq!(&*received, &[expected]);
            }
        }

        let after = udp_packet(1000, 2000, b"after");
        assert!(process_device_read(&after, &mut sessions, packet_sender, &config).is_none());
        assert_eq!(&*rt.block_on(stream.recv()).unwrap(), b"after");
    }

    #[tokio::test]
    async fn process_device_read_bounds_live_tcp_session_queue() {
        let config = IpStackConfig::default();
        let (packet_sender, _packet_receiver) = async_channel::unbounded();
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
        let stream_sender = stream.stream_sender();
        let capacity = stream_sender.capacity().expect("TCP queue must be bounded");

        for _ in 0..capacity + 1 {
            let ack = tcp_packet(1000, 2000, 1001, Some(100), tcp_flags::ACK, &[]);
            assert!(
                process_device_read(&ack, &mut sessions, packet_sender.clone(), &config).is_none()
            );
        }

        assert_eq!(stream_sender.len(), capacity);
        assert_eq!(capacity, 64);
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
        sessions.insert(
            removed_tuple,
            SessionEntry {
                sender,
                generation: 1,
            },
        );
        assert!(sessions.get(&removed_tuple).is_some());

        let mut drop_packet = packet.clone();
        match &mut drop_packet.ip {
            packet::IpHeader::Ipv4(ip) => ip.time_to_live = DROP_TTL,
            packet::IpHeader::Ipv6(ip) => ip.hop_limit = DROP_TTL,
        }
        drop_packet.teardown_generation = Some(1);
        let (device_sender, _device_receiver) = async_channel::unbounded();

        process_upstream_recv(drop_packet, &mut sessions, device_sender).unwrap();
        assert!(sessions.get(&removed_tuple).is_none());
    }

    #[test]
    fn stale_drop_ttl_does_not_remove_replacement_session() {
        let config = IpStackConfig::default();
        let mut sessions: SessionCollection = Cache::builder()
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .build();

        let raw = udp_packet(1000, 2000, b"payload");
        let mut stale_drop = NetworkPacket::parse(&raw).unwrap();
        let tuple = stale_drop.reverse_network_tuple();
        let (sender, _receiver) = async_channel::unbounded();
        sessions.insert(
            tuple,
            SessionEntry {
                sender,
                generation: 2,
            },
        );
        match &mut stale_drop.ip {
            packet::IpHeader::Ipv4(ip) => ip.time_to_live = DROP_TTL,
            packet::IpHeader::Ipv6(ip) => ip.hop_limit = DROP_TTL,
        }
        stale_drop.teardown_generation = Some(1);
        let (device_sender, _device_receiver) = async_channel::unbounded();

        process_upstream_recv(stale_drop, &mut sessions, device_sender).unwrap();

        assert_eq!(sessions.get(&tuple).unwrap().generation, 2);
    }

    #[test]
    fn closed_device_output_channel_is_reported() {
        let config = IpStackConfig::default();
        let mut sessions: SessionCollection = Cache::builder()
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .build();
        let packet = NetworkPacket::parse(&udp_packet(1000, 2000, b"payload")).unwrap();
        let (device_sender, device_receiver) = async_channel::unbounded();
        drop(device_receiver);

        let error = process_upstream_recv(packet, &mut sessions, device_sender).unwrap_err();

        assert!(error.to_string().contains("device output channel closed"));
    }

    #[tokio::test]
    async fn tcp_happy_path_handshake_write_ack_and_read_payload() {
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
        let first_read = poll_once(poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut empty);
            stream.as_mut().poll_read(cx, &mut rb)
        }))
        .await;
        assert!(first_read.is_none());

        let syn_ack = packet_receiver.try_recv().unwrap();
        let syn_ack_tcp = packet_tcp_header(&syn_ack);
        assert!(syn_ack_tcp.syn);
        assert!(syn_ack_tcp.ack);
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
        let establish = poll_once(poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut empty);
            stream.as_mut().poll_read(cx, &mut rb)
        }))
        .await;
        assert!(establish.is_none());

        let written = poll_fn(|cx| stream.as_mut().poll_write(cx, b"server-data"))
            .await
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
        let ack_poll = poll_once(poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut empty);
            stream.as_mut().poll_read(cx, &mut rb)
        }))
        .await;
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
        let read = poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut read_buf);
            match stream.as_mut().poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
        .unwrap();
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
