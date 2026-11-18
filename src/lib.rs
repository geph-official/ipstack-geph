use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport},
};
use async_channel::{Receiver, Sender, TrySendError};
use bytes::Bytes;
use log::trace;
use moka::{sync::Cache, Expiry};
use packet::{NetworkPacket, NetworkTuple, TransportHeader};
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
const EGRESS_QUEUE_CAPACITY: usize = 4096;
const PACKET_BATCH: usize = 64;
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
    let sessions = LiveSessions(
        Cache::builder()
            .max_capacity(MAX_SESSIONS)
            .expire_after(SessionExpiry {
                tcp_timeout: config.tcp_timeout,
                udp_timeout: config.udp_timeout,
            })
            .eviction_listener(|_, entry: SessionEntry, _| {
                entry.sender.close();
            })
            .build(),
    );
    let sessions = Mutex::new(sessions);
    let (pkt_sender, pkt_receiver) = async_channel::bounded::<NetworkPacket>(EGRESS_QUEUE_CAPACITY);

    let accept_loop = async {
        loop {
            for _ in 0..PACKET_BATCH {
                let packet = recv_packet.recv().await?;
                let mut sessions = sessions.lock();
                if let Some(stream) =
                    process_device_read(&packet, &mut sessions.0, pkt_sender.clone(), &config)
                {
                    match accept_sender.try_send(stream) {
                        Ok(()) => {}
                        Err(TrySendError::Full(stream)) => {
                            remove_stream_session(&stream, &mut sessions.0);
                            trace!("dropping new stream because the accept queue is full");
                        }
                        Err(TrySendError::Closed(stream)) => {
                            remove_stream_session(&stream, &mut sessions.0);
                            anyhow::bail!("accept channel closed");
                        }
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    };

    let inject_loop = async {
        loop {
            for _ in 0..PACKET_BATCH {
                let packet = pkt_receiver.recv().await?;
                process_upstream_recv(packet, &mut sessions.lock().0, send_packet.clone())?;
            }
            tokio::task::yield_now().await;
        }
    };

    let maintenance_loop = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sessions.lock().0.run_pending_tasks();
        }
    };

    futures_lite::future::race(
        futures_lite::future::race(accept_loop, inject_loop),
        maintenance_loop,
    )
    .await
}

struct LiveSessions(SessionCollection);

impl Drop for LiveSessions {
    fn drop(&mut self) {
        self.0.invalidate_all();
        self.0.run_pending_tasks();
    }
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

    if let TransportHeader::Unknown {
        protocol,
        fragmented,
    } = packet.transport
    {
        if fragmented {
            return None;
        }
        return Some(IpStackStream::UnknownTransport(
            IpStackUnknownTransport::new(
                packet.src_addr().ip(),
                packet.dst_addr().ip(),
                packet.payload,
                protocol,
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
            let stream = stream.with_session_generation(session_generation);
            let _ = stream.stream_sender().try_send(packet);
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
    if let Some(generation) = packet.session_generation {
        let tuple = packet.reverse_network_tuple();
        let Some(session) = sessions.get(&tuple) else {
            return Ok(());
        };
        if session.generation != generation {
            return Ok(());
        }
        if packet.ttl() == DROP_TTL {
            session.sender.close();
            sessions.invalidate(&tuple);
            return Ok(());
        }
    } else if packet.ttl() == DROP_TTL {
        return Ok(());
    }
    let Ok(packet_bytes) = packet.to_bytes() else {
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
        if let Some(session) = sessions.remove(&tuple) {
            session.sender.close();
        }
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
            extensions: Vec::new(),
            session_generation: None,
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
        drop_packet.session_generation = Some(1);
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
        stale_drop.session_generation = Some(1);
        let (device_sender, _device_receiver) = async_channel::unbounded();

        process_upstream_recv(stale_drop, &mut sessions, device_sender).unwrap();

        assert_eq!(sessions.get(&tuple).unwrap().generation, 2);
    }

    #[test]
    fn replacing_a_session_rejects_queued_packets_from_the_previous_stream() {
        let mut sessions: SessionCollection = Cache::new(8);
        let (sender, receiver) = async_channel::unbounded();
        let mut reply = NetworkPacket::parse(&udp_packet(2000, 1000, b"reply")).unwrap();
        sessions.insert(
            reply.reverse_network_tuple(),
            SessionEntry {
                sender,
                generation: 2,
            },
        );
        let (device, output) = async_channel::unbounded();
        reply.session_generation = Some(1);
        process_upstream_recv(reply.clone(), &mut sessions, device.clone()).unwrap();
        assert!(output.is_empty());

        // A final packet queued before the stream was dropped remains valid.
        drop(receiver);
        reply.session_generation = Some(2);
        process_upstream_recv(reply, &mut sessions, device).unwrap();
        assert!(output.try_recv().is_ok());
    }

    #[tokio::test]
    async fn dropping_stack_closes_an_accepted_udp_stream() {
        let (input, capture) = async_channel::bounded(1);
        let (inject, _output) = async_channel::bounded(1);
        let stack = IpStack::new(IpStackConfig::default(), capture, inject);
        input
            .send(udp_packet(1000, 2000, b"hello").into())
            .await
            .unwrap();
        let IpStackStream::Udp(stream) = stack.accept().await.unwrap() else {
            panic!("expected UDP stream");
        };
        assert_eq!(stream.recv().await.unwrap().as_ref(), b"hello");
        drop(stack);
        let result = tokio::time::timeout(Duration::from_secs(1), stream.recv()).await;
        assert!(matches!(result, Ok(Err(_))));
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

    #[tokio::test(start_paused = true)]
    async fn tcp_write_first_recovers_lost_syn_ack_and_delivers_third_packet_payload() {
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

        let mut empty = [0];
        let first_write =
            poll_once(poll_fn(|cx| stream.as_mut().poll_write(cx, b"server-data"))).await;
        assert!(first_write.is_none());

        let syn_ack = packet_receiver.try_recv().unwrap();
        let syn_ack_tcp = packet_tcp_header(&syn_ack);
        assert!(syn_ack_tcp.syn);
        assert!(syn_ack_tcp.ack);
        assert_eq!(syn_ack_tcp.acknowledgment_number, 1001);

        tokio::time::advance(Duration::from_millis(101)).await;
        assert!(
            poll_once(poll_fn(|cx| stream.as_mut().poll_write(cx, b"server-data")))
                .await
                .is_none()
        );
        let retry = packet_receiver.try_recv().unwrap();
        assert_eq!(packet_tcp_header(&retry), syn_ack_tcp);

        let client_ack = tcp_packet(
            1000,
            2000,
            1001,
            Some(syn_ack_tcp.sequence_number + 1),
            tcp_flags::ACK,
            b"first",
        );
        assert!(
            process_device_read(&client_ack, &mut sessions, packet_sender.clone(), &config)
                .is_none()
        );
        let written = poll_fn(|cx| stream.as_mut().poll_write(cx, b"server-data"))
            .await
            .unwrap();
        assert_eq!(written, b"server-data".len());

        let outbound = packet_receiver.try_recv().unwrap();
        let outbound_tcp = packet_tcp_header(&outbound);
        assert!(outbound_tcp.psh);
        assert!(outbound_tcp.ack);
        assert_eq!(outbound.payload, b"server-data");

        let server_next_seq = outbound_tcp
            .sequence_number
            .wrapping_add(outbound.payload.len() as u32);
        let mut initial_data = [0; 5];
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.read_exact(&mut initial_data).await.unwrap();
        assert_eq!(&initial_data, b"first");
        assert_eq!(
            packet_tcp_header(&packet_receiver.try_recv().unwrap()).acknowledgment_number,
            1006
        );

        let ack_server_data =
            tcp_packet(1000, 2000, 1006, Some(server_next_seq), tcp_flags::ACK, &[]);
        assert!(process_device_read(
            &ack_server_data,
            &mut sessions,
            packet_sender.clone(),
            &config
        )
        .is_none());

        // A local shutdown sends FIN, but still permits reading peer data.
        assert!(poll_once(stream.shutdown()).await.is_none());
        let fin = packet_receiver.try_recv().unwrap();
        assert!(packet_tcp_header(&fin).fin);
        assert!(poll_once(stream.read(&mut empty)).await.is_none());
        tokio::time::advance(Duration::from_millis(101)).await;
        assert!(poll_once(stream.shutdown()).await.is_none());
        let retry = packet_receiver.try_recv().unwrap();
        assert_eq!(packet_tcp_header(&retry), packet_tcp_header(&fin));

        let inbound = tcp_packet(
            1000,
            2000,
            1006,
            Some(server_next_seq.wrapping_add(1)),
            tcp_flags::PSH | tcp_flags::ACK,
            b"client-data",
        );
        assert!(
            process_device_read(&inbound, &mut sessions, packet_sender.clone(), &config).is_none()
        );

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
            1006 + b"client-data".len() as u32
        );

        let end = data_ack_tcp.acknowledgment_number;
        let duplicate = tcp_packet(
            1000,
            2000,
            1006,
            Some(server_next_seq.wrapping_add(1)),
            tcp_flags::ACK,
            b"client-data",
        );
        assert!(
            process_device_read(&duplicate, &mut sessions, packet_sender.clone(), &config)
                .is_none()
        );
        assert!(poll_once(stream.read(&mut read_buf)).await.is_none());
        assert_eq!(
            packet_tcp_header(&packet_receiver.try_recv().unwrap()).acknowledgment_number,
            end
        );

        let overlap = tcp_packet(
            1000,
            2000,
            end.wrapping_sub(4),
            Some(server_next_seq.wrapping_add(1)),
            tcp_flags::ACK,
            b"data and more",
        );
        assert!(process_device_read(&overlap, &mut sessions, packet_sender, &config).is_none());
        let n = stream.read(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf[..n], b" and more");
    }
}
