use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport},
};
use ahash::AHashMap;
use async_channel::{Receiver, Sender};
use async_executor::Executor;
use bytes::Bytes;
use log::{error, trace};
use packet::{NetworkPacket, NetworkTuple};
use parking_lot::Mutex;
use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    time::Duration,
};

pub(crate) type PacketSender = Sender<NetworkPacket>;
pub(crate) type PacketReceiver = Receiver<NetworkPacket>;
pub(crate) type SessionCollection = AHashMap<NetworkTuple, PacketSender>;

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
            mtu: u16::MAX,

            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
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
    let sessions: SessionCollection = AHashMap::new();
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

    match sessions.entry(packet.network_tuple()) {
        Occupied(mut entry) => {
            if let Err(async_channel::TrySendError::Full(e)) = entry.get().try_send(packet) {
                create_stream(e, config, pkt_sender).map(|s| {
                    entry.insert(s.0);
                    s.1
                })
            } else {
                None
            }
        }
        Vacant(entry) => create_stream(packet, config, pkt_sender).map(|s| {
            entry.insert(s.0);
            s.1
        }),
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
                    error!("IpStackTcpStream::new failed \"{}\"", e);

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
