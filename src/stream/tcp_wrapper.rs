use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::tcp::IpStackTcpStream as IpStackTcpStreamInner;
use crate::{packet::TcpHeaderWrapper, PacketSender};
use std::{net::SocketAddr, pin::Pin, time::Duration};

const TCP_PACKET_QUEUE_CAPACITY: usize = 64;

pub struct IpStackTcpStream {
    inner: Option<Box<IpStackTcpStreamInner>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    stream_sender: PacketSender,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        tcp: TcpHeaderWrapper,
        pkt_sender: PacketSender,
        mtu: u16,
        tcp_timeout: Duration,
        session_generation: u64,
    ) -> anyhow::Result<IpStackTcpStream> {
        let (stream_sender, stream_receiver) = async_channel::bounded(TCP_PACKET_QUEUE_CAPACITY);
        IpStackTcpStreamInner::new(
            local_addr,
            peer_addr,
            tcp,
            pkt_sender,
            stream_receiver,
            mtu,
            tcp_timeout,
        )
        .map(|inner| IpStackTcpStream {
            inner: Some(Box::new(inner.with_session_generation(session_generation))),
            peer_addr,
            local_addr,
            stream_sender,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    /// Aborts a not-yet-established connection by sending a RST to the peer, so
    /// its `connect()` fails immediately with "connection refused". Use this
    /// when the application actively refuses the connection (e.g. an upstream
    /// dial returned `ConnectionRefused`). For unreachable/timeout failures,
    /// just drop the stream instead, so the SYN stays unanswered and the peer's
    /// Happy Eyeballs can fall back to another address.
    ///
    /// Taking the inner stream here also bypasses the graceful-shutdown spawn in
    /// `Drop`, which would otherwise complete the handshake before closing.
    pub fn reset(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.reset();
        }
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner.as_mut()).poll_read(cx, buf),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner.as_mut()).poll_write(cx, buf),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner.as_mut()).poll_flush(cx),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner.as_mut()).poll_shutdown(cx),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // Only attempt the graceful shutdown if we are inside a tokio
            // runtime; otherwise just drop the stream (its own Drop impl emits
            // the teardown packet).
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut inner = *inner;
                    let _ = inner.shutdown().await;
                });
            }
        }
    }
}
