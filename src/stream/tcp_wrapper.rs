use futures_lite::{AsyncRead, AsyncWrite, AsyncWriteExt};


use super::tcp::IpStackTcpStream as IpStackTcpStreamInner;
use crate::{
    packet::{TcpHeaderWrapper},
    PacketSender,
};
use std::{net::SocketAddr, pin::Pin, time::Duration};

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
    ) -> anyhow::Result<IpStackTcpStream> {
        let (stream_sender, stream_receiver) = async_channel::unbounded();
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
            inner: Some(Box::new(inner)),
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
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.inner.as_mut() {
            Some(mut inner) => Pin::new(&mut inner).poll_read(cx, buf),
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
            Some(mut inner) => Pin::new(&mut inner).poll_write(cx, buf),
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
            Some(mut inner) => Pin::new(&mut inner).poll_flush(cx),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.inner.as_mut() {
            Some(mut inner) => Pin::new(&mut inner).poll_close(cx),
            None => {
                std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
            }
        }
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            std::thread::spawn(move || async move {
                Box::pin(inner.close()).await;
            });
        }
    }
}
