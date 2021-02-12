use async_tls::{client::TlsStream, TlsConnector};
use async_trait::async_trait;
use deadpool::managed::{Manager, Object, RecycleResult};
use futures_io::{AsyncRead, AsyncWrite};
use http_types::Url;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "rt-async-std")]
use async_std::net::{TcpStream, ToSocketAddrs};
#[cfg(feature = "rt-tokio")]
use tokio::net::{lookup_host, TcpStream};
#[cfg(feature = "rt-tokio")]
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

pub struct WebPushManager {
    url: Url,
}

impl WebPushManager {
    pub fn new(url: &Url) -> Self {
        Self { url: url.clone() }
    }
}

#[async_trait]
impl Manager<WebPushStream, io::Error> for WebPushManager {
    #[cfg(feature = "rt-async-std")]
    async fn create(&self) -> io::Result<WebPushStream> {
        let port = self.url.port().unwrap_or(443);
        let host = self.url.host_str().unwrap_or("localhost");

        for addr in (host, port).to_socket_addrs().await? {
            if let Ok(tcp) = TcpStream::connect(addr).await {
                let connector = TlsConnector::default();
                let inner = connector.connect(host, tcp).await?;

                return Ok(WebPushStream { inner });
            }
        }

        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused"));
    }

    #[cfg(feature = "rt-tokio")]
    async fn create(&self) -> io::Result<WebPushStream> {
        let port = self.url.port().unwrap_or(443);
        let host = self.url.host_str().unwrap_or("localhost");

        for addr in lookup_host((host, port)).await? {
            if let Ok(tcp) = TcpStream::connect(addr).await {
                let connector = TlsConnector::default();
                let inner = connector.connect(host, tcp.compat_write()).await?;

                return Ok(WebPushStream { inner });
            }
        }

        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused"));
    }

    async fn recycle(&self, _conn: &mut WebPushStream) -> RecycleResult<std::io::Error> {
        Ok(())
    }
}

pub struct TlsConnWrapper {
    conn: Object<WebPushStream, io::Error>,
}

impl TlsConnWrapper {
    pub fn new(conn: Object<WebPushStream, io::Error>) -> Self {
        Self { conn }
    }
}

impl AsyncRead for TlsConnWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut *self.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnWrapper {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let amt = futures_core::ready!(Pin::new(&mut *self.conn).poll_write(cx, buf))?;
        Poll::Ready(Ok(amt))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.conn).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.conn).poll_close(cx)
    }
}

pub struct WebPushStream {
    #[cfg(feature = "rt-async-std")]
    inner: TlsStream<TcpStream>,
    #[cfg(feature = "rt-tokio")]
    inner: TlsStream<Compat<TcpStream>>,
}

impl AsyncRead for WebPushStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for WebPushStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let amt = futures_core::ready!(Pin::new(&mut self.get_mut().inner).poll_write(cx, buf))?;
        Poll::Ready(Ok(amt))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}
