//! Bound sockets before HTTP parsing; idle readers cannot retain slots forever.
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, Sleep},
};
/// Requests a connection is currently processing. While any are, the idle
/// timeout is suspended: a long compile or commit is not an idle client.
#[derive(Clone, Debug, Default)]
pub struct Activity(Arc<AtomicUsize>);
impl Activity {
    /// Mark one request as processing until the guard drops.
    pub fn enter(&self) -> Busy {
        self.0.fetch_add(1, Ordering::AcqRel);
        Busy(self.0.clone())
    }
    fn busy(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }
}
pub struct Busy(Arc<AtomicUsize>);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Exposes each connection's activity marker to request middleware.
impl Connected<IncomingStream<'_, ManagementListener>> for Activity {
    fn connect_info(stream: IncomingStream<'_, ManagementListener>) -> Self {
        stream.io().activity.clone()
    }
}
pub struct ManagementListener {
    inner: TcpListener,
    slots: Arc<Semaphore>,
    idle: Duration,
}
impl ManagementListener {
    pub fn new(inner: TcpListener, connections: usize, idle: Duration) -> Self {
        Self {
            inner,
            slots: Arc::new(Semaphore::new(connections.max(1))),
            idle,
        }
    }
}
impl Listener for ManagementListener {
    type Io = ManagedStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // This private semaphore is never closed; still handle closure without panic.
            let Ok(permit) = self.slots.clone().acquire_owned().await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            match self.inner.accept().await {
                Ok((stream, address)) => {
                    return (
                        ManagedStream {
                            stream,
                            _permit: permit,
                            idle: self.idle,
                            timer: Box::pin(tokio::time::sleep(self.idle)),
                            activity: Activity::default(),
                        },
                        address,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error,"management accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
pub struct ManagedStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
    activity: Activity,
}
impl ManagedStream {
    fn poll_idle(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.activity.busy() {
            // The window restarts when processing ends.
            self.progress();
            return Ok(());
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "management connection idle timeout",
            ))
        } else {
            Ok(())
        }
    }
    fn progress(&mut self) {
        self.timer.as_mut().reset(Instant::now() + self.idle);
    }
}
impl AsyncRead for ManagedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        if let Err(error) = stream.poll_idle(cx) {
            return Poll::Ready(Err(error));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut stream.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            stream.progress();
        }
        result
    }
}
impl AsyncWrite for ManagedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self.get_mut();
        if let Err(error) = stream.poll_idle(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut stream.stream).poll_write(cx, buf);
        if matches!(result,Poll::Ready(Ok(n)) if n>0) {
            stream.progress();
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn connection_bound_and_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = ManagementListener::new(listener, 1, Duration::from_millis(20));
        let _first = TcpStream::connect(addr).await.unwrap();
        let (mut managed, _) = listener.accept().await;
        let _second = TcpStream::connect(addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(5), listener.accept())
                .await
                .is_err()
        );
        let error = managed.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(managed);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_ok()
        );
    }
}
