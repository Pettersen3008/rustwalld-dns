use crate::{Engine, Prepared, Transport};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;
/// Listener address and ingress bounds for [`Server`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// UDP and TCP listen address (both transports share the port).
    pub listen: SocketAddr,
    /// UDP queries being parsed, policy-checked or answered locally at once.
    /// Further datagrams are dropped. Queries waiting on an upstream do not
    /// count against this limit.
    pub max_udp_queries: usize,
    /// UDP cache misses waiting on upstream resolution at once (including
    /// coalesced waiters). Further misses are answered SERVFAIL immediately, so
    /// a slow upstream cannot starve blocked, rewritten or cached answers.
    pub max_udp_upstream_waits: usize,
    /// Concurrent TCP connections; each serves one query at a time.
    pub max_tcp_connections: usize,
    /// Per-read/write idle limit for TCP connections.
    pub tcp_idle_timeout: Duration,
    /// Drain time for in-flight work after cancellation.
    pub shutdown_timeout: Duration,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 5353)),
            max_udp_queries: 256,
            max_udp_upstream_waits: 1024,
            max_tcp_connections: 128,
            tcp_idle_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
        }
    }
}
/// Bounded UDP/TCP DNS listener for one [`Engine`].
pub struct Server {
    config: ServerConfig,
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    engine: Arc<Engine>,
}
impl Server {
    /// Bind TCP, then UDP on the same address (the OS-selected port when 0).
    ///
    /// # Errors
    ///
    /// `InvalidInput` for zero limits or idle timeout, and bind failures.
    pub async fn bind(config: ServerConfig, engine: Arc<Engine>) -> io::Result<Self> {
        if config.max_udp_queries == 0
            || config.max_udp_upstream_waits == 0
            || config.max_tcp_connections == 0
            || config.tcp_idle_timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid server limits",
            ));
        }
        let tcp = TcpListener::bind(config.listen).await?;
        let udp = Arc::new(UdpSocket::bind(tcp.local_addr()?).await?);
        Ok(Self {
            config,
            udp,
            tcp,
            engine,
        })
    }
    /// The bound address.
    ///
    /// # Errors
    ///
    /// When the socket address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
    /// Serve until `cancel` fires, then drain workers within `shutdown_timeout`.
    ///
    /// Listener errors never end service: per-connection errors are skipped and
    /// resource exhaustion (for example `EMFILE`) pauses only the failing
    /// listener briefly, so one transport cannot take the other down.
    pub async fn run(self, cancel: CancellationToken) -> io::Result<()> {
        let udp_limit = Arc::new(Semaphore::new(self.config.max_udp_queries));
        let wait_limit = Arc::new(Semaphore::new(self.config.max_udp_upstream_waits));
        let tcp_limit = Arc::new(Semaphore::new(self.config.max_tcp_connections));
        let metrics = self.engine.telemetry().metrics.clone();
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; MAX_QUERY_BYTES + 1];
        // A paused listener resumes at its deadline; `placeholder` only fills
        // the disabled timer branches and is never awaited.
        let placeholder = Instant::now();
        let mut udp_pause: Option<Instant> = None;
        let mut tcp_pause: Option<Instant> = None;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result {
                        tracing::error!(%error, "DNS worker failed");
                    }
                }
                () = sleep_until(udp_pause.unwrap_or(placeholder)), if udp_pause.is_some() => udp_pause = None,
                () = sleep_until(tcp_pause.unwrap_or(placeholder)), if tcp_pause.is_some() => tcp_pause = None,
                packet = self.udp.recv_from(&mut buffer), if udp_pause.is_none() => {
                    let (len, client) = match packet {
                        Ok(packet) => packet,
                        Err(error) => {
                            udp_pause = listener_failed(&metrics, &error, "UDP receive");
                            continue;
                        }
                    };
                    if len > MAX_QUERY_BYTES {
                        continue;
                    }
                    let Ok(permit) = udp_limit.clone().try_acquire_owned() else {
                        metrics.udp_overloads.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    tasks.spawn(serve_udp(
                        UdpQuery {
                            bytes: buffer[..len].to_vec(),
                            client,
                            permit,
                        },
                        self.engine.clone(),
                        self.udp.clone(),
                        wait_limit.clone(),
                    ));
                }
                connection = self.tcp.accept(), if tcp_pause.is_none() => {
                    let (stream, client) = match connection {
                        Ok(connection) => connection,
                        Err(error) => {
                            tcp_pause = listener_failed(&metrics, &error, "TCP accept");
                            continue;
                        }
                    };
                    let Ok(permit) = tcp_limit.clone().try_acquire_owned() else {
                        metrics.tcp_overloads.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let engine = self.engine.clone();
                    let cancel = cancel.clone();
                    let idle = self.config.tcp_idle_timeout;
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = serve_tcp(stream, client.ip(), engine, cancel, idle).await;
                    });
                }
            }
        }
        cancel.cancel();
        if timeout(self.config.shutdown_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        self.engine.resolver.shutdown();
        Ok(())
    }
}

/// One received datagram holding a local-work slot.
struct UdpQuery {
    bytes: Vec<u8>,
    client: SocketAddr,
    permit: OwnedSemaphorePermit,
}
/// Answer a datagram. The local slot covers only synchronous work; a cache
/// miss waits under the separate upstream-wait bound or is shed with SERVFAIL.
async fn serve_udp(
    query: UdpQuery,
    engine: Arc<Engine>,
    socket: Arc<UdpSocket>,
    waits: Arc<Semaphore>,
) {
    let UdpQuery {
        bytes,
        client,
        permit,
    } = query;
    let (reply, permit) = match engine.prepare(&bytes, client.ip(), Transport::Udp) {
        Prepared::Drop => (None, permit),
        Prepared::Reply(reply) => (Some(reply), permit),
        Prepared::Forward(pending) => {
            if let Ok(wait) = waits.try_acquire_owned() {
                drop(permit);
                (engine.forward(pending).await, wait)
            } else {
                engine
                    .telemetry()
                    .metrics
                    .forward_overloads
                    .fetch_add(1, Ordering::Relaxed);
                (engine.reject(pending), permit)
            }
        }
    };
    if let Some(reply) = reply {
        let _ = send_reply(socket.send_to(&reply, client), permit).await;
    }
}
/// Keep admission through a reply's send. Socket backpressure cannot accumulate
/// unbounded tasks after upstream completion or overload rejection.
async fn send_reply(
    send: impl std::future::Future<Output = io::Result<usize>>,
    _permit: OwnedSemaphorePermit,
) -> io::Result<usize> {
    timeout(Duration::from_secs(1), send)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP reply send timed out"))?
}
/// Count a listener failure and decide whether to pause that listener.
fn listener_failed(
    metrics: &crate::telemetry::Metrics,
    error: &io::Error,
    operation: &str,
) -> Option<Instant> {
    metrics.listener_errors.fetch_add(1, Ordering::Relaxed);
    let pause = listener_backoff(error)?;
    tracing::warn!(%error, operation, "DNS listener failed");
    Some(Instant::now() + pause)
}

/// Largest accepted query message on either transport.
const MAX_QUERY_BYTES: usize = 4096;
/// Pause after a listener error that a retry cannot fix immediately.
const LISTENER_BACKOFF: Duration = Duration::from_millis(100);

/// `None` for errors tied to one peer (retry at once); otherwise a pause that
/// keeps a persistent failure such as descriptor exhaustion from spinning.
fn listener_backoff(error: &io::Error) -> Option<Duration> {
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => None,
        _ => Some(LISTENER_BACKOFF),
    }
}
async fn serve_tcp(
    mut stream: TcpStream,
    client: IpAddr,
    engine: Arc<Engine>,
    cancel: CancellationToken,
    idle: Duration,
) -> io::Result<()> {
    // Replies are written whole; disable Nagle so they are not held back
    // waiting for the client's ACK of a previous reply.
    stream.set_nodelay(true)?;
    loop {
        let bytes = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = timeout(idle, async {
                let len = usize::from(stream.read_u16().await?);
                if !(12..=MAX_QUERY_BYTES).contains(&len) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNS frame")); }
                let mut bytes = vec![0; len];
                stream.read_exact(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            }) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS idle timeout"))??,
        };
        let Some(response) = engine.answer(&bytes, client, Transport::Tcp).await else {
            return Ok(());
        };
        // Length prefix and message leave in one write (one segment when small).
        let len = u16::try_from(response.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS response too long"))?;
        let mut frame = Vec::with_capacity(response.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&response);
        timeout(idle, stream.write_all(&frame))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS write timeout"))??;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn stalled_reply_retains_admission_and_releases_it_on_cancel_or_timeout() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let task = tokio::spawn(send_reply(std::future::pending(), permit));
        tokio::task::yield_now().await;
        assert!(slots.clone().try_acquire_owned().is_err());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let permit = slots.clone().try_acquire_owned().unwrap();
        let result = send_reply(std::future::pending(), permit).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(slots.available_permits(), 1);
        let permit = slots.clone().try_acquire_owned().unwrap();
        assert_eq!(send_reply(async { Ok(42) }, permit).await.unwrap(), 42);
        assert_eq!(slots.available_permits(), 1);
    }
}
