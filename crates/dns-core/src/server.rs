use crate::Engine;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub max_udp_queries: usize,
    pub max_tcp_connections: usize,
    pub tcp_idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 5353)),
            max_udp_queries: 256,
            max_tcp_connections: 128,
            tcp_idle_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
        }
    }
}
pub struct Server {
    config: ServerConfig,
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    engine: Arc<Engine>,
}
impl Server {
    pub async fn bind(config: ServerConfig, engine: Arc<Engine>) -> io::Result<Self> {
        if config.max_udp_queries == 0
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
                            metrics.listener_errors.fetch_add(1, Ordering::Relaxed);
                            if let Some(pause) = listener_backoff(&error) {
                                tracing::warn!(%error, "DNS UDP receive failed");
                                udp_pause = Some(Instant::now() + pause);
                            }
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
                    let bytes = buffer[..len].to_vec();
                    let engine = self.engine.clone();
                    let socket = self.udp.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Some(response) = engine.answer(&bytes, client.ip(), false).await {
                            let _ = socket.send_to(&response, client).await;
                        }
                    });
                }
                connection = self.tcp.accept(), if tcp_pause.is_none() => {
                    let (stream, client) = match connection {
                        Ok(connection) => connection,
                        Err(error) => {
                            metrics.listener_errors.fetch_add(1, Ordering::Relaxed);
                            if let Some(pause) = listener_backoff(&error) {
                                tracing::warn!(%error, "DNS TCP accept failed");
                                tcp_pause = Some(Instant::now() + pause);
                            }
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
    // Length and DNS payload are separate writes. Disable Nagle once per
    // connection so a delayed ACK cannot stall the remaining frame payload.
    stream.set_nodelay(true)?;
    loop {
        let bytes = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = timeout(idle, async {
                let len = stream.read_u16().await? as usize;
                if !(12..=MAX_QUERY_BYTES).contains(&len) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNS frame")); }
                let mut bytes = vec![0; len];
                stream.read_exact(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            }) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS idle timeout"))??,
        };
        let Some(response) = engine.answer(&bytes, client, true).await else {
            return Ok(());
        };
        timeout(idle, async {
            stream
                .write_u16(u16::try_from(response.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "DNS response too long")
                })?)
                .await?;
            stream.write_all(&response).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS write timeout"))??;
    }
}
