use crate::Engine;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
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
    pub async fn run(self, cancel: CancellationToken) -> io::Result<()> {
        let udp_limit = Arc::new(Semaphore::new(self.config.max_udp_queries));
        let tcp_limit = Arc::new(Semaphore::new(self.config.max_tcp_connections));
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; 4097];
        let result = loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break Ok(()),
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result { tracing::error!(%error, "DNS worker failed"); }
                }
                packet = self.udp.recv_from(&mut buffer) => {
                    let (len, client) = match packet { Ok(packet) => packet, Err(error) => break Err(error) };
                    if len > 4096 { continue; }
                    let Ok(permit) = udp_limit.clone().try_acquire_owned() else { continue; };
                    let bytes = buffer[..len].to_vec();
                    let engine = self.engine.clone(); let socket = self.udp.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Some(response) = engine.answer(&bytes, client.ip(), false).await {
                            let _ = socket.send_to(&response, client).await;
                        }
                    });
                }
                connection = self.tcp.accept() => {
                    let (stream, client) = match connection { Ok(connection) => connection, Err(error) => break Err(error) };
                    let Ok(permit) = tcp_limit.clone().try_acquire_owned() else { continue; };
                    let engine = self.engine.clone(); let cancel = cancel.clone(); let idle = self.config.tcp_idle_timeout;
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = serve_tcp(stream, client.ip(), engine, cancel, idle).await;
                    });
                }
            }
        };
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
        result
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
                if !(12..=4096).contains(&len) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNS frame")); }
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
