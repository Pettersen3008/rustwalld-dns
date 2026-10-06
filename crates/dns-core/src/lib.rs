//! Bounded DNS transport and request processing. No storage/control-plane dependencies.
use hickory_proto::{
    op::{Edns, Message, MessageType, Metadata, OpCode, ResponseCode},
    rr::{DNSClass, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use std::time::Instant;
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

pub mod telemetry;
use arc_swap::ArcSwap;
use filtering::{Action, Decision};
use policy::PolicySnapshot;
use resolver::{
    ResolutionSource, Resolver,
    cache::{BoundedCache, Equivalent},
};
use std::sync::atomic::Ordering;
use telemetry::{QueryEvent, QuerySource, ShadowDecision, Telemetry};

#[derive(Clone, Hash, Eq, PartialEq)]
struct DecisionKey {
    domain: String,
    policy: usize,
    generation: u64,
}
// Keep field order and Hash semantics identical to DecisionKey. Only cache
// misses need an owned domain; policy/generation are always part of lookup.
#[derive(Hash)]
struct DecisionLookup<'a> {
    domain: &'a str,
    policy: usize,
    generation: u64,
}
impl Equivalent<DecisionKey> for DecisionLookup<'_> {
    fn equivalent(&self, key: &DecisionKey) -> bool {
        self.domain == key.domain && self.policy == key.policy && self.generation == key.generation
    }
}
pub struct Engine {
    pub active: Arc<ArcSwap<PolicySnapshot>>,
    pub shadow: Arc<arc_swap::ArcSwapOption<PolicySnapshot>>,
    pub resolver: Arc<Resolver>,
    pub telemetry: Telemetry,
    decisions: BoundedCache<DecisionKey, Decision>,
}
impl Engine {
    pub fn new(
        snapshot: PolicySnapshot,
        cache_entries: usize,
        decision_entries: usize,
        max_inflight: usize,
        telemetry: Telemetry,
    ) -> Self {
        Self {
            active: Arc::new(ArcSwap::from_pointee(snapshot)),
            shadow: Arc::new(arc_swap::ArcSwapOption::empty()),
            resolver: Resolver::new(cache_entries, max_inflight),
            telemetry,
            decisions: BoundedCache::new(decision_entries),
        }
    }
    pub async fn answer(&self, bytes: &[u8], client: IpAddr, tcp: bool) -> Option<Vec<u8>> {
        let client = client.to_canonical();
        let start = Instant::now();
        let snapshot = self.active.load_full();
        if !snapshot.permits(client) {
            return None;
        }
        let request = Message::from_vec(bytes).ok()?;
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        self.telemetry
            .metrics
            .requests
            .fetch_add(1, Ordering::Relaxed);
        let code = if request.metadata.op_code != OpCode::Query {
            Some(ResponseCode::NotImp)
        } else if request.queries.len() != 1 {
            Some(ResponseCode::FormErr)
        } else if !request.metadata.recursion_desired
            || request.queries[0].query_class() != DNSClass::IN
            || matches!(
                request.queries[0].query_type(),
                RecordType::AXFR | RecordType::IXFR | RecordType::ANY
            )
            || request.signature.is_some()
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !request.additionals.is_empty()
            || request
                .edns
                .as_ref()
                .is_some_and(|edns| !edns.options().as_ref().is_empty())
        {
            Some(ResponseCode::Refused)
        } else if request.version() != 0 {
            Some(ResponseCode::BADVERS)
        } else {
            None
        };
        let mut event = None;
        let mut response = if let Some(code) = code {
            reply(&request, code)
        } else {
            let selected = snapshot.select(client);
            let policy = selected.policy;
            let mut ascii = request.queries[0].name().to_lowercase().to_ascii();
            let domain = ascii.strip_suffix('.').unwrap_or(&ascii);
            let rewrite = policy.rewrite(domain, request.queries[0].query_type());
            let mut temporary = if rewrite.is_none() {
                policy.temporary_allow(domain, start)
            } else {
                None
            };
            let mut decision_cached = false;
            let mut decision = if rewrite.is_some() || temporary.is_some() {
                Decision::ALLOW
            } else {
                let key = DecisionLookup {
                    domain,
                    policy: policy.id,
                    generation: snapshot.generation,
                };
                if let Some(decision) = self.decisions.get(&key) {
                    decision_cached = true;
                    self.telemetry
                        .metrics
                        .decision_hits
                        .fetch_add(1, Ordering::Relaxed);
                    decision
                } else {
                    let decision = policy.filters.evaluate(domain);
                    self.decisions.insert(
                        DecisionKey {
                            domain: domain.to_owned(),
                            policy: key.policy,
                            generation: key.generation,
                        },
                        decision,
                    );
                    decision
                }
            };
            let (mut response, mut source) = if let Some(records) = rewrite {
                self.telemetry
                    .metrics
                    .rewrites
                    .fetch_add(1, Ordering::Relaxed);
                let mut response = reply(&request, ResponseCode::NoError);
                response.answers = records;
                (response, QuerySource::Rewrite)
            } else if decision.action == Action::Block {
                self.telemetry
                    .metrics
                    .blocked
                    .fetch_add(1, Ordering::Relaxed);
                (
                    reply(&request, ResponseCode::NXDomain),
                    QuerySource::Blocked,
                )
            } else {
                match self
                    .resolver
                    .resolve(
                        &request,
                        policy.upstream,
                        snapshot.generation,
                        snapshot.upstreams[policy.upstream].clone(),
                    )
                    .await
                {
                    Ok(result) => (
                        result.response,
                        match result.source {
                            ResolutionSource::Cache => QuerySource::Cache,
                            ResolutionSource::Upstream => QuerySource::Upstream,
                            ResolutionSource::Coalesced => QuerySource::Coalesced,
                        },
                    ),
                    Err(_) => (
                        reply(&request, ResponseCode::ServFail),
                        QuerySource::Failure,
                    ),
                }
            };
            if let Some(found) = &temporary {
                if let Some(ttl) = found.remaining_ttl(Instant::now()) {
                    // Only this client's private response copy is constrained.
                    for record in response
                        .answers
                        .iter_mut()
                        .chain(&mut response.authorities)
                        .chain(&mut response.additionals)
                    {
                        record.ttl = record.ttl.min(ttl);
                    }
                    self.telemetry
                        .metrics
                        .temporary_allows
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    // An upstream/coalesced wait cannot carry an allow across expiry.
                    temporary = None;
                    decision = policy.filters.evaluate(domain);
                    if decision.action == Action::Block {
                        self.telemetry
                            .metrics
                            .blocked
                            .fetch_add(1, Ordering::Relaxed);
                        response = reply(&request, ResponseCode::NXDomain);
                        source = QuerySource::Blocked;
                    }
                }
            }
            if source == QuerySource::Failure {
                self.telemetry
                    .metrics
                    .failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            let shadow = self.shadow.load_full().map(|shadow| {
                let selected = shadow.select(client);
                let rewrite = selected.policy.has_rewrite(domain);
                let temporary = if rewrite {
                    None
                } else {
                    selected.policy.temporary_allow(domain, Instant::now())
                };
                let shadow_decision = if rewrite || temporary.is_some() {
                    Decision::ALLOW
                } else {
                    selected.policy.filters.evaluate(domain)
                };
                let differs = shadow_decision.action != decision.action
                    || rewrite != (source == QuerySource::Rewrite);
                if differs {
                    self.telemetry
                        .metrics
                        .shadow_differences
                        .fetch_add(1, Ordering::Relaxed);
                }
                ShadowDecision {
                    generation: shadow.generation,
                    policy: selected.policy.id,
                    decision: shadow_decision,
                    rewrite,
                    differs,
                    temporary_exception: temporary.map(|found| found.index),
                }
            });
            // Matching is finished: move the already-normalized buffer into
            // telemetry rather than copying it. Only the trailing root dot is
            // removed, preserving Hickory's escapes within DNS labels.
            let domain_len = domain.len();
            ascii.truncate(domain_len);
            event = Some(QueryEvent {
                client,
                domain: ascii,
                qtype: u16::from(request.queries[0].query_type()),
                generation: snapshot.generation,
                policy: policy.id,
                decision,
                decision_cached,
                response_code: u16::from(response.metadata.response_code),
                source,
                latency_us: 0,
                shadow,
                temporary_exception: temporary.map(|found| found.index),
            });
            response
        };
        response.metadata.id = request.metadata.id;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.checking_disabled = request.metadata.checking_disabled;
        response.metadata.authentic_data = false;
        if request.queries.len() == 1 {
            response.queries.clone_from(&request.queries);
        }
        response.edns = request.edns.as_ref().map(|edns| {
            let mut out = Edns::new();
            out.set_max_payload(edns.max_payload().clamp(512, 1232));
            out.set_dnssec_ok(edns.flags().dnssec_ok);
            out
        });
        let max = if tcp {
            u16::MAX
        } else {
            request.max_payload().clamp(512, 1232)
        };
        let mut output = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut output);
        encoder.set_max_size(max);
        response.emit(&mut encoder).ok()?;
        let latency = self.telemetry.metrics.observe(start);
        if let Some(mut event) = event {
            event.latency_us = latency;
            self.telemetry.emit(event);
        }
        Some(output)
    }
}
pub fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata = Metadata::response_from_request(&request.metadata);
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    // An invalid multiple-question message need not echo every question.
    response
        .queries
        .extend(request.queries.iter().take(1).cloned());
    response
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::hash_map::RandomState, hash::BuildHasher};

    #[test]
    fn borrowed_decisions_hash_like_owned_keys_and_keep_all_partitions() {
        let hash = RandomState::new();
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        for domain in [
            "",
            "example",
            "sub.example",
            "a\\.b.example",
            "a\\\\b.example",
            "\\000\\377.example",
            "xn--bcher-kva.example",
            &longest,
        ] {
            for policy in [0, 1, usize::MAX] {
                for generation in [0, 1, u64::MAX] {
                    let owned = DecisionKey {
                        domain: domain.into(),
                        policy,
                        generation,
                    };
                    let borrowed = DecisionLookup {
                        domain,
                        policy,
                        generation,
                    };
                    assert!(borrowed.equivalent(&owned));
                    assert_eq!(hash.hash_one(&owned), hash.hash_one(&borrowed));
                    assert!(
                        !DecisionLookup {
                            policy: policy.wrapping_add(1),
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    assert!(
                        !DecisionLookup {
                            generation: generation.wrapping_add(1),
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    assert!(
                        !DecisionLookup {
                            domain: "different.test",
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    let cache = BoundedCache::new(128);
                    cache.insert(owned, 42);
                    assert_eq!(cache.get(&borrowed), Some(42));
                    assert_eq!(
                        cache.get(&DecisionLookup {
                            policy: policy.wrapping_add(1),
                            ..borrowed
                        }),
                        None
                    );
                    assert_eq!(
                        cache.get(&DecisionLookup {
                            generation: generation.wrapping_add(1),
                            ..borrowed
                        }),
                        None
                    );
                    assert_eq!(
                        cache.get(&DecisionLookup {
                            domain: "different.test",
                            ..borrowed
                        }),
                        None
                    );
                }
            }
        }
    }
}
