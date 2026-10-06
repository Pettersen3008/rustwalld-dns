//! Isolated comparative fixture and bounded Hickory wire client, never public DNS.
use clap::{Parser, Subcommand, ValueEnum};
use dns_core::reply;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, SOA},
    },
};
use serde_json::json;
use std::{
    error::Error,
    io::{self, BufRead, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Barrier, Semaphore},
    task::JoinSet,
    time::{sleep, sleep_until, timeout},
};
#[path = "support/histogram.rs"]
mod histogram;
use histogram::Histogram;
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        inject_wrong_answer: bool,
    },
    Check {
        #[arg(long, default_value_t = 100000)]
        rules: u32,
    },
    Run {
        #[arg(long, value_enum)]
        scenario: Scenario,
        #[arg(long, value_enum)]
        transport: Transport,
        #[arg(long, default_value_t = 100000)]
        iterations: u32,
        #[arg(long, default_value_t = 4)]
        concurrency: u16,
        #[arg(long, default_value_t = 100000)]
        rules: u32,
        #[arg(long, default_value_t = 0)]
        nonce: u32,
        #[arg(long, default_value_t = 0)]
        queries_per_second: u32,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Scenario {
    Blocked,
    Suffix,
    Cache,
    Aaaa,
    Cname,
    Negative,
    Cold,
    Coalescing,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Transport {
    Udp,
    Tcp,
}
impl Scenario {
    fn domain(self, index: u32, nonce: u32, rules: u32) -> String {
        match self {
            Self::Blocked => format!("d{}.blocked.bench.test.", index % rules.min(1024)),
            Self::Suffix => "x.suffix.bench.test.".into(),
            Self::Cache => "cache.bench.test.".into(),
            Self::Aaaa => "ipv6.bench.test.".into(),
            Self::Cname => "alias.bench.test.".into(),
            Self::Negative => "nx-cache.bench.test.".into(),
            Self::Cold => format!("cold-{nonce}-{index}.bench.test."),
            Self::Coalescing => format!("burst-{nonce}.bench.test."),
        }
    }
    fn qtype(self) -> RecordType {
        if self == Self::Aaaa {
            RecordType::AAAA
        } else {
            RecordType::A
        }
    }
}
fn query(domain: &str, qtype: RecordType, id: u16) -> Result<Message> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.metadata.id = id;
    m.add_query(Query::query(Name::from_ascii(domain)?, qtype));
    Ok(m)
}
fn negative(name: &str) -> bool {
    name.starts_with("nx-") || name.starts_with("nodata-")
}
fn blocked(name: &str) -> bool {
    (name.starts_with('d')
        && name.ends_with(".blocked.bench.test.")
        && name.trim_end_matches('.').split('.').count() == 4)
        || ((name == "suffix.bench.test." || name.ends_with(".suffix.bench.test."))
            && name != "allowed.suffix.bench.test.")
}
fn mock_answer(request: &Message, tcp: bool, corrupt: bool) -> Result<Message> {
    let q = request
        .queries
        .first()
        .ok_or_else(|| invalid("fixture requires one question"))?;
    let name = q.name().to_ascii().to_ascii_lowercase();
    let code = if name.starts_with("nx-") {
        ResponseCode::NXDomain
    } else {
        ResponseCode::NoError
    };
    let mut response = reply(request, code);
    if name == "truncate.bench.test." && !tcp {
        response.metadata.truncation = true;
        return Ok(response);
    }
    if negative(&name) {
        let ttl = if name.ends_with("ttl.bench.test.") {
            3
        } else {
            300
        };
        response.authorities.push(Record::from_rdata(
            Name::from_ascii("bench.test.")?,
            ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.bench.test.")?,
                Name::from_ascii("hostmaster.bench.test.")?,
                1,
                30,
                30,
                60,
                ttl,
            )),
        ));
    } else {
        let ttl = if name == "ttl.bench.test." { 3 } else { 300 };
        let address = if corrupt {
            std::net::Ipv4Addr::new(192, 0, 2, 99)
        } else {
            std::net::Ipv4Addr::new(192, 0, 2, 1)
        };
        let mut owner = q.name().clone();
        if name == "alias.bench.test." {
            owner = Name::from_ascii("target.bench.test.")?;
            response.add_answer(Record::from_rdata(
                q.name().clone(),
                ttl,
                RData::CNAME(CNAME(owner.clone())),
            ));
        }
        let data = if q.query_type() == RecordType::AAAA {
            RData::AAAA(AAAA("2001:db8::1".parse()?))
        } else {
            RData::A(A(address))
        };
        response.add_answer(Record::from_rdata(owner, ttl, data));
    }
    Ok(response)
}
fn validate_header(request: &Message, response: &Message, allow_truncated: bool) -> Result<()> {
    let q = request
        .queries
        .first()
        .ok_or_else(|| invalid("missing request question"))?;
    let name = q.name().to_ascii().to_ascii_lowercase();
    let code = if blocked(&name) || name.starts_with("nx-") {
        ResponseCode::NXDomain
    } else {
        ResponseCode::NoError
    };
    if response.metadata.id != request.metadata.id
        || response.metadata.message_type != MessageType::Response
        || (response.metadata.truncation && !allow_truncated)
        || response.metadata.response_code != code
        || response.queries != request.queries
        || response
            .queries
            .first()
            .is_none_or(|found| found.name().to_ascii() != q.name().to_ascii())
    {
        return Err(invalid("ID/question/casing/code/header mismatch").into());
    }
    Ok(())
}
fn validate(request: &Message, response: &Message) -> Result<()> {
    validate_header(request, response, false)?;
    let q = &request.queries[0];
    let name = q.name().to_ascii().to_ascii_lowercase();
    if blocked(&name) {
        if !response.answers.is_empty() {
            return Err(invalid("blocked answer has data").into());
        }
        return Ok(());
    }
    if negative(&name) {
        let ttl = if name.ends_with("ttl.bench.test.") {
            3
        } else {
            300
        };
        let zone = Name::from_ascii("bench.test.")?;
        if !response.answers.is_empty()
            || !response.authorities.iter().any(|r| {
                matches!(&r.data, RData::SOA(soa) if soa.minimum == ttl)
                    && r.ttl <= ttl
                    && r.name == zone
            })
        {
            return Err(invalid("negative answer lacks correct SOA").into());
        }
        return Ok(());
    }
    let mut owner = q.name().clone();
    let expected = if name == "alias.bench.test." {
        owner = Name::from_ascii("target.bench.test.")?;
        if !response
            .answers
            .iter()
            .any(|r| r.name == *q.name() && r.data == RData::CNAME(CNAME(owner.clone())))
        {
            return Err(invalid("incorrect CNAME chain").into());
        }
        2
    } else {
        1
    };
    let data = if q.query_type() == RecordType::AAAA {
        RData::AAAA(AAAA("2001:db8::1".parse()?))
    } else {
        RData::A(A("192.0.2.1".parse()?))
    };
    let max_ttl = if name == "ttl.bench.test." { 3 } else { 300 };
    if response.answers.len() != expected
        || !response
            .answers
            .iter()
            .any(|r| r.name == owner && r.data == data)
        || response.answers.iter().any(|r| r.ttl > max_ttl)
    {
        return Err(invalid("incorrect answer address/owner/TTL").into());
    }
    Ok(())
}
async fn hits() -> Result<u64> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect("127.0.0.1:1054").await?;
    let mut count = [0; 8];
    timeout(Duration::from_secs(2), async {
        socket.send(b"count").await?;
        if socket.recv(&mut count).await? != 8 {
            return Err(invalid("invalid fixture count"));
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(u64::from_be_bytes(count))
}
enum Connection {
    Udp(UdpSocket),
    Tcp {
        stream: TcpStream,
        peer: std::net::SocketAddr,
        reconnects: u64,
    },
}
impl Connection {
    async fn connect(transport: Transport) -> Result<Self> {
        Ok(match transport {
            Transport::Udp => {
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                socket.connect("127.0.0.1:5353").await?;
                Self::Udp(socket)
            }
            Transport::Tcp => {
                let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 5353));
                let stream = timeout(Duration::from_secs(2), TcpStream::connect(peer)).await??;
                stream.set_nodelay(true)?;
                Self::Tcp {
                    stream,
                    peer,
                    reconnects: 0,
                }
            }
        })
    }
    async fn exchange(&mut self, request: &Message) -> Result<(u64, Message)> {
        let bytes = request.to_vec()?;
        let mut frame = Vec::with_capacity(bytes.len() + 2);
        frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(&bytes);
        let mut buffer = vec![0; 65535];
        let start = Instant::now();
        let n = timeout(Duration::from_secs(2), async {
            for attempt in 0..2 {
                let result = match self {
                    Self::Udp(socket) => {
                        socket.send(&bytes).await?;
                        socket.recv(&mut buffer).await
                    }
                    Self::Tcp { stream, .. } => {
                        async {
                            stream.write_all(&frame).await?;
                            let n = stream.read_u16().await? as usize;
                            if n < 12 {
                                return Err(invalid("short DNS frame"));
                            }
                            stream.read_exact(&mut buffer[..n]).await?;
                            Ok(n)
                        }
                        .await
                    }
                };
                if let Err(error) = &result
                    && attempt == 0
                    && matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                    )
                    && let Self::Tcp {
                        stream,
                        peer,
                        reconnects,
                    } = self
                {
                    *stream = TcpStream::connect(*peer).await?;
                    stream.set_nodelay(true)?;
                    *reconnects += 1;
                    continue;
                }
                return result;
            }
            Err(invalid("TCP retry exhausted"))
        })
        .await??;
        let elapsed = start.elapsed().as_micros() as u64;
        Ok((elapsed, Message::from_vec(&buffer[..n])?))
    }
    fn reconnects(&self) -> u64 {
        match self {
            Self::Udp(_) => 0,
            Self::Tcp { reconnects, .. } => *reconnects,
        }
    }
    async fn checked(&mut self, request: &Message) -> Result<Message> {
        let (_, response) = self.exchange(request).await?;
        validate(request, &response).map_err(|e| {
            invalid(&format!(
                "{}: {e}; metadata={:?}; answers={:?}; authorities={:?}",
                request.queries[0].name(),
                response.metadata,
                response.answers,
                response.authorities
            ))
        })?;
        Ok(response)
    }
}
async fn serve(corrupt: bool) -> Result<()> {
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:1053").await?);
    let control = UdpSocket::bind("127.0.0.1:1054").await?;
    let tcp = TcpListener::bind("127.0.0.1:1053").await?;
    let count = Arc::new(AtomicU64::new(0));
    let limits = Arc::new(Semaphore::new(256));
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65535];
    let mut command = [0; 16];
    loop {
        tokio::select! {
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            received = control.recv_from(&mut command) => {
                let (n,peer) = received?;
                if &command[..n] == b"count" { control.send_to(&count.load(Ordering::Relaxed).to_be_bytes(),peer).await?; }
            }
            received = udp.recv_from(&mut buffer) => {
                let (n, peer) = received?;
                let Ok(request) = Message::from_vec(&buffer[..n]) else { continue };
                let Ok(permit) = limits.clone().try_acquire_owned() else { continue };
                let socket = udp.clone(); let counter = count.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    fixture_delay(&request,&counter).await;
                    if let Ok(response) = mock_answer(&request,false,corrupt).and_then(|m| m.to_vec().map_err(Into::into)) { let _ = socket.send_to(&response,peer).await; }
                });
            }
            accepted = tcp.accept() => {
                let (mut stream,_) = accepted?;
                stream.set_nodelay(true)?;
                let Ok(permit) = limits.clone().try_acquire_owned() else { continue };
                let counter = count.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut buffer = vec![0;65535];
                    for _ in 0..4096 {
                        let result = timeout(Duration::from_secs(2), async {
                            let n = stream.read_u16().await? as usize;
                            if n < 12 { return Err(invalid("short upstream frame").into()); }
                            stream.read_exact(&mut buffer[..n]).await?;
                            let request = Message::from_vec(&buffer[..n])?;
                            fixture_delay(&request,&counter).await;
                            let response = mock_answer(&request,true,corrupt)?.to_vec()?;
                            stream.write_u16(response.len() as u16).await?;
                            stream.write_all(&response).await?;
                            Ok::<_, Box<dyn Error + Send + Sync>>(())
                        }).await;
                        if !matches!(result, Ok(Ok(()))) { break; }
                    }
                });
            }
        }
    }
}
async fn fixture_delay(request: &Message, count: &AtomicU64) {
    if let Some(q) = request.queries.first() {
        let name = q.name().to_ascii().to_ascii_lowercase();
        if name.ends_with(".bench.test.") {
            count.fetch_add(1, Ordering::Relaxed);
        }
        if name.starts_with("burst-") {
            sleep(Duration::from_millis(25)).await;
        }
        if name.starts_with("cold-") {
            sleep(Duration::from_millis(5)).await;
        }
    }
}
async fn check(rules: u32) -> Result<()> {
    let mut socket = Connection::connect(Transport::Udp).await?;
    let ready = query("ready.bench.test.", RecordType::A, 1)?;
    let start = Instant::now();
    loop {
        if let Ok((_, response)) = socket.exchange(&ready).await
            && response.metadata.response_code == ResponseCode::NoError
        {
            validate(&ready, &response)?;
            break;
        }
        if start.elapsed() > Duration::from_secs(60) {
            return Err(invalid("appliance did not become ready").into());
        }
        sleep(Duration::from_millis(100)).await;
    }
    let mut checks = 0;
    for transport in [Transport::Udp, Transport::Tcp] {
        let mut socket = Connection::connect(transport).await?;
        for (name, qtype) in [
            ("d0.blocked.bench.test.".to_owned(), RecordType::A),
            (format!("d{}.blocked.bench.test.", rules / 2), RecordType::A),
            (
                format!("d{}.blocked.bench.test.", rules - 1),
                RecordType::AAAA,
            ),
            ("child.d0.blocked.bench.test.".into(), RecordType::A),
            ("x.suffix.bench.test.".into(), RecordType::A),
            ("suffix.bench.test.".into(), RecordType::A),
            ("notsuffix.bench.test.".into(), RecordType::A),
            ("child.allowed.suffix.bench.test.".into(), RecordType::A),
            ("allowed.suffix.bench.test.".into(), RecordType::A),
            ("cache.bench.test.".into(), RecordType::A),
            ("ipv6.bench.test.".into(), RecordType::AAAA),
            ("alias.bench.test.".into(), RecordType::A),
            ("MiXeD.bench.test.".into(), RecordType::A),
        ] {
            let before = hits().await?;
            socket
                .checked(&query(&name, qtype, 31)?)
                .await
                .map_err(|e| invalid(&format!("{name}: {e}")))?;
            if blocked(&name) && hits().await? != before {
                return Err(invalid("blocked request reached upstream").into());
            }
            checks += 1;
        }
    }
    for name in [
        "ttl.bench.test.",
        "nx-ttl.bench.test.",
        "nodata-ttl.bench.test.",
    ] {
        let request = query(name, RecordType::A, 71)?;
        let first = socket.checked(&request).await?;
        let before = hits().await?;
        socket.checked(&request).await?;
        if hits().await? != before {
            return Err(invalid("positive/negative cache did not hit").into());
        }
        sleep(Duration::from_millis(1100)).await;
        let aged = socket.checked(&request).await?;
        let ttl = |m: &Message| {
            m.answers
                .iter()
                .chain(m.authorities.iter())
                .map(|r| r.ttl)
                .min()
                .unwrap_or(0)
        };
        if ttl(&aged) >= ttl(&first) || hits().await? != before {
            return Err(invalid("cache TTL failed to age").into());
        }
        sleep(Duration::from_millis(2200)).await;
        socket.checked(&request).await?;
        if hits().await? != before + 1 {
            return Err(invalid("expired cache was not refreshed exactly once").into());
        }
        checks += 4;
    }
    let before = hits().await?;
    let request = query("truncate.bench.test.", RecordType::A, 91)?;
    let (_, response) = socket.exchange(&request).await?;
    let client_tcp_retry = response.metadata.truncation;
    if client_tcp_retry {
        validate_header(&request, &response, true)?;
        Connection::connect(Transport::Tcp)
            .await?
            .checked(&request)
            .await?;
    } else {
        validate(&request, &response)?;
    }
    let truncation_upstream_requests = hits().await? - before;
    if !(2..=3).contains(&truncation_upstream_requests) {
        return Err(invalid("unexpected truncated-response recovery count").into());
    }
    println!(
        "{}",
        json!({"protocol_checks":checks+1,"passed":true,
        "client_tcp_retry":client_tcp_retry,"truncation_upstream_requests":truncation_upstream_requests})
    );
    Ok(())
}
async fn run(
    scenario: Scenario,
    transport: Transport,
    iterations: u32,
    concurrency: u16,
    rules: u32,
    nonce: u32,
    queries_per_second: u32,
) -> Result<()> {
    let mut warm = Connection::connect(transport).await?;
    if !matches!(scenario, Scenario::Cold | Scenario::Coalescing) {
        for i in 0..1024 {
            warm.checked(&query(
                &scenario.domain(i, nonce, rules),
                scenario.qtype(),
                i as u16,
            )?)
            .await?;
        }
    }
    drop(warm);
    let before = hits().await?;
    let mut connections = Vec::new();
    for _ in 0..concurrency {
        connections.push(Connection::connect(transport).await?);
    }
    println!("READY");
    io::stdout().flush()?;
    let go = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        io::stdin().lock().take(16).read_line(&mut line)?;
        if line != "GO\n" {
            return Err(invalid("expected bounded GO handshake"));
        }
        Ok::<_, io::Error>(())
    })
    .await?;
    go?;
    let barrier = Arc::new(Barrier::new(concurrency as usize));
    let mut tasks = JoinSet::new();
    let start = Instant::now();
    for (worker, mut socket) in connections.into_iter().enumerate() {
        let barrier = barrier.clone();
        tasks.spawn(async move {
            let mut histogram = Histogram::new();
            let mut exchange_errors = 0u64;
            let mut first_error = None;
            barrier.wait().await;
            for i in (worker as u32..iterations).step_by(concurrency as usize) {
                if queries_per_second > 0 {
                    let offset = Duration::from_nanos(
                        u64::from(i) * 1_000_000_000 / u64::from(queries_per_second),
                    );
                    sleep_until((start + offset).into()).await;
                }
                let request = query(
                    &scenario.domain(i, nonce, rules),
                    scenario.qtype(),
                    i as u16,
                )?;
                match socket.exchange(&request).await {
                    Ok((us, response)) => {
                        let wrong = validate(&request, &response).is_err();
                        histogram.record((us, false, wrong));
                        if wrong {
                            break;
                        }
                    }
                    Err(error) => {
                        if error.is::<tokio::time::error::Elapsed>() {
                            histogram.record((0, true, false));
                        } else {
                            exchange_errors += 1;
                        }
                        first_error = Some(format!("{}: {error}", request.queries[0].name()));
                        break;
                    }
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>((
                histogram,
                socket.reconnects(),
                exchange_errors,
                first_error,
            ))
        });
    }
    let mut histogram = Histogram::new();
    let mut tcp_reconnects = 0;
    let mut exchange_errors = 0;
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        let (worker, reconnects, errors, error) = result??;
        histogram.merge(worker);
        tcp_reconnects += reconnects;
        exchange_errors += errors;
        if first_error.is_none() {
            first_error = error;
        }
    }
    let elapsed = start.elapsed().as_nanos() as u64;
    let upstream = hits().await? - before;
    let stats = histogram.report();
    let correct = stats["replies"] == iterations
        && stats["timeouts"] == 0
        && stats["incorrect"] == 0
        && stats["latencies_clipped"] == 0
        && exchange_errors == 0;
    let upstream_ok = match scenario {
        Scenario::Cold => upstream == u64::from(iterations),
        Scenario::Coalescing => (1..=u64::from(iterations)).contains(&upstream),
        _ => upstream == 0,
    };
    println!(
        "{}",
        json!({"scenario":format!("{scenario:?}").to_lowercase(),"transport":format!("{transport:?}").to_lowercase(),"queries":iterations,"concurrency":concurrency,"queries_per_second_limit":queries_per_second,"elapsed_ns":elapsed,"upstream_requests":upstream,"tcp_reconnects":tcp_reconnects,"exchange_errors":exchange_errors,"first_error":first_error,"histogram":stats,"passed":correct&&upstream_ok})
    );
    if !correct || !upstream_ok {
        return Err(invalid("DNS correctness/upstream accounting gate failed").into());
    }
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Serve {
            inject_wrong_answer,
        } => serve(inject_wrong_answer).await,
        Command::Check { rules } if (1..=1_000_000).contains(&rules) => check(rules).await,
        Command::Run {
            scenario,
            transport,
            iterations,
            concurrency,
            rules,
            nonce,
            queries_per_second,
        } if (1..=1_000_000).contains(&iterations)
            && (1..=64).contains(&concurrency)
            && u32::from(concurrency) <= iterations
            && (1..=1_000_000).contains(&rules) =>
        {
            if queries_per_second != 0 && !(100..=100_000).contains(&queries_per_second) {
                return Err(invalid("query rate must be zero (unpaced) or 100..100000").into());
            }
            run(
                scenario,
                transport,
                iterations,
                concurrency,
                rules,
                nonce,
                queries_per_second,
            )
            .await
        }
        _ => Err(invalid(
            "rules/iterations must be 1..1000000; concurrency 1..64 and <= iterations",
        )
        .into()),
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[tokio::test]
    #[allow(deprecated)] // Linger-zero deliberately simulates a peer TCP reset.
    async fn tcp_connection_closure_retries_once_and_preserves_validation() {
        for reset in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let peer = listener.local_addr().unwrap();
            let stream = TcpStream::connect(peer).await.unwrap();
            let server = tokio::spawn(async move {
                for attempt in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let n = stream.read_u16().await.unwrap() as usize;
                    let mut frame = vec![0; n];
                    stream.read_exact(&mut frame).await.unwrap();
                    if attempt == 0 && reset {
                        stream.set_linger(Some(Duration::ZERO)).unwrap();
                    }
                    if attempt == 1 {
                        let request = Message::from_vec(&frame).unwrap();
                        let answer = mock_answer(&request, true, false)
                            .unwrap()
                            .to_vec()
                            .unwrap();
                        let mut frame = (answer.len() as u16).to_be_bytes().to_vec();
                        frame.extend_from_slice(&answer);
                        stream.write_all(&frame).await.unwrap();
                    }
                }
            });
            let mut connection = Connection::Tcp {
                stream,
                peer,
                reconnects: 0,
            };
            let request = query("cache.bench.test.", RecordType::A, 29).unwrap();
            connection.checked(&request).await.unwrap();
            assert_eq!(connection.reconnects(), 1);
            server.await.unwrap();
        }
    }
    #[test]
    fn validator_rejects_wrong_addresses_ids_and_questions() {
        let request = query("cache.bench.test.", RecordType::A, 17).unwrap();
        validate(&request, &mock_answer(&request, true, false).unwrap()).unwrap();
        assert!(validate(&request, &mock_answer(&request, true, true).unwrap()).is_err());
        let mut wrong = mock_answer(&request, true, false).unwrap();
        wrong.metadata.id = 18;
        assert!(validate(&request, &wrong).is_err());
        wrong = mock_answer(&request, true, false).unwrap();
        wrong.queries.clear();
        assert!(validate(&request, &wrong).is_err());
    }
    #[test]
    fn validator_requires_cname_and_negative_soa() {
        for domain in [
            "alias.bench.test.",
            "nx-cache.bench.test.",
            "nodata-ttl.bench.test.",
        ] {
            let q = query(domain, RecordType::A, 19).unwrap();
            let mut m = mock_answer(&q, true, false).unwrap();
            validate(&q, &m).unwrap();
            m.answers.clear();
            m.authorities.clear();
            assert!(validate(&q, &m).is_err());
        }
    }
    #[test]
    fn equivalent_rule_boundaries_and_truncation_are_required() {
        assert!(blocked("d0.blocked.bench.test."));
        assert!(blocked("child.suffix.bench.test."));
        assert!(!blocked("child.d0.blocked.bench.test."));
        assert!(!blocked("allowed.suffix.bench.test."));
        assert!(!blocked("notsuffix.bench.test."));
        let q = query("truncate.bench.test.", RecordType::A, 21).unwrap();
        let mut truncated = mock_answer(&q, false, false).unwrap();
        assert!(validate(&q, &truncated).is_err());
        validate_header(&q, &truncated, true).unwrap();
        truncated.metadata.id += 1;
        assert!(validate_header(&q, &truncated, true).is_err());
        validate(&q, &mock_answer(&q, true, false).unwrap()).unwrap();
    }
    #[test]
    fn valid_zero_ttl_answers_are_accepted_without_relaxing_data_validation() {
        for name in [
            "cache.bench.test.",
            "alias.bench.test.",
            "nx-cache.bench.test.",
        ] {
            let q = query(name, RecordType::A, 23).unwrap();
            let mut answer = mock_answer(&q, true, false).unwrap();
            for record in answer
                .answers
                .iter_mut()
                .chain(answer.authorities.iter_mut())
            {
                record.ttl = 0;
            }
            validate(&q, &answer).unwrap();
        }
    }
}
