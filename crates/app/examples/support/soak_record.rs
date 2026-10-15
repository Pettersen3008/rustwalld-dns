//! Strict, bounded controller input. Descriptions document authority; they do not grant it.
use hickory_proto::{
    op::Message,
    rr::DNSClass,
    serialize::binary::{BinDecodable, BinDecoder},
};
use rustix::fs::{Mode as FileMode, OFlags, open};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
pub fn bounded_file(path: &std::path::Path, cap: u64) -> io::Result<Vec<u8>> {
    // Trusted local parents; never follow the leaf or wait for a FIFO writer.
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        FileMode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(invalid("input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(invalid("input byte limit exceeded"));
    }
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Qualification,
    Soak,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub instruction: String,
    pub window: String,
    pub stop_owner: String,
    pub allowed_actions: String,
    pub reversal: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub revision: String,
    pub source_sha256: String,
    pub binary_sha256: String,
    pub dataset_sha256: String,
    pub appliance_config_sha256: String,
    pub controller_plan_sha256: String,
    pub appliance_limits: std::collections::BTreeMap<String, u64>,
    pub platform: String,
    pub topology: String,
    pub clock_check: String,
    pub workload_basis: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Collector {
    pub path: PathBuf,
    pub target_id: String,
    pub max_age_ms: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub outstanding: usize,
    pub latency_us: u64,
    /// RSS KiB, FDs, threads, managed-disk bytes, cache entries, inflight.
    pub resources: [u64; 6],
    pub artifact_bytes: u64,
    pub aggregate_bytes: u64,
    pub window_bytes: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub id: String,
    pub bind: IpAddr,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    pub id: String,
    pub client: usize,
    pub endpoint: SocketAddr,
    pub transport: Transport,
    pub weight: u16,
    pub responses: Vec<String>,
    pub ttl_floor: u32,
    pub tcp_fallback: bool,
    pub fresh: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    pub id: String,
    pub seconds: u64,
    pub qps: u32,
    pub deadline_ms: u64,
    pub max_lag_ms: u64,
    pub accepted: Vec<usize>,
    pub generations: Vec<u64>,
    pub allow_timeouts: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub format: u8,
    pub run_id: String,
    pub seed: u64,
    pub mode: Mode,
    pub authority: Authority,
    pub identity: Identity,
    pub collector: Collector,
    pub limits: Limits,
    pub clients: Vec<Client>,
    pub lanes: Vec<Lane>,
    pub phases: Vec<Phase>,
    pub external_checks: Vec<String>,
}
pub struct Prepared {
    pub record: Run,
    pub templates: Vec<Vec<Message>>,
    pub raw: Vec<u8>,
}
fn text(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn hash(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unique_local() || v.is_unicast_link_local(),
    }
}
pub fn complete_message(bytes: &[u8]) -> io::Result<Message> {
    // This strict tooling profile compares zero-Z references; Hickory discards Z.
    if !(12..=65535).contains(&bytes.len()) || bytes[3] & 0x40 != 0 {
        return Err(invalid("DNS packet length or reserved header bit"));
    }
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(|_| invalid("DNS packet parse"))?;
    if !decoder.is_empty() {
        return Err(invalid("trailing DNS packet bytes"));
    }
    Ok(message)
}
pub fn decode(hex: &str) -> io::Result<Message> {
    if hex.len() < 24 || hex.len() > 8192 || !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return Err(invalid("reference DNS packet length/encoding"));
    }
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| {
                (b as char)
                    .to_digit(16)
                    .ok_or_else(|| invalid("reference hex"))
            };
            Ok((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect::<io::Result<Vec<_>>>()?;
    complete_message(&bytes)
}
impl Prepared {
    pub fn load(path: &std::path::Path) -> io::Result<Self> {
        Self::parse(bounded_file(path, 256 * 1024)?)
    }
    pub fn parse(raw: Vec<u8>) -> io::Result<Self> {
        if raw.len() > 256 * 1024 {
            return Err(invalid("run record byte limit"));
        }
        let r: Run =
            serde_json::from_slice(&raw).map_err(|_| invalid("invalid strict run record"))?;
        let a = &r.authority;
        let i = &r.identity;
        let l = &r.limits;
        if r.format != 1
            || !id(&r.run_id)
            || ![
                &a.instruction,
                &a.window,
                &a.stop_owner,
                &a.allowed_actions,
                &a.reversal,
                &i.platform,
                &i.topology,
                &i.clock_check,
                &i.workload_basis,
            ]
            .into_iter()
            .all(|s| text(s))
            || !hash(&i.revision, 40)
            || ![
                &i.source_sha256,
                &i.binary_sha256,
                &i.dataset_sha256,
                &i.appliance_config_sha256,
                &i.controller_plan_sha256,
            ]
            .into_iter()
            .all(|s| hash(s, 64))
            || i.appliance_limits.len() != 8
            || ![
                "raw_cache",
                "decision_cache",
                "inflight",
                "udp_tasks",
                "upstream_waiters",
                "tcp_connections",
                "event_queue",
                "history",
            ]
            .iter()
            .all(|key| {
                i.appliance_limits
                    .get(*key)
                    .is_some_and(|v| *v > 0 && *v <= u64::from(u32::MAX))
            })
            || !id(&r.collector.target_id)
            || !r.collector.path.is_absolute()
            || r.collector.path.as_os_str().len() > 4096
            || !(1000..=3000).contains(&r.collector.max_age_ms)
            || !(1..=16).contains(&r.clients.len())
            || !(1..=32).contains(&r.lanes.len())
            || !(1..=64).contains(&r.phases.len())
            || !(1..=32).contains(&r.external_checks.len())
            || !r.external_checks.iter().all(|s| text(s))
            || !(1..=256).contains(&l.outstanding)
            || !(1..=2_000_000).contains(&l.latency_us)
            || l.resources.contains(&0)
            || !(1024..=16 * 1024).contains(&l.window_bytes)
            || !(256 * 1024..=16 * 1024 * 1024).contains(&l.aggregate_bytes)
            || l.artifact_bytes > 128 * 1024 * 1024
            || l.artifact_bytes < l.aggregate_bytes + 512 * 1024
        {
            return Err(invalid(
                "missing/unsafe identity, authority, budget or cardinality",
            ));
        }
        let mut ids = HashSet::new();
        for c in &r.clients {
            if !id(&c.id) || !ids.insert(&c.id) || !private(c.bind) {
                return Err(invalid("invalid/duplicate client or public bind"));
            }
        }
        let mut templates = Vec::new();
        ids.clear();
        for lane in &r.lanes {
            if !id(&lane.id)
                || !ids.insert(&lane.id)
                || lane.client >= r.clients.len()
                || !private(lane.endpoint.ip())
                || lane.endpoint.port() == 0
                || lane.endpoint.is_ipv4() != r.clients[lane.client].bind.is_ipv4()
                || !(1..=10000).contains(&lane.weight)
                || !(1..=4).contains(&lane.responses.len())
                || (lane.tcp_fallback && lane.transport != Transport::Udp)
            {
                return Err(invalid("invalid lane, endpoint or response count"));
            }
            let messages = lane
                .responses
                .iter()
                .map(|s| decode(s))
                .collect::<io::Result<Vec<_>>>()?;
            for m in &messages {
                if m.queries.len() != 1
                    || m.queries[0].query_class() != DNSClass::IN
                    || !m.queries[0]
                        .name()
                        .to_ascii()
                        .to_ascii_lowercase()
                        .ends_with(".test.")
                    || m.metadata.message_type != hickory_proto::op::MessageType::Response
                    || m.metadata.op_code != hickory_proto::op::OpCode::Query
                    || m.metadata.truncation
                    || !m.metadata.recursion_desired
                    || m.signature.is_some()
                    || (lane.fresh && m.queries[0].name().to_ascii().len() > 217)
                    || m.answers
                        .iter()
                        .chain(&m.authorities)
                        .chain(&m.additionals)
                        .any(|rr| rr.ttl < lane.ttl_floor)
                    || m.queries != messages[0].queries
                    || m.metadata.checking_disabled != messages[0].metadata.checking_disabled
                {
                    return Err(invalid("unsafe/inconsistent reference DNS message"));
                }
            }
            templates.push(messages);
        }
        let (mut seconds, mut windows) = (0, 0);
        ids.clear();
        for p in &r.phases {
            if !id(&p.id)
                || !ids.insert(&p.id)
                || !(1..=259200).contains(&p.seconds)
                || !(1..=100000).contains(&p.qps)
                || !(1..=2000).contains(&p.deadline_ms)
                || !(1..=1000).contains(&p.max_lag_ms)
                || l.latency_us > p.deadline_ms * 1000
                || !(1..=4).contains(&p.accepted.len())
                || !(1..=32).contains(&p.generations.len())
                || p.accepted
                    .iter()
                    .any(|&index| templates.iter().any(|t| index >= t.len()))
            {
                return Err(invalid("invalid phase/rate/deadline/oracle"));
            }
            seconds += p.seconds;
            windows += p.seconds.div_ceil(60);
        }
        if seconds > 259200
            || windows > 4320
            || (matches!(r.mode, Mode::Qualification) && seconds > 900)
        {
            return Err(invalid("duration/window limit"));
        }
        Ok(Self {
            record: r,
            templates,
            raw,
        })
    }
}
