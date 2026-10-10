//! Linux benchmark-only CPU accounting. No proc reads occur inside Engine.
use fixtures::Engine;
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{RData, rdata::A},
};
use rustwalld_dns_core::Transport;
use std::{error::Error, io, time::Instant};

#[path = "../benches/support/fixtures.rs"]
mod fixtures;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Blocked,
    Cache,
    Temporary,
    Rewrite,
    LongCache,
    DnssecCache,
}
impl Scenario {
    const ALL: [Self; 6] = [
        Self::Blocked,
        Self::Cache,
        Self::Temporary,
        Self::Rewrite,
        Self::LongCache,
        Self::DnssecCache,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Cache => "cache",
            Self::Temporary => "temporary",
            Self::Rewrite => "rewrite",
            Self::LongCache => "long-cache",
            Self::DnssecCache => "dnssec-cache",
        }
    }
    fn fixture(self) -> (Engine, Vec<u8>) {
        match self {
            Self::Blocked => {
                let (engine, blocked, _) = fixtures::setup(None);
                (engine, blocked)
            }
            Self::Cache => {
                let (engine, _, cached) = fixtures::setup(None);
                (engine, cached)
            }
            Self::Temporary => {
                let (engine, _, cached) = fixtures::setup(Some("cached.test"));
                (engine, cached)
            }
            Self::Rewrite => fixtures::rewrite(),
            Self::LongCache => fixtures::dnssec_cache(true),
            Self::DnssecCache => fixtures::dnssec_cache(false),
        }
    }
    fn counter(self, engine: &Engine) -> u64 {
        match self {
            Self::Blocked => engine.telemetry().metrics.snapshot().blocked,
            Self::Rewrite => engine.telemetry().metrics.snapshot().rewrites,
            _ => engine.resolver().metrics.snapshot().cache_hits,
        }
    }
}
struct Options {
    iterations: u64,
    batches: u16,
    scenario: Option<Scenario>,
    inject_cache_miss: bool,
}
impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let (mut iterations, mut batches, mut scenario, mut inject_cache_miss) =
            (None, None, None, None);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| invalid("every option requires a value"))?;
            match flag.as_str() {
                "--iterations" if iterations.is_none() => iterations = Some(value.parse::<u64>()?),
                "--batches" if batches.is_none() => batches = Some(value.parse::<u16>()?),
                "--scenario" if scenario.is_none() => {
                    scenario = Some(
                        Scenario::ALL
                            .into_iter()
                            .find(|s| s.name() == value)
                            .ok_or_else(|| invalid("unknown scenario"))?,
                    )
                }
                "--inject-cache-miss" if inject_cache_miss.is_none() => {
                    inject_cache_miss = Some(value.parse::<bool>()?)
                }
                _ => return Err(invalid("unknown or repeated option").into()),
            }
        }
        let options = Self {
            iterations: iterations.unwrap_or(2_000_000),
            batches: batches.unwrap_or(3),
            scenario,
            inject_cache_miss: inject_cache_miss.unwrap_or(false),
        };
        if !(10_000..=5_000_000).contains(&options.iterations)
            || !(1..=5).contains(&options.batches)
        {
            return Err(invalid("iterations must be 10000..5000000 and batches 1..5").into());
        }
        Ok(options)
    }
}
#[derive(Debug, Eq, PartialEq)]
struct CpuTicks {
    user: u64,
    system: u64,
}
impl CpuTicks {
    fn parse(stat: &str) -> io::Result<Self> {
        // comm may contain spaces and closing parentheses. Fields after the
        // final ') ' begin at field 3; utime/stime are fields 14/15. Child CPU
        // (fields 16/17) is deliberately excluded.
        let (_, tail) = stat
            .rsplit_once(") ")
            .ok_or_else(|| invalid("missing proc comm"))?;
        let mut fields = tail.split_whitespace();
        let user = fields
            .nth(11)
            .ok_or_else(|| invalid("missing utime"))?
            .parse()
            .map_err(|_| invalid("invalid utime"))?;
        let system = fields
            .next()
            .ok_or_else(|| invalid("missing stime"))?
            .parse()
            .map_err(|_| invalid("invalid stime"))?;
        Ok(Self { user, system })
    }
    fn read() -> io::Result<Self> {
        Self::parse(&std::fs::read_to_string("/proc/self/stat")?)
    }
    fn since(self, before: Self) -> io::Result<Self> {
        Ok(Self {
            user: self
                .user
                .checked_sub(before.user)
                .ok_or_else(|| invalid("user CPU moved backwards"))?,
            system: self
                .system
                .checked_sub(before.system)
                .ok_or_else(|| invalid("system CPU moved backwards"))?,
        })
    }
}
fn clock_ticks() -> Result<u64, Box<dyn Error>> {
    let output = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()?;
    if !output.status.success() {
        return Err(invalid("getconf CLK_TCK failed").into());
    }
    let hz = std::str::from_utf8(&output.stdout)?.trim().parse::<u64>()?;
    if hz == 0 {
        return Err(invalid("zero clock tick frequency").into());
    }
    Ok(hz)
}
fn validate(scenario: Scenario, bytes: &[u8], response: &[u8]) -> Result<(), Box<dyn Error>> {
    let request = Message::from_vec(bytes)?;
    let reply = Message::from_vec(response)?;
    let code = if scenario == Scenario::Blocked {
        ResponseCode::NXDomain
    } else {
        ResponseCode::NoError
    };
    let address = if scenario == Scenario::Rewrite {
        std::net::Ipv4Addr::new(192, 0, 2, 2)
    } else {
        std::net::Ipv4Addr::new(192, 0, 2, 1)
    };
    if request.queries.len() != 1
        || reply.metadata.id != request.metadata.id
        || reply.metadata.message_type != MessageType::Response
        || reply.metadata.response_code != code
        || reply.metadata.truncation
        || reply.queries != request.queries
        || reply.answers.len() != usize::from(scenario != Scenario::Blocked)
        || reply.queries[0].name().to_ascii() != request.queries[0].name().to_ascii()
        || reply.answers.iter().any(|record| {
            &record.name != request.queries[0].name()
                || record.data != RData::A(A(address))
                || record.ttl == 0
        })
    {
        return Err(invalid("fixture returned an incorrect reply").into());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    if !cfg!(target_os = "linux") {
        return Err(invalid("CPU probe requires Linux procfs").into());
    }
    let options = Options::parse(std::env::args().skip(1))?;
    let hz = clock_ticks()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = "127.0.0.1".parse()?;
    println!(
        "scenario\tbatch\tqueries\tuser_ticks\tsystem_ticks\tclock_hz\twall_ns\tupstream_requests"
    );
    for scenario in Scenario::ALL
        .into_iter()
        .filter(|s| options.scenario.is_none_or(|wanted| *s == wanted))
    {
        let (mut engine, bytes) = scenario.fixture();
        let warm = runtime
            .block_on(engine.answer(&bytes, client, Transport::Udp))
            .ok_or_else(|| invalid("missing warm reply"))?;
        validate(scenario, &bytes, &warm)?;
        for _ in 0..10_000 {
            if std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, Transport::Udp)))
                .is_none()
                || engine.resolver().metrics.snapshot().upstream_lookups != 0
            {
                return Err(invalid("warm-up failed or attempted upstream work").into());
            }
        }
        // This benchmark links no allocation-counter hooks. Criterion measures
        // allocations separately using these same fixtures.
        if options.inject_cache_miss && scenario == Scenario::Cache {
            engine = engine.without_response_cache();
        }
        for batch in 1..=options.batches {
            let count = scenario.counter(&engine);
            let requests = engine.telemetry().metrics.snapshot().requests;
            let temporary = engine.telemetry().metrics.snapshot().temporary_allows;
            let before = CpuTicks::read()?;
            let start = Instant::now();
            for _ in 0..options.iterations {
                // This guard is part of the measured workload. Abort on the
                // first accidental miss (loopback-only, 50ms timeout), rather
                // than measuring millions of unintended upstream exchanges.
                if std::hint::black_box(runtime.block_on(engine.answer(
                    std::hint::black_box(&bytes),
                    client,
                    Transport::Udp,
                )))
                .is_none()
                    || engine.resolver().metrics.snapshot().upstream_lookups != 0
                {
                    return Err(invalid("probe failed or attempted upstream work").into());
                }
            }
            let wall = start.elapsed().as_nanos();
            let cpu = CpuTicks::read()?.since(before)?;
            if scenario.counter(&engine) - count != options.iterations
                || engine.telemetry().metrics.snapshot().requests - requests != options.iterations
                || (scenario == Scenario::Temporary
                    && engine.telemetry().metrics.snapshot().temporary_allows - temporary
                        != options.iterations)
            {
                return Err(invalid("query/source counters failed to reconcile").into());
            }
            let sample = runtime
                .block_on(engine.answer(&bytes, client, Transport::Udp))
                .ok_or_else(|| invalid("missing final reply"))?;
            validate(scenario, &bytes, &sample)?;
            println!(
                "{}\t{batch}\t{}\t{}\t{}\t{hz}\t{wall}\t0",
                scenario.name(),
                options.iterations,
                cpu.user,
                cpu.system,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn stat_parser_handles_comm_delimiters_and_excludes_child_cpu() {
        assert_eq!(
            CpuTicks::parse("17 (worker ) name) R 1 2 3 4 5 6 7 8 9 10 111 222 99999 88888")
                .unwrap(),
            CpuTicks {
                user: 111,
                system: 222
            }
        );
        for bad in [
            "",
            "17 (worker) R 1",
            "17 (worker) R 1 2 3 4 5 6 7 8 9 10 -1 2",
            "17 (worker) R 1 2 3 4 5 6 7 8 9 10 1 x",
        ] {
            assert!(CpuTicks::parse(bad).is_err());
        }
        assert!(
            CpuTicks { user: 1, system: 2 }
                .since(CpuTicks { user: 2, system: 1 })
                .is_err()
        );
    }
    #[test]
    fn options_reject_invalid_or_unbounded_work() {
        for args in [
            vec!["--iterations", "0"],
            vec!["--iterations", "5000001"],
            vec!["--batches", "6"],
            vec!["--scenario", "unknown"],
            vec!["--batches", "1", "--batches", "2"],
            vec!["--iterations"],
            vec!["--unknown", "1"],
        ] {
            assert!(Options::parse(args.into_iter().map(str::to_owned)).is_err());
        }
        let valid = Options::parse(
            [
                "--iterations",
                "10000",
                "--batches",
                "1",
                "--scenario",
                "cache",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(valid.iterations, 10000);
        assert_eq!(valid.scenario, Some(Scenario::Cache));
    }
    #[test]
    fn fixture_validation_rejects_wrong_answers() {
        let (engine, bytes) = Scenario::Cache.fixture();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = runtime
            .block_on(engine.answer(&bytes, "127.0.0.1".parse().unwrap(), Transport::Udp))
            .unwrap();
        validate(Scenario::Cache, &bytes, &response).unwrap();
        let mut wrong = Message::from_vec(&response).unwrap();
        wrong.answers[0].data = RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 99)));
        assert!(validate(Scenario::Cache, &bytes, &wrong.to_vec().unwrap()).is_err());
        let mut wrong = Message::from_vec(&response).unwrap();
        wrong.metadata.id = wrong.metadata.id.wrapping_add(1);
        assert!(validate(Scenario::Cache, &bytes, &wrong.to_vec().unwrap()).is_err());
    }
}
