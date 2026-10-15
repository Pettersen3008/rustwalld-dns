//! Fresh-process timing/RSS: compile_compare <rules> <workers: 0|2|4> [mixed|suffix|idna|adguard|badfilter|denyallow|dnstype|client|tags].
//! Zero workers selects the sequential implementation. Linux proc reads are outside compilation.
use rustwalld_dns_filter::{FilterSnapshot, ParallelCompiler};
use std::{error::Error, time::Instant};
#[path = "../benches/support/compilation.rs"]
mod support;
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let size: usize = args.next().ok_or("missing size")?.parse()?;
    let workers: usize = args.next().ok_or("missing workers")?.parse()?;
    let workload = args.next().unwrap_or_else(|| "mixed".into());
    if args.next().is_some() || ![0, 2, 4].contains(&workers) {
        return Err(
            "expected <rules> <workers: 0|2|4> [mixed|suffix|idna|adguard|badfilter|denyallow|dnstype|client|tags]"
                .into(),
        );
    }
    let lists = support::fixture(size, &workload)?;
    let raw_budget = lists
        .iter()
        .map(|list| list.rules.lines().count())
        .sum::<usize>()
        .max(size)
        + 1;
    let start = Instant::now();
    let compiler = if workers == 0 {
        None
    } else {
        Some(ParallelCompiler::new(workers)?)
    };
    let startup_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let snapshot = match &compiler {
        None => FilterSnapshot::compile(&lists, raw_budget, usize::MAX)?,
        Some(compiler) => compiler.compile(&lists, raw_budget, usize::MAX)?,
    };
    let compile_ns = start.elapsed().as_nanos();
    if snapshot.effective_rules() != size {
        return Err("fixture did not retain the expected rule count".into());
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kib = |key| -> Result<usize, Box<dyn Error>> {
        Ok(status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next())
            .ok_or("missing memory counter")?
            .parse()?)
    };
    println!(
        "rules={size} workers={workers} workload={workload} startup_ns={startup_ns} compile_ns={compile_ns} effective_rules={} payload_bytes_estimate={} rss_kib={} peak_rss_kib={}",
        snapshot.effective_rules(),
        snapshot.payload_bytes(),
        kib("VmRSS:")?,
        kib("VmHWM:")?
    );
    std::hint::black_box(snapshot);
    std::hint::black_box(compiler);
    Ok(())
}
