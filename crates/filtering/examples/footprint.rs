//! Run one dataset per process: cargo run --release -p filtering --example footprint -- 1000000
//! Linux RSS/HWM include compiler transients retained by the allocator, not just the snapshot.
use filtering::{Action, FilterSnapshot, ListInput};
use std::{error::Error, fmt::Write, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    let size = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "100000".into())
        .parse::<usize>()?;
    if !(100..=10_000_000).contains(&size) {
        return Err("size must be between 100 and 10000000".into());
    }
    let mut rules = String::new();
    for i in 0..size {
        if i % 2 == 0 {
            writeln!(rules, "=exact{i}.bench")?;
        } else {
            writeln!(rules, "suffix{i}.bench")?;
        }
    }
    let start = Instant::now();
    let snapshot = FilterSnapshot::compile(
        &[ListInput {
            name: "fixture".into(),
            action: Action::Block,
            rules,
        }],
        size + 1,
        usize::MAX,
    )?;
    let compile_ms = start.elapsed().as_millis();
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kib = |key| -> Result<usize, Box<dyn Error>> {
        Ok(status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|value| value.split_whitespace().next())
            .ok_or("missing process memory counter")?
            .parse()?)
    };
    println!(
        "rules={} effective_rules={} compile_ms={} payload_bytes_estimate={} rss_kib={} peak_rss_kib={}",
        size,
        snapshot.effective_rules(),
        compile_ms,
        snapshot.payload_bytes(),
        kib("VmRSS:")?,
        kib("VmHWM:")?
    );
    std::hint::black_box(snapshot);
    Ok(())
}
