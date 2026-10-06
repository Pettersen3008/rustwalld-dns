//! Fixed-memory latency histogram. Quantiles are bucket upper bounds, without sampling.
//! Resolution: 10ns through 100us, 1us through 10ms, then 1ms through 2s.
const BUCKETS: usize = 21892;
pub struct Histogram {
    counts: Vec<u64>,
    total: u64,
}
impl Histogram {
    pub fn new() -> Self {
        Self {
            counts: vec![0; BUCKETS],
            total: 0,
        }
    }
    pub fn record(&mut self, ns: u64) {
        let index = if ns <= 100_000 {
            ns.div_ceil(10)
        } else if ns <= 10_000_000 {
            10_000 + (ns - 100_000).div_ceil(1000)
        } else {
            19_900 + (ns - 10_000_000).div_ceil(1_000_000).min(1991)
        };
        self.counts[index as usize] += 1;
        self.total += 1;
    }
    pub fn merge(&mut self, other: Self) {
        for (out, input) in self.counts.iter_mut().zip(other.counts) {
            *out += input;
        }
        self.total += other.total;
    }
    pub fn quantile(&self, per_thousand: u64) -> Option<u64> {
        if self.total == 0 || per_thousand > 1000 {
            return None;
        }
        let rank = ((self.total - 1) * per_thousand).div_ceil(1000) + 1;
        let mut cumulative = 0;
        for (index, count) in self.counts.iter().enumerate() {
            cumulative += count;
            if cumulative >= rank {
                return Some(match index {
                    0..=10000 => index as u64 * 10,
                    10001..=19900 => 100_000 + (index as u64 - 10000) * 1000,
                    19901..=21890 => 10_000_000 + (index as u64 - 19900) * 1_000_000,
                    _ => u64::MAX,
                });
            }
        }
        None
    }
    pub fn report(&self, phase: &str) {
        assert!(self.total > 0);
        println!(
            "phase={phase} samples={} p50_ns={} p95_ns={} p99_ns={} p999_ns={}",
            self.total,
            self.quantile(500).unwrap_or(u64::MAX),
            self.quantile(950).unwrap_or(u64::MAX),
            self.quantile(990).unwrap_or(u64::MAX),
            self.quantile(999).unwrap_or(u64::MAX)
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregation_preserves_counts_and_quantile_ranks_with_bounded_rounding() {
        let mut combined = Histogram::new();
        assert_eq!(combined.quantile(500), None);
        let mut expected = Vec::new();
        for worker in 0..4 {
            let mut histogram = Histogram::new();
            for value in [
                0, 1, 99999, 100000, 100001, 100999, 101000, 10000000, 10000001, 2000000000,
            ] {
                let ns = value + worker;
                histogram.record(ns);
                expected.push(ns);
            }
            combined.merge(histogram);
        }
        expected.sort_unstable();
        assert_eq!(combined.total, expected.len() as u64);
        assert_eq!(combined.counts.len(), BUCKETS);
        for q in [0, 100, 500, 950, 990, 999, 1000] {
            let exact = expected[((expected.len() - 1) * q).div_ceil(1000)];
            let estimate = combined.quantile(q as u64).unwrap_or(u64::MAX);
            let width = if exact <= 100000 {
                10
            } else if exact <= 10000000 {
                1000
            } else {
                1000000
            };
            if exact <= 2000000000 {
                assert!(estimate >= exact && estimate - exact < width);
            } else {
                assert_eq!(estimate, u64::MAX);
            }
        }
        assert_eq!(combined.quantile(1001), None);
    }
}
