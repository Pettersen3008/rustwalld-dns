//! Fixed-memory latency measurement shared by real-process rehearsals.
use serde_json::{Value, json};
#[derive(serde::Serialize)]
pub struct Histogram {
    bins: Vec<u64>,
    replies: u64,
    timeouts: u64,
    incorrect: u64,
    clipped: u64,
    max_us: u64,
}
impl Histogram {
    pub fn new() -> Self {
        Self {
            bins: vec![0; 21001],
            replies: 0,
            timeouts: 0,
            incorrect: 0,
            clipped: 0,
            max_us: 0,
        }
    }
    pub fn record(&mut self, (us, lost, wrong): (u64, bool, bool)) {
        if lost {
            self.timeouts += 1;
            return;
        }
        self.replies += 1;
        self.incorrect += u64::from(wrong);
        self.max_us = self.max_us.max(us);
        self.clipped += u64::from(us > 2_000_000);
        // Exact microseconds through 1 ms; 100 us buckets thereafter, capped at 2 s.
        let us = us.min(2_000_000) as usize;
        let bucket = if us <= 1000 {
            us
        } else {
            1000 + (us - 1000).div_ceil(100)
        };
        self.bins[bucket] += 1;
    }
    pub fn merge(&mut self, other: Self) {
        self.replies += other.replies;
        self.timeouts += other.timeouts;
        self.incorrect += other.incorrect;
        self.clipped += other.clipped;
        self.max_us = self.max_us.max(other.max_us);
        for (a, b) in self.bins.iter_mut().zip(other.bins) {
            *a += b;
        }
    }
    pub fn report(&self) -> Value {
        let quantile = |p: u64| {
            if self.replies == 0 {
                return 0;
            }
            let rank = (self.replies * p).div_ceil(1000);
            let mut sum = 0;
            for (i, n) in self.bins.iter().enumerate() {
                sum += n;
                if sum >= rank {
                    return if i <= 1000 {
                        i
                    } else {
                        1000 + (i - 1000) * 100
                    };
                }
            }
            2_000_000
        };
        json!({"replies":self.replies,"timeouts":self.timeouts,"incorrect":self.incorrect,"latencies_clipped":self.clipped,"max_us":self.max_us,"p50_us":quantile(500),"p95_us":quantile(950),"p99_us":quantile(990),"p999_us":quantile(999)})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_repeated_samples_remain_bounded_and_preserve_counts() {
        let mut h = Histogram::new();
        assert_eq!(h.report()["p99_us"], 0);
        let capacity = h.bins.capacity();
        for _ in 0..500_000 {
            h.record((1101, false, false));
        }
        h.record((2_000_000, false, false));
        h.record((2_000_001, false, false));
        assert_eq!(h.bins.capacity(), capacity);
        assert_eq!(h.report()["replies"], 500_002);
        assert_eq!(h.report()["p99_us"], 1200);
        assert_eq!(h.report()["latencies_clipped"], 1);
        assert_eq!(h.report()["max_us"], 2_000_001);
    }
    #[test]
    fn histogram_quantiles_round_up_and_exclude_timeouts() {
        let mut h = Histogram::new();
        for us in [1, 1000, 1001, 500_000] {
            h.record((us, false, false));
        }
        h.record((500_001, true, false));
        let r = h.report();
        assert_eq!(r["replies"], 4);
        assert_eq!(r["timeouts"], 1);
        assert_eq!(r["p50_us"], 1000);
        assert_eq!(r["p95_us"], 500_000);
        let mut small = Histogram::new();
        small.record((1001, false, false));
        assert_eq!(small.report()["p50_us"], 1100);
    }
    #[test]
    fn histogram_merge_preserves_error_and_clipping_evidence() {
        let mut left = Histogram::new();
        left.record((5, false, false));
        let mut right = Histogram::new();
        right.record((2_000_001, false, true));
        right.record((500_000, true, false));
        left.merge(right);
        let r = left.report();
        assert_eq!(r["replies"], 2);
        assert_eq!(r["incorrect"], 1);
        assert_eq!(r["timeouts"], 1);
        assert_eq!(r["latencies_clipped"], 1);
        assert_eq!(r["p99_us"], 2_000_000);
        assert_eq!(r["max_us"], 2_000_001);
    }
    #[test]
    fn slow_replies_within_the_query_deadline_are_measured() {
        let mut h = Histogram::new();
        h.record((1_500_001, false, false));
        assert_eq!(h.report()["p99_us"], 1_500_100);
        assert_eq!(h.report()["max_us"], 1_500_001);
        assert_eq!(h.report()["latencies_clipped"], 0);
    }
}
