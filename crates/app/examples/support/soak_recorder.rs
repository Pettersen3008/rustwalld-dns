//! Fixed live state, streaming windows, reserved final evidence, no per-query trace.
use super::{
    histogram::Histogram,
    soak_probe::Outcome,
    soak_record::{Phase, Run, invalid},
    soak_samples::{Sample, Summary, continuity},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Default, Serialize)]
pub struct Counts {
    pub offered: u64,
    pub sent: u64,
    pub replies: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub wrong: u64,
    pub skipped: u64,
    pub cancelled: u64,
}
impl Counts {
    fn add(&mut self, b: Self) {
        self.offered += b.offered;
        self.sent += b.sent;
        self.replies += b.replies;
        self.timeouts += b.timeouts;
        self.errors += b.errors;
        self.wrong += b.wrong;
        self.skipped += b.skipped;
        self.cancelled += b.cancelled;
    }
    pub fn reconciled(&self) -> bool {
        self.offered == self.sent + self.skipped
            && self.sent == self.replies + self.timeouts + self.errors + self.cancelled
    }
}
pub struct Stats {
    pub counts: Counts,
    pub histogram: Histogram,
    completed_phase_counts: std::collections::BTreeMap<String, u64>,
}
impl Stats {
    fn new() -> Self {
        Self {
            counts: Counts::default(),
            histogram: Histogram::new(),
            completed_phase_counts: Default::default(),
        }
    }
}
pub struct Recorder {
    pub current: Vec<Stats>,
    totals: Vec<Stats>,
    pub last_sample: Option<Sample>,
    pub resources: Summary,
    window_resources: Summary,
    run: Run,
    directory: PathBuf,
    windows: File,
    used: u64,
    reserve: u64,
    index: u64,
    window_start_ms: u64,
    inflight_start: Vec<u64>,
    offer_start_ms: u64,
    offer_end_ms: u64,
}
fn private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
impl Recorder {
    pub fn new(run: &Run, raw: &[u8], directory: &Path) -> io::Result<Self> {
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        private_file(&directory.join("run.json"))?.write_all(raw)?;
        let windows = private_file(&directory.join("windows.ndjson"))?;
        Ok(Self {
            current: (0..run.lanes.len()).map(|_| Stats::new()).collect(),
            totals: (0..run.lanes.len()).map(|_| Stats::new()).collect(),
            last_sample: None,
            resources: Summary::default(),
            window_resources: Summary::default(),
            run: run.clone(),
            directory: directory.into(),
            windows,
            used: raw.len() as u64,
            reserve: run.limits.aggregate_bytes + 64 * 1024,
            index: 0,
            window_start_ms: 0,
            inflight_start: vec![0; run.lanes.len()],
            offer_start_ms: 0,
            offer_end_ms: 0,
        })
    }
    pub fn begin_phase(&mut self, start_ms: u64, seconds: u64) {
        self.offer_start_ms = start_ms;
        self.offer_end_ms = start_ms + seconds * 1000;
    }
    pub fn sample(&mut self, phase: &Phase) -> io::Result<()> {
        let next = Sample::read(&self.run, phase)?;
        if let Some(previous) = &self.last_sample {
            continuity(previous, &next)?;
            if previous.sequence == next.sequence {
                return Ok(());
            }
        }
        self.resources
            .record(self.last_sample.as_ref(), next.clone())?;
        self.window_resources
            .record(self.last_sample.as_ref(), next.clone())?;
        self.last_sample = Some(next);
        Ok(())
    }
    pub fn sent(&mut self, lane: usize) {
        self.current[lane].counts.offered += 1;
        self.current[lane].counts.sent += 1;
    }
    pub fn skipped(&mut self, start: u64, count: u64) {
        let weight: u64 = self.run.lanes.iter().map(|l| u64::from(l.weight)).sum();
        let prefix =
            |end: u64, lo: u64, w: u64| end / weight * w + (end % weight).saturating_sub(lo).min(w);
        let mut lo = 0;
        for (lane, stats) in self.run.lanes.iter().zip(&mut self.current) {
            let w = u64::from(lane.weight);
            let n = prefix(start + count, lo, w) - prefix(start, lo, w);
            stats.counts.offered += n;
            stats.counts.skipped += n;
            lo += w;
        }
    }
    pub fn outcome(&mut self, lane: usize, result: Outcome, phase: &Phase) -> Option<&'static str> {
        let s = &mut self.current[lane];
        *s.completed_phase_counts
            .entry(phase.id.clone())
            .or_default() += 1;
        match result {
            Outcome::Reply { us, wrong } => {
                s.counts.replies += 1;
                s.counts.wrong += u64::from(wrong);
                s.histogram.record((us, false, wrong));
                if wrong {
                    Some("wrong_answer")
                } else if us > 2_000_000 {
                    Some("clipped_latency")
                } else if us > self.run.limits.latency_us {
                    Some("latency_budget")
                } else {
                    None
                }
            }
            Outcome::Timeout => {
                s.counts.timeouts += 1;
                s.histogram.record((0, true, false));
                if phase.allow_timeouts {
                    None
                } else {
                    Some("unexpected_timeout")
                }
            }
            Outcome::Error => {
                s.counts.errors += 1;
                Some("exchange_error")
            }
        }
    }
    pub fn cancel(&mut self, pending: &[u64]) {
        for (s, &n) in self.current.iter_mut().zip(pending) {
            s.counts.cancelled += n;
        }
    }
    pub fn flush(&mut self, phase: &Phase, elapsed_ms: u64, pending: &[u64]) -> io::Result<()> {
        let mut records = Vec::new();
        let result = (|| {
            if self.index >= 4320 {
                return Err(invalid("window count limit"));
            }
            for (i, (lane, s)) in self.run.lanes.iter().zip(&self.current).enumerate() {
                let c = s.counts;
                if c.offered != c.sent + c.skipped
                    || self.inflight_start[i] + c.sent
                        != c.replies + c.timeouts + c.errors + c.cancelled + pending[i]
                {
                    return Err(invalid("window accounting mismatch"));
                }
                let value = json!({"run_id":self.run.run_id,"phase":phase.id,"lane":lane.id,
                    "transport":lane.transport,"client":self.run.clients[lane.client].id,
                    "window":self.index,"start_ms":self.window_start_ms,"end_ms":elapsed_ms,
                    "offer_start_ms":self.offer_start_ms,"offer_end_ms":self.offer_end_ms,
                    "counts":s.counts,"inflight_start":self.inflight_start[i],"inflight_end":pending[i],
                    "histogram":s.histogram.report(),"resources":self.window_resources,
                    "completed_phase_counts":s.completed_phase_counts,
                    "last_generation":self.last_sample.as_ref().map(|s|s.generation)});
                let mut bytes = serde_json::to_vec(&value)?;
                bytes.push(b'\n');
                if bytes.len() as u64 > self.run.limits.window_bytes {
                    return Err(invalid("window record limit"));
                }
                records.push(bytes);
            }
            let bytes: u64 = records.iter().map(|r| r.len() as u64).sum();
            if self.used + bytes + self.reserve > self.run.limits.artifact_bytes {
                return Err(invalid("artifact limit"));
            }
            for bytes in &records {
                self.windows.write_all(bytes)?;
                self.used += bytes.len() as u64;
            }
            self.windows.sync_data()?;
            Ok(())
        })();
        // Preserve aggregates even if the window write/cap fails; never double count on finish.
        for (total, current) in self.totals.iter_mut().zip(&mut self.current) {
            let old = std::mem::replace(current, Stats::new());
            total.counts.add(old.counts);
            total.histogram.merge(old.histogram);
            for (phase, n) in old.completed_phase_counts {
                *total.completed_phase_counts.entry(phase).or_default() += n;
            }
        }
        self.window_resources = Summary::default();
        self.window_start_ms = elapsed_ms;
        self.inflight_start = pending.to_vec();
        self.index += 1;
        result
    }
    fn final_file(&mut self, name: &str, value: &Value, cap: u64) -> io::Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > cap
            || self.used + bytes.len() as u64 > self.run.limits.artifact_bytes
        {
            return Err(invalid("final evidence limit"));
        }
        let mut file = private_file(&self.directory.join(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        self.used += bytes.len() as u64;
        Ok(())
    }
    pub fn finish(
        mut self,
        phase: &Phase,
        elapsed_ms: u64,
        failure: Option<String>,
        completed: bool,
    ) -> io::Result<Value> {
        let mut failure = failure;
        let pending = vec![0; self.run.lanes.len()];
        if self.current.iter().any(|s| {
            s.counts.offered > 0
                || s.counts.replies + s.counts.timeouts + s.counts.errors + s.counts.cancelled > 0
        }) && let Err(e) = self.flush(phase, elapsed_ms, &pending)
        {
            failure = Some(e.to_string());
        }
        let mut clients = vec![Counts::default(); self.run.clients.len()];
        let mut counts = Counts::default();
        let mut lanes = Vec::new();
        for (lane, total) in self.run.lanes.iter().zip(&self.totals) {
            counts.add(total.counts);
            clients[lane.client].add(total.counts);
            lanes.push(
                json!({"lane":lane.id,"transport":lane.transport,"counts":total.counts,
                "quantiles":total.histogram.report(),"histogram":total.histogram,"completed_phase_counts":total.completed_phase_counts}),
            );
        }
        let intended: u64 = self
            .run
            .phases
            .iter()
            .map(|p| p.seconds * u64::from(p.qps))
            .sum();
        let passed = failure.is_none()
            && completed
            && counts.offered == intended
            && counts.reconciled()
            && self.totals.iter().all(|s| s.counts.replies > 0)
            && counts.wrong + counts.skipped + counts.cancelled + counts.errors == 0
            && self.resources.samples > 0;
        if !passed && failure.is_none() {
            failure = Some("incomplete driver evidence".into());
        }
        let aggregate = json!({"precision":"exact us through 1 ms, 100 us upper bounds thereafter; 2 s cap; 21001 bins",
            "lanes":lanes});
        if let Err(error) = self.final_file(
            "aggregate.json",
            &aggregate,
            self.run.limits.aggregate_bytes,
        ) {
            failure = Some(error.to_string());
        }
        let report = json!({"format":1,"run_id":self.run.run_id,"driver_passed":passed&&failure.is_none(),
            "failure":failure,"completed":completed,"elapsed_ms":elapsed_ms,"intended":intended,
            "counts":counts,"unoffered":intended.saturating_sub(counts.offered),"accounting_reconciled":counts.reconciled(),"windows":self.index,
            "clients":self.run.clients.iter().zip(clients).map(|(c,n)|json!({"client":c.id,"counts":n})).collect::<Vec<_>>(),
            "resources":self.resources,"external_checks_unverified":self.run.external_checks,
            "scope":"DNS driver only; sent counts dispatched exchange attempts, not verified wire delivery; phase labels identify dispatch intervals and completed_phase_counts preserves outcome origins; no independent provenance or representative acceptance"});
        self.final_file("summary.json", &report, 64 * 1024)?;
        Ok(report)
    }
}
