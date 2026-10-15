//! Collector envelopes are trusted operator inputs, never fabricated host telemetry.
use super::soak_record::{Phase, Run, bounded_file, invalid};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub run_id: String,
    pub target_id: String,
    pub process_id: String,
    pub sequence: u64,
    pub unix_ms: u64,
    pub generation: u64,
    pub resources: [u64; 6],
    pub counters: BTreeMap<String, u64>,
}
#[derive(Default, Serialize)]
pub struct Summary {
    pub samples: u64,
    pub first: Option<Sample>,
    pub last: Option<Sample>,
    pub min: Option<[u64; 6]>,
    pub max: Option<[u64; 6]>,
    pub counter_deltas: BTreeMap<String, u64>,
    pub counter_resets: u64,
    pub resets: Vec<Reset>,
}
#[derive(Serialize)]
pub struct Reset {
    pub from_process: String,
    pub to_process: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub counters: Vec<String>,
}
pub fn now_ms() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("clock before epoch"))?
        .as_millis() as u64)
}
impl Sample {
    pub fn read(run: &Run, phase: &Phase) -> io::Result<Self> {
        let s: Self = serde_json::from_slice(&bounded_file(&run.collector.path, 16 * 1024)?)
            .map_err(|_| invalid("invalid collector envelope"))?;
        s.validate(run, phase, now_ms()?)?;
        Ok(s)
    }
    pub fn validate(&self, run: &Run, phase: &Phase, now: u64) -> io::Result<()> {
        if self.run_id != run.run_id
            || self.target_id != run.collector.target_id
            || self.process_id.is_empty()
            || self.process_id.len() > 64
            || !self
                .process_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
            || self.unix_ms > now.saturating_add(500)
            || now.saturating_sub(self.unix_ms) > run.collector.max_age_ms
            || !phase.generations.contains(&self.generation)
            || self.counters.is_empty()
            || self.counters.len() > 16
            || self.counters.keys().any(|s| {
                s.is_empty()
                    || s.len() > 64
                    || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        {
            return Err(invalid(
                "collector identity, freshness, generation or counter schema",
            ));
        }
        if self
            .resources
            .iter()
            .zip(run.limits.resources)
            .any(|(v, b)| *v > b)
        {
            return Err(invalid("resource budget exceeded"));
        }
        Ok(())
    }
}
pub fn continuity(previous: &Sample, next: &Sample) -> io::Result<()> {
    if next.sequence < previous.sequence
        || next.unix_ms < previous.unix_ms
        || (next.sequence == previous.sequence
            && serde_json::to_vec(previous)? != serde_json::to_vec(next)?)
        || previous.counters.keys().ne(next.counters.keys())
    {
        return Err(invalid("collector sequence/clock/counter schema changed"));
    }
    Ok(())
}
impl Summary {
    pub fn record(&mut self, previous: Option<&Sample>, s: Sample) -> io::Result<()> {
        if let Some(p) = previous {
            let reset = p.process_id != s.process_id || p.generation != s.generation;
            let reset_names: Vec<_> = s
                .counters
                .iter()
                .filter(|(name, value)| reset || **value < p.counters[*name])
                .map(|(name, _)| name.clone())
                .collect();
            if !reset_names.is_empty() {
                if self.resets.len() >= 16 {
                    return Err(invalid("counter reset evidence limit"));
                }
                self.resets.push(Reset {
                    from_process: p.process_id.clone(),
                    to_process: s.process_id.clone(),
                    from_generation: p.generation,
                    to_generation: s.generation,
                    counters: reset_names,
                });
            }
            for (name, &value) in &s.counters {
                let before = p.counters[name];
                if reset || value < before {
                    self.counter_resets += 1;
                } else {
                    let delta = self.counter_deltas.entry(name.clone()).or_default();
                    *delta = delta
                        .checked_add(value - before)
                        .ok_or_else(|| invalid("counter delta overflow"))?;
                }
            }
        }
        self.samples += 1;
        self.min = Some(std::array::from_fn(|i| {
            self.min
                .map_or(s.resources[i], |m| m[i].min(s.resources[i]))
        }));
        self.max = Some(std::array::from_fn(|i| {
            self.max
                .map_or(s.resources[i], |m| m[i].max(s.resources[i]))
        }));
        if self.first.is_none() {
            self.first = Some(s.clone());
        }
        self.last = Some(s);
        Ok(())
    }
}
