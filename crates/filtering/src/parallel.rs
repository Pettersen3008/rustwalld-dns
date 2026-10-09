//! Optional bounded control-plane work. Query snapshots never retain this pool.
use crate::{CompileError, FilterSnapshot, ListInput, compile};
use compile::{ParsedRules, Work};
use rayon::{ThreadPool, ThreadPoolBuilder, prelude::*};

const BATCH_LINES: usize = 8192;
const BATCH_BYTES: usize = 1024 * 1024;
const PARSE_MIN_BYTES: usize = 64 * 1024;
const INDEX_MIN_RULES: usize = 32768;

/// Why a [`ParallelCompiler`] could not be created.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PoolError {
    /// Worker count outside 1..=4.
    #[error("compilation workers must be between 1 and 4")]
    Workers,
    /// The thread pool failed to start.
    #[error("could not start compilation workers: {0}")]
    Start(#[from] rayon::ThreadPoolBuildError),
}

/// Owned compilation pool. Create once on the control plane and share as needed.
/// Never call compilation or construct this pool from a DNS query task.
pub struct ParallelCompiler {
    pool: ThreadPool,
}
impl ParallelCompiler {
    /// Start an owned pool of `workers` threads.
    ///
    /// # Errors
    ///
    /// [`PoolError::Workers`] outside 1..=4, or [`PoolError::Start`].
    pub fn new(workers: usize) -> Result<Self, PoolError> {
        if !(1..=4).contains(&workers) {
            return Err(PoolError::Workers);
        }
        let pool = ThreadPoolBuilder::new()
            .num_threads(workers)
            .thread_name(|index| format!("dns-compile-{index}"))
            .build()?;
        Ok(Self { pool })
    }
    /// Same result as [`FilterSnapshot::compile`], parsing and indexing large
    /// inputs on this pool.
    ///
    /// # Errors
    ///
    /// As for [`FilterSnapshot::compile`].
    pub fn compile(
        &self,
        lists: &[ListInput],
        max_rules: usize,
        max_bytes: usize,
    ) -> Result<FilterSnapshot, CompileError> {
        compile::build(lists, max_rules, max_bytes, self)
    }
}
impl Work for ParallelCompiler {
    fn parse(
        &self,
        list: &ListInput,
        budget: usize,
        mut consume: impl FnMut(usize, ParsedRules) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        if list.rules.len() < PARSE_MIN_BYTES {
            return compile::Sequential.parse(list, budget, consume);
        }
        let mut lines = list.rules.lines().enumerate().peekable();
        let mut raw = 0;
        loop {
            let mut batch = Vec::new();
            let mut bytes = 0;
            while let Some(&(index, line)) = lines.peek() {
                let Some(content) = compile::content(line) else {
                    lines.next();
                    continue;
                };
                if raw == budget
                    || batch.len() == BATCH_LINES
                    || line.len() > BATCH_BYTES
                    || bytes + line.len() > BATCH_BYTES
                {
                    break;
                }
                lines.next();
                raw += 1;
                bytes += line.len();
                batch.push((index, content));
            }
            if !batch.is_empty() {
                // Indexed collection retains input order. Commit and deduplicate
                // below on the caller, never concurrently or by worker order.
                let parsed: Vec<_> = self.pool.install(|| {
                    batch
                        .par_iter()
                        .map(|&(index, line)| (index, crate::parse_rule(line, list.action)))
                        .collect()
                });
                for (index, rules) in parsed {
                    consume(index, rules)?;
                }
                continue;
            }
            let Some((index, line)) = lines.next() else {
                return Ok(());
            };
            let Some(line) = compile::content(line) else {
                continue;
            };
            if raw == budget {
                return Err(CompileError::Limit);
            }
            // An oversized individual line follows the original parser alone;
            // never expand several oversized hosts lines concurrently.
            raw += 1;
            consume(index, crate::parse_rule(line, list.action))?;
        }
    }
    fn finish(&self, snapshot: &mut FilterSnapshot) {
        if snapshot.rules.len() < INDEX_MIN_RULES {
            return compile::Sequential.finish(snapshot);
        }
        let FilterSnapshot { rules, suffix, .. } = &mut *snapshot;
        let suffix = &*suffix;
        self.pool.install(|| {
            rules
                .par_iter_mut()
                .for_each(|rule| rule.redundant = compile::redundant(suffix, rule));
        });
        compile::index_exact(snapshot);
        compile::retain_effective_suffixes(snapshot);
    }
}
