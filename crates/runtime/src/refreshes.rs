//! One bounded control-plane worker. Timers never promote production policy.
mod job;
mod schedule;
mod types;
mod worker;

pub use schedule::Refresher;
use std::time::Duration;
pub use types::{EntryStatus, Outcome, Queued, Running, Status};
pub use worker::run;

const RETRY_BUSY: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests;
