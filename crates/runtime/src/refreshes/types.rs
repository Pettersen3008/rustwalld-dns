//! Serialized schedule, queue and outcome status.
use serde::Serialize;

/// Result of the most recent check of a source.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Not checked yet.
    #[default]
    Waiting,
    /// The content matched the live list.
    Unchanged,
    /// New content was staged as a shadow for review.
    Staged,
    /// The check failed; see the error.
    Failed,
    /// Postponed by a concurrent download, mutation or change.
    Deferred,
    /// Stopped by shutdown or retirement.
    Cancelled,
}
/// The check currently in progress.
#[derive(Clone, Serialize)]
pub struct Running {
    pub(super) generation: u64,
    pub(super) source: usize,
    pub(super) policy: String,
    pub(super) list: String,
}
/// A manual check waiting for a download slot.
#[derive(Clone, Copy, Serialize)]
pub struct Queued {
    pub(super) generation: u64,
    pub(super) source: usize,
}
/// Schedule and last result for one source.
#[derive(Serialize)]
pub struct EntryStatus {
    pub(super) source: usize,
    pub(super) policy: String,
    pub(super) list: String,
    pub(super) interval_secs: u64,
    pub(super) next_check_at: u64,
    pub(super) last_checked_at: Option<u64>,
    pub(super) checked_generation: Option<u64>,
    pub(super) outcome: Outcome,
    pub(super) error: Option<String>,
    pub(super) last_http_status: Option<u16>,
    pub(super) last_download_bytes: Option<usize>,
}
/// Refresh state for the active generation.
#[derive(Serialize)]
pub struct Status {
    pub(super) generation: u64,
    pub(crate) paused: Option<&'static str>,
    pub(super) running: Option<Running>,
    pub(super) queued: Option<Queued>,
    pub(super) entries: Vec<EntryStatus>,
}
