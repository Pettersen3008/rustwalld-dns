//! Public durable revision and query-history values.
use super::SCHEMA_VERSION;
use serde::Serialize;
use serde_json::Value;

/// Persisted revision state, serialized with the existing schema vocabulary.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevisionMode {
    /// Published as the active revision.
    Promoted,
    /// Staged as the shadow revision.
    Shadow,
}
impl RevisionMode {
    /// Stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Promoted => "promoted",
            Self::Shadow => "shadow",
        }
    }
}
/// Durable runtime pointers and source policy content.
#[derive(Debug, Serialize)]
pub struct Bootstrap {
    /// Active revision.
    pub active: u64,
    /// Next unused revision identifier, above every stored one.
    pub next: u64,
    /// Active revision content as JSON.
    pub config: String,
    /// Shadow revision, if staged.
    pub shadow: Option<u64>,
}
/// A successful durable revision commit.
#[derive(Debug, Serialize)]
pub struct CommitReport {
    /// Committed revision.
    pub generation: u64,
    /// Whether it was promoted or staged.
    pub state: RevisionMode,
}
/// A successful durable shadow removal.
#[derive(Debug, Serialize)]
pub struct ClearShadowReport {
    /// The shadow revision that was removed, if any.
    pub shadow: Option<u64>,
}
/// Historical revision content. Malformed stored JSON is an explicit
/// [`StoreError::CorruptRevision`], never `null`.
#[derive(Serialize)]
pub struct Revision {
    /// Revision identifier.
    pub id: u64,
    /// Stored configuration.
    pub config: Value,
}
/// Revision metadata without content.
#[derive(Debug, Serialize)]
pub struct RevisionSummary {
    /// Revision identifier.
    pub id: u64,
    /// Creation time (UTC, RFC 3339).
    pub timestamp: String,
    /// Who created it (`api`, `rollback`, `scheduled-refresh`, ...).
    pub actor: String,
    /// `promoted` or `shadow`.
    pub state: String,
    /// Changed top-level configuration sections.
    pub diff: String,
}
/// One persisted query event.
#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    /// Row identifier (increasing).
    pub id: u64,
    /// Persistence time (UTC, RFC 3339).
    pub timestamp: String,
    /// Client address.
    pub client: String,
    /// Source identity was intentionally omitted by the logging preference.
    pub client_masked: bool,
    /// Normalized query name.
    pub domain: String,
    /// Reachable alias target responsible for a block, if present.
    pub matched_domain: Option<String>,
    /// Record type of the matched response subject; original qtype is separate.
    pub matched_type: Option<u16>,
    /// Query type code.
    pub qtype: u16,
    /// Deciding generation.
    pub generation: u64,
    /// Selected policy index.
    pub policy_id: i64,
    /// `allow` or `block`.
    pub action: String,
    /// Deciding rule, if any.
    pub rule_id: Option<u32>,
    /// Whether the decision cache answered.
    pub decision_cached: bool,
    /// Response code sent.
    pub response_code: u16,
    /// How the answer was produced.
    pub source: String,
    /// Processing time in microseconds.
    pub latency_us: i64,
    /// Shadow decision, when one was staged.
    pub shadow: Option<Value>,
    /// Temporary exception index, if one allowed the query.
    pub temporary_exception: Option<u16>,
    /// Actual final scheduled filter state, not database insertion time.
    pub service_schedule: Option<rustwalld_dns_policy::ServiceScheduleState>,
}
/// Bounded store admission and worker failures; never returned by DNS queries.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Preference bounds are invalid; the current mode remains in place.
    #[error("invalid privacy preferences: {0}")]
    InvalidPrivacy(String),
    /// Preference revision changed before durable mutation.
    #[error("privacy preferences changed")]
    StalePrivacy,
    /// The bounded command queue is full or closed.
    #[error("database command queue unavailable")]
    QueueUnavailable,
    /// The worker stopped before replying.
    #[error("database worker stopped")]
    WorkerStopped,
    /// SQLite failure, including lock contention and constraint violations.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// Stored revision content is not JSON; it is never replaced by `null`.
    #[error("stored revision {id} is not valid JSON")]
    CorruptRevision {
        /// The unreadable revision.
        id: u64,
        /// The parse failure.
        #[source]
        source: serde_json::Error,
    },
    /// A runtime pointer names a revision that no longer exists.
    #[error("runtime {pointer} pointer refers to missing revision {id}")]
    DanglingPointer {
        /// `active` or `shadow`.
        pointer: &'static str,
        /// The missing revision.
        id: u64,
    },
    /// Revisions exist without an active pointer; bootstrapping would reuse IDs.
    #[error("database has revisions but no active runtime pointer")]
    MissingActive,
    /// The database was written by a newer, incompatible release.
    #[error("unsupported database schema {found}; expected {SCHEMA_VERSION}")]
    Schema {
        /// Schema version found.
        found: i64,
    },
    /// Concurrent writers and crash recovery require write-ahead logging.
    #[error("database journal mode is {0:?}; write-ahead logging is required")]
    JournalMode(String),
    /// The database file could not be created.
    #[error("database file could not be created")]
    Create(#[source] std::io::Error),
    /// The worker replied with an unexpected message.
    #[error("unexpected database worker response")]
    Response,
    /// The worker thread or its runtime could not start.
    #[error("database worker could not start")]
    Spawn(#[source] std::io::Error),
}
