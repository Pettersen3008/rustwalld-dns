#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod compiler;
/// Host-specific configuration checks.
pub mod config;
/// Durable, assertion-gated policy operations.
pub mod control;
/// Bounded HTTPS downloads of remote filter lists.
pub mod downloads;
mod lifecycle;
/// Offline database verification and online backup.
pub mod maintenance;
/// Scheduled checks of remote filter lists.
pub mod refreshes;
/// SQLite persistence for revisions and query history.
pub mod store;
pub use control::{Candidate, ControlError, ControlService};
pub use lifecycle::{Runtime, RuntimeConfig};
