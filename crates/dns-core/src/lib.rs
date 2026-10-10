#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod control;
mod decision_cache;
mod engine;
mod response;
mod server;
pub mod telemetry;

pub use control::{
    PendingPublication, PolicyController, PolicyVersion, PublicationError, PublicationTarget,
};
pub use engine::{Engine, EngineConfig, PendingQuery, Prepared, Transport};
pub use response::reply;
pub use rustwalld_dns_filter::{Action, ListInput};
pub use rustwalld_dns_policy::{
    Assertion, Binding, BindingMetadata, PolicyConfig, PolicyConfigSet, PolicySnapshot, Rewrite,
    TemporaryException, UpstreamProfile, UpstreamTransport,
};
pub use rustwalld_dns_resolver::response_cache::ServeStale;
pub use server::{Server, ServerConfig};
pub use telemetry::{QueryEvent, QuerySource, Telemetry};
