#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod assertions;
mod compile;
mod config;
mod exceptions;
mod metadata;
mod rewrite;
mod selection;
mod snapshot;
mod sources;

pub use assertions::{
    AssertionFailure, AssertionResult, AssertionTrace, CheckReport, MatchedRule, PolicyListStats,
};
pub use config::{
    Assertion, Binding, PolicyConfig, PolicyConfigSet, PolicyError, Rewrite, UpstreamProfile,
};
pub use exceptions::{MAX_EXCEPTION_REMAINING, TemporaryException, TemporaryMatch};
pub use metadata::{BindingMetadata, MAX_METADATA_BYTES};
pub use rustwalld_dns_resolver::UpstreamTransport;
pub use snapshot::{CompiledPolicy, Explanation, PolicySnapshot, Selection};
pub use sources::{
    DownloadStamp, FilterSource, MAX_DOWNLOAD_BYTES, MAX_REFRESH_INTERVAL, MIN_REFRESH_INTERVAL,
    is_unicast_destination,
};
