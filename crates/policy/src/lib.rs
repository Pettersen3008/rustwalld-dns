#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod assertions;
mod compile;
mod config;
mod exceptions;
mod local_dns;
mod metadata;
mod rewrite;
mod safe_search;
mod schedules;
mod selection;
mod services;
mod snapshot;
mod sources;

pub use assertions::{
    AssertionFailure, AssertionResult, AssertionTrace, CheckReport, MatchedRule, PolicyListStats,
};
pub use config::{
    Assertion, Binding, DsRouting, PolicyConfig, PolicyConfigSet, PolicyError, Rewrite,
    UpstreamProfile,
};
pub use exceptions::{MAX_EXCEPTION_REMAINING, TemporaryException, TemporaryMatch};
pub use local_dns::{AddressFamily, BlockMode, DomainRoute, LocalData, LocalRecord, ServiceParams};
pub use metadata::{BindingMetadata, MAX_METADATA_BYTES};
pub use rustwalld_dns_resolver::UpstreamTransport;
pub use safe_search::{SafeSearchConfig, SafeSearchMatch, SafeSearchProvider, YouTubeMode};
pub use schedules::{
    SCHEDULE_TZDB_VERSION, ScheduleDay, ScheduleEvaluation, ScheduleExplanation, ScheduleMode,
    ScheduleWindow, ServiceScheduleState, WeeklySchedule,
};
pub use services::{
    BlockedServices, LATEST_SERVICE_CATALOG_VERSION, ServiceDefinition, service_catalog,
    service_catalog_for_version,
};
pub use snapshot::{CompiledPolicy, Explanation, PolicySnapshot, Selection};
pub use sources::{
    DownloadStamp, FilterSource, MAX_DOWNLOAD_BYTES, MAX_REFRESH_INTERVAL, MIN_REFRESH_INTERVAL,
    is_unicast_destination,
};
