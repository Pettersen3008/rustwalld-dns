#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod badfilter;
mod clients;
mod compile;
mod exclusions;
mod index;
mod model;
#[cfg(feature = "parallel")]
mod parallel;
mod parsing;
mod regex_rules;
mod snapshot;
mod tags;
mod types;
mod values;

pub use clients::{ClientContext, ClientSelector, ClientValue};
pub use exclusions::DomainExclusions;
pub use model::{
    Action, Cancellation, CompileError, Decision, ListInput, ListStats, Matcher, Rule, RuleSyntax,
    Source,
};
#[cfg(feature = "parallel")]
pub use parallel::{ParallelCompiler, PoolError};
pub use parsing::normalize;
pub use snapshot::FilterSnapshot;
pub use tags::{CLIENT_TAGS, ClientTags, FilterContext, TagSelector};
pub use types::{RuleScope, TypeSelector};
