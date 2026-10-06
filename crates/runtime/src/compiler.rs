//! Owned control-plane backend, shared by startup, restore, checks and staging.
use rustwalld_dns_policy::{CheckReport, PolicyConfigSet, PolicyError, PolicySnapshot};
#[derive(Clone, Default)]
pub(crate) enum Compiler {
    #[default]
    Sequential,
    #[cfg(feature = "parallel-compilation")]
    Parallel(std::sync::Arc<rustwalld_dns_filter::ParallelCompiler>),
}
impl Compiler {
    pub fn compile(
        &self,
        config: PolicyConfigSet,
        generation: u64,
    ) -> Result<PolicySnapshot, PolicyError> {
        match self {
            Self::Sequential => PolicySnapshot::compile(config, generation),
            #[cfg(feature = "parallel-compilation")]
            Self::Parallel(compiler) => {
                PolicySnapshot::compile_parallel(config, generation, compiler)
            }
        }
    }
    pub fn check(&self, config: PolicyConfigSet) -> Result<CheckReport, PolicyError> {
        match self {
            Self::Sequential => PolicySnapshot::check(config),
            #[cfg(feature = "parallel-compilation")]
            Self::Parallel(compiler) => PolicySnapshot::check_parallel(config, compiler),
        }
    }
}
