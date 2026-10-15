use super::{Engine, Outcome, Pending, PendingQuery};
use crate::{reply, telemetry::QuerySource};
use hickory_proto::op::{Message, ResponseCode};
use rustwalld_dns_resolver::ResolutionSource;
use std::time::Instant;

impl Engine {
    /// Resolve a prepared cache miss upstream (coalescing identical misses) and
    /// encode the reply under the generation that admitted the query.
    pub async fn forward(&self, pending: PendingQuery) -> Option<Vec<u8>> {
        let pending = pending.0;
        let resolved = self
            .resolver
            .forward(
                pending.lookup_request.as_ref().unwrap_or(&pending.request),
                pending.key.clone(),
                pending.upstream.clone(),
            )
            .await;
        let (response, source) = match resolved {
            Ok(result) => (
                result.response,
                match result.source {
                    ResolutionSource::Cache => QuerySource::Cache,
                    ResolutionSource::Coalesced => QuerySource::Coalesced,
                    ResolutionSource::Stale => QuerySource::Stale,
                    // Any other resolver source still came from an upstream.
                    _ => QuerySource::Upstream,
                },
            ),
            Err(_) => (
                reply(&pending.request, ResponseCode::ServFail),
                QuerySource::Failure,
            ),
        };
        self.complete(pending, response, source)
    }

    /// Answer a prepared cache miss with SERVFAIL without forwarding it, for
    /// servers shedding load when too many queries already wait on upstreams.
    pub fn reject(&self, pending: PendingQuery) -> Option<Vec<u8>> {
        let pending = pending.0;
        let response = reply(&pending.request, ResponseCode::ServFail);
        self.complete(pending, response, QuerySource::Failure)
    }

    fn complete(
        &self,
        pending: Box<Pending>,
        response: Message,
        source: QuerySource,
    ) -> Option<Vec<u8>> {
        self.complete_at(pending, response, source, None)
    }
    pub(super) fn complete_at(
        &self,
        pending: Box<Pending>,
        mut response: Message,
        mut source: QuerySource,
        at: Option<std::time::SystemTime>,
    ) -> Option<Vec<u8>> {
        let Pending {
            start,
            client,
            transport,
            request,
            snapshot,
            domain,
            qtype,
            decision,
            decision_cached,
            excepted,
            schedule,
            aliases,
            ..
        } = *pending;
        if let Some(aliases) = aliases.filter(|_| source != QuerySource::Failure) {
            response.answers.splice(0..0, aliases);
            if snapshot
                .select(client)
                .policy
                .safe_search_match(&domain)
                .is_some()
            {
                source = QuerySource::SafeSearch;
            } else {
                source = QuerySource::Rewrite;
            }
        }
        // Selection is deterministic for a pinned generation and client.
        let selected = snapshot.select(client);
        let policy = selected.policy;
        let exception = if excepted {
            policy.temporary_allow_for(&domain, client, Instant::now())
        } else {
            None
        };
        self.finish_at(
            &mut Outcome {
                start,
                client,
                transport,
                request: &request,
                policy,
                client_name: selected.client_name,
                filter_tags: selected.filter_tags,
                generation: snapshot.generation(),
                domain,
                qtype,
                decision,
                decision_cached,
                excepted,
                schedule,
                exception,
                response,
                source,
            },
            at,
        )
    }
}
