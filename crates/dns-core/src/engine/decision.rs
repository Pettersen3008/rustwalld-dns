use super::{Engine, Step};
use crate::{
    decision_cache::{DecisionKey, DecisionLookup},
    reply,
    telemetry::QuerySource,
};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::Name,
};
use rustwalld_dns_filter::{Action, Decision};
use rustwalld_dns_policy::{CompiledPolicy, PolicySnapshot};
use rustwalld_dns_resolver::Lookup;
use std::sync::atomic::Ordering;

impl Engine {
    /// Choose how an admitted query is answered: rewrite, block, cache hit, or
    /// a miss to forward.
    pub(super) fn step(
        &self,
        request: &Message,
        snapshot: &PolicySnapshot,
        policy: &CompiledPolicy,
        rewrite: Option<(&[hickory_proto::rr::Record], Option<&Name>)>,
        decision: Decision,
        rewrite_source: QuerySource,
    ) -> Step {
        let local_forward =
            rewrite.and_then(|(records, target)| target.map(|target| (target, records)));
        if let Some((records, _)) = rewrite.filter(|(_, target)| target.is_none()) {
            let mut response = reply(request, ResponseCode::NoError);
            response.answers = records.to_vec();
            if response
                .answers
                .first()
                .is_some_and(|record| record.name.is_wildcard())
            {
                let Some(question) = request.queries.first() else {
                    return Step::Local(
                        reply(request, ResponseCode::ServFail),
                        QuerySource::Failure,
                    );
                };
                for record in &mut response.answers {
                    record.name = question.name().clone();
                }
            }
            return Step::Local(response, rewrite_source);
        }
        if decision.action == Action::Block {
            return Step::Local(
                crate::response::blocked(request, policy.block_mode()),
                QuerySource::Blocked,
            );
        }
        // Compilation validates profile indexes; never panic on the query path.
        let servfail = || Step::Local(reply(request, ResponseCode::ServFail), QuerySource::Failure);
        let lookup_request = local_forward.map(|(target, _)| {
            let mut lookup = request.clone();
            if let Some(question) = lookup.queries.first_mut() {
                question.set_name(target.clone());
            }
            lookup
        });
        let lookup = lookup_request.as_ref().unwrap_or(request);
        let Some(question) = lookup.queries.first() else {
            return servfail();
        };
        let Some(upstream) = snapshot
            .upstreams()
            .get(policy.upstream_for_query(question.name(), question.query_type()))
        else {
            return servfail();
        };
        match self.resolver.lookup(lookup, upstream) {
            Ok(Lookup::Hit(mut response)) => {
                let source = if let Some((_, aliases)) = local_forward {
                    response.answers.splice(0..0, aliases.iter().cloned());
                    rewrite_source
                } else {
                    QuerySource::Cache
                };
                Step::Local(response, source)
            }
            Ok(Lookup::Miss(key)) => Step::Miss(
                key,
                upstream.clone(),
                lookup_request,
                local_forward.map(|(_, aliases)| aliases.to_vec()),
            ),
            Err(_) => servfail(),
        }
    }

    /// Filter decision through the per-generation decision cache.
    pub(super) fn decide(
        &self,
        policy: &CompiledPolicy,
        domain: &str,
        generation: u64,
        services_active: bool,
        qtype: u16,
        client: rustwalld_dns_filter::FilterContext<'_>,
    ) -> (Decision, bool) {
        let filters = policy.filters_for_services(services_active);
        let key = DecisionLookup {
            client_class: filters.context_partition(client),
            qtype: if filters.has_type_rules() { qtype } else { 0 },
            domain,
            // Validated policy IDs are <256. Bit 0 partitions the immutable on/off sets.
            policy: (policy.id() << 1) | usize::from(!services_active),
            generation,
        };
        if let Some(decision) = self.decisions.get(&key) {
            self.telemetry
                .metrics
                .decision_hits
                .fetch_add(1, Ordering::Relaxed);
            return (decision, true);
        }
        let decision = policy
            .filters_for_services(services_active)
            .evaluate_client(domain, qtype, client);
        self.decisions.insert(
            DecisionKey {
                domain: domain.to_owned(),
                policy: key.policy,
                generation,
                qtype: key.qtype,
                client_class: key.client_class,
            },
            decision,
        );
        (decision, false)
    }
}
