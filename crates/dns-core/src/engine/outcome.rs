use super::wire::{encode, finalize};
use super::{Engine, Outcome};
use crate::{
    reply,
    telemetry::{QueryEvent, QuerySource, ShadowDecision},
};
use hickory_proto::{op::ResponseCode, rr::RecordType};
use rustwalld_dns_filter::{Action, Decision};
use std::{sync::atomic::Ordering, time::Instant};

impl Engine {
    /// Apply exception expiry and TTL limits, evaluate shadow policy, encode the
    /// reply and emit telemetry. Shared by local answers and forwarded misses.
    pub(super) fn finish_at(
        &self,
        outcome: &mut Outcome<'_>,
        at: Option<std::time::SystemTime>,
    ) -> Option<Vec<u8>> {
        let metrics = &self.telemetry.metrics;
        let now = if outcome.schedule.is_some() {
            Some(at.unwrap_or_else(std::time::SystemTime::now))
        } else {
            at
        };
        let schedule = now.and_then(|now| outcome.policy.service_schedule_at(now));
        let services_active = schedule.is_none_or(|evaluation| evaluation.state.blocking());
        let filters = outcome.policy.filters_for_services(services_active);
        let changed = outcome
            .schedule
            .is_some_and(|initial| initial.state.blocking() != services_active);
        let live = outcome.exception.as_ref().and_then(|found| {
            found
                .remaining_ttl(Instant::now())
                .map(|ttl| (found.index, ttl))
        });
        let temporary_exception = if let Some((index, ttl)) = live {
            // Only this client's private response copy is constrained.
            let response = &mut outcome.response;
            for record in response
                .answers
                .iter_mut()
                .chain(&mut response.authorities)
                .chain(&mut response.additionals)
            {
                record.ttl = record.ttl.min(ttl);
            }
            metrics.temporary_allows.fetch_add(1, Ordering::Relaxed);
            Some(index)
        } else {
            if outcome.excepted || changed {
                // An upstream/coalesced wait cannot carry an allow across expiry.
                outcome.decision = if outcome
                    .policy
                    .has_rewrite_for(&outcome.domain, RecordType::from(outcome.qtype))
                {
                    Decision::ALLOW
                } else {
                    filters.evaluate_client(
                        &outcome.domain,
                        outcome.qtype,
                        rustwalld_dns_filter::ClientContext {
                            ip: outcome.client,
                            name: outcome.client_name,
                        }
                        .with_tags(outcome.filter_tags),
                    )
                };
                outcome.decision_cached = false;
                if outcome.decision.action == Action::Block {
                    outcome.response =
                        crate::response::blocked(outcome.request, outcome.policy.block_mode());
                    outcome.source = QuerySource::Blocked;
                } else if outcome.source == QuerySource::Blocked {
                    // No upstream answer was obtained for the now-expired synthesized block.
                    outcome.response = reply(outcome.request, ResponseCode::ServFail);
                    outcome.source = QuerySource::Failure;
                }
            }
            None
        };
        let mut matched_domain = None;
        let mut matched_type = None;
        let mut cname_code = None;
        if !matches!(outcome.source, QuerySource::Blocked | QuerySource::Failure) {
            let exempt = outcome.source == QuerySource::Rewrite
                || temporary_exception.is_some()
                || (outcome.decision.action == Action::Allow && outcome.decision.rule.is_some());
            match crate::cname::inspect_client(
                outcome.request,
                &outcome.response,
                filters,
                exempt,
                Some(
                    rustwalld_dns_filter::ClientContext {
                        ip: outcome.client,
                        name: outcome.client_name,
                    }
                    .with_tags(outcome.filter_tags),
                ),
            ) {
                crate::cname::Inspection::Clean => {}
                crate::cname::Inspection::Blocked {
                    decision,
                    domain,
                    kind,
                } => {
                    outcome.decision = decision;
                    outcome.decision_cached = false;
                    outcome.source = QuerySource::Blocked;
                    matched_domain = Some(domain);
                    matched_type = Some(kind);
                    cname_code = Some(ResponseCode::NXDomain);
                }
                crate::cname::Inspection::Invalid => {
                    outcome.source = QuerySource::Failure;
                    cname_code = Some(ResponseCode::ServFail);
                }
            }
        }
        // Shadow observes the same raw answer before synthesis removes its chain.
        let shadow = self.shadow_decision(outcome, now, services_active);
        if let Some(code) = cname_code {
            outcome.response = if code == ResponseCode::NXDomain {
                crate::response::blocked(outcome.request, outcome.policy.block_mode())
            } else {
                reply(outcome.request, code)
            };
        }
        if let Some(evaluation) = schedule {
            for record in outcome
                .response
                .answers
                .iter_mut()
                .chain(&mut outcome.response.authorities)
                .chain(&mut outcome.response.additionals)
            {
                if record.record_type() != RecordType::OPT {
                    record.ttl = record.ttl.min(evaluation.ttl_cap);
                }
            }
        }
        if outcome.source == QuerySource::Blocked {
            metrics.blocked.fetch_add(1, Ordering::Relaxed);
        }
        if outcome.source == QuerySource::Stale {
            metrics.stale_answers.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(
            outcome.source,
            QuerySource::Rewrite | QuerySource::SafeSearch
        ) {
            metrics.rewrites.fetch_add(1, Ordering::Relaxed);
        }
        if outcome.source == QuerySource::Failure {
            metrics.failures.fetch_add(1, Ordering::Relaxed);
        }
        finalize(outcome.request, &mut outcome.response);
        let output = encode(outcome.request, &outcome.response, outcome.transport)?;
        let latency_us = metrics.observe(outcome.start);
        self.telemetry.emit(QueryEvent {
            client: outcome.client,
            // Matching is finished: move the normalized name into telemetry.
            domain: std::mem::take(&mut outcome.domain),
            matched_domain,
            matched_type,
            qtype: outcome.qtype,
            generation: outcome.generation,
            policy: outcome.policy.id(),
            decision: outcome.decision,
            decision_cached: outcome.decision_cached,
            response_code: u16::from(outcome.response.metadata.response_code),
            source: outcome.source,
            latency_us,
            shadow,
            temporary_exception,
            service_schedule: schedule.map(|evaluation| evaluation.state),
        });
        Some(output)
    }

    /// How the shadow generation, if any, would have decided this query.
    fn shadow_decision(
        &self,
        outcome: &Outcome<'_>,
        at: Option<std::time::SystemTime>,
        services_active: bool,
    ) -> Option<ShadowDecision> {
        let shadow = self.shadow.load();
        let shadow = shadow.as_ref()?;
        let binding = shadow.select(outcome.client);
        let context = rustwalld_dns_filter::ClientContext {
            ip: outcome.client,
            name: binding.client_name,
        }
        .with_tags(binding.filter_tags);
        let selected = binding.policy;
        let schedule = if selected.has_service_schedule() {
            selected.service_schedule_at(at.unwrap_or_else(std::time::SystemTime::now))
        } else {
            None
        };
        let filters = selected
            .filters_for_services(schedule.is_none_or(|evaluation| evaluation.state.blocking()));
        let rewrite = selected.has_rewrite_for(&outcome.domain, RecordType::from(outcome.qtype));
        let temporary = if rewrite {
            None
        } else {
            selected.temporary_allow_for(&outcome.domain, outcome.client, Instant::now())
        };
        let mut decision = if rewrite || temporary.is_some() {
            Decision::ALLOW
        } else {
            filters.evaluate_client(&outcome.domain, outcome.qtype, context)
        };
        let safe_search = if !rewrite && decision.action == Action::Allow {
            selected.safe_search_match(&outcome.domain)
        } else {
            None
        };
        let active_rewrite = outcome
            .policy
            .has_rewrite_for(&outcome.domain, RecordType::from(outcome.qtype));
        let active_safe_search = if !active_rewrite
            && (outcome
                .exception
                .as_ref()
                .is_some_and(|found| found.remaining_ttl(Instant::now()).is_some())
                || outcome
                    .policy
                    .filters_for_services(services_active)
                    .evaluate_client(
                        &outcome.domain,
                        outcome.qtype,
                        rustwalld_dns_filter::ClientContext {
                            ip: outcome.client,
                            name: outcome.client_name,
                        }
                        .with_tags(outcome.filter_tags),
                    )
                    .action
                    == Action::Allow)
        {
            outcome.policy.safe_search_match(&outcome.domain)
        } else {
            None
        };
        if !rewrite
            && temporary.is_none()
            && decision == Decision::ALLOW
            && safe_search == active_safe_search
            && let crate::cname::Inspection::Blocked {
                decision: target, ..
            } = crate::cname::inspect_client(
                outcome.request,
                &outcome.response,
                filters,
                false,
                Some(context),
            )
        {
            decision = target;
        }
        let kind = RecordType::from(outcome.qtype);
        let shadow_records = selected.rewrite(&outcome.domain, kind);
        let active_records = outcome.policy.rewrite(&outcome.domain, kind);
        // Record equality deliberately excludes TTL; a TTL change must still be
        // visible before promotion. Compare compiled templates, never serialize
        // configuration or allocate DNS replies for shadow evaluation.
        let rewrite_changed = shadow_records != active_records
            || shadow_records
                .zip(active_records)
                .is_some_and(|(shadow, active)| {
                    shadow.iter().zip(active).any(|(a, b)| a.ttl != b.ttl)
                });
        let differs = decision.action != outcome.decision.action
            || rewrite_changed
            || safe_search != active_safe_search;
        if differs {
            self.telemetry
                .metrics
                .shadow_differences
                .fetch_add(1, Ordering::Relaxed);
        }
        Some(ShadowDecision {
            generation: shadow.generation(),
            policy: selected.id(),
            decision,
            rewrite: rewrite || safe_search.is_some(),
            differs,
            temporary_exception: temporary.map(|found| found.index),
            service_schedule: schedule.map(|evaluation| evaluation.state),
        })
    }
}
