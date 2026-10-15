use super::wire::{accepted_question, canonical_ascii, encode, finalize};
use super::{Engine, Outcome, Pending, PendingQuery, Prepared, Step, Transport};
use crate::{reply, telemetry::QuerySource};
use hickory_proto::op::{Message, MessageType};
use rustwalld_dns_filter::{Action, Decision};
use std::{net::IpAddr, sync::atomic::Ordering, time::Instant};

impl Engine {
    /// Parse, validate and apply policy without waiting. Refusals, blocks,
    /// rewrites and response-cache hits are answered here; only cache misses
    /// need [`Engine::forward`]. Servers can therefore bound slow upstream
    /// waits separately from fast local answers.
    pub fn prepare(&self, bytes: &[u8], client: IpAddr, transport: Transport) -> Prepared {
        self.prepare_at(bytes, client, transport, None)
    }
    pub(super) fn prepare_at(
        &self,
        bytes: &[u8],
        client: IpAddr,
        transport: Transport,
        at: Option<std::time::SystemTime>,
    ) -> Prepared {
        let client = client.to_canonical();
        let start = Instant::now();
        let snapshot = self.active.load_full();
        if !snapshot.permits(client) {
            return Prepared::Drop;
        }
        let Ok(request) = Message::from_vec(bytes) else {
            return Prepared::Drop;
        };
        if request.metadata.message_type != MessageType::Query {
            return Prepared::Drop;
        }
        self.telemetry
            .metrics
            .requests
            .fetch_add(1, Ordering::Relaxed);
        let question = match accepted_question(&request) {
            Ok(question) => question,
            Err(code) => {
                let mut response = reply(&request, code);
                finalize(&request, &mut response);
                let output = encode(&request, &response, transport);
                if output.is_some() {
                    self.telemetry.metrics.observe(start);
                }
                return output.into();
            }
        };
        let selected = snapshot.select(client);
        let policy = selected.policy;
        let mut domain = canonical_ascii(question.name());
        // Only the trailing root dot is removed, preserving Hickory's escapes
        // within DNS labels.
        if domain.ends_with('.') {
            domain.pop();
        }
        let schedule = if policy.has_service_schedule() {
            policy.service_schedule_at(at.unwrap_or_else(std::time::SystemTime::now))
        } else {
            None
        };
        let services_active = schedule.is_none_or(|evaluation| evaluation.state.blocking());
        let qtype = u16::from(question.query_type());
        let rewrite = policy
            .rewrite(&domain, question.query_type())
            .map(|records| {
                (
                    records,
                    policy
                        .rewrite_forward(&domain, question.query_type())
                        .map(|(name, _)| name),
                )
            });
        let exception = if rewrite.is_none() {
            policy.temporary_allow_for(&domain, client, start)
        } else {
            None
        };
        let (decision, decision_cached) = if rewrite.is_some() || exception.is_some() {
            (Decision::ALLOW, false)
        } else {
            self.decide(
                policy,
                &domain,
                snapshot.generation(),
                services_active,
                qtype,
                rustwalld_dns_filter::ClientContext {
                    ip: client,
                    name: selected.client_name,
                }
                .with_tags(selected.filter_tags),
            )
        };
        // SafeSearch is a redirect after filtering, never an implicit allow.
        let safe_search = if rewrite.is_none() && decision.action == Action::Allow {
            policy.safe_search_answer(&domain, question.query_type())
        } else {
            None
        };
        let rewrite_source = if safe_search.is_some() {
            QuerySource::SafeSearch
        } else {
            QuerySource::Rewrite
        };
        let step = self.step(
            &request,
            &snapshot,
            policy,
            rewrite.or(safe_search),
            decision,
            rewrite_source,
        );
        match step {
            Step::Local(response, source) => {
                let excepted = exception.is_some();
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
                .into()
            }
            Step::Miss(key, upstream, lookup_request, aliases) => {
                let excepted = exception.is_some();
                Prepared::Forward(PendingQuery(Box::new(Pending {
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
                    key,
                    upstream,
                    lookup_request,
                    aliases,
                })))
            }
        }
    }
}
