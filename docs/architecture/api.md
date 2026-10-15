# Management API

```sh
curl -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/config > candidate.json
# Edit candidate.json, then validate its required assertions.
curl -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @candidate.json \
  http://127.0.0.1:8080/api/v1/policy/test
# Mutations require the current ETag in If-Match.
TAG=$(curl -sI -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/config | awk 'tolower($1)=="etag:" {print $2}' | tr -d '\r')
# Observe differences on real traffic, then promote the shadow candidate.
curl -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" -H "If-Match: $TAG" \
  -H 'Content-Type: application/json' --data-binary @candidate.json \
  http://127.0.0.1:8080/api/v1/shadow
TAG=$(curl -sI -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/config | awk 'tolower($1)=="etag:" {print $2}' | tr -d '\r')
curl -X POST -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" -H "If-Match: $TAG" \
  http://127.0.0.1:8080/api/v1/shadow/promote
```

| Endpoint | Behavior |
| --- | --- |
| `GET /api/v1/status` | Version, active/shadow generation, cache and inflight counts |
| `GET /api/v1/queries?limit=100` | Most recent persisted events (maximum 1,000) |
| `GET /api/v1/clients` | Client bindings and allowed networks |
| `GET /api/v1/policies` | Compiled policy summaries |
| `GET /api/v1/service-catalog` | Frozen service-domain catalog and coverage |
| `GET /api/v1/temporary-exceptions` | Active generation and configured exceptions with live expiry state; no SQLite read |
| `GET /api/v1/filter-lists` | Deduplication, invalid/subsumed counts, payload estimate |
| `GET /api/v1/filter-sources` | Active source metadata and retrieval fingerprints; no SQLite read |
| `POST /api/v1/filter-sources/preview` | Fetch `{config, source: index}` into a checked draft; requires current `If-Match`, never publishes |
| `GET /api/v1/filter-refreshes` | Runtime schedules, running/queued check, last outcome, successful HTTP status/body bytes and pause state |
| `POST /api/v1/filter-refreshes/check` | Queue `{source: index}` for an active schedule; requires `If-Match`, returns 202, never promotes |
| `GET /api/v1/upstreams` | Profiles, transport/identity, attempts, successes and EWMA latency |
| `GET /api/v1/config` | Current complete `PolicyConfigSet` JSON and revision ETag |
| `GET /api/v1/shadow` | Current shadow generation/configuration or null, with revision ETag |
| `PUT /api/v1/config` | Validate, assert, compile, persist and atomically promote |
| `POST /api/v1/policy/test` | Compile and report all assertions without publication; failures return 422 with a report |
| `GET /api/v1/explain?client=127.0.0.1&domain=ads.example` | Current policy, matcher, rule and source explanation; `permitted: false` means DNS drops the client and the trace is hypothetical |
| `POST /api/v1/shadow` | Compile/persist a non-enforcing candidate |
| `DELETE /api/v1/shadow` | Clear the candidate |
| `POST /api/v1/shadow/promote` | Promote candidate content as a fresh generation |
| `GET /api/v1/revisions` | IDs, timestamps, actor, state and changed top-level fields |
| `GET /api/v1/revisions/{id}` | Inspect complete stored policy content |
| `POST /api/v1/revisions/{id}/rollback` | Recompile revision content into a fresh generation |
| `GET /healthz`, `GET /metrics` | Health and Prometheus counters/latency histogram |

Configuration and shadow reads provide an opaque ETag covering active and shadow
generations. Every mutation (`PUT /config`, `POST`/`DELETE /shadow`, shadow
promotion, rollback, list preview and scheduled checks) requires that exact value
in `If-Match`: a missing tag returns 428 and a stale one 412, before compilation
or persistence, so no client can overwrite a change it has not seen. Promotion captures the shadow under the same single-permit mutation
admission used for its precondition check; no mutex spans compilation or SQLite
I/O. Responses use `Cache-Control: no-store`; served assets receive a restrictive
CSP, `nosniff` and a no-referrer policy.

API mutations serialize: a concurrent compilation returns 409. Failed validation
returns 422; unavailable persistence returns 503 and leaves the running snapshot
untouched. A durable commit completes publication even if its HTTP client goes
away. Explanations are on demand; events store source/cache decisions, rule IDs,
latency and optional shadow differences. Shadow comparisons currently distinguish
action/rewrite changes; they do not compare upstream answer contents. Required
assertions check permanent allow/block behavior, excluding temporary exceptions,
not the contents of rewritten RRsets. Temporary decisions record a nullable
exception index alongside the policy/generation; old history has null provenance.

SQLite lives on a dedicated thread. Events use bounded `try_send`; dropped events
and failed history writes are counted. History retains the configured row count;
revisions retain the latest 32 plus active/shadow references. Disk files reuse
space after deletion but are not automatically vacuumed. Event timestamps are
persistence timestamps. Revision diffs identify changed configuration fields;
inspect the two full revisions for their detailed contents.

## DNS behavior and limits

- One recursive IN question per query; UDP and persistent client TCP supported.
- A/AAAA/CNAME and other ordinary records are forwarded through Hickory.
- Sequential fallback across up to eight addresses/profile; no racing of providers.
- Random upstream IDs and connected ephemeral UDP sockets; match ID, QR, opcode
  and question. Truncated or oversized UDP upstream replies retry TCP; truncated
  TCP/TLS replies are rejected. Client UDP replies respect 512 bytes without EDNS
  and a capped advertised size of 1,232 with EDNS.
- Separate bounded decision/response caches. Decisions partition by policy
  generation and policy. Responses partition by upstream identity (ordered
  addresses plus transport trust/identity settings, not timeouts or pool sizes),
  name, type, class and DO/CD, so publishing unchanged upstream profiles keeps
  warm answers while any upstream change starts a disjoint partition. Blocking
  and rewrites are decided before the response cache. TTLs age on hits. Whole messages
  expire conservatively at the earliest RR TTL; negative responses require SOA
  and use `min(SOA TTL, SOA MINIMUM)`. SERVFAIL, zero TTL and truncated responses
  are not cached. Final block/rewrite answers never enter the upstream cache.
- Bounded, sharded single-flight entries survive individual waiter cancellation.
  Cache/inflight mutexes never cover awaits or network operations.
- The engine passes DO/CD but performs **no DNSSEC validation** and clears AD.
  EDNS options (including ECS and cookies) are ignored and never forwarded.
  TSIG, transfers, ANY, non-IN, updates and nonrecursive requests are refused.
  Malformed packets are dropped.
- UDP ingress bounds local work (`max_udp_queries`) separately from cache misses
  waiting on upstreams (`max_udp_upstream_waits`, default 1,024). Blocks,
  rewrites and cache hits are answered without waiting, so a slow upstream
  cannot starve them; misses beyond the wait limit get SERVFAIL at once.
  Listener errors (including descriptor exhaustion) pause only that listener.
- Input frames are capped at 4,096 bytes; upstream responses at the DNS wire
  maximum. Cache limits are entry counts, not exact byte budgets; record/message
  and request bounds keep growth finite. Tune limits for available memory.
- Direct self-upstreams are rejected (addresses compared canonically; a wildcard
  listener rejects only loopback/unspecified upstreams on its port, so remote
  resolvers such as `1.1.1.1:53` work with `0.0.0.0:53`). Upstreams at this
  host's own interface addresses are not detected. Operators must prevent such
  and indirect forwarding loops. No firewall, port redirection or DNS bypass
  enforcement is installed.
