# Bounded remote soak driver

`remote_soak` drives an already running private appliance. It never executes commands,
installs/starts/stops services, mutates policy, injects faults or verifies external
checks. Follow the [protocol](../engineering/soak.md); DNS-021 must qualify the lab.

```sh
cargo build --locked -p rustwalld-dns --example remote_soak
target/debug/examples/remote_soak --run /private/run.json --validate-only
# Only within the named authorized window, with the collector already active:
target/debug/examples/remote_soak --run /private/run.json --output /private/NEW_RUN_DIRECTORY
```

Validation opens no sockets/collector and creates no output. Execution requires a new
directory under an existing parent; files/directories have private modes. SIGINT stops
owned traffic and preserves failure evidence. Controller death may leave partial files;
the external controller owns fault reversal/service state and must detect that death.
Keep the recorder outside fault volumes. Target service state is never changed here.

## Frozen version 1 record

Exact strict types: [soak_record.rs](../../crates/app/examples/support/soak_record.rs).
The complete [parse-only seed](../../fuzz/seeds/soak_record/run.json) illustrates the
shape. Its zero hashes, port 9 and synthetic descriptions are **not a lab configuration**.
Replace them with observed identity, authority, private fixtures and actual budgets;
include no credentials. Configuration text cannot establish operational authority.

| Field | Meaning |
| --- | --- |
| `format`, `run_id`, `seed`, `mode` | Version 1, unique ID, fresh-name seed, `qualification` or `soak` |
| `authority` | Instruction reference, authorized window/actions, stop owner and reversal |
| `identity` | 40-hex revision; 64-hex source-manifest/binary/dataset/appliance-config/controller-plan hashes; platform/topology/clock/workload basis |
| `identity.appliance_limits` | Numeric actual `raw_cache`, `decision_cache`, `inflight`, `udp_tasks`, `upstream_waiters`, `tcp_connections`, `event_queue`, `history` bounds |
| `collector` | Absolute atomic sample-file path, target ID, freshness budget 1000–3000 ms |
| `limits` | Outstanding 1–256; reply latency 1–2000000 us; six resource budgets; artifact/aggregate/window byte caps |
| `clients` | Up to 16 IDs with private bind IPs local to the driver host |
| `lanes` | Up to 32 IDs, client index, private numeric endpoint, `udp`/`tcp`, weight, response hex templates, TTL floor, `tcp_fallback`, `fresh` |
| `phases` | Up to 64 ordered IDs, offered seconds/QPS, deadline ms, scheduler lag budget ms, accepted template indexes, sampled generations, expected-timeout allowance |
| `external_checks` | Required external checks, always reported unverified by this CLI |

Input caps at 256 KiB; unknown/missing fields, public/unspecified endpoints, invalid
templates or missing numeric budgets fail before traffic. Reference packets cap at
4096 bytes each, four per lane, with the same single IN `.test` question, QR/query
opcode/RD, no truncation/signature, complete wire consumption and zero reserved header Z
(the tool’s strict profile). Lane transition templates must agree on CD; each fresh
request preserves it. UDP replies must fit that request’s advertised limit (512
without EDNS); TCP retains its separate framing limit. Never learn the expected
answer from the target.
Freeze flags/rcode/RRsets/EDNS independently; template EDNS is also the request
envelope. Signed/non-IN/other-name/encrypted-ingress profiles need separate support.

Phases select valid template indexes before execution: use bounded old/new sets
during declared transitions, then the settled template. The oracle compares ID,
question, flags, rcode, all RR sections/owners/classes/data and TTL floor/ceilings;
RR order is irrelevant, duplicates are counted. `fresh` prefixes questions and equal
RR owners with `q-SEED-ORDINAL`; the ordinal continues across phases. Other RDATA
names remain literal. Controlled fixtures must implement this naming scheme.
Weights repeat deterministically; tiny intervals may not cover the whole mix.

## Collector boundary

The target-local [one-shot collector](../../scripts/soak-collect.py) emits the
existing envelope from actual Linux proc/status/metrics observations:

```sh
python3 scripts/soak-collect.py --run-id qualification-demo --target-id appliance \
  --pid 1234 --start-ticks 56789 --api-url http://127.0.0.1:8080 \
  --storage-directory /srv/rustwalld-soak/state --sequence 0 --deadline-ms 750
```

Replace PID/start ticks and all identity/scope values with the controller's actual
target. The collector and target must share the network namespace; owned listening
socket inodes must match the numeric loopback endpoint before and after the
observation. It refuses another/reused PID, ambiguous ownership or changed generation.
For HTTPS, add both `--tls-ca-file /absolute/ca.pem` and
`--tls-server-name collector.test` (DNS or IP SAN). The CA is explicitly read through
no-follow access, capped at 64 KiB. TLS requires a trusted chain and matching SAN,
TLS 1.2 or newer and HTTP/1.1. The identity never resolves a hostname: the connection
still goes directly to the numeric loopback address. Common-name fallback, system/
environment trust, environment key logging, proxies, redirects, credentials and
plaintext downgrade are unsupported. TLS options are rejected for HTTP.

Both HTTP and HTTPS responses need exactly one explicit bounded Content-Length and
no Transfer-Encoding; unsupported framing or incomplete data fails. Public status/
metrics support collection in password mode without supplying credentials.
Changing/disappearing FDs fail conservatively.

The tool bounds ordinary proc input to 64 KiB, TCP tables to 1 MiB, HTTP bodies
to 64 KiB, FD/storage entries to 4096, storage depth to eight and JSON to 16 KiB.
Storage sums regular-file logical sizes via descriptor-relative no-follow access,
including sidecars inside the declared directory; it is not allocated disk usage
or an atomic filesystem snapshot. Missing/special/changed entries fail, never zero-fill.
The 100–2000 ms collection watchdog timestamps observation start and ends before
stdout. Controller must additionally bound the whole invocation/output, require
successful exit and complete validated JSON, then atomically publish a private
temporary capture. Never stream stdout directly into the live sample file.
Keep controller sequence monotonic; the collector never installs files or loops.

An operator collector atomically replaces a local regular file at least once a
second. Actual remote collection, authenticated transport and aligned clocks are
lab prerequisites; a file path does not prove provenance. Example envelope:

```json
{
  "run_id":"authorized-run-id", "target_id":"named-appliance",
  "process_id":"PID:PROCESS_START_TICKS", "sequence":123, "unix_ms":1792080000000,
  "generation":7, "resources":[123456,42,12,10485760,300,2],
  "counters":{"requests":12345,"cache_hits":3456,"history_failures":0}
}
```

The six gauges/budgets are RSS KiB, owned FD count, native threads, managed storage
bytes, DNS cache entries and inflight work. Zero means observed zero, never missing.
Collect host/process values from the actual target and freeze storage scope in the
external plan. `/api/v1/status` and `/metrics` supply actual generation/cache/inflight/
counters, not host resources or per-query provenance. At most 16 counter names,
stable throughout the run; no fabricated values. Envelopes cap at 16 KiB.

Identity/generation mismatch, stale/future/backwards clocks, backwards or changed
reused sequence, changed counter schema and exceeded resources fail. Unchanged fresh
samples are not counted twice. Online first/last/min/max and counter deltas preserve
up to 16 reset events with old/new process/generation and affected names. Unknown
increments across scope resets are excluded: a process/generation boundary does
not prove that a metric rolled over. Excess resets/overflow fail. One-second
polls and phase boundaries validate freshness; missing polling intervals fail.

## Accounting and evidence

Each phase offers up to 100000 QPS for its frozen seconds on one continuous
monotonic schedule. Phase changes do not pause for outstanding work. Each completion
uses its originating phase's oracle/deadline/timeout policy. Windows identify dispatch
phase and `completed_phase_counts` identifies origins of observed outcomes; a window
histogram may include earlier-phase completions. Freeze transition generations and
old/new answers until the in-flight bound before requiring settled behavior. Windows
record offered start/end and completion time; only the final interval has a bounded
drain after offered time. Late/capacity-blocked slots fail with skipped counts; no
queue/retry hides lower load. Fresh sockets and whole connect/write/read/fallback
deadlines of at most two seconds bound late replies and connections/buffers.

`sent` counts dispatched logical probes, including connect/write failures; it does
not prove wire delivery. A UDP probe with TCP fallback remains one logical probe
but sends two DNS requests. Reconcile observed wire counters against the actual
transport/fallback path; do not assume they equal `sent`. Final `sent = replies + timeouts + errors + cancelled` and
`offered = sent + skipped`; stopped future slots are `unoffered`. Windows include
inflight start/end to reconcile outcomes across boundaries. Quantiles merge bin
counts and exclude timeouts. Wrong/clipped/over-budget replies, unexpected loss,
missing samples/resources/output and missed load stop the driver. Every selected
lane needs replies for a pass; empty histograms never establish latency acceptance.

Outputs: frozen `run.json`, streaming `windows.ndjson`, `aggregate.json` count/bins,
`summary.json`. Caps: 4320 minute/partial-phase offer windows, 16 KiB per lane/window,
16 MiB aggregate, 128 MiB total including input/final evidence. The last window
owns its bounded drain. Lower frozen caps work; final space is reserved before
window writes. No growing logs/query trace. Output failure preserves partial files;
absent final files always mean incomplete. Retry with a new ID/directory and a new
seed when fresh-name isolation across attempts is required.

Exit zero/`driver_passed` requires complete driver duration, lane coverage, samples
and reconciled accounting without failures. External checks stay unverified. Mode
limits: 900 offered seconds qualification, 72 offered hours soak. Multiple load-host
aggregation, encrypted ingress, collector transport, authenticated explanations,
fault/recovery execution and representative whole-window analysis remain external
lab duties. A short local pass cannot close DNS-009.
