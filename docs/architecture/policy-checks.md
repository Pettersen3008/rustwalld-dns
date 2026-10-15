# Offline policy checks

## Offline policy checks

Goal: inspect every required assertion before staging a candidate, using the
same compiler, client admission, policy selection and matcher as publication.
The command must not start DNS/HTTP workers, open SQLite or contact upstreams.

Ownership: policy owns an immutable, bounded diagnostic report. A private builder
is shared by strict compilation and checking; only strict compilation returns a
runtime snapshot. app owns file loading, CLI formatting and HTTP serialization.
Existing publication, shadow, rollback and backup assertion gates stay strict.
The DNS request path and persistent schema remain unchanged. The console consumes
the same report from the existing authenticated test endpoint.

Alternative: expose compilation with an `ignore_assertions` flag. Rejected:
callers could accidentally publish an unchecked snapshot. Returning only a
report gives the offline checker the information it needs without that escape.

Structural/configuration errors prevent checking. An invalid assertion domain,
an unadmitted client or an unexpected allow/block decision is reported per case;
checking continues through the remaining assertions. A rejected client's trace
is hypothetical and does not grant DNS access. Rewrites count as ALLOW, matching
the existing assertion contract. Reports describe configured decisions, not
resolver connectivity, cache state or historical query execution.

Reports contain at most 10,000 cases (the existing assertion limit). Each matching
rule includes at most 16 provenance sources and its total source count, so one
heavily duplicated rule cannot multiply all its provenance across every case.
Text output quotes untrusted configuration strings. No new dependencies or
network bootstrap are needed.

Verification: real CLI invocations with text/JSON and exit codes; multiple failed
cases, IPv4/IPv6 longest-prefix policies, allow precedence, IDNA, rewrite decisions,
denied clients, invalid domains, relative filter files and truncated provenance.
Occupy listener ports and monitor local upstream sockets; keep an existing
database byte-for-byte unchanged. Exercise the test API and strict promotion
rejection. Run formatting, Clippy and workspace tests, then the existing local
DNS-engine Criterion benchmark; do not claim a throughput improvement.

### Use

```sh
rustwalld-dns policy test --config /etc/rustwalld-dns/config.toml
rustwalld-dns policy test --config ./candidate.toml --format json > report.json
```

The input is the appliance's TOML configuration, including relative `filter_files`
and normal listener/resource validation. It checks the file's policy, not the
active SQLite revision. The CLI needs no management token. `--check-config` keeps
its original first-failure behavior; `policy test` is the complete diagnostic
alternative. Do not combine standalone commands with serving flags.

Exit `0` means structural validation and all configured assertions passed. An
empty assertion set is explicit and does not establish policy test coverage.
Exit `1` means one or more assertion failures; the complete report is on stdout.
Exit `2` means invalid arguments, unreadable input or structural configuration
errors; diagnostics go to stderr and no check report is emitted. JSON stdout
contains only the report, even if `RUST_LOG=trace` is set.

The JSON report contains `basis`, `valid`, `assertions`, `failed`, `policies` and `results`.
`basis: "permanent_policy"` means temporary allows are excluded from every
required assertion. An exception cannot make an unsafe permanent policy pass
validation until the exception expires. Current-policy explanations instead
include active temporary allows. See [expiry semantics](policy.md).
Each result contains the original assertion, `permitted`, an optional `trace` and
an optional typed `failure` (`unexpected_decision`, `client_not_permitted` or
`invalid_domain`). A valid-domain trace includes its normalized domain, selected
policy/client/network, allow/block decision, rewrite flag, upstream profile and
matching rule/source locations. Invalid domains have no trace. Rule IDs describe
this compilation; they are not persistent identifiers or a live generation.
Reports also include `list_stats`: each policy's compiled raw/unique/duplicate/
invalid/redundant counts. Download previews use these diagnostics without
compiling the full candidate twice. Offline checks validate downloaded-source
metadata and fingerprints against stored list text; they never fetch a URL.

`POST /api/v1/policy/test` keeps its bearer authentication, request/body limits
and single compilation admission. It runs the checker on the blocking control
executor without SQLite. Passing reports return HTTP 200 with the existing
`valid`, `assertions`, `policies` fields plus the new report fields. Assertion
failures return HTTP 422 with `{ "error": "...", "report": { ... } }`; structural
errors keep the existing 422 error envelope. No revision IDs are consumed by
checking. Failed candidates still cannot be shadowed or promoted.

The workbench initially displays failures, renders at most ten cases per page,
and expands traces on demand. Passing reports remain collapsed. Users can include
passing cases for comparison. Editing, reloading or publishing clears the report;
the server independently rechecks assertions before publication.
