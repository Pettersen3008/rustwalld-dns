# Client and network metadata

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: annotate existing IP/subnet policy bindings, make them searchable and
reviewable in the console, and retain those annotations through revisions,
shadow, promotion, backup, recovery and rollback. DNS admission, longest-prefix
selection and cache semantics must stay unchanged.

Observed: Binding owns a name, IP network and policy. Policy compilation builds
separate prefix-indexed IPv4/IPv6 maps; data-plane Selection borrows the winning
policy/name/network. GET clients and explanations read the current immutable
snapshot. Revisions already persist complete configuration. The current clients
table and network editor render every binding without pagination.

Design: optional BindingMetadata on each Binding with group, owner, VLAN label,
tags and note. Limits: group/owner 128 bytes, VLAN 1–4094, at most 16 unique ASCII
tags of 32 bytes each, note 1024 bytes, and at most 8 MiB combined metadata per
generation. Reject control characters, blank/edge-whitespace labels, empty
metadata and unknown fields. Metadata is descriptive; group/VLAN labels do not
create inheritance, network identity or admission. More-specific bindings use
their own metadata, never annotations from a broader binding.

PolicySnapshot compiles a sparse network-to-config-index metadata map. Only
explanations/assertion reports read that map; ClientBinding, Selection and DNS
workers remain unchanged. This avoids adding metadata strings/pointers to every
hot lookup or telemetry event. The source configuration owns the strings.

Alternative: separate client/network inventory with references from bindings.
Deferred because it adds identity and dangling-reference semantics without an
inventory discovery provider. Optional inline metadata completes a useful slice
using the existing durable safety workflow. Future inventory import must stay
outside the query path.

Compatibility: empty metadata is omitted. Existing configuration and schema-2
stores need no migration; binaries predating binding metadata require a compatible
pre-feature backup when downgrading. History continues to identify client IP,
policy ID and generation; it does not relabel historical queries with current
metadata. Explanations describe the currently selected generation.

Checklist: explore/design; quiet matched-binding benchmark baseline; implement
pure validation and control-only lookup, API/console, durable workflows; review
before fixes; fmt/Clippy/tests, browser and failure/recovery checks; compare local
benchmarks and allocations; package and verify installation/recovery.

Use the policy workbench's Clients & networks tab. Expand a binding's annotations,
edit labels, validate, stage in shadow, review and promote. Clearing every field
removes metadata. The clients inventory searches names, CIDRs, policy and all
annotation text and renders at most 20 rows; the draft editor renders at most 10.
Notes stay collapsed until requested. Metadata edits create new generations and
use the existing revision preconditions.

An individual binding in advanced JSON can look like:

```json
{
  "name": "Work laptop",
  "network": "192.0.2.10/32",
  "policy": "work",
  "metadata": {
    "group": "Work",
    "owner": "Operator",
    "vlan": 20,
    "tags": ["managed", "laptop"],
    "note": "Fixed DHCP reservation"
  }
}
```

`GET /api/v1/clients` returns generation, default_policy, allowed_clients and
bindings with optional metadata. Explain and policy-check traces include optional
binding_metadata. The offline policy-test text output prints these annotations;
JSON retains the same typed object. Group/owner/note limits count UTF-8 bytes.
The 8 MiB aggregate limit counts annotation string/tag payload, not process RSS.

Review corrected table note wrapping, row identity across pagination and client
name/caption markup. Validation rejects malformed, unknown, duplicate and oversized
annotations before publication. Empty metadata objects are rejected by the
compiler; the editor omits them. Sources and metadata share the existing schema-2
backup verification and durable publication gates.

Verification: `cargo fmt --all --check`, strict workspace/all-targets/all-features
Clippy and workspace tests pass (86 Rust tests). Strict TypeScript/Vite and
Prettier checks pass; 36 desktop/mobile browser checks cover draft-only editing,
invalid tags, promotion, explanations, removal, pagination, search and theme/
keyboard flows. Final desktop/mobile screenshots were visually inspected. Root
and fuzz-lock RustSec audits, cargo-deny and npm audit pass. Extended policy-check
fuzzing exercised 77,712 cases in 21 seconds without a failure. Packaging's five
unit tests pass. Local raw evidence is retained in `target/metadata-*.log`.

The control-plane integration verifies old JSON, unknown-field rejection, invalid
metadata rejection on check/stage/direct publication, shadow isolation, mapped-IP
and overlapping-prefix explanations, stored revision recompilation, SQLite write
failure isolation, metadata removal, immutable old generations and rollback as a
new generation. All blocked-query upstream lookup counts remain zero. Offline
CLI tests cover TOML metadata, text/JSON traces and absence of listener/database/
upstream activity. The packaged smoke verifies annotations after backup, restart,
upgrade and restore while the downloaded-list publisher is unavailable.

Performance comparison: AMD Ryzen 7 9800X3D, x86_64 Linux 7.2.5-3-omarchy,
rustc 1.98.1, shared unpinned desktop; 20 Criterion samples, one-second warm-up
and two-second measurement. Both fixtures use the same four IPv4/IPv6 subnet/
device bindings and cache contents. Before has no annotations; after fills every
binding with maximum-length group, owner, note and 16 tags, plus a VLAN label.
No builds, browser tests, containers or fuzzing for this project ran during
measurement. Other activity on the shared desktop was not controlled.

| Path | Before estimate | After estimate |
| --- | ---: | ---: |
| IPv4 binding selection | 14.815 ns | 14.744 ns |
| IPv6 binding selection | 26.966 ns | 26.684 ns |
| Mapped IPv4 binding selection | 23.785 ns | 23.241 ns |
| Blocked decision-cache pipeline | 630.95 ns | 622.56 ns |
| DNS response-cache pipeline | 1,001.5 ns | 983.77 ns |
| Active temporary allow / DNS cache | 1,044.3 ns | 1,010.6 ns |
| Blocked / unmatched temporary exception | 641.45 ns | 638.40 ns |
| Blocked / expired temporary exception | 648.18 ns | 645.78 ns |

All differences are below 3.3% and do not establish a speedup or zero overhead.
Allocator probes include parsing, response cloning, serialization and a full
telemetry queue: blocked paths remain 10 allocations / 1,151 bytes per query;
DNS cache paths remain 13 / 1,259. Pipeline measurements use one Tokio thread,
preseeded cache and zero upstream lookups. They exclude socket scheduling and
cannot establish wire latency percentiles, RSS, CPU/query or absolute throughput.
The unchanged selection maps have no annotation access or new hot-path locks.
