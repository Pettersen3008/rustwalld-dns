# Install, upgrade and recover a Rustwall appliance

The bundler accepts native x86_64/aarch64 Linux GNU builds; smoke evidence currently
covers x86_64 Debian only. Runtime installation uses systemd and Python 3.11+.
Build hosts need Rust, Bun 1.4.3+, Node 22.22+ and a C toolchain. Runtime hosts need compatible
GLIBC (recorded in manifest.json), systemd, Python and useradd. Node and a separate
SQLite executable are not required at runtime. Cross-compilation is not supported.

## Build and inspect

```
python3 scripts/release.py
```

This runs locked release/Bun builds and emits a content-addressed `.tar.gz` and
`.sha256` under `target/releases/`. The manifest records file hashes, source hash,
toolchains and the highest required GLIBC symbol. Tar/gzip order, timestamps,
owner and modes are deterministic; repacking identical built inputs gives identical
bytes. Builds on arbitrary toolchains/OS versions are not promised bit-identical.
`--skip-build` is only a local packaging test; use a full build for release.
Checksums detect corruption, not authenticity; obtain artifacts from a trusted
source. Inspect manifest and bundled service/config before running the installer.

## Install

On the target host, unpack the trusted archive into an ordinary directory:

```
sha256sum -c rustwalld-dns-RELEASE.tar.gz.sha256
mkdir bundle
tar -xzf rustwalld-dns-RELEASE.tar.gz -C bundle
sudo python3 bundle/install.py bundle
sudo systemctl daemon-reload
```

The installer verifies every member against the manifest, rejects payload symlinks
and keeps releases in `/opt/rustwalld-dns/releases/`. `current` switches atomically.
It creates the dedicated `rustwalld-dns` user, `/etc/rustwalld-dns/config.toml`, a
random 0600 root-owned `service.env` token, and a private service-owned state
directory. Existing configuration, secret and database are preserved. It installs
the unit but never enables/starts/stops it or changes host DNS/firewall settings.
`--root /absolute/staging/path` tests file installation without creating accounts
or contacting the host service manager.

Review `/etc/rustwalld-dns/config.toml` and read the token from `service.env` as
root. Keep the token private. Then explicitly validate and activate:

```
sudo -u rustwalld-dns /opt/rustwalld-dns/current/bin/rustwalld-dns --config /etc/rustwalld-dns/config.toml --check-config
sudo systemd-analyze verify /usr/lib/systemd/system/rustwalld-dns.service
sudo systemctl enable --now rustwalld-dns
systemctl status rustwalld-dns
journalctl -u rustwalld-dns
curl http://127.0.0.1:8080/healthz
```

Default DNS is loopback UDP/TCP5353, management loopback8080. Do not point clients
at the appliance until you have verified local resolution. Configure explicit
admitted CIDRs before exposing DNS to a subnet. Administration defaults to
loopback/SSH. Explicit HTTPS enables LAN administration; configure certificates
and writable private identity state as described in [administration](../architecture/security.md).
Incoming DoT/DoH listeners are independently opt-in; see the same security contract. Port53 requires an explicit unit drop-in granting only
`CAP_NET_BIND_SERVICE` in CapabilityBoundingSet and AmbientCapabilities. Adjust
`dns_listen` explicitly; installation grants no capabilities by default.

The unit has strict filesystem protection, a writable StateDirectory, private
tmp/devices, no privileges/capabilities by default and kernel/syscall protections.
`TimeoutStopSec=15` covers bounded graceful shutdown. Verify actual sandbox
activation on the deployment host; unit validation and a non-root container smoke
check do not prove every host kernel/systemd protection was activated.

## Native host acceptance proposal

The initial verified target was a disposable x86_64 Debian 13/KVM guest, with systemd as PID1,
Python 3.11+, `useradd`, private writable persistent storage and GLIBC at least the
bundle's `glibc_required`. [Sprint 04](../reviews/sprint-04.md) records its tested
scope. A different deployment needs its own identified authorized target.
AArch64 needs a native build and separate hardware acceptance.
Record hostname, OS/kernel, architecture, systemd/GLIBC versions, manifest and
available disk space/inodes. The current development workstation is not selected.

The bounded first acceptance run installs the account/files/unit, starts and stops
only `rustwalld-dns`, exercises restart/backup/restore/reversal, and leaves it
stopped and disabled on a fresh guest. It uses loopback UDP/TCP5353 and HTTP8080;
no boot enablement, port53 capability, LAN listeners, incoming TLS, router DNS,
firewall or DHCP changes. Confirm the target and this authority before executing
the privileged steps. Existing installations need their original active/enabled
state and verified backups recorded, with an explicit restoration plan.

1. Inspect the trusted archive and compare its manifest hashes to the intended
   build. Confirm compatible GLIBC and that `ss -lntup` shows the chosen ports
   free. Do not displace an existing listener. Save prior `current`, config,
   service environment, identity/TLS files and unit/drop-ins privately if present.
   Take and verify a database backup before upgrade; record expected active/shadow
   generations. Keep originals outside the release tree and preserve ownership.
2. Install using the commands above, omitting `enable --now`. On a fresh guest,
   before the first start, replace the sample public upstream addresses with
   `127.0.0.1:15453` (confirm unused) and `timeout_ms = 100`. Add an offline block
   list and local record to the sample policy:

   ```toml
   lists = [{ name = "acceptance", action = "block", rules = "blocked.test" }]
   dns_records = [{ domain = "acceptance.home.arpa", ttl = 60, data = { type = "A", address = "192.0.2.10" } }]
   ```

   These replace/add fields in `[[policy.policies]]`, not at TOML root. Keep the
   loopback admission/default listeners and disabled stale default. Validate as
   the service user. Existing database policy takes precedence over file policy;
   use reviewed API publication or a fresh guest instead of overwriting live state.
3. Check config directory root:service-group0750, config root:service-group0640,
   environment root:root0600, state service-user:service-group0750, executable
   root-owned0755 and unit root-owned0644. As the service user, read config and
   create/remove a private scratch file in state; config/release/unit writes and
   environment-file reads must fail. Backups are private0600. Authentication
   identity, when configured, must be writable within StateDirectory; `/etc` is
   read-only in the service sandbox.
4. Run `systemd-analyze verify` and `systemctl daemon-reload`, then
   `sudo systemctl start rustwalld-dns`. Record `systemctl show rustwalld-dns`
   including MainPID, User/Group, ActiveState/SubState, NoNewPrivileges,
   CapabilityBoundingSet/AmbientCapabilities, ProtectSystem/Home, PrivateTmp/Devices,
   kernel/control-group protections, RestrictAddressFamilies and SystemCallFilter.
   Compare with the bundled unit; warnings or unsupported protections are failures
   to investigate. Inspect `/proc/PID/status`: non-root UID/GID, `NoNewPrivs: 1`,
   zero `CapEff` and `Seccomp: 2` are expected. Inspect the process mount namespace to confirm
   read-only config/release mounts, writable state and private tmp/devices. Retain
   `systemd-analyze security rustwalld-dns.service` and journal output as supporting
   evidence; a score or configured property alone does not prove enforcement.
5. Verify `/healthz`, authenticated status/config and the installed console. Keep
   the credential out of command arguments, URLs and evidence. With a local DNS
   client such as `dig`, use `@127.0.0.1 -p 5353` for UDP and `+tcp`: local A must
   be 192.0.2.10, blocked.test NXDOMAIN and a fresh unlisted.test SERVFAIL within a
   bounded client timeout (for example two seconds). No public resolver is contacted. A later
   forwarding run requires an explicitly selected local mock/resolver endpoint;
   this closed-port phase proves failure behavior, not successful forwarding.
6. Back up the running database with the commands below, verify schema and
   active/shadow IDs, and check private permissions. Restart and compare DNS/API
   results. For upgrade rehearsal, retain the old release and preserve config,
   credentials and database. For recovery, stop first, move main/WAL/SHM/journal
   together to a protected directory, restore into an absent destination, then
   restart and compare generations, policy and DNS results. Preserve failed state.
7. Reversal: stop the service; verify the saved release. When its binary supports
   the stored schema **and policy content**, create a sibling temporary symlink to
   that retained release and atomically rename it over `current`; validate, start
   and repeat the checks. With incompatible content/schema, restore a verified
   compatible pre-upgrade backup into a new database destination and restore its
   matching configuration before starting. Never edit schema IDs. Retain the
   replaced database and both releases until verified. Stop the fresh-guest service
   at the end and confirm no listener and inactive/disabled state; do not remove
   saved recovery material. Existing targets restore their agreed prior state.

Acceptance requires the named host, observations and actual outcomes for each
phase. The isolated package fixture also rehearses switching back/forward, but
uses the same binary in two differently identified bundles. Neither that fixture
nor a closed-port native run establishes older-binary compatibility, complete
kernel sandbox enforcement, representative-network soak or release readiness.

### Automated fresh-VM rehearsal

Only in a new disposable VM authorized for destructive acceptance, unpack the
trusted package at `/bundle` and copy the matching source files `packaging/smoke.py`,
`packaging/native_service.py` and `packaging/native_probe.py` into one guest directory.
The guest needs Python 3.11+, the maintained Python `h2` fixture package and its
dependencies, systemd, `systemd-analyze`, `useradd` and ordinary Linux tools.
Prepare dependencies before isolating the test network, or copy offline fixture
dependencies. No public DNS/upstream is needed by the test.

Run as root **inside that guest**, from the copied fixture directory:

```sh
python3 smoke.py --native-systemd
```

The mode refuses non-VMs, containers, unprivileged execution and pre-existing
managed paths before installation. It installs test policy/state, starts/stops
the actual unit and runs the existing UDP/TCP, encrypted local mocks, publication,
same-binary upgrade/reversal and backup/restore checks. A temporary ExecStartPost
probe exercises the unit's effective mount/identity/socket protections; a security
score alone is not treated as proof. Python imports do not modify the verified
bundle. No production unit protection is relaxed for the probe.

Successful completion leaves the unit inactive/disabled and removes the probe
drop-in/markers. Reports are `native-*.json`/`native-*.txt` under the guest's private
`/var/lib/rustwalld-dns`; collect them and the guest identity/journal before powering
off. On an ordinary Python failure, an exit handler stops/disables the unit and
retains failed state/probes for diagnosis. A controller must still shut down the
disposable VM after timeout, forced termination or lost connectivity. Never reuse
this destructive fixture against an existing installation. The default Docker
smoke mode remains a direct-process test without native systemd activation.

## Upgrade or roll back the executable

Ordinary policy changes use the API/console without restarting DNS. Executable/UI
upgrades require a service restart and a brief outage; automatic failover is not implemented. Reviewed peer policy copying does not
synchronize state or make an upgrade outage-free.
Save the old `current` target and take a verified backup before upgrading.

```
readlink /opt/rustwalld-dns/current
sudo systemctl stop rustwalld-dns
sudo python3 bundle/install.py bundle
sudo systemctl daemon-reload
sudo -u rustwalld-dns /opt/rustwalld-dns/current/bin/rustwalld-dns --config /etc/rustwalld-dns/config.toml --check-config
sudo systemctl start rustwalld-dns
```

Check health, authenticated status, a local rewrite/blocked query and the expected
active generation. File policy content only bootstraps an empty database; normal
starts restore durable active/shadow content from SQLite. Startup upgrades
supported older schemas to schema 6 transactionally, retaining exception, response
subject and schedule history with separate matched record types, without replacing
revisions or queries. Take the verified pre-upgrade backup before starting this
release. Read-only backup verification accepts schemas 1–6; restoring an older
supported schema with this release migrates it on startup.

For an executable rollback, stop the service. If the saved binary only supports
schema 1, restore the verified pre-upgrade schema-1 backup to a new destination
and configure that database path before switching `current` to the saved release.
Do not lower `PRAGMA user_version` or reuse a schema-2 database with that binary.
Keep the failed release's database separately for inspection. Switching only the
release symlink is sufficient when the old binary supports both the stored
schema and policy content. Restart and repeat the health/DNS checks. Changes
after the selected backup are absent from the restored state.

Never reuse live policy cache keys: policy rollback uses the console and creates
a fresh generation. Future database schema versions are refused by this binary.

## Back up live state

Use the SQLite backup command, not a copy of the live main file. WAL changes must
be included. Place backups outside the release directory and protect them because
they contain client names, policy content and query history.

```
sudo install -d -o rustwalld-dns -g rustwalld-dns -m 0700 /var/backups/rustwalld-dns
sudo -u rustwalld-dns /opt/rustwalld-dns/current/bin/rustwalld-dns backup --database /var/lib/rustwalld-dns/rustwalld.sqlite --output /var/backups/rustwalld-dns/snapshot.sqlite
sudo -u rustwalld-dns /opt/rustwalld-dns/current/bin/rustwalld-dns verify-backup --database /var/backups/rustwalld-dns/snapshot.sqlite
```

The output is a single 0600 SQLite file. The destination directory must not be
group/world writable. Copy uses one online-backup step under a single WAL read
transaction (writers are not blocked and cannot restart it), retried on busy until
a 30-second deadline, validates integrity/schema and compiles active/shadow
required assertions, fsyncs and publishes without replacing an existing target.
Validation can take longer for large rule sets. Failures before publication do
not create a target. A directory-sync error after publication explicitly reports
the existing target; verify it before use. Choose a new filename for each backup. No API token or DNS runtime is used.
Also preserve config.toml, any referenced filter files, service.env and custom unit
drop-ins separately with private permissions. They are not part of the database.
A backup contains only state durable at its snapshot, not pending telemetry.

## Restore or recover

First verify the snapshot. Stop the service before touching its database, and
move the old main/WAL/SHM/journal files together to a protected recovery directory.
Do not delete them until the new installation is verified. Restore requires an
absent destination and absent destination sidecars; it never replaces a live file.

```
sudo systemctl stop rustwalld-dns
# Move existing database and its sidecars out of /var/lib/rustwalld-dns first.
sudo -u rustwalld-dns /opt/rustwalld-dns/current/bin/rustwalld-dns restore --backup /var/backups/rustwalld-dns/snapshot.sqlite --database /var/lib/rustwalld-dns/rustwalld.sqlite
sudo systemctl start rustwalld-dns
```

Verify the reported active/shadow generations, query admission, rewrites, blocking
and health. Restore reuses the snapshot's generations after a full process restart;
all volatile caches are empty. Live policy rollback still creates a fresh generation.
A missing or corrupt backup, dangling runtime pointer, failed assertion, future
schema or destination collision produces a nonzero exit and no published target.
The verifier checks currently referenced policy assertions, not every historical
revision; rollback separately recompiles/tests the selected historical content.

If history writes fail, DNS continues and counters show dropped telemetry/history
failures; new policy publication returns 503 when it cannot persist. Inspect disk
capacity, directory ownership and SQLite lock holders. Do not repeatedly remove
WAL files or reset the database to diagnose a persistence error.

## Reproduce deployment and failure checks

```
python3 scripts/release.py
python3 -m unittest discover -s scripts/tests -v
scripts/deployment-smoke.sh target/releases/RELEASE.tar.gz
cargo run -p rustwalld-dns --release --example resilience --locked -- --binary target/release/rustwalld-dns --duration-ms 5000 --output target/resilience.json
cargo run -p rustwalld-dns --release --example encrypted_resilience --locked -- --binary target/release/rustwalld-dns --duration-ms 5000 --output target/encrypted-resilience.json
```

The smoke container is isolated with `--network none`, has only a read-only bundle
mount and does not activate the host service manager. The unit is validated with
systemd-analyze, and the actual installed process runs as the service user. It
also tests installed ownership/service-user access, upgrade preservation,
same-binary release reversal, online WAL backup and recovery followed by boot.
The reversal uses two differently identified bundles of the same executable;
older-binary/schema/content compatibility needs separate evidence.
The smoke enables serve-stale only in its isolated config and checks expired-cache
TTL-30 answers over UDP/TCP, the stale metric and uncached outage SERVFAIL.
The packaged default remains disabled. Use the [measurement procedure](../engineering/performance.md) for current evidence.
The separate real-process benchmark exercises stalled body admission, concurrent
shadow compilation, history-write failure and a scheduled authenticated HTTPS
body stall while DNS traffic continues. The scheduled phase is capped at five
seconds and checks download closure during shutdown. It
retains quantiles, timeouts, wrong-answer counts, admission/publication statuses
and telemetry drop counters. Its compilation phase contains one overlapping
candidate request; recorded HTTP duration is separate from the DNS sample window.
A shared workstation is not a dedicated latency regression runner.

The encrypted rehearsal runs real UDP DNS clients against the child appliance and
local TLS/HTTP2 fixtures. It covers bad replies, resets, single/complete upstream
stalls, fallback and policy promotion. Two clients per lane run without think
time by default. `--duration-ms` sets each phase's duration, not the whole run;
five seconds takes approximately 100 seconds plus setup/retirement. The JSON report
records cache hits/evictions, expected SERVFAIL, wrong answers/timeouts, durable
revisions, retention, socket/FD/thread/RSS samples and quiescent/exit checks.
Linux /proc is required. The fixture and clients share a harness runtime, so this
is a failure rehearsal rather than an independent capacity measurement. See the
[measurement method](../engineering/performance.md).

For longer repetition, build the example once and run separate reports:

```sh
cargo build -p rustwalld-dns --release --example encrypted_resilience --locked
for run in 1 2 3; do
  target/release/examples/encrypted_resilience --binary target/release/rustwalld-dns \
    --duration-ms 30000 --output "target/encrypted-resilience-$run.json"
done
```

Each repetition takes approximately ten minutes. Retain hardware, binary hashes
and JSON rather than comparing only throughput. These runs do not substitute for
a production-host soak with real router clients, storage and network failure.

### Recover an encrypted upstream outage

`/healthz` reports process liveness; it does not prove upstream reachability.
Inspect `/api/v1/upstreams` generation, attempts, successes, inflight and fixed
failure reasons, plus the metrics' logical failures, inflight overloads and cache
hits. Deadline includes pool admission and network/handshake waits. TLS
authentication points to certificate identity/trust/validity; TLS protocol includes
missing h2 ALPN; HTTP status/envelope/protocol and rejected DNS replies remain
separate. Upstream SERVFAIL/REFUSED are endpoint outcomes, distinct from the
appliance's final SERVFAIL. Cancellation counts dropped endpoint futures, not
necessarily client departure. Historical failures can coexist with recovery;
confirm new successful uncached exchanges. Health data belongs to the current generation and resets
on publication; global counters remain available. Cached and blocked replies can
continue during an outage, while fresh misses return SERVFAIL when every endpoint
fails. Client timeouts or incorrect answers merit separate investigation.

Check bootstrap IPs/ports, routes, the resolver's certificate DNS name and validity,
and the configured trust roots. HTTPS additionally needs h2 ALPN and the correct
POST path; redirects, compressed bodies and invalid DNS media types are refused.
Restore a known-good endpoint profile through validate/shadow/promote, or roll
back a known-good revision as a new generation. Required policy assertions and
shadow comparisons do not probe connectivity: verify a fresh uncached DNS answer
and upstream success counters after recovery. Do not disable certificate checks
or silently substitute plaintext to make an authentication failure disappear.

### Encrypted upstream trust and binary downgrade

Public TLS roots are compiled into the release, so root updates require a binary
upgrade. Private CA certificates are inline policy content and travel with
revisions/backups. Policy compilation validates their encoding and bounds;
connectivity and presented certificate validity are checked during exchanges.
All addresses in a TLS or HTTPS profile use one certificate identity. No plaintext
fallback is attempted when authentication or connectivity fails. HTTPS additionally
requires HTTP/2; redirects and environment proxies are not used. The container
smoke verifies a local CA-signed HTTPS policy through backup, upgrade and restore.

Older binaries cannot decode transport kinds they predate (`tls` or `https`),
independently of the SQLite schema number. Downgrading requires compatible
policy revisions in a backup/configuration rather than relying on schema number
alone. Existing UDP and TLS revisions remain readable by this release.

### Temporary exception recovery

Temporary allows keep their original absolute `expires_at` through durable
revisions, shadow promotion, restart and rollback. They expire in DNS workers
even when SQLite or management is unavailable. Restart/recompilation requires a
trustworthy system clock for exact timing; if the clock lags at boot, DNS still
starts and each allowance lasts at most seven days of monotonic time or until
its corrected absolute expiry. DNS responses cap record TTLs to remaining allowance;
already-used answers and application connections cannot be withdrawn. Expired
entries remain inspectable until removed through the normal policy workflow.
See [temporary exceptions](../architecture/policy.md).

### Downloaded lists and recovery

Downloaded sources and exact list contents are stored together in policy
revisions. Restart, backup verification, shadow promotion and rollback do not
contact a publisher. The system can boot and filter from stored content while
the publisher is offline. Failed refreshes never replace active content. URL
query tokens, if configured, are secrets in policy content/backups; explicit
bootstrap IPs and optional private trust also travel with revisions.

Downloaded-source introduction kept schema 2; the current schema is 6.
Binaries predating `filter_sources` cannot decode revisions
that contain the new field. Binary downgrade needs a compatible pre-feature
backup even when both binaries support schema 2. Removing a source through
reviewed promotion leaves its current list text; remove the list separately to
retire those rules. Maintenance verification rejects mismatched content hashes
before publishing a backup/restore destination. See
[downloaded lists](../architecture/feeds.md) for bounds, workflow and limitations.

## Endpoint cooldown and console recovery

Repeated transport/validation failures now temporarily skip a configured
endpoint. Inspect admission, backoff_skips, recovery_probes and historical failure
reasons in Upstreams. At most one traffic-driven probe enters after a cooldown;
validated recovery restores the primary. All unavailable endpoints produce
uncached SERVFAIL. Cancellation and ambiguous deadlines do not increase delay;
SERVFAIL/REFUSED are query-specific and do not trip the gate. See
[admission contract](../architecture/upstreams.md) and [measurement procedure](../engineering/performance.md).

The console loads its editor and query table on demand. If an old browser tab
cannot load an asset after an upgrade, it reports the error while other views
remain available. Refresh and reconnect to fetch the installed console; export
any draft before an upgrade or refresh. The theme and management token remain
in tab memory.

Scheduled-list configuration persists with complete revisions and backups. A
pending candidate survives upgrade/restore and keeps checks paused until review.
Runtime attempt results are not backed up; restart reconstructs next deadlines
from active retrieval stamps. Older binaries cannot read refresh_interval_secs:
use a compatible backup with the older policy format when downgrading. Scheduled
configurations must fit the 16 MiB configuration API limit, including JSON escaping.
See [scheduled refreshes](../architecture/feeds.md) for bounds and failure handling.

Conditional scheduled checks expose `last_http_status` and `last_download_bytes`
in refresh status and the console: a successful HTTP 304 transfers no body and
preserves the stored retrieval stamp and revision. These fields describe the
accepted response for the last completed check (null if none), not total
TLS/header traffic. Validator hints are bounded
and runtime-only; restart or source/trust changes start with a full retrieval.
Malformed conditional replies preserve live DNS, discard hints and allow a full
GET at the next scheduled/check-now attempt. Manual preview remains unconditional.
Changed bytes still require shadow review and explicit promotion. See
[conditional retrieval](../architecture/feeds.md).

## Homelab additions

[Container installation](container.md) describes verified image builds, private
master-token files, non-root ownership and Compose port mapping.
[Administration](../architecture/security.md) describes writable authentication state
under `/var/lib/rustwalld-dns`, TOTP enrollment/recovery and scoped tokens. Identity
files, master credentials and TLS settings need separately protected backups;
they are deliberately excluded from policy/SQLite exports.
[Privacy](../architecture/security.md) documents history mode/retention, clear semantics and
schema 4 (upgraded by the weekly schedule schema below). [Integrations](integrations.md) describes optional maintained
DHCP, advisory inventory, reviewed peer copying and monitoring access.


## Weekly service schedule upgrade

Weekly windows persist with active/shadow revisions and SQLite backups. Schema 5
adds nullable actual-state metadata to history, migrating schemas 1–4 before
serving. Existing unscheduled rows remain valid with null state. Old binaries
cannot open schema 5; retain a pre-upgrade backup for downgrade and restore it to
a new target with the compatible binary. Replacing the executable alone is
insufficient. Retained scheduled explanations need the original revision and
recorded phase; missing metadata is reported as unavailable rather than guessed.

Use a synchronized host clock and the explicit configured zone. The console/API
expose the deployed timezone database version; updates require a tested new binary.
Schedule TTL caps affect private replies, including unrelated/local answers in
that policy. Host time jumps, already cached client answers and delayed sends
prevent an exact network cutover guarantee. See [weekly schedule contracts and
recovery evidence](../architecture/policy.md).


## Service catalog compatibility

Catalog v2 is opt-in: choose it in a policy draft and review the selected coverage
before promotion. Stored v1 policies are never automatically upgraded; omitted
versions and the default coverage API remain v1. Weekly windows and chosen IDs
survive reviewed upgrades. Remove IDs absent from v1 before downgrading the draft.
Older binaries cannot compile v2 revisions; use a compatible pre-upgrade database
backup when downgrading. That slice kept SQLite schema 5; V4 type provenance now requires schema 6. Provider-reference links and
coverage notes are packaged static metadata, not remote catalogs or DNS lookups.
See [catalog version contracts](../architecture/policy.md).


V4 filtering adds typed assertions and schema 6 response-type provenance. Existing
schema-5 CNAME subjects are labeled type 5 during migration; new address/HTTPS
subjects preserve their actual type separately from the original question type.
Backup verification rejects missing/invalid response-type columns and orphaned
provenance. New AdGuard imports now use V6. Stored Native/AdGuard/V2/V3 policies remain
frozen; type selectors require an explicit switch to V4. A previous binary cannot
open schema 6 or V4 policy content: downgrade using a verified compatible
pre-upgrade backup in a fresh destination, never by editing `user_version`.
See [DNS type rules](../architecture/filtering.md) for syntax, limits and local release evidence.


V5 imports add per-rule IP/CIDR and exact-name restrictions. Native binding names
are identities for these rules: changing a name can change filtering after a
reviewed new generation. Discovered DHCP/router labels and binding annotations
remain advisory and never grant DNS admission. Missing source names are blockers
when named rules exist. Stored old syntax keeps its interpretation. SQLite remains
schema 6, but an older binary cannot read V5 policy content; use a compatible
verified backup for downgrade. See [client rules](../architecture/filtering.md).


V6 source imports preserve supported persistent-client tags in explicit binding
`filter_tags`. Editing them can change DNS decisions. Existing `metadata.tags`
remain descriptive and are never converted into filtering tags automatically.
More-specific bindings use their own assignments; no tag inheritance is implied.
Supported source names are listed in [filter tag vocabulary](../architecture/filtering.md).
Unknown/duplicate assigned tags or unknown rule vocabulary fail validation and
cannot publish. Native through V5 syntax stays frozen; use V6 explicitly for ctag.

Schema6 is unchanged. An older binary cannot parse V6 rules or bindings containing
`filter_tags`, even if their list version is older. Downgrade with a compatible
backup/configuration, preserving generation/revision validation. An explicit tag
assignment never grants DNS admission; keep `allowed_clients` restricted.
