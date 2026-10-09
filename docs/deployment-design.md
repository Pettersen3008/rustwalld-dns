# ADR 003: release, recovery and management-failure isolation

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: a complete deployment slice without changing DNS protocol or matching.
Done: deterministic bundle verified twice; staged and clean-container installation,
upgrade and backup recovery; non-root service unit validated; real-process DNS
traffic measured during stalled HTTP, large compilation and SQLite lock failure.
Native PID 1 sandbox activation must be verified separately on the deployment host.

Checklist: inspect lifecycle/store/tests; package and installer; standalone
maintenance commands; failure harness; review; native checks and container smoke.

Ownership: app adds standalone backup/verify-backup/restore subcommands before
runtime creation. Use SQLite online backup, not a copy of the live main file:
WAL changes belong in the snapshot. Copy into a private sibling temporary file,
normalize to rollback journal, validate schema/integrity plus active/shadow policy
assertions, fsync and publish without overwriting a target. Restore requires an
absent target and absent WAL/SHM/journal sidecars. Existing running stores are
never replaced by this command. Reads do not bootstrap or migrate a backup.
The backup copies all pages in one step (incremental steps restart on every
concurrent write) with a 30-second busy deadline; validation may take longer.
Reject future schema versions on daemon startup instead of resetting their marker.

Packaging: locked Rust/npm builds, recorded toolchains/source hashes, manifest
hashes and deterministic tar/gzip metadata. Repacking identical built inputs is
byte-identical; arbitrary different toolchains/OS builds are not promised identical.
Native Linux GNU only initially; record required GLIBC symbols. Content-addressed
release directories and an atomically switched current symlink. Installer checks
all manifest files before mutation, keeps original config/secret/state and does
not enable/start/stop services or change DNS settings. Test --root stages without
accounts or host service changes. Normal install requires root and a dedicated
system user. No arbitrary tar extraction or symlink payloads are accepted.

Service: static non-root account permits clear backup/restore ownership. Explicit
/etc config and /var/lib state; /opt immutable binary/UI. StateDirectory, strict
filesystem protection, no capabilities by default, private tmp/devices, bounded
stop/restart policy and kernel/system-call protections. DNS remains loopback5353
and management loopback8080. Port53 needs an explicit capability drop-in; external
DNS also needs explicit allowed client CIDRs. Alternative DynamicUser complicates
offline recovery ownership; separate frontend hosting complicates installation.

Verification: meaningful maintenance failure tests (WAL, source unchanged, target
collision, invalid assertions/schema/corruption, recovery boot); Python packaging
and staged-install tests; clean offline container with actual non-root daemon,
unit verification, upgrade and recovery; release-mode failure benchmark recording
hardware/toolchain/quantiles/timeouts/admission/drop counts. Network tests use only
loopback mocks. Normal fmt/Clippy/workspace tests and audits/fuzzing remain required.

Primary references reviewed 2026-10-05:
- https://www.sqlite.org/backup.html
- https://sqlite.org/c3ref/backup_finish.html
- rusqlite 0.38 backup API source in the installed Cargo registry
- https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml
- https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html

Review corrections: future schemas are refused before bootstrap, destinations
with sidecars or writable directory permissions cannot receive backups, payload
and managed-path symlinks are rejected, staged copies are rechecked, and installer
modes are independent of the caller umask. Candidate HTTP elapsed time is
reported separately from its broader DNS sample window.

Verification: 32 workspace Rust tests; five Python packaging/install tests;
clean Debian container installation, non-root UDP/TCP, unit validation, upgrade,
WAL snapshot and recovery; release real-process failure benchmark (see
resilience-baseline.md); fmt/Clippy/audit/deny and existing DNS/filter fuzz targets.
No DNS-library code or dependencies changed. The SQLite backup feature and
standalone app maintenance paths were added; native sandbox activation is not
asserted by the container results.

A directory-sync failure after snapshot publication reports the existing target
explicitly, rather than implying no file exists. Benchmark JSON includes the
measured binary SHA-256; the original five-second sample precedes this diagnostic
message change, with unchanged DNS-library code.
