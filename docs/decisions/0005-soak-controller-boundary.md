# ADR 0005: Keep the soak driver separate from service/fault control

Accepted, 2026-10-15, DNS-020. Codex self-review; personal repository planning.

Existing examples own local children and cannot exercise an independently hosted
appliance without resetting it. Production status/metrics lack host RSS/FD/disk
values. A remote SSH/fault framework inside a traffic tool would mix credentials,
service authority, collection and the correctness oracle.

Use an example-only read-only UDP/TCP driver with frozen reference packets and
bounded input/output. An operator collector supplies identity-bound fresh resource/
counter envelopes through an atomic regular file. The external lab plan owns
remote collection/authentication, faults, backup/undo and final acceptance. Its hash
and actual appliance limits are frozen in the run record. A JSON description does
not grant user authority or prove representativeness.

This avoids production query-path/API dependencies and preserves local rehearsals.
The cost is an explicit collector/controller prerequisite before real lab readiness;
driver success alone cannot close DNS-009. Continuous phase timing and outcome-origin
accounting stay inside the driver; service ownership stays outside it. See the
[spec](../specs/DNS-020-remote-soak.md) and [operator contract](../operations/soak-runner.md).
