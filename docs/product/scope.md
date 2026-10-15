# Product scope and release gates

Build explainable, local-first DNS protection for a homelab, with independently
embeddable Rust libraries and a compact management appliance. Judge AI delivery
on correctness, latency, code quality, folder ownership and usable interactions.
Avoid a feature-count race or a custom DHCP/recursive resolver implementation.

## Working tree capabilities

The code includes UDP/TCP forwarding, bounded caching/coalescing, authenticated
DoT/HTTP2 DoH upstreams, incoming DoT/DoH, compiled exact/suffix/regex filtering,
allow precedence, response CNAME/value inspection and client/subnet policy.
Versioned AdGuard interpreters through V6 add bounded cancellation, exclusions,
type/client/tag scopes. Unknown/unsupported source semantics are explicit blockers.

Local DNS covers typed records, descendant suffixes, family passthrough and
conditional routes including explicit DS routing. HTTPS/SVCB supports AliasMode,
ServiceMode and optional numeric port; complete alias graph validation, chasing,
Additional synthesis and other service parameters remain open.

The optional runtime provides immutable durable revisions, assertions, shadow,
explicit promotion, fresh-generation rollback, best-effort original-generation
history, temporary actions and reviewed/scheduled downloaded lists. SafeSearch,
versioned service-domain catalogs and explicit-zone weekly schedules are opt-in.

The app includes supported-subset Pi-hole/AdGuard draft import, HTTPS single-admin
Argon2id/TOTP sessions, scoped tokens, privacy controls and advisory inventory.
Peer copying is a reviewed one-way draft, not HA. Inventory/MAC/VLAN labels do not
grant admission. Unbound supplies optional recursion/validation; dnsmasq can supply
separately managed DHCP. The React console supports local/offline assets and
reviewed policy actions; no fabricated counters or unavailable-service badges.

This is a code inventory, not fresh acceptance of every feature. Existing local
results are historical; each changed slice must be checked against its current
source. The public alpha label remains. Published downloads may lag this working
tree; library registry publication remains separate.

## Release gates

- Native deployment-host systemd sandbox, install/upgrade/backup/recovery validation.
- Representative 24–72-hour network soak with query correctness, overload, restart,
  policy updates, storage faults, latency and resource observations.
- ARM hardware validation before claiming support; Windows/macOS appliance support
  is unverified.
- Independent security review of exposed administration, parsers, publication and
  DNS correctness before representing the appliance as security-audited.
- Verified default and optional feature builds, real-daemon UI flows, bounded
  resources, licenses/notices and reproducible release identity.

Host activation, router DNS/DHCP changes, public releases and registry uploads need
explicit authorization. Agents can prepare fixtures and a reviewable runbook.
Local/container fixtures do not substitute for hardware or a representative soak.

## Later scope

Broader source compatibility, service coverage and service-record parameters are
separate bounded stories. DoQ/DNSCrypt, automated HA, external identity and firewall
bypass prevention remain candidates, not commitments. Each needs a user outcome,
measured resource impact and a design that preserves query-path boundaries.
