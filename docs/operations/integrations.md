# Optional homelab integrations

## Homelab control-plane adapters

Process configuration owns at most eight explicitly named integrations. No adapter
runs on a DNS executor. Inventory is advisory: an IP/name/MAC/lease never grants
admission, creates a local record, changes a binding or rewrites query history.

Supported adapters: bounded dnsmasq DHCPv4 lease-file snapshots; the official local
UniFi Network client API; OPNsense Kea DHCPv4 lease search; and a second Rustwall
node's policy configuration. Remote adapters use HTTPS with explicit bootstrap
IPs and normal certificate/hostname verification (private CA optional). Secrets
come from private files, are held separately from configuration, and never appear
in DTOs, logs, policy exports or errors. They are loaded at startup. Only GET
requests to adapter-owned paths are permitted; redirects, compression and trailers
are rejected. No system command, account auto-discovery or public bootstrap DNS.

Manual refresh has two global slots, one slot per source, an overall fifteen-second
deadline, 1 MiB JSON bodies per inventory page, 4096 devices and sixteen pages.
Keep last successful inventory with a timestamp; errors do not erase last-good
state. Cache lives only in memory. No timer contacts third-party services by default.
Lease snapshots cap input at 1 MiB and 4096 lines, ignore expired leases, reject
invalid records and bound displayed names. Peer policy downloads cap at 16 MiB,
validate all local DNS listener/admission/assertion contracts, return a draft with
a pinned local ETag and recheck it after fetching. Peers do not synchronize secrets,
process listeners, sessions, history, privacy preferences, cache or generation IDs.
Promotion always uses the existing assertion/durable publication workflow. This
is reviewed one-way policy copying, not automatic failover or DHCP HA.

Optional DHCP uses maintained dnsmasq with DNS disabled, a dedicated interface,
explicit pool/gateway/DNS options and its own process. The checked-in example is
inactive until an operator edits and enables it. Keep router DHCP when already in
use. Home Assistant and other monitoring consumers use an expiring read-only API
token and existing health/metrics endpoints; no separate DNS query plugin.

References inspected 2026-10-12:
- https://developer.ui.com/network/v10.1.84/getconnectedclientoverviewpage
- https://docs.opnsense.org/development/api/core/kea.html
- https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Kea/Api/Leases4Controller.php
- https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html

Example process configuration (paths relative to the appliance config file):

```toml
[[integrations]]
name = "router-leases"
[integrations.source]
kind = "dnsmasq"
lease_file = "/var/lib/misc/dnsmasq.leases"

[[integrations]]
name = "second-node"
[integrations.source]
kind = "peer"
[integrations.source.endpoint]
url = "https://dns2.home.arpa:8443"
bootstrap_ips = ["192.168.1.3"]
token_file = "/var/lib/rustwalld-dns/peer.token"
## ca_pem = "...your private root CA PEM..."
```

For UniFi use kind `unifi`, `site = "...site UUID..."` under source and the same
endpoint table. `controller = true` selects `/integration` for a standalone
Network application; default selects the console's `/proxy/network/integration`.
The token file contains the local Network API key. OPNsense kind `opnsense` uses
`/api/kea/leases4/search`; its private token file contains `API-key:API-secret`.
Use permissions limited to lease search. Token contents are ASCII, 16..4096 bytes,
mode 0600, one optional final line ending. CA PEM replaces public roots. All
configuration changes need restart. Secrets/files must be readable by the service
user; writable authentication state remains in StateDirectory.

Home Assistant can use its REST integration with an expiring read-only token to
poll `/api/v1/status`, `/api/v1/upstreams` and `/metrics`. Avoid copying that token
into query logs or shared configuration. No appliance-specific automatic device
registration or Home Assistant discovery is claimed.

## Optional Unbound upstream

Use Rustwalld for filtering, client policy, caching and the console. Keep DHCP on
an existing router (including a UniFi gateway). Add Unbound only if you want a
local recursive resolver and DNSSEC validation rather than trusting an external
recursive provider. An authenticated DoT/DoH upstream is a simpler alternative.
Encryption to a provider and DNSSEC validation are different protections.

```text
LAN clients -> Rustwalld UDP/TCP :53 -> Unbound 127.0.0.1:5335 -> authoritative DNS
                     |
             loopback management console
```

Unbound is a separate Linux service, not a plugin or a query-path subprocess.
This is the same division of responsibilities described by the
[Pi-hole Unbound guide](https://docs.pi-hole.net/guides/dns/unbound/).
Our offline fixture verifies actual Unbound UDP/TCP forwarding, blocking, cache
hits, NXDOMAIN, NODATA and DNSSEC validation of a locally signed zone. It rejects
a tampered signed RRset and verifies that Rustwalld returns SERVFAIL while
clearing AD on valid answers. It does not test Internet recursion or root
trust-anchor updates.

### Setup on a deployment host

Install the distribution-supported Unbound package and its DNS root-data package.
Use the distribution's service account, sandbox and trust-anchor initialization.
Do not overwrite its main configuration or root trust anchor with this snippet.
Review existing listener/forward-zone snippets to avoid duplicate bindings or
sending Unbound back to Rustwalld. Keep accurate system time and root-data
security updates enabled.

Place [packaging/unbound.conf](../../packaging/unbound.conf) in the distribution's
included `unbound.conf.d` directory, then run `unbound-checkconf` against the
complete configuration before restarting Unbound. The snippet listens on IPv4
loopback port 5335, permits loopback clients, uses one worker and gives its
message/RRset caches 8/16 MiB. Those cache budgets are not total process RSS.
It requires validation even when a client requests checking disabled (CD).
Consult the [Unbound configuration manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
for the installed version and its trust-anchor/service requirements.

In the console's upstream profile editor, use only `127.0.0.1:5335`, plain UDP
transport with TCP fallback, and a timeout suitable for cold recursion (start
with 3000 ms). Validate, stage and promote this change. For a **new database**,
the corresponding bootstrap TOML is:

```toml
[[policy.upstreams]]
name = "default"
addresses = ["127.0.0.1:5335"]
timeout_ms = 3000
```

Changing a file does not replace an existing durable policy; use the console/API
for that. Do not leave an external fallback in this profile if all answers must
pass through Unbound's validator. Rustwalld still clears AD because it does not
validate signatures itself; an absent AD flag at the filtered listener does not
mean Unbound was bypassed. Use the distribution/Pi-hole guide's signed and bogus
validation checks against Unbound directly during deployment, then verify valid
answers and bogus SERVFAIL through Rustwalld. Those public checks are operator
checks and are deliberately absent from this repository's test suite.

Advertise the Rustwalld host's LAN address through router DHCP and IPv6 router
advertisements. Advertise only filtered resolvers: clients can use any advertised
DNS address, so a public secondary address can bypass filtering. Configure
Rustwalld's admitted LAN CIDRs and port-53 service capability as described in
[operations](install.md). Use loopback/SSH administration or explicitly configured HTTPS for LAN
administration; see administration-design.md. Device identification is by source IP; a router DNS
proxy can collapse all devices into the router's identity. Rustwalld does not
install bypass-prevention firewall rules. Optional dnsmasq DHCP and advisory
lease/UniFi/OPNsense inventory are documented in integrations-design.md.

Cold recursion can take longer than a warm public resolver. Unbound also adds
its own process/cache memory. Rustwalld's front cache remains TTL-aware; neither
layer should artificially raise minimum TTLs. Keep the engine's default stale
fallback disabled when expiry semantics are important. Measure real client
workloads before increasing cache sizes or worker counts.

### Reproduce the isolated integration check

Build the release binary first. Preparing the image downloads Debian packages;
the actual DNS check has no Internet route, host services or published ports.

```sh
cargo build --release --locked -p rustwalld-dns
docker build -f packaging/unbound-smoke.Dockerfile -t rustwalld-unbound-smoke:local packaging
docker run --rm --network none \
  --mount "type=bind,src=$PWD/target/release/rustwalld-dns,dst=/binary/rustwalld-dns,readonly" \
  rustwalld-unbound-smoke:local
```

The fixture builds Unbound 1.26.1 from its pinned official source checksum and
uses a local authoritative test zone, with no Internet route during testing.
Version/checksum were checked against the [NLnet Labs release page](https://nlnetlabs.nl/projects/unbound/download/)
on 2026-10-12. Native deployments should use a distribution-maintained patched
package; manually built/container versions need deliberate security updates.
The script cleans up its processes and temporary state.
