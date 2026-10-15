# Container installation

Build a native x86_64 or aarch64 GNU release on that architecture with
`python3 scripts/release.py`. Verify the checksum, then build a release image:
`scripts/container-build.sh target/releases/RELEASE.tar.gz rustwalld-dns:RELEASE`.
The image contains the verified binary/console, runs as UID/GID 10001 by default,
needs no capabilities, and listens on unprivileged internal ports. ARM deployment
still needs testing on actual ARM hardware; this does not establish multiarch
image compatibility by emulation.

Copy `packaging/compose.yaml` into a dedicated deployment directory; create
`config/` and `state/`, owned by the chosen non-root UID/GID. Put a reviewed copy
of `packaging/container-config.toml` at `config/config.toml`; replace the example
LAN CIDR, upstream provider and admin hostname. Bootstrap IPs avoid resolver loops.
The encrypted example uses no plaintext fallback; DNSSEC validation is delegated
to that provider. To use recursive Unbound, install it separately with the checked
snippet, use a reachable host/sidecar address on port 5335, and admit only the DNS
container's address there. Container loopback never reaches a separate host.

Supply your locally trusted certificate at `config/cert.pem` and its private key
at `config/key.pem`; key ownership must match the runtime UID and mode 0600.
Generate a random master token in `config/master.token` (0600, owner runtime UID),
for example `openssl rand -hex 32 > config/master.token` under a private umask.
The token is read from that file and never placed in Compose environment values.
Bind-mounted secrets retain host permissions; Docker Compose file secrets cannot
be assumed to apply requested UID/GID/mode.

Initialize the local admin while the service is stopped, using the same image,
UID and state bind mount:

```
docker run --rm -i --network none --user 10001:10001 \
  --mount type=bind,src="$PWD/state",dst=/var/lib/rustwalld-dns \
  rustwalld-dns:RELEASE auth init --output /var/lib/rustwalld-dns/auth.json \
  --username admin --password-stdin
```

Feed a password from your password manager on stdin. Save the printed enrollment
URI privately in your authenticator; it is shown once. No password is passed in
argv. After enrollment, set `RUSTWALL_IMAGE`, `RUSTWALL_BIND` (specific host LAN IP)
and optional UID/GID in a private `.env`, validate with `docker compose config`,
and start explicitly with `docker compose up -d`. The management UI is HTTPS on
8443; UDP and TCP 53 both map to 5353. DoT/DoH are opt-in process listeners, with
matching additional port mappings. The app never configures the host firewall,
changes router DHCP or takes over another service automatically.

The 512 MiB Compose limit is an adjustable deployment default, not a measured
maximum for arbitrary filter sets. Use smaller lists/history/cache for small
machines, or increase it after measuring compiler/reload and concurrent password
hashing peaks. Onboarding reports actual configured limits/listeners, and
upstream health distinguishes no samples from successful traffic.

Use CLI `backup` for a live consistent private SQLite snapshot; copy `auth.json`
separately while authentication is quiescent. Include private master token,
certificates and process configuration in protected operator backups. Stop the
container before restore, verify the snapshot, restore into an absent database,
and keep its ownership correct. Policy IDs are never synchronized with a peer.
Recreate the container for certificate renewal or process-setting changes. Upgrade
by backing up, building a new verified release image and changing its explicit
image tag; never replace the state directory. A rollback to schema-incompatible
old code requires restoration of its old snapshot, not just an old image tag.

Optional DHCP: use the maintained distribution's dnsmasq, with the inactive
`packaging/dnsmasq.conf` example. Review interface, pool, gateway and advertised
Rustwall IP first. Keep DHCP on the existing router when possible. Mount a readable
lease snapshot into the DNS container and configure its `dnsmasq` integration;
lease names/MACs do not grant admission or automatically create records. A
separate DHCP process has a different capability/network requirement and should
not share the capability-free DNS container.
