# Public alpha

`v0.1.0-alpha.1` opens the source and provides an experimental native Linux
bundle for homelab feedback. Cargo packages and the bundle manifest retain the
development version `0.1.0`; the GitHub prerelease tag identifies alpha status.
The libraries have not been published to crates.io.

The alpha includes DNS filtering and forwarding, bounded caching and coalescing,
client/subnet policies, local rewrites, encrypted TLS/HTTPS upstreams, opt-in
serve-stale and a local web console. Configuration changes use validation,
shadow evaluation, explicit promotion and rollback. See the
[README](../README.md) for protocol and resource limits.

The provided bundle is native x86_64 Linux GNU and requires GLIBC 2.34 or newer,
systemd and Python 3.11+. Rust and Node are needed only when building from source.
ARM64, Windows and macOS deployment have not been verified. Download the archive
and its SHA-256 file from [GitHub releases](https://github.com/Pettersen3008/rustwalld-dns/releases),
check the checksum and inspect the bundle before following
[installation instructions](operations.md). Checksums detect corruption; they
are not release signatures.

DNS defaults to loopback UDP/TCP port 5353. Before using it on a LAN, configure
explicit admitted client CIDRs, review the port-53 capability settings and verify
resolution on the target host. Management remains on loopback; use an SSH local
port forward to access the console remotely. Installation does not change router
DNS, firewall rules or host resolver settings and does not start the service.

Local Rust, browser, fuzz, dependency, packaging and container recovery checks
provide development evidence. Native systemd sandbox activation and the
24–72-hour representative-network soak remain pending. No independent security
audit, production availability guarantee or complete Pi-hole/AdGuard feature
parity is claimed. The engine does not perform DNSSEC validation, provide DHCP,
discover devices or serve encrypted DNS to clients.

[@Pettersen3008](https://github.com/Pettersen3008) maintains this repository and
reviews every contributor change. Forks and pull requests are welcome;
[CONTRIBUTING.md](../CONTRIBUTING.md) explains local checks and review requirements.
The project intentionally has no hosted CI/CD or `.github` directory. Actions
remain disabled; Dependabot PRs receive manual verification and maintainer review.
Report usability and installation feedback through [SUPPORT.md](../SUPPORT.md)
and security concerns privately through [SECURITY.md](../SECURITY.md).

Source is licensed under MIT OR Apache-2.0, at your option. Bundled trust anchors
have the separate notice in [LICENSE-WEBPKI-ROOTS](../LICENSE-WEBPKI-ROOTS).
Source availability, alpha artifact publication and a stable appliance release
are separate milestones; native deployment and longer testing continue after
this public alpha.
