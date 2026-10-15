# Security

The current supported development line is 0.1.x, including public alpha releases.
This is an MVP with local verification, not a claim of production hardening or a
completed network soak.
Do not expose the management API outside loopback. Use explicit allowed-client
CIDRs when binding DNS outside loopback, and authenticated trust settings for
TLS/HTTPS upstreams. See [operations](docs/operations/install.md).

Report suspected vulnerabilities using
[GitHub's private vulnerability reporting](https://github.com/Pettersen3008/rustwalld-dns/security/advisories/new).
Use the repository's Security → Advisories → Report a vulnerability action.
Do not report vulnerabilities through public issues or pull requests.
Do not include tokens, private certificates, real query histories or production
backups. Include the affected version, minimal local reproduction, impact and
relevant sanitized logs. No response-time guarantee is promised.

The maintainer coordinates investigation, regression tests and any fix privately
before publishing an advisory. Do not publish exploit details until disclosure
has been coordinated. Other questions and sanitized bug reports belong in
[SUPPORT.md](SUPPORT.md).

GitHub secret scanning/push protection and Dependabot alerts complement local
checks. Dependency update pull requests require maintainer review and local
verification; updates are never automatically merged. GitHub Actions are disabled
for this repository. These settings do not replace a code or deployment audit.

Dependency checks use RustSec (`cargo audit`) and the license/source policy in
`deny.toml`. Parser, cache, transport and configuration fuzz targets are retained
under `fuzz/`. Security fixes must preserve resource bounds and include appropriate
regression/fuzz evidence. Neither a passing scan nor a short fuzz run proves the
absence of vulnerabilities.
