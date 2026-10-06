# Security

The current supported development line is 0.1.x. This is an MVP with local
verification, not a claim of production hardening or a completed network soak.
Do not expose the management API outside loopback. Use explicit allowed-client
CIDRs when binding DNS outside loopback, and authenticated trust settings for
TLS/HTTPS upstreams. See [operations](docs/operations.md).

During private development, authorized collaborators can report problems through
[the private repository issues](https://github.com/Pettersen3008/rustwalld-dns/issues).
Do not include tokens, private certificates, real query histories or production
backups. Include the affected version, minimal local reproduction, impact and
relevant sanitized logs. No response-time guarantee is promised.

Before making the repository public, configure and document a private disclosure
channel. Private repository issues are suitable only while access is restricted;
they must not become a public exploit-reporting channel. No public private-reporting
service is claimed until it is configured.

Dependency checks use RustSec (`cargo audit`) and the license/source policy in
`deny.toml`. Parser, cache, transport and configuration fuzz targets are retained
under `fuzz/`. Security fixes must preserve resource bounds and include appropriate
regression/fuzz evidence. Neither a passing scan nor a short fuzz run proves the
absence of vulnerabilities.
