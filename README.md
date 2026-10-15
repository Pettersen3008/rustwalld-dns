# rustwalld-dns

A local-first DNS policy and security engine in Rust, with five embeddable libraries
and an optional managed appliance. Policies compile into immutable generations;
DNS keeps serving while management validates, shadows and durably promotes changes.

The working tree is a **homelab alpha**: UDP/TCP, encrypted DNS, filtering, caching,
client policies, typed local DNS, reviewed migration and a React console are
implemented. Native-host deployment, a representative network soak and independent
security review remain release gates. Published alpha downloads may lag the tree.
See [scope and limits](docs/product/scope.md) before deployment.

## Build and run locally

Use the pinned Rust toolchain (library MSRV 1.95), a C/C++ toolchain for bundled
SQLite, Bun 1.4.3+ and Node 22.22+ for the console.

```sh
cargo run -p rustwalld-dns --locked -- --print-default-config > config.toml
cargo run -p rustwalld-dns --locked -- --config config.toml --check-config
export RUSTWALLD_API_TOKEN="$(openssl rand -hex 32)"
cargo run -p rustwalld-dns --release --locked -- --config config.toml
```

Defaults: UDP/TCP DNS `127.0.0.1:5353`, API `127.0.0.1:8080`, local SQLite state.
No root privileges are needed. Non-loopback DNS requires explicit client CIDRs;
LAN administration requires explicitly configured HTTPS. Installation never changes
host DNS/firewall/DHCP or starts the native service automatically.

```sh
bun install --cwd web --frozen-lockfile
(cd web && bun run build)
```

Set top-level `web_root = "web/dist"` before policy sections, relative to the
configuration file. Open the local API address and sign in. Leave web_root unset
for backend-only use. Node is not needed at runtime. For frontend development run
`bun run dev` in web/ alongside the appliance; Vite proxies to loopback port 8080.

A new database initializes policy from configuration. Existing databases restore
last durable policy; use validate → shadow → review → promote to change it.
Listener/process settings still come from the file. Credentials and unsaved drafts
stay in browser memory; refresh requires sign-in again. See
[operator recovery](docs/operations/install.md) and [API/limits](docs/architecture/api.md).

## Use the libraries

| Crate | Responsibility |
| --- | --- |
| [rustwalld-dns-filter](crates/filtering/README.md) | Pure compiled matching and provenance |
| [rustwalld-dns-resolver](crates/resolver/README.md) | Bounded forwarding, caching and coalescing |
| [rustwalld-dns-policy](crates/policy/README.md) | Checked snapshots and client selection |
| [rustwalld-dns-core](crates/dns-core/README.md) | Embeddable engine, publication and UDP/TCP |
| [rustwalld-dns-runtime](crates/runtime/README.md) | Optional durable services and lifecycle |

```sh
cargo run --locked -p rustwalld-dns-core --example embedded
python3 scripts/verify-consumers.py
```

These libraries are prepared locally; registry publication is separate.
[Embedding](docs/architecture/embedding.md) covers host ownership/cancellation.
Core does not depend on app, runtime, Axum, SQLite or management JSON.

## Develop with agents

Start with [AGENTS.md](AGENTS.md) and the [documentation index](docs/README.md).
Agents own story refinement, specs, implementation, review, acceptance evidence,
sprint planning and retrospectives within the authorized scope.
[Roadmap](docs/roadmap.md) · [Backlog](docs/planning/backlog.md) ·
[Sprint 02](docs/planning/sprints/sprint-02.md) ·
[Local verification](docs/engineering/verification.md) ·
[Performance](docs/engineering/performance.md) · [UI acceptance](docs/engineering/design.md).
No hosted CI/CD is used; evidence stays under ignored target/.

[Install/recover](docs/operations/install.md) · [Containers](docs/operations/container.md)
· [Optional Unbound/inventory](docs/operations/integrations.md) ·
[Release preparation](docs/operations/releasing.md) · [Changelog](CHANGELOG.md).

Licensed MIT OR Apache-2.0. [Contributing](CONTRIBUTING.md) requires maintainer
review before merge. [Support](SUPPORT.md) and [private security reporting](SECURITY.md).
