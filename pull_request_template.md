Describe the concrete problem, resulting behavior and any related issue.

Explain the change and material risks or compatibility effects.

List the verification commands and results. Include sanitized benchmark or fuzz
evidence when relevant; do not attach tokens, private network data or backups.

- [ ] Read CONTRIBUTING.md and AGENTS.md.
- [ ] Ran cargo fmt --all --check.
- [ ] Ran strict workspace Clippy with all targets/features and --locked.
- [ ] Ran cargo test --workspace --locked and the Rust 1.95 check.
- [ ] Used local mocks for network tests; no public DNS queries.
- [ ] Updated documentation and CHANGELOG.md where needed.
- [ ] Included relevant performance/security/dependency verification, or explained why it does not apply.

Every contributor change needs review and approval by @Pettersen3008. Dependency
update PRs follow the same process. Leave merging to the maintainer.
