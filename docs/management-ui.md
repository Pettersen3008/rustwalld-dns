# ADR 002: local management console and revision-safe editing

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: complete Phase 8 as a working console for existing backend capabilities.
Done: production build served by Axum; real-browser authentication, query
explanations and validate/shadow/promote/rollback verified against the real API.
No changes to DNS library dependencies, parsing, caches or query evaluation.

Checklist: inspect API/schema; add revision preconditions/static hosting; build
React views; verify real browser/failure cases/mobile layout; review and document.

Use React 19, strict TypeScript, Vite, TanStack Query/Table and Tailwind. Use Base
UI for accessible confirmation dialogs. Dependencies are pinned by npm's lockfile.
No CDN, analytics or external assets. Fetch only relative same-origin API paths.
A bearer token stays in React memory, never browser storage, URL or a bundle.
Disconnect clears query cache and draft state. Page reload requires reconnecting.

Keep views small: overview, query history/explanation, policy workbench,
clients, filter intelligence, upstream health and revision history. Structured
editing covers policies, rules, rewrites, bindings, assertions and upstreams;
advanced JSON import/export permits complete inspectable configuration. Drafts
are local, explicit and never automatically replaced by background polling.
Validation does not publish. Shadow requires validation; promotion/rollback
review the concrete candidate and require a deliberate button press.

GET configuration/shadow responses carry an opaque ETag built from active and
shadow generation IDs. UI writes send If-Match. Check this under the existing
single-permit management mutation admission before compilation/commit; reject stale writes with
412, preserving the draft. Capture shadow content under that same permit.
Legacy CLI clients without If-Match retain explicit unconditional behavior.
An API poll must not label older configuration with a newer generation.

Optional web_root points to a compiled web/dist directory. Axum serves assets on
the isolated management runtime with existing admission/idle bounds. Unknown API
paths remain API errors. Static paths use tower-http's directory service; missing
assets remain 404. Hash navigation permits refreshing tabs without SPA fallback
turning API/asset misses into HTML. Apply no-store to protected JSON and a CSP
suited to the bundled SPA. Startup checks the configured index exists.

Alternative: separate frontend server in production. Prefer the existing local
management listener for same-origin authentication and a simpler install. Vite's
loopback development proxy is used only during development.

Verification: Rust API tests for stale writes, shadow/clear/rollback preconditions,
ETag/body consistency and static/unknown-path behavior; existing DNS regression
suite; TS/build and browser tests covering workflow, errors and draft conflict;
manual responsive inspection. Audit new Rust/npm dependencies. A DNS benchmark
is unnecessary because this milestone does not change the data plane.

Primary API references reviewed 2026-10-05:
- https://react.dev/reference/react-dom/client/createRoot
- https://tanstack.com/query/latest/docs/framework/react/overview
- https://tanstack.com/table/latest/docs/guide/introduction
- https://tailwindcss.com/docs/installation/using-vite
- https://vite.dev/guide/
- https://base-ui.com/react/components/dialog

Review findings resolved: mobile disconnect was hidden by responsive layout;
stopping an unrelated candidate could have rebased an older draft's ETag without
updating its content; JSON object key order caused false draft/candidate mismatch.
The console now exposes disconnect in the top bar, preserves stale drafts when
active content differs, and canonicalizes object keys for content comparison.
Multiline network/address editors preserve separators while compiling arrays.

No DNS library/query-path code changed. The app mutation mutex became one
nonblocking semaphore permit, retaining cancellation-safe serialization without
holding a lock across compilation or durable I/O. Static hosting is opt-in.

Verified on 2026-10-05:
- `cargo fmt --all --check`: pass.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: pass.
- `cargo test --workspace --locked`: 28 tests passed.
- `npm --prefix web run format:check`, `run build`: pass (strict TS included).
- `npm --prefix web test`: 10 desktop/mobile Playwright cases passed against the
  real appliance and isolated SQLite/local mock upstreams. Real DNS answers
  remained unchanged in shadow, changed on promotion and returned on rollback.
- `cargo audit`, `cargo deny check`, `npm --prefix web audit`: pass; zero known
  vulnerabilities. Existing allowed duplicate crate version warnings remain.
- Existing ASAN DNS/filter fuzz targets: 1,256,115 / 347,725 inputs in 21 seconds
  each, no crashes. Static hosting/revision guards are covered by HTTP regression
  tests; these fuzz targets exercise DNS/filter parsing, not the browser or HTTP.

Browser screenshots/traces are in ignored `web/test-results/`, retained by CI.
Local Rust/fuzz command logs are under ignored `target/ui-*-*.log`.
Optional asset hosting needs a built directory and a process restart to configure;
ordinary policy reloads/promotions continue without a DNS restart.
