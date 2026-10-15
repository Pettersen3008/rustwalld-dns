# Management console

Use Bun 1.4.3+ and Node 22.22+ (Node runs Vite and the browser fixture).
All direct dependencies are exact versions, resolved from the registry's latest
stable tags on 2026-10-12. Commit `bun.lock` with dependency changes.

```sh
bun install --frozen-lockfile
bun run dev
bun run format:check
bun run lint
bun run build
bunx --no-install playwright install chromium
TMPDIR="$PWD/../target/tool-tmp" bun run test
TMPDIR="$PWD/../target/tool-tmp" bun run test:auth
bun audit
```

The browser suite needs `cargo build -p rustwalld-dns --locked` from the repository
root. It starts a real appliance and loopback mocks; it never uses public DNS.

```text
src/
  app/                 session, router and appliance shell
  features/
    overview/          counters and sampled traffic chart
    queries/           TanStack Table v9 query log and explanations
    policies/          draft, editors, sources, assertions and temporary allows
    clients/           source-network inventory
    filters/           compiled list statistics
    upstreams/         transport and failure diagnostics
    revisions/         durable history and rollback
  components/
    ui/                owned shadcn/ui primitives
    common.tsx         appliance panels, fields, notices and dialogs
  hooks/               shared TanStack Query integration
  lib/                 API types, schemas, session cancellation and utilities
  styles/              semantic Tailwind theme and responsive appliance layouts
  main.tsx             browser entry point and legacy bookmark migration
```

Imports use `@/` aliases. React Router owns real document paths; the Rust server
serves only the seven known document routes, preserving missing asset and API
errors. Legacy hash bookmarks migrate on entry. Session/draft ownership stays
above the routes, so navigating does not discard a draft. A browser refresh
requires authentication again and opens the bookmarked view.

Within policies, workbench owns async draft/validation/publication handlers and
review dialogs. Publication, assertion results and section tabs have dedicated
presentation modules. Policies, networks, upstreams and assertions each own their
editor module; editors.tsx preserves existing imports. Local DNS keeps the selected
policy visible beside Add; adding a record selects its page and focuses its domain.
Extended validation/local-record guidance is available in native disclosures.
The cohesive API/schema module and semantic CSS remain existing size exceptions;
split them only for an actual ownership or behavior need.

TanStack Query owns remote data, cancellation and polling. Only the small status
summary polls for revision changes; complete active/shadow configurations are
fetched when their version changes or after an explicit action. Expensive draft
serialization is memoized by immutable object identity. Draft mutations must
return new objects, as the existing editors do.

The interface follows the useful UniFi conventions: neutral surfaces, a blue
selection state, compact persistent navigation, aligned numeric counters and
dense operational tables. No remote fonts, imagery, CDN assets or fabricated
traffic. shadcn source is owned here; `components.json` configures future additions.
See `THIRD_PARTY_NOTICES.md` for attribution. Credentials and drafts remain in
memory; disconnect aborts outstanding API requests and clears the credential.
Oxc checks correctness, React hooks and accessibility. Playwright verifies
keyboard focus, contrasting themes, mobile layout and actual revision/DNS flows.
