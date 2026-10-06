# Console design system

Scope was confirmed by the user: finish the current release and performance work,
then redesign the existing console. Ward.pdf is a six-page reference, not a new
feature specification. Temporary exceptions, downloads, DHCP/group metadata and
DNS Guard remain separate roadmap work. The product keeps its rustwall identity.

## Direction

A compact network instrument: cool graphite, chalk surfaces and a restrained
indigo accent. Status colors communicate operational meaning, never branding.
A narrow navigation rail and persistent generation/status line replace the large
forest-green sidebar and promotional headings. Titles name the task directly.
System fonts and local assets preserve offline operation; no font/CDN requests.

Use Tailwind v4 semantic tokens following shadcn conventions (background,
foreground, card, muted, primary, accent, border, input, ring). Accessible Base UI
dialog primitives are already installed. Keep small owned components rather
than a second component framework. Light and dark use explicit tokens; the theme
preference stays in memory and never stores management credentials.

Different page structures serve different tasks:

- Overview: a compact counter strip, one outcome visualization with an honest
  retained-event sample/time range, and current protection/shadow state.
- Query log: a full-width ledger with search and decision filtering; detailed
  explanations appear only after selecting a query.
- Policies: editing workspace with assertions/shadow/promotion safety intact.
- Networks: admission tiles and explicit compiled policy bindings, without
  pretending subnet bindings are discovered devices or MAC/VLAN identities.
- Filters: compilation quality summary followed by rule-accounting tables.
  Payload estimates remain estimates; there is no invented overlap or RSS.
- Upstreams: endpoint health/admission reads and diagnostic detail. Cooldown,
  probing and historical failures are distinct concepts.
- Revisions: a compact chronology; complete configuration and rollback remain
  behind deliberate inspection/review.

## Acceptance

All real DNS/API/browser flows remain functional. Desktop and phone layouts fit
without document overflow. Keyboard navigation, focus visibility and modal focus
return work in both themes. Charts have text equivalents and never invent missing
latency, historical traffic, allocation, or failure measurements. Counters are
explicit about process lifetime, generations and retained samples. No additional
DNS telemetry/persistence work is added for visual styling. No external requests,
large chart library, animation loop, new runtime dependency or faster polling.

Verify all existing browser tests, add theme/mobile/keyboard/contrast coverage,
visually inspect screenshots for every page, and ship the tested release bundle.

## Delivered evidence

The palette and component rules live in web/src/style.css; Base UI owns dialog
focus/keyboard behavior and Tailwind v4 maps the semantic colors. Overview uses
a bounded, accessible SVG of up to 500 retained events with a count-table
alternative. No p99 or allocation numbers are invented for the live console.
Query outcome filters operate on the same retained sample; failure events are
distinguished from policy-allowed answers. Diagnostics separate historical
failures, current admission, skips and probes.

Twenty-two Playwright tests passed on desktop and a 393 px touch viewport, using
real local DNS/API/SQLite fixtures. The new cases cover both themes across seven
views, no document overflow, outcome selection, chart counts, dialog focus return,
sampled dialog text contrast >=4.5:1, no external asset requests or browser token
storage, a deliberately aborted editor chunk, and top-of-page navigation after scrolling. This is targeted coverage, not
a full accessibility certification. Screenshots are in web/test-results and were
visually inspected; failed loading preserves navigation/session state.

Production assets: initial JavaScript 435.99 kB (134.09 kB gzip), deferred query
view 57.28 kB (15.32 kB gzip), deferred editor 19.49 kB (5.71 kB gzip), CSS 36.05 kB
(8.10 kB gzip). Figures come from Vite build output, not browser CPU timings.
Polling intervals and DNS telemetry/persistence interfaces remain unchanged.

Final release checks also pass fmt, strict Clippy, 64 Rust tests, five packaging
tests, Rust audit/deny and npm audit. The non-root Debian container verifies
installation, DNS transports, upgrades, WAL backup and encrypted policy recovery.
Native systemd sandbox activation remains a deployment-host check.
