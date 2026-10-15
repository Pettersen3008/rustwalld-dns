# Console interaction and visual acceptance

The console is a compact network instrument. Use neutral surfaces, restrained blue
selection, clear hierarchy, aligned numeric counters and dense operational tables.
Keep the product's rustwall identity, semantic light/dark tokens and owned
shadcn/Radix primitives. System fonts and local assets support offline operation.
Current folder and tooling conventions are in [web/README.md](../../web/README.md).

## Design before implementation

For a significant UI story, the spec names the operator task, entry point,
information hierarchy, action sequence and loading/empty/error/permission/conflict
states. Describe desktop and narrow-screen behavior, keyboard flow and the real
API/data source. Use a small wireframe only when it resolves an actual choice.

Overview shows live counters and honestly labeled retained samples. Queries use
a searchable ledger with details on demand. Policies preserve draft → validate →
shadow → review → promote. Clients distinguish admission, explicit bindings,
filtering tags and advisory inventory. Filters show bounded provenance and payload
estimates. Upstreams distinguish current failure, cooldown/probe and old counters.
Revisions require deliberate inspection before rollback.

The policy workbench keeps validation/staging and active shadow review actions
visible in one compact panel. Explanatory validation/shadow and local-record prose
uses native disclosures. Local DNS names the selected policy beside Add; adding
selects the new row's page and focuses its domain. Empty-record acceptance at
390×844 keeps Add within the first viewport in both themes, with before/after
task-distance evidence. Disclosure guidance and publication safeguards remain
available by keyboard.

## Acceptance for changed flows

- Desktop and 390px-class phone layouts have no document/dialog overflow; tables
  retain meaningful headers and a usable narrow-screen interaction.
- Every action works by keyboard with visible focus, named controls, sensible tab
  order and modal focus return. Verify both themes and readable contrast.
  Asynchronous review captures its initiating control before disabling it or
  fetching data; closing restores that control or falls back to main content
  when it is gone, disabled, inert or unable to receive focus.
- Loading, empty, invalid, expired-session, read-only, disconnected and stale ETag
  states preserve usable navigation and unsaved drafts where applicable.
- Mutations show scope and impact; server validation and revision preconditions
  are authoritative. No misleading success toast before durable completion.
- Graphs have a text equivalent; label sample/window/process/generation scope.
  Missing latency or health data is unavailable, never invented or zero-filled.
- No credentials in browser storage, URLs, logs, screenshots or exports. Disconnect
  cancels requests and clears session/drafts. Refresh requires authentication again.
- No remote font/CDN requests, surprise polling, dependency bloat or extra DNS work.

Run relevant real-daemon Playwright flows and visually inspect desktop/mobile
screenshots for every changed screen. Store screenshots under target/ or the ignored
web test-results folder, and summarize findings in the story. Automated selectors
alone do not establish visual quality or complete accessibility compliance.
