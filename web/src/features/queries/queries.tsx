import { useMemo, useState } from "react";
import {
  flexRender,
  createFilteredRowModel,
  createSortedRowModel,
  createPaginatedRowModel,
  useTable,
  tableFeatures,
  columnFilteringFeature,
  globalFilteringFeature,
  rowSortingFeature,
  rowPaginationFeature,
  filterFn_includesString,
  sortFn_alphanumeric,
  sortFn_basic,
} from "@tanstack/react-table";
import type { ColumnDef, SortingState } from "@tanstack/react-table";
import { ArrowUpRight, Search, ChevronLeft, ChevronRight } from "lucide-react";
import type { Api, Explanation, HistoryEvent } from "@/lib/api";
import { Badge, Empty, ErrorNotice, Field, Loading, Modal, Panel } from "@/components/common";
import type { Versioned, Configuration } from "@/lib/api";
type RecordedTrace = {
  basis: "recorded_generation";
  event: HistoryEvent;
  revision_available: boolean;
  policy: string | null;
  rule: {
    domain: string;
    matcher: string;
    action: string;
    denyallow?: string[];
    dnstype?: { include: number[]; exclude: number[] };
    client?: { include: string[]; exclude: string[] };
    ctag?: { include: string[]; exclude: string[] };
    sources: { list: string; line: number }[];
  } | null;
  temporary_exception: { name: string; domain: string; expires_at: number } | null;
  service_schedule?: { time_zone: string; state: "active" | "inactive" | "invalid_clock" } | null;
  safe_search?: { provider: string; target: string; catalog_version: number } | null;
};
import { dnsTypeName, typeScopeText, clientScopeText } from "@/lib/dns-types";
import { useApi } from "@/hooks/use-api";
const features = tableFeatures({
  columnFilteringFeature,
  globalFilteringFeature,
  rowSortingFeature,
  rowPaginationFeature,
  filteredRowModel: createFilteredRowModel(),
  sortedRowModel: createSortedRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
  filterFns: { includesString: filterFn_includesString },
  sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
});
export function Queries({ api, published }: { api: Api; published: () => Promise<void> }) {
  const history = useApi<HistoryEvent[]>(api, "queries", "/api/v1/queries?limit=500");
  const [search, setSearch] = useState("");
  const [outcome, setOutcome] = useState("all");
  const events = useMemo(
    () =>
      (history.data ?? []).filter(
        (event) =>
          outcome === "all" ||
          (outcome === "blocked"
            ? event.action === "block"
            : outcome === "forwarded"
              ? ["upstream", "coalesced"].includes(event.source)
              : outcome === "cache"
                ? ["cache", "stale"].includes(event.source)
                : event.source === outcome),
      ),
    [history.data, outcome],
  );
  const [sorting, setSorting] = useState<SortingState>([]);
  const [selected, setSelected] = useState<HistoryEvent | null>(null);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [recorded, setRecorded] = useState<RecordedTrace | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [action, setAction] = useState<"allow" | "pause" | null>(null);
  const [actionBase, setActionBase] = useState<Versioned<Configuration> | null>(null);
  const [duration, setDuration] = useState("300");
  const [notice, setNotice] = useState("");
  async function reviewAction(operation: "allow" | "pause") {
    setBusy(true);
    setError(null);
    try {
      setActionBase(await api.configuration());
      setAction(operation);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function applyAction() {
    if (!selected || !action || !actionBase) return;
    setBusy(true);
    setError(null);
    try {
      await api.request("/api/v1/temporary-actions", {
        method: "POST",
        etag: actionBase.etag,
        body: {
          operation: action,
          client: selected.client,
          ...(action === "allow" ? { domain: selected.domain } : {}),
          duration_secs: Number(duration),
        },
      });
      await published();
      setAction(null);
      setSelected(null);
      setActionBase(null);
      setNotice(
        `Temporary ${action === "allow" ? "domain allow" : "filtering pause"} applied to ${selected.client} for ${Number(duration) / 60} minutes.`,
      );
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  const columns = useMemo<ColumnDef<typeof features, HistoryEvent>[]>(
    () => [
      {
        accessorKey: "domain",
        header: "Domain",
        cell: ({ row }) => (
          <button
            className="domain-button mono"
            onClick={() => {
              setSelected(row.original);
              setExplanation(null);
              setRecorded(null);
              setError(null);
            }}
          >
            {row.original.domain}
            <ArrowUpRight size={13} />
          </button>
        ),
      },
      {
        accessorKey: "client",
        header: "Client",
        cell: (c) => <span className="mono">{String(c.getValue())}</span>,
      },
      {
        accessorKey: "action",
        header: "Decision",
        cell: ({ row }) => (
          <Badge
            tone={
              row.original.source === "failure"
                ? "red"
                : row.original.action === "block"
                  ? "amber"
                  : "green"
            }
          >
            {row.original.source === "failure"
              ? "FAILED"
              : row.original.source === "rewrite"
                ? "REWRITE"
                : row.original.source === "safe_search"
                  ? "SAFESEARCH"
                  : row.original.action.toUpperCase()}
          </Badge>
        ),
      },
      { accessorKey: "source", header: "Path" },
      {
        accessorKey: "latency_us",
        sortFn: "basic",
        header: "Latency",
        cell: (c) => <span className="mono">{String(c.getValue())} µs</span>,
      },
      {
        accessorKey: "generation",
        sortFn: "basic",
        header: "Revision",
        cell: (c) => <span className="mono">G{String(c.getValue())}</span>,
      },
      {
        id: "shadow",
        header: "Shadow",
        cell: ({ row }) =>
          row.original.shadow ? (
            <Badge tone={row.original.shadow.differs ? "amber" : "neutral"}>
              {row.original.shadow.differs ? "DIFFERS" : "SAME"} · G{row.original.shadow.generation}
            </Badge>
          ) : (
            <span className="muted">—</span>
          ),
      },
    ],
    [],
  );
  const table = useTable({
    features,
    globalFilterFn: "includesString",
    defaultColumn: { sortFn: "alphanumeric" },
    data: events,
    columns,
    state: { globalFilter: search, sorting },
    onGlobalFilterChange: setSearch,
    onSortingChange: setSorting,
    initialState: { pagination: { pageIndex: 0, pageSize: 20 } },
  });
  async function explain() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      setExplanation(
        (
          await api.request<Explanation>(
            `/api/v1/explain?client=${encodeURIComponent(selected.client)}&domain=${encodeURIComponent(selected.matched_type ? selected.domain : (selected.matched_domain ?? selected.domain))}&qtype=${selected.qtype}${selected.matched_domain && selected.matched_type ? `&answer_value=${encodeURIComponent(selected.matched_domain)}&answer_type=${selected.matched_type}` : ""}`,
          )
        ).value,
      );
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function explainRecorded() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const trace = (await api.request<RecordedTrace>(`/api/v1/queries/${selected.id}/explain`))
        .value;
      if (
        trace.event.timestamp !== selected.timestamp ||
        trace.event.generation !== selected.generation ||
        trace.event.domain !== selected.domain ||
        trace.event.policy_id !== selected.policy_id
      )
        throw new Error("This retained event changed. Refresh the query log before inspecting it.");
      setRecorded(trace);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      {notice && <output className="notice notice-success">{notice}</output>}
      <Panel
        title="Traffic ledger"
        detail="Up to 500 retained events, refreshed every 5 seconds."
        action={
          <div className="search">
            <Search size={16} />
            <input
              aria-label="Search queries"
              placeholder="Search domain, client, decision…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                table.setPageIndex(0);
              }}
            />
          </div>
        }
      >
        <ErrorNotice
          error={history.error}
          retry={() => {
            void history.refetch();
          }}
        />
        <fieldset className="outcome-filter" aria-label="Filter by outcome">
          {[
            ["all", "All"],
            ["blocked", "Blocked"],
            ["cache", "Cached"],
            ["forwarded", "Forwarded"],
            ["rewrite", "Local"],
            ["safe_search", "SafeSearch"],
            ["failure", "Failed"],
          ].map(([value, label]) => (
            <button
              key={value}
              aria-pressed={outcome === value}
              onClick={() => {
                setOutcome(value ?? "all");
                table.setPageIndex(0);
              }}
            >
              {label}
            </button>
          ))}
        </fieldset>
        {history.isPending ? (
          <Loading />
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  {table.getHeaderGroups().map((group) => (
                    <tr key={group.id}>
                      {group.headers.map((header) => (
                        <th
                          key={header.id}
                          aria-sort={
                            header.column.getIsSorted() === "asc"
                              ? "ascending"
                              : header.column.getIsSorted() === "desc"
                                ? "descending"
                                : "none"
                          }
                        >
                          <button
                            disabled={!header.column.getCanSort()}
                            onClick={header.column.getToggleSortingHandler()}
                          >
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {header.column.getIsSorted() === "asc"
                              ? " ↑"
                              : header.column.getIsSorted() === "desc"
                                ? " ↓"
                                : ""}
                          </button>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {table.getRowModel().rows.map((row) => (
                    <tr key={row.id}>
                      {row.getAllCells().map((cell) => (
                        <td key={cell.id}>
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {table.getFilteredRowModel().rows.length === 0 && (
              <Empty>No queries match this view.</Empty>
            )}
            <div className="table-footer">
              <span>{table.getFilteredRowModel().rows.length} matching events</span>
              <div>
                <button
                  aria-label="Previous page"
                  disabled={!table.getCanPreviousPage()}
                  onClick={() => table.previousPage()}
                >
                  <ChevronLeft size={16} />
                </button>
                <span>
                  Page {table.state.pagination.pageIndex + 1} of {Math.max(1, table.getPageCount())}
                </span>
                <button
                  aria-label="Next page"
                  disabled={!table.getCanNextPage()}
                  onClick={() => table.nextPage()}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
      <Modal
        open={selected !== null}
        onClose={() => {
          if (!busy) {
            setSelected(null);
            setAction(null);
            setActionBase(null);
          }
        }}
        title={selected?.domain ?? "Query"}
        description="Recorded event and an optional evaluation against the currently active policy."
      >
        {selected && (
          <>
            {action ? (
              <Panel
                title="Review temporary client action"
                detail="This publishes a new durable revision immediately. Required permanent assertions remain enforced."
              >
                <p className="body-copy">
                  {action === "allow"
                    ? `Allow ${selected.domain} and its CNAME chain for`
                    : "Pause filtering for"}{" "}
                  {selected.client}. Other clients keep their existing policy. The action expires
                  automatically; client admission and local DNS stay enforced.
                </p>
                <Field label="Temporary action duration">
                  <select
                    disabled={busy}
                    value={duration}
                    onChange={(e) => setDuration(e.target.value)}
                  >
                    <option value="300">5 minutes</option>
                    <option value="900">15 minutes</option>
                    <option value="3600">1 hour</option>
                  </select>
                </Field>
                <div className="button-row">
                  <button disabled={busy} onClick={() => setAction(null)}>
                    Cancel temporary action
                  </button>
                  <button
                    className="primary"
                    disabled={busy || !api.canWrite}
                    onClick={() => void applyAction()}
                  >
                    Apply to this client
                  </button>
                </div>
              </Panel>
            ) : (
              <div className="button-row">
                <button
                  disabled={busy || !api.canWrite || !!selected.client_masked}
                  onClick={() => void reviewAction("allow")}
                >
                  Temporarily allow for this client
                </button>
                <button
                  disabled={busy || !api.canWrite || !!selected.client_masked}
                  onClick={() => void reviewAction("pause")}
                >
                  Pause filtering for this client
                </button>
              </div>
            )}
            <dl className="detail-list">
              <div>
                <dt>Recorded decision</dt>
                <dd>
                  {selected.action.toUpperCase()} · {selected.source}
                </dd>
              </div>
              <div>
                <dt>Client / query</dt>
                <dd className="mono">
                  {selected.client} / {dnsTypeName(selected.qtype)}
                </dd>
              </div>
              <div>
                <dt>Event generation</dt>
                <dd>
                  G{selected.generation} · policy {selected.policy_id}
                </dd>
              </div>
              {selected.matched_domain && (
                <div>
                  <dt>Matched response value</dt>
                  <dd className="mono">
                    {selected.matched_domain}
                    {selected.matched_type ? ` · ${dnsTypeName(selected.matched_type)}` : ""}
                  </dd>
                </div>
              )}
              <div>
                <dt>Response code / latency</dt>
                <dd>
                  {selected.response_code} / {selected.latency_us} µs
                </dd>
              </div>
              <div>
                <dt>Decision cache</dt>
                <dd>{selected.decision_cached ? "Hit" : "Miss"}</dd>
              </div>
              {selected.temporary_exception != null && (
                <div>
                  <dt>Temporary allow</dt>
                  <dd>
                    Exception {selected.temporary_exception + 1} in recorded policy{" "}
                    {selected.policy_id}
                  </dd>
                </div>
              )}
              {selected.shadow && (
                <div>
                  <dt>Shadow G{selected.shadow.generation}</dt>
                  <dd>
                    {selected.shadow.decision.action.toUpperCase()}{" "}
                    {selected.shadow.differs ? "· differs" : "· same"}
                  </dd>
                </div>
              )}
            </dl>
            <div className="button-row">
              <button onClick={() => void explainRecorded()} disabled={busy}>
                Explain recorded decision
              </button>
              <button
                onClick={explain}
                className="primary"
                disabled={busy || !!selected.client_masked}
              >
                {busy ? "Evaluating…" : "Explain with current policy"}
              </button>
            </div>
            <ErrorNotice error={error} />
            {recorded && (
              <section className="explanation">
                <h3>Recorded policy provenance · G{selected.generation}</h3>
                {recorded.revision_available ? (
                  <>
                    <p>
                      Policy: {recorded.policy}. These details come from the event’s original
                      revision.
                    </p>
                    {recorded.service_schedule && (
                      <p>
                        Recorded service schedule: {recorded.service_schedule.state} ·{" "}
                        {recorded.service_schedule.time_zone}. This state was recorded at reply
                        time.
                      </p>
                    )}
                    {recorded.rule?.sources.some((source) =>
                      source.list.startsWith("@service/"),
                    ) && (
                      <p>
                        Recorded service block:{" "}
                        {recorded.rule.sources
                          .filter((source) => source.list.startsWith("@service/"))
                          .map((source) => source.list)
                          .join(", ")}
                      </p>
                    )}
                    {recorded.rule && (
                      <>
                        <p className="mono">
                          {recorded.rule.action.toUpperCase()} · {recorded.rule.matcher} ·{" "}
                          {recorded.rule.domain}
                        </p>
                        {recorded.rule.denyallow && (
                          <p className="source-url">
                            Excluded from this rule: {recorded.rule.denyallow.join(", ")}. Other
                            rules can still apply.
                          </p>
                        )}
                        {recorded.rule.ctag && (
                          <p className="source-url">
                            Rule tag scope: {clientScopeText(recorded.rule.ctag)}
                          </p>
                        )}
                        {recorded.rule.client && (
                          <p className="source-url">
                            Rule client scope: {clientScopeText(recorded.rule.client)}
                          </p>
                        )}
                        {recorded.rule.dnstype && (
                          <p>Rule type scope: {typeScopeText(recorded.rule.dnstype)}</p>
                        )}
                        <details>
                          <summary>Original rule sources (up to 100)</summary>
                          <ul>
                            {recorded.rule.sources.map((source, i) => (
                              <li key={i}>
                                {source.list} · line {source.line}
                              </li>
                            ))}
                          </ul>
                        </details>
                      </>
                    )}
                    {recorded.temporary_exception && (
                      <p>
                        Recorded temporary exception: {recorded.temporary_exception.name} · expiry{" "}
                        {new Date(recorded.temporary_exception.expires_at * 1000).toLocaleString()}
                      </p>
                    )}
                    {recorded.safe_search && (
                      <p>
                        Recorded SafeSearch route: {recorded.safe_search.provider} →{" "}
                        <span className="mono">{recorded.safe_search.target}</span> · catalog v
                        {recorded.safe_search.catalog_version}. The event outcome shows whether the
                        route succeeded.
                      </p>
                    )}
                    {!recorded.rule && !recorded.temporary_exception && !recorded.safe_search && (
                      <p>
                        The event has no filter-rule or temporary-exception reference. Its recorded
                        response path remains shown above.
                      </p>
                    )}
                  </>
                ) : (
                  <p>
                    The event remains retained, but its original configuration revision has expired.
                    Original rule provenance is unavailable.
                  </p>
                )}
              </section>
            )}
            {explanation && (
              <section className="explanation">
                <h3>Current policy explanation · G{explanation.generation}</h3>
                <p>
                  This evaluation uses the current configuration; it may differ from the recorded
                  event.
                </p>
                {!explanation.permitted && (
                  <p role="alert">
                    This client is outside the allowed client networks. DNS drops its queries
                    without an answer; the trace below is hypothetical.
                  </p>
                )}
                <dl className="detail-list">
                  <div>
                    <dt>Decision</dt>
                    <dd>
                      {!explanation.permitted
                        ? "DROPPED (client not admitted)"
                        : explanation.rewrite
                          ? "REWRITE"
                          : explanation.safe_search
                            ? "SAFESEARCH"
                            : explanation.decision.action.toUpperCase()}
                    </dd>
                  </div>
                  <div>
                    <dt>Client admitted</dt>
                    <dd>{explanation.permitted ? "Yes" : "No"}</dd>
                  </div>
                  <div>
                    <dt>Effective policy</dt>
                    <dd>{explanation.policy}</dd>
                  </div>
                  <div>
                    <dt>Identity</dt>
                    <dd>
                      {explanation.client_name ?? "Unidentified"} ·{" "}
                      {explanation.network ?? "Default network"}
                    </dd>
                  </div>
                  <div>
                    <dt>Matcher / rule</dt>
                    <dd>
                      {explanation.rule
                        ? `${explanation.rule.matcher} / ${explanation.rule.domain}`
                        : "No matching filter rule"}
                    </dd>
                  </div>
                  {explanation.rule?.denyallow && (
                    <div>
                      <dt>Excluded from this rule</dt>
                      <dd>
                        {explanation.rule.denyallow.join(", ")}
                        <br />
                        <span className="muted">Other rules can still apply.</span>
                      </dd>
                    </div>
                  )}
                  {(explanation.rule?.ctag || explanation.filter_tags?.length) && (
                    <>
                      <dt>Filtering tags</dt>
                      <dd>{explanation.filter_tags?.join(", ") || "Unassigned"}</dd>
                    </>
                  )}
                  {explanation.rule?.ctag && (
                    <>
                      <dt>Rule tag scope</dt>
                      <dd>{clientScopeText(explanation.rule.ctag)}</dd>
                    </>
                  )}
                  {explanation.rule?.client && (
                    <>
                      <dt>Rule client scope</dt>
                      <dd>{clientScopeText(explanation.rule.client)}</dd>
                    </>
                  )}
                  {explanation.rule?.dnstype && (
                    <div>
                      <dt>Rule type scope</dt>
                      <dd>{typeScopeText(explanation.rule.dnstype)}</dd>
                    </div>
                  )}
                  {explanation.binding_metadata && (
                    <div>
                      <dt>Binding annotations</dt>
                      <dd>
                        {[
                          explanation.binding_metadata.group,
                          explanation.binding_metadata.owner,
                          explanation.binding_metadata.vlan
                            ? `VLAN ${explanation.binding_metadata.vlan}`
                            : undefined,
                          ...(explanation.binding_metadata.tags ?? []),
                          explanation.binding_metadata.note,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      </dd>
                    </div>
                  )}
                  <div>
                    <dt>Upstream profile</dt>
                    <dd>{explanation.upstream}</dd>
                  </div>
                </dl>
                {explanation.temporary_exception && (
                  <p className="source">
                    Temporary allow: {explanation.temporary_exception.name} · expires{" "}
                    {new Date(explanation.temporary_exception.expires_at * 1000).toLocaleString()}
                  </p>
                )}
                {explanation.service_schedule && (
                  <p>
                    Current service schedule: {explanation.service_schedule.state} ·{" "}
                    {explanation.service_schedule.time_zone}. Reply TTL cap:{" "}
                    {explanation.service_schedule.ttl_cap}s.
                  </p>
                )}
                {explanation.rule?.sources.some((source) =>
                  source.list.startsWith("@service/"),
                ) && (
                  <p>
                    Service block:{" "}
                    {explanation.rule.sources
                      .filter((source) => source.list.startsWith("@service/"))
                      .map((source) => source.list)
                      .join(", ")}
                  </p>
                )}
                {explanation.safe_search && (
                  <p>
                    SafeSearch: {explanation.safe_search.provider} →{" "}
                    <span className="mono">{explanation.safe_search.target}</span> · catalog v
                    {explanation.safe_search.catalog_version}
                  </p>
                )}
                {explanation.rule?.sources.map((source, i) => (
                  <p className="mono source" key={i}>
                    Source: {source.list} · line {source.line}
                  </p>
                ))}
              </section>
            )}
          </>
        )}
      </Modal>
    </>
  );
}
