import { useMemo, useState } from "react";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import type { ColumnDef, SortingState } from "@tanstack/react-table";
import { ArrowUpRight, Search, ChevronLeft, ChevronRight } from "lucide-react";
import type { Api, Explanation, HistoryEvent } from "./api";
import { Badge, Empty, ErrorNotice, Loading, Modal, Panel } from "./components";
import { useApi } from "./hooks";
export function Queries({ api }: { api: Api }) {
  const history = useApi<HistoryEvent[]>(
    api,
    "queries",
    "/api/v1/queries?limit=500",
  );
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
              : event.source === outcome),
      ),
    [history.data, outcome],
  );
  const [sorting, setSorting] = useState<SortingState>([]);
  const [selected, setSelected] = useState<HistoryEvent | null>(null);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const columns = useMemo<ColumnDef<HistoryEvent>[]>(
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
                : row.original.action.toUpperCase()}
          </Badge>
        ),
      },
      { accessorKey: "source", header: "Path" },
      {
        accessorKey: "latency_us",
        header: "Latency",
        cell: (c) => <span className="mono">{String(c.getValue())} µs</span>,
      },
      {
        accessorKey: "generation",
        header: "Revision",
        cell: (c) => <span className="mono">G{String(c.getValue())}</span>,
      },
      {
        id: "shadow",
        header: "Shadow",
        cell: ({ row }) =>
          row.original.shadow ? (
            <Badge tone={row.original.shadow.differs ? "amber" : "neutral"}>
              {row.original.shadow.differs ? "DIFFERS" : "SAME"} · G
              {row.original.shadow.generation}
            </Badge>
          ) : (
            <span className="muted">—</span>
          ),
      },
    ],
    [],
  );
  const table = useReactTable({
    data: events,
    columns,
    state: { globalFilter: search, sorting },
    onGlobalFilterChange: setSearch,
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 20 } },
  });
  async function explain() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      setExplanation(
        (
          await api.request<Explanation>(
            `/api/v1/explain?client=${encodeURIComponent(selected.client)}&domain=${encodeURIComponent(selected.domain)}`,
          )
        ).value,
      );
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
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
        <div
          className="outcome-filter"
          role="group"
          aria-label="Filter by outcome"
        >
          {[
            ["all", "All"],
            ["blocked", "Blocked"],
            ["cache", "Cached"],
            ["forwarded", "Forwarded"],
            ["rewrite", "Local"],
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
        </div>
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
                            {flexRender(
                              header.column.columnDef.header,
                              header.getContext(),
                            )}
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
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id}>
                          {flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext(),
                          )}
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
              <span>
                {table.getFilteredRowModel().rows.length} matching events
              </span>
              <div>
                <button
                  aria-label="Previous page"
                  disabled={!table.getCanPreviousPage()}
                  onClick={() => table.previousPage()}
                >
                  <ChevronLeft size={16} />
                </button>
                <span>
                  Page {table.getState().pagination.pageIndex + 1} of{" "}
                  {Math.max(1, table.getPageCount())}
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
        onClose={() => setSelected(null)}
        title={selected?.domain ?? "Query"}
        description="Recorded event and an optional evaluation against the currently active policy."
      >
        {selected && (
          <>
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
                  {selected.client} / type {selected.qtype}
                </dd>
              </div>
              <div>
                <dt>Event generation</dt>
                <dd>
                  G{selected.generation} · policy {selected.policy_id}
                </dd>
              </div>
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
                    Exception {selected.temporary_exception + 1} in recorded
                    policy {selected.policy_id}
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
            <button onClick={explain} className="primary" disabled={busy}>
              {busy ? "Evaluating…" : "Explain with current policy"}
            </button>
            <ErrorNotice error={error} />
            {explanation && (
              <section className="explanation">
                <h3>Current policy explanation · G{explanation.generation}</h3>
                <p>
                  This evaluation uses the current configuration; it may differ
                  from the recorded event.
                </p>
                <dl className="detail-list">
                  <div>
                    <dt>Decision</dt>
                    <dd>
                      {explanation.rewrite
                        ? "REWRITE"
                        : explanation.decision.action.toUpperCase()}
                    </dd>
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
                    Temporary allow: {explanation.temporary_exception.name} ·
                    expires{" "}
                    {new Date(
                      explanation.temporary_exception.expires_at * 1000,
                    ).toLocaleString()}
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
