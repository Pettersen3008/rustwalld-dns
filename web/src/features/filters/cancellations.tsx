import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Api, Filter } from "@/lib/api";
import { Badge, ErrorNotice, Loading } from "@/components/common";

function Sources({ sources, total }: { sources: { list: string; line: number }[]; total: number }) {
  return (
    <>
      {sources.map((source, i) => (
        <div key={i}>
          {source.list} · line {source.line}
        </div>
      ))}
      {total > sources.length && (
        <span className="muted">
          +{(total - sources.length).toLocaleString()} more in saved revision
        </span>
      )}
    </>
  );
}
export function CancellationReview({ api, filter }: { api: Api; filter: Filter }) {
  const [page, setPage] = useState(0);
  const [open, setOpen] = useState(false);
  const total = filter.cancellation_targets ?? 0;
  const initial = filter.cancellations ?? [];
  const missing = initial.length < Math.min(total, 200);
  const details = useQuery({
    queryKey: ["filter-cancellations", filter.policy, filter.generation],
    queryFn: ({ signal }) =>
      api
        .request<Filter[]>(`/api/v1/filter-lists?policy=${encodeURIComponent(filter.policy)}`, {
          signal,
        })
        .then((response) => response.value[0]),
    enabled: open && missing,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const changed = details.data && details.data.generation !== filter.generation;
  const reports = !changed && details.data ? (details.data.cancellations ?? []) : initial;
  if (total === 0) return null;
  const pages = Math.max(1, Math.ceil(reports.length / 20));
  const current = Math.min(page, pages - 1);
  return (
    <details
      className="cancellation-review"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>Rule cancellation · {total.toLocaleString()} targets</summary>
      <p className="panel-note">
        Identical V2 pattern text and action are disabled across lists in this policy. Other text
        variants and Native/legacy lists remain effective. An unmatched target changes no rules.
        Removing an allow exception can expose a block.
      </p>
      <ErrorNotice
        error={details.error}
        retry={() => {
          void details.refetch();
        }}
      />
      {open && missing && details.isPending && <Loading />}
      {changed && (
        <p className="notice notice-warning">
          Policy changed during review. Refresh live data to inspect the current generation.
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Target pattern</th>
              <th>Action</th>
              <th>Declarations</th>
              <th>Disabled lines</th>
            </tr>
          </thead>
          <tbody>
            {reports.slice(current * 20, (current + 1) * 20).map((report, i) => (
              <tr key={i}>
                <td className="mono source-url">{report.pattern}</td>
                <td>
                  <Badge>{report.action}</Badge>
                </td>
                <td>
                  <strong className="mono">{report.directives.toLocaleString()}</strong>
                  <Sources sources={report.directive_sources} total={report.directives} />
                </td>
                <td>
                  <strong className="mono">{report.disabled.toLocaleString()}</strong>
                  <Sources sources={report.disabled_sources} total={report.disabled} />
                  {report.disabled === 0 && <span className="muted">No matching rule</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {total > reports.length && (
        <p className="panel-note">
          Showing the first {reports.length} of {total.toLocaleString()} targets. Per-list counts
          include every target; complete source text is retained in the saved revision.
        </p>
      )}
      {pages > 1 && (
        <div className="button-row">
          <button disabled={current === 0} onClick={() => setPage(current - 1)}>
            Previous targets
          </button>
          <span>
            Page {current + 1} of {pages}
          </span>
          <button disabled={current + 1 === pages} onClick={() => setPage(current + 1)}>
            Next targets
          </button>
        </div>
      )}
    </details>
  );
}
