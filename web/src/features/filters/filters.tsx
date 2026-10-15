import { CancellationReview } from "@/features/filters/cancellations";
import { useApi } from "@/hooks/use-api";

import { Api } from "@/lib/api";
import type { Configuration, Filter } from "@/lib/api";
import { Badge, Empty, ErrorNotice, Loading, Panel } from "@/components/common";
export function Filters({ api }: { api: Api }) {
  const filters = useApi<Filter[]>(api, "filters", "/api/v1/filter-lists");
  const sources = useApi<{
    generation: number;
    sources: NonNullable<Configuration["filter_sources"]>;
  }>(api, "filter-sources", "/api/v1/filter-sources");
  return (
    <>
      <ErrorNotice
        error={sources.error}
        retry={() => {
          void sources.refetch();
        }}
      />
      <ErrorNotice
        error={filters.error}
        retry={() => {
          void filters.refetch();
        }}
      />
      {filters.isPending && <Loading />}
      {filters.data?.map((filter) => (
        <Panel
          key={filter.policy}
          title={filter.policy}
          detail={`${filter.effective_rules.toLocaleString()} effective rules · generation ${filter.generation}`}
          action={
            <Badge>{(filter.payload_bytes_estimate / 1024).toFixed(1)} KiB payload estimate</Badge>
          }
        >
          <div className="quality-strip">
            {[
              { label: "Effective", value: filter.effective_rules },
              {
                label: "Duplicates",
                value: filter.lists.reduce((n, list) => n + list.duplicates, 0),
              },
              {
                label: "Subsumed",
                value: filter.lists.reduce((n, list) => n + list.redundant, 0),
              },
              {
                label: "Disabled",
                value: filter.lists.reduce((n, list) => n + (list.disabled ?? 0), 0),
              },
              {
                label: "Invalid",
                value: filter.lists.reduce((n, list) => n + list.invalid, 0),
              },
            ].map((item) => (
              <div key={item.label}>
                <span>{item.label}</span>
                <strong className="mono">{item.value.toLocaleString()}</strong>
              </div>
            ))}
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>List</th>
                  <th>Raw</th>
                  <th>Unique</th>
                  <th>Duplicates</th>
                  <th>Invalid</th>
                  <th>Redundant</th>
                  <th>Badfilter declarations</th>
                  <th>Disabled lines</th>
                </tr>
              </thead>
              <tbody>
                {filter.lists.map((list) => (
                  <tr key={list.name}>
                    <td>
                      {list.name}
                      {sources.data?.sources
                        .filter(
                          (source) => source.policy === filter.policy && source.list === list.name,
                        )
                        .map((source) => (
                          <details key={source.list}>
                            <summary>Downloaded source</summary>
                            <p className="source-url">{source.url}</p>
                            {source.download && (
                              <>
                                <p className="muted">
                                  Retrieved{" "}
                                  {new Date(source.download.retrieved_at * 1000).toLocaleString()}
                                </p>
                                <p className="mono source-url">SHA-256 {source.download.sha256}</p>
                              </>
                            )}
                          </details>
                        ))}
                    </td>
                    {[
                      list.raw,
                      list.unique,
                      list.duplicates,
                      list.invalid,
                      list.redundant,
                      list.badfilters ?? 0,
                      list.disabled ?? 0,
                    ].map((n, i) => (
                      <td key={i} className="mono">
                        {n.toLocaleString()}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {filter.lists.length === 0 && <Empty>No filter lists assigned to this policy.</Empty>}
          </div>
          <CancellationReview key={filter.generation} api={api} filter={filter} />
          <p className="panel-note">
            Payload estimates exclude allocator and container overhead. Redundant rules are retained
            for provenance.
          </p>
        </Panel>
      ))}
    </>
  );
}
