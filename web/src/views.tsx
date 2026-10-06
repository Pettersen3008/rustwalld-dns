import { useState } from "react";
import { Traffic } from "./traffic";
import { useApi } from "./hooks";
import {
  ArrowUpRight,
  ShieldCheck,
  Activity,
  Layers,
  Radio,
  Network,
} from "lucide-react";
import { Api, formatTime, countRules, pretty } from "./api";
import type {
  Configuration,
  Filter,
  HistoryEvent,
  Revision,
  Status,
  Upstream,
  UpstreamFailure,
  Versioned,
} from "./api";
import {
  Badge,
  Empty,
  ErrorNotice,
  Field,
  Loading,
  Modal,
  Panel,
} from "./components";
export function Overview({
  api,
  status,
  navigate,
}: {
  api: Api;
  status?: Status;
  navigate: (id: string) => void;
}) {
  const metrics = useApi<string>(api, "metrics", "/metrics");
  const recent = useApi<HistoryEvent[]>(
    api,
    "queries",
    "/api/v1/queries?limit=500",
  );
  const counts = Object.fromEntries(
    (metrics.data ?? "")
      .split("\n")
      .filter((s) => s.startsWith("rustwalld_") && !s.includes("{"))
      .map((s) => s.split(" "))
      .map(([k, v]) => [k, Number(v)]),
  );
  const metric = (name: string) => counts[`rustwalld_${name}_total`] ?? 0;
  const hasMetrics = metrics.data !== undefined;
  const requests = metric("requests");
  const blocked = metric("blocked");
  const shadowEvents = (recent.data ?? []).filter(
    (e) => e.shadow?.generation === status?.shadow_generation,
  );
  const changed = shadowEvents.filter((e) => e.shadow?.differs).length;
  return (
    <>
      <ErrorNotice
        error={metrics.error}
        retry={() => {
          void metrics.refetch();
        }}
      />
      <div className="stat-grid">
        {[
          {
            label: "DNS requests",
            value: hasMetrics ? requests.toLocaleString() : "—",
            note: "Since this process started",
            icon: Activity,
          },
          {
            label: "Blocked queries",
            value: hasMetrics ? blocked.toLocaleString() : "—",
            note: requests
              ? `${((blocked / requests) * 100).toFixed(1)}% of all requests`
              : "Waiting for traffic",
            icon: ShieldCheck,
          },
          {
            label: "Cached responses",
            value: hasMetrics ? metric("dns_cache_hits").toLocaleString() : "—",
            note: `${status?.cache_entries ?? 0} entries in bounded cache`,
            icon: Layers,
          },
          {
            label: "Upstream lookups",
            value: hasMetrics
              ? metric("upstream_lookups").toLocaleString()
              : "—",
            note: `${status?.inflight ?? 0} currently in flight`,
            icon: Radio,
          },
        ].map((item) => (
          <section className="stat" key={item.label}>
            <div>
              <span>{item.label}</span>
              <item.icon size={18} />
            </div>
            <strong>{item.value}</strong>
            <small>{item.note}</small>
          </section>
        ))}
      </div>
      <div className="two-col">
        <Panel
          title="Recent traffic"
          detail="Outcomes across the latest retained query sample."
        >
          <ErrorNotice
            error={recent.error}
            retry={() => {
              void recent.refetch();
            }}
          />
          {recent.isPending ? (
            <Loading />
          ) : (
            <Traffic events={recent.data ?? []} />
          )}
        </Panel>
        <Panel
          title="Active policy"
          detail="The generation currently serving your network."
        >
          <div className="generation-hero">
            <strong className="mono">G{status?.generation ?? "—"}</strong>
            <Badge tone={status ? "green" : "neutral"}>
              {status ? "Enforcing" : "Loading"}
            </Badge>
          </div>
          <div className="runtime-summary">
            <span>{status?.policies ?? "—"} policies</span>
            <span>{status?.cache_entries ?? "—"} cached</span>
            <span>{status?.inflight ?? "—"} in flight</span>
          </div>
          <div className="workflow">
            <span>
              01 <b>Validate</b>
            </span>
            <span>
              02 <b>Shadow</b>
            </span>
            <span>
              03 <b>Promote</b>
            </span>
          </div>
          {status?.shadow_generation ? (
            <>
              <Badge tone="amber">SHADOW G{status.shadow_generation}</Badge>
              <p className="body-copy">
                {changed} different decisions in {shadowEvents.length} recorded
                queries evaluated against this candidate.
              </p>
              <small className="muted">
                Sample: up to 500 recent retained events. Dropped or older
                traffic is excluded.
              </small>
            </>
          ) : (
            <p className="body-copy">
              No candidate is running in shadow. Draft and test a change without
              affecting live answers.
            </p>
          )}
          <button className="text-button" onClick={() => navigate("policies")}>
            Open policy workbench <ArrowUpRight size={17} />
          </button>
          <details className="health-details">
            <summary>Inspect process counters</summary>
            <dl className="detail-list">
              <div>
                <dt>Local rewrites</dt>
                <dd>{hasMetrics ? metric("rewrites") : "—"}</dd>
              </div>
              <div>
                <dt>Coalesced requests</dt>
                <dd>{hasMetrics ? metric("coalesced") : "—"}</dd>
              </div>
              <div>
                <dt>Resolution failures</dt>
                <dd>{hasMetrics ? metric("failures") : "—"}</dd>
              </div>
              <div>
                <dt>Dropped telemetry events</dt>
                <dd>{hasMetrics ? metric("events_dropped") : "—"}</dd>
              </div>
              <div>
                <dt>History write failures</dt>
                <dd>{hasMetrics ? metric("history_write_failures") : "—"}</dd>
              </div>
            </dl>{" "}
          </details>
        </Panel>
      </div>
      <Panel
        title="Recent activity"
        detail="The latest retained events. Query history may lag live counters."
        action={
          <button className="text-button" onClick={() => navigate("queries")}>
            View query log <ArrowUpRight size={17} />
          </button>
        }
      >
        <ErrorNotice
          error={recent.error}
          retry={() => {
            void recent.refetch();
          }}
        />
        {recent.isPending ? (
          <Loading />
        ) : (
          <div className="activity-list">
            {recent.data?.slice(0, 3).map((event) => (
              <div key={event.id}>
                <span
                  className={`activity-dot ${event.action === "block" ? "dot-block" : ""}`}
                />
                <div>
                  <strong className="mono">{event.domain}</strong>
                  <small>
                    {event.client} · {formatTime(event.timestamp)}
                  </small>
                </div>
                <Badge
                  tone={
                    event.source === "failure"
                      ? "red"
                      : event.action === "block"
                        ? "amber"
                        : "green"
                  }
                >
                  {event.source === "failure"
                    ? "FAILED"
                    : event.source === "rewrite"
                      ? "REWRITE"
                      : event.action.toUpperCase()}
                </Badge>
                <span className="mono muted">{event.latency_us} µs</span>
              </div>
            ))}
            {recent.data?.length === 0 && (
              <Empty>
                No recorded queries yet. Send DNS traffic to{" "}
                {status?.dns_listen ?? "your listener"}.
              </Empty>
            )}
          </div>
        )}
      </Panel>
    </>
  );
}
export function Clients({ api }: { api: Api }) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const clients = useApi<{
    generation: number;
    default_policy: string;
    bindings: Configuration["bindings"];
    allowed_clients: string[];
  }>(api, "clients", "/api/v1/clients");
  const matches = (clients.data?.bindings ?? []).filter((binding) =>
    [
      binding.name,
      binding.network,
      binding.policy,
      ...Object.values(binding.metadata ?? {}).flat(),
    ]
      .join(" ")
      .toLocaleLowerCase()
      .includes(search.toLocaleLowerCase()),
  );
  const lastPage = Math.max(0, Math.ceil(matches.length / 20) - 1);
  const currentPage = Math.min(page, lastPage);
  return (
    <>
      <ErrorNotice
        error={clients.error}
        retry={() => {
          void clients.refetch();
        }}
      />
      <Panel
        title="Client admission"
        detail="Only these source networks may use recursive DNS."
      >
        {clients.isPending ? (
          <Loading />
        ) : (
          <div className="network-tiles">
            {clients.data?.allowed_clients.map((network) => (
              <article className="network-tile" key={network}>
                <Network size={20} />
                <strong className="mono">{network}</strong>
                <span>DNS admission allowed</span>
              </article>
            ))}
          </div>
        )}
      </Panel>
      <Panel
        title="Network → effective policy"
        detail="Longest matching prefix wins. A binding does not grant DNS admission."
      >
        <Field
          label="Find client or network"
          hint="Search names, subnets, policies, groups, owners, VLAN labels, tags or notes."
        >
          <input
            type="search"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
        </Field>
        {clients.data && (
          <p className="panel-note">
            Generation {clients.data.generation} · Unbound clients use{" "}
            {clients.data.default_policy}.
          </p>
        )}
        {clients.isPending ? (
          <Loading />
        ) : (
          <div className="table-wrap">
            <table className="client-bindings-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th className="client-network">Subnet or device</th>
                  <th className="client-policy">Policy</th>
                  <th>Context</th>
                </tr>
              </thead>
              <tbody>
                {matches
                  .slice(currentPage * 20, currentPage * 20 + 20)
                  .map((binding) => (
                    <tr key={binding.network}>
                      <td className="client-name">
                        <span>{binding.name}</span>
                        <small className="table-secondary">
                          {binding.network.endsWith("/32") ||
                          binding.network.endsWith("/128")
                            ? "Device"
                            : "Network"}
                        </small>
                        <small className="mobile-client-detail">
                          <span className="mono">{binding.network}</span>
                          <br />
                          {binding.policy}
                        </small>
                      </td>
                      <td className="mono client-network">{binding.network}</td>
                      <td className="client-policy">
                        <Badge>{binding.policy}</Badge>
                      </td>
                      <td className="binding-context">
                        {binding.metadata ? (
                          <>
                            <span>
                              {[
                                binding.metadata.group,
                                binding.metadata.owner,
                                binding.metadata.vlan
                                  ? `VLAN ${binding.metadata.vlan}`
                                  : undefined,
                              ]
                                .filter(Boolean)
                                .join(" · ")}
                            </span>
                            {binding.metadata.tags?.length ? (
                              <div className="binding-tags">
                                {binding.metadata.tags.map((tag) => (
                                  <Badge key={tag}>{tag}</Badge>
                                ))}
                              </div>
                            ) : null}
                            {binding.metadata.note && (
                              <details>
                                <summary>Note</summary>
                                <p>{binding.metadata.note}</p>
                              </details>
                            )}
                          </>
                        ) : (
                          <span className="muted">No annotations</span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
            {matches.length === 0 && (
              <Empty>
                {clients.data?.bindings.length === 0
                  ? "No client bindings. Admitted clients use the default policy."
                  : "No clients or networks match this search."}
              </Empty>
            )}
            <div className="button-row">
              <button
                disabled={currentPage === 0}
                onClick={() => setPage(currentPage - 1)}
              >
                Previous clients
              </button>
              <span className="panel-note">
                {matches.length} matches · Page {currentPage + 1} of{" "}
                {lastPage + 1}
              </span>
              <button
                disabled={currentPage === lastPage}
                onClick={() => setPage(currentPage + 1)}
              >
                Next clients
              </button>
            </div>
          </div>
        )}
        <p className="panel-note">
          Edit networks and annotations in the policy workbench. VLAN labels
          describe source subnets; they do not detect or enforce VLAN
          membership.
        </p>
      </Panel>
    </>
  );
}
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
            <Badge>
              {(filter.payload_bytes_estimate / 1024).toFixed(1)} KiB payload
              estimate
            </Badge>
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
                </tr>
              </thead>
              <tbody>
                {filter.lists.map((list) => (
                  <tr key={list.name}>
                    <td>
                      {list.name}
                      {sources.data?.sources
                        .filter(
                          (source) =>
                            source.policy === filter.policy &&
                            source.list === list.name,
                        )
                        .map((source) => (
                          <details key={source.list}>
                            <summary>Downloaded source</summary>
                            <p className="source-url">{source.url}</p>
                            {source.download && (
                              <>
                                <p className="muted">
                                  Retrieved{" "}
                                  {new Date(
                                    source.download.retrieved_at * 1000,
                                  ).toLocaleString()}
                                </p>
                                <p className="mono source-url">
                                  SHA-256 {source.download.sha256}
                                </p>
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
                    ].map((n, i) => (
                      <td key={i} className="mono">
                        {n.toLocaleString()}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {filter.lists.length === 0 && (
              <Empty>No filter lists assigned to this policy.</Empty>
            )}
          </div>
          <p className="panel-note">
            Payload estimates exclude allocator and container overhead.
            Redundant rules are retained for provenance.
          </p>
        </Panel>
      ))}
    </>
  );
}
const upstreamFailureLabels: Record<UpstreamFailure, string> = {
  deadline: "Deadline exceeded",
  connection: "Connection / I/O",
  tls_authentication: "TLS authentication",
  tls_protocol: "TLS protocol / ALPN",
  http_protocol: "HTTP/2 protocol / reset",
  http_status: "HTTP status",
  http_envelope: "HTTP envelope",
  dns_response: "Rejected DNS reply",
  servfail: "Upstream SERVFAIL",
  refused: "Upstream REFUSED",
  cancelled: "Cancelled",
  local_error: "Local exchange error",
};
export function Upstreams({ api }: { api: Api }) {
  const upstreams = useApi<Upstream[]>(api, "upstreams", "/api/v1/upstreams");
  return (
    <>
      <ErrorNotice
        error={upstreams.error}
        retry={() => {
          void upstreams.refetch();
        }}
      />
      {upstreams.isPending && <Loading />}
      {upstreams.data?.map((profile) => (
        <Panel
          key={profile.name}
          title={profile.name}
          detail="Sequential fallback preserves privacy; queries are not raced across providers."
        >
          <div className="endpoint-grid">
            {profile.servers.map((server, index) => (
              <article className="endpoint" key={server.address}>
                <header>
                  <span className="endpoint-rank">
                    {index === 0 ? "PRIMARY" : `FALLBACK ${index}`}
                  </span>
                  <Badge
                    tone={
                      server.admission.state === "ready" ? "green" : "amber"
                    }
                  >
                    {server.admission.state === "ready"
                      ? "Ready"
                      : server.admission.state === "probing"
                        ? "Probing"
                        : "Cooldown"}
                  </Badge>
                </header>
                <h3 className="mono">{server.address}</h3>
                <div className="endpoint-stats">
                  <div>
                    <span>Attempts</span>
                    <strong>{server.attempts}</strong>
                  </div>
                  <div>
                    <span>Success rate</span>
                    <strong>
                      {server.attempts
                        ? `${((server.successes / server.attempts) * 100).toFixed(1)}%`
                        : "—"}
                    </strong>
                  </div>
                  <div>
                    <span>In flight</span>
                    <strong>{server.inflight}</strong>
                  </div>
                  <div>
                    <span>Success EWMA</span>
                    <strong>
                      {server.successes ? `${server.ewma_us} µs` : "—"}
                    </strong>
                  </div>
                </div>
                <p className="endpoint-admission">
                  {server.admission.state === "ready"
                    ? "Ready for queries"
                    : server.admission.state === "probing"
                      ? "Recovery probe in progress"
                      : `Next probe eligible in ${server.admission.retry_after_ms} ms`}
                </p>
                <div className="endpoint-retries">
                  <span>{server.backoff_skips} skipped</span>
                  <span>{server.recovery_probes} recovery probes</span>
                  <span>{server.successes} successes</span>
                </div>
                <details
                  className="endpoint-details"
                  open={Object.values(server.failures).some(
                    (count) => count > 0,
                  )}
                >
                  <summary>Failure history</summary>
                  {Object.values(server.failures).some((count) => count > 0) ? (
                    <ul aria-label={`Failure reasons for ${server.address}`}>
                      {(Object.keys(upstreamFailureLabels) as UpstreamFailure[])
                        .filter((kind) => server.failures[kind] > 0)
                        .map((kind) => (
                          <li key={kind}>
                            <span>{upstreamFailureLabels[kind]}: </span>
                            <strong>{server.failures[kind]}</strong>
                          </li>
                        ))}
                    </ul>
                  ) : (
                    <p>
                      {server.attempts ? "No failures recorded" : "No samples"}
                    </p>
                  )}
                </details>
              </article>
            ))}
          </div>
          <p className="panel-note">
            {profile.transport === "tls"
              ? `DNS over TLS · ${profile.server_name}.`
              : profile.transport === "https"
                ? `DNS over HTTPS · ${profile.server_name}${profile.path}.`
                : "UDP with TCP fallback."}{" "}
            Generation {profile.generation}. Counters reset on promotion.
            Failures are historical; a resolver may have recovered. Deadlines
            include connection-pool waits. Live counts may change while read.
          </p>
        </Panel>
      ))}
    </>
  );
}
export function Revisions({
  api,
  published,
}: {
  api: Api;
  published: () => Promise<void>;
}) {
  const revisions = useApi<Revision[]>(api, "revisions", "/api/v1/revisions");
  const status = useApi<Status>(api, "status", "/api/v1/status");
  const [selected, setSelected] = useState<Revision | null>(null);
  const [review, setReview] = useState<{
    candidate: Configuration;
    active: Versioned<Configuration>;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function inspect(revision: Revision) {
    setSelected(revision);
    setReview(null);
    setError(null);
    setBusy(true);
    try {
      const [candidate, active] = await Promise.all([
        api.request<{ id: number; config: Configuration }>(
          `/api/v1/revisions/${revision.id}`,
        ),
        api.configuration(),
      ]);
      setReview({ candidate: candidate.value.config, active });
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function rollback() {
    if (!selected || !review) return;
    setBusy(true);
    setError(null);
    try {
      await api.request(`/api/v1/revisions/${selected.id}/rollback`, {
        method: "POST",
        etag: review.active.etag,
      });
      await published();
      setSelected(null);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Panel
        title="Durable revisions"
        detail="Rollback creates a fresh generation. It validates assertions before publication."
      >
        <ErrorNotice
          error={revisions.error}
          retry={() => {
            void revisions.refetch();
          }}
        />
        {revisions.isPending ? (
          <Loading />
        ) : (
          <div className="revision-list">
            {revisions.data?.map((revision) => (
              <div key={revision.id}>
                <div className="revision-number mono">G{revision.id}</div>
                <div>
                  <div className="revision-title">
                    <strong>{revision.actor}</strong>
                    <Badge
                      tone={
                        status.data?.generation === revision.id
                          ? "green"
                          : status.data?.shadow_generation === revision.id
                            ? "amber"
                            : "neutral"
                      }
                    >
                      {status.data?.generation === revision.id
                        ? "ACTIVE"
                        : status.data?.shadow_generation === revision.id
                          ? "SHADOW"
                          : revision.state.toUpperCase()}
                    </Badge>
                  </div>
                  <p>{revision.diff || "No configuration fields changed"}</p>
                  <small>{formatTime(revision.timestamp)}</small>
                </div>
                <button
                  onClick={() => {
                    void inspect(revision);
                  }}
                >
                  Inspect revision
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>
      <Modal
        open={selected !== null}
        onClose={() => {
          if (!busy) setSelected(null);
        }}
        title={`Inspect revision G${selected?.id ?? ""}`}
        description="Review the stored candidate and changed fields before creating a new active generation."
      >
        <ErrorNotice error={error} />
        {busy && !review && <Loading />}
        {review && (
          <>
            <div className="notice">
              Candidate: {review.candidate.policies.length} policies,{" "}
              {countRules(review.candidate)} raw rules,{" "}
              {review.candidate.assertions.length} assertions.
            </div>
            <Field label="Changed configuration fields">
              <div className="chips">
                {(Object.keys(review.candidate) as (keyof Configuration)[])
                  .filter(
                    (key) =>
                      pretty(review.candidate[key]) !==
                      pretty(review.active.value[key]),
                  )
                  .map((key) => (
                    <Badge key={key}>{key}</Badge>
                  ))}
              </div>
            </Field>
            <details>
              <summary>Inspect complete stored configuration</summary>
              <pre>{pretty(review.candidate)}</pre>
            </details>
            <div className="dialog-actions">
              <button onClick={() => setSelected(null)} disabled={busy}>
                Close
              </button>
              <button className="danger" onClick={rollback} disabled={busy}>
                {busy
                  ? "Publishing…"
                  : "Validate and roll back to this revision"}
              </button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
