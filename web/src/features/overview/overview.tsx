import { Traffic } from "@/features/overview/traffic";
import { useApi } from "@/hooks/use-api";
import { ArrowUpRight, ShieldCheck, Activity, Layers, Radio } from "lucide-react";
import { Api, formatTime } from "@/lib/api";
import type { HistoryEvent, Status } from "@/lib/api";
import { Badge, Empty, ErrorNotice, Loading, Panel } from "@/components/common";
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
  const recent = useApi<HistoryEvent[]>(api, "queries", "/api/v1/queries?limit=500");
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
            value: hasMetrics ? metric("upstream_lookups").toLocaleString() : "—",
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
        <Panel title="Recent traffic" detail="Outcomes across the latest retained query sample.">
          <ErrorNotice
            error={recent.error}
            retry={() => {
              void recent.refetch();
            }}
          />
          {recent.isPending ? <Loading /> : <Traffic events={recent.data ?? []} />}
        </Panel>
        <Panel title="Active policy" detail="The generation currently serving your network.">
          <div className="generation-hero">
            <strong className="mono">G{status?.generation ?? "—"}</strong>
            <Badge tone={status ? "green" : "neutral"}>{status ? "Enforcing" : "Loading"}</Badge>
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
                {changed} different decisions in {shadowEvents.length} recorded queries evaluated
                against this candidate.
              </p>
              <small className="muted">
                Sample: up to 500 recent retained events. Dropped or older traffic is excluded.
              </small>
            </>
          ) : (
            <p className="body-copy">
              No candidate is running in shadow. Draft and test a change without affecting live
              answers.
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
                <span className={`activity-dot ${event.action === "block" ? "dot-block" : ""}`} />
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
                      : event.source === "safe_search"
                        ? "SAFESEARCH"
                        : event.action.toUpperCase()}
                </Badge>
                <span className="mono muted">{event.latency_us} µs</span>
              </div>
            ))}
            {recent.data?.length === 0 && (
              <Empty>
                No recorded queries yet. Send DNS traffic to {status?.dns_listen ?? "your listener"}
                .
              </Empty>
            )}
          </div>
        )}
      </Panel>
    </>
  );
}
