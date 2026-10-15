import { useApi } from "@/hooks/use-api";

import { Api } from "@/lib/api";
import type { Upstream, UpstreamFailure } from "@/lib/api";
import { Badge, ErrorNotice, Loading, Panel } from "@/components/common";
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
                      server.admission.state === "ready"
                        ? server.attempts
                          ? "green"
                          : "neutral"
                        : "amber"
                    }
                  >
                    {server.admission.state === "ready"
                      ? server.attempts
                        ? "Ready"
                        : "Untested"
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
                    <strong>{server.successes ? `${server.ewma_us} µs` : "—"}</strong>
                  </div>
                </div>
                <p className="endpoint-admission">
                  {server.admission.state === "ready"
                    ? server.attempts
                      ? "Ready for queries"
                      : "Ready for queries · awaiting traffic"
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
                  open={Object.values(server.failures).some((count) => count > 0)}
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
                    <p>{server.attempts ? "No failures recorded" : "No samples"}</p>
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
            Generation {profile.generation}. Counters reset on promotion. Failures are historical; a
            resolver may have recovered. Deadlines include connection-pool waits. Live counts may
            change while read.
          </p>
        </Panel>
      ))}
    </>
  );
}
