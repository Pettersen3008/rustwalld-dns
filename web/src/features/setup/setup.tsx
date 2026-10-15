import { useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import type { Api } from "@/lib/api";
import { Badge, ErrorNotice, Loading, Panel } from "@/components/common";
export type IntegrationView = {
  name: string;
  kind: "dnsmasq" | "unifi" | "opnsense" | "peer";
  inventory: {
    devices: {
      address: string;
      name: string | null;
      mac: string | null;
      expires_at: number | null;
    }[];
    refreshed_at: number | null;
    error: string | null;
  };
};
type SetupInfo = {
  process: {
    dns: string | null;
    administration: string | null;
    https: boolean;
    dot: string | null;
    doh: string | null;
    password_login: boolean;
    limits: Record<string, number>;
  };
  generation: number;
  admitted_networks: string[];
  policies: number;
  filters: number;
  local_records: number;
  assertions: number;
  totp: boolean;
};
export function Setup({ api }: { api: Api }) {
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: ({ signal }) =>
      api.request<SetupInfo>("/api/v1/setup", { signal }).then((r) => r.value),
    refetchInterval: 10000,
  });
  const value = setup.data;
  return (
    <>
      <ErrorNotice
        error={setup.error}
        retry={() => {
          void setup.refetch();
        }}
      />
      {setup.isPending && <Loading />}
      {value && (
        <div className="setup-layout">
          <Panel
            title="Appliance setup"
            detail={`Serving generation ${value.generation}. Process settings take effect after a controlled restart.`}
          >
            <ol className="setup-steps">
              <li>
                <strong>Bring your policy</strong>
                <p>
                  {value.policies} policies · {value.filters} filter lists · {value.local_records}{" "}
                  local records.
                </p>
                <Link to="/policies?section=migration">Open migration and policy workbench</Link>
              </li>
              <li>
                <strong>Choose a resolver</strong>
                <p>Choose encrypted forwarding or a separate validating Unbound resolver.</p>
                <Link to="/policies?section=upstreams">Configure resolver profiles</Link> ·{" "}
                <Link to="/upstreams">Inspect health</Link>
              </li>
              <li>
                <strong>Admit your network</strong>
                <p>
                  Allowed sources:{" "}
                  <span className="mono">{value.admitted_networks.join(", ")}</span>.
                </p>
                <Link to="/clients">Review clients and admission</Link>
              </li>
              <li>
                <strong>Secure administration</strong>
                <p>
                  {value.process.https
                    ? "HTTPS administration is bound."
                    : "Administration uses plaintext on loopback."}{" "}
                  {value.process.password_login
                    ? `Local password login${value.totp ? " and 2FA" : " without 2FA"} configured.`
                    : "Emergency bearer token authentication configured."}
                </p>
                <Link to="/security">Review access and history privacy</Link>
              </li>
              <li>
                <strong>Test before switching clients</strong>
                <p>
                  {value.assertions} required checks. Validate the draft, observe it in shadow and
                  test one device before switching router DHCP.
                </p>
                <Link to="/policies?section=assertions">Review required checks</Link> ·{" "}
                <Link to="/queries">Inspect live queries</Link>
              </li>
            </ol>
          </Panel>
          <Panel
            title="Bound listeners"
            detail="Loaded process settings. Changes require a controlled restart."
          >
            <dl className="assertion-trace">
              <dt>UDP / TCP DNS</dt>
              <dd className="mono">{value.process.dns ?? "Unavailable"}</dd>
              <dt>Administration</dt>
              <dd className="mono">{value.process.administration ?? "Unavailable"}</dd>
              <dt>DNS over TLS</dt>
              <dd className="mono">{value.process.dot ?? "Disabled"}</dd>
              <dt>DNS over HTTPS</dt>
              <dd className="mono">
                {value.process.doh ? `${value.process.doh}/dns-query` : "Disabled"}
              </dd>
            </dl>
            <p className="panel-note">
              Router DNS must point to this host on port 53. External reachability depends on port
              mapping and firewall settings.
            </p>
            <p className="panel-note">
              DNSSEC validation is delegated to the upstream. Encryption secures the transport; it
              does not establish DNSSEC validation. Resolver health needs successful traffic.
            </p>
            <details>
              <summary>Resource limits</summary>
              <dl className="assertion-trace">
                {Object.entries(value.process.limits).map(([name, limit]) => (
                  <div key={name}>
                    <dt>{name.replaceAll("_", " ")}</dt>
                    <dd>{limit.toLocaleString()}</dd>
                  </div>
                ))}
              </dl>
            </details>
          </Panel>
        </div>
      )}
      <Integrations api={api} />
    </>
  );
}
function Integrations({ api }: { api: Api }) {
  const integrations = useQuery({
    queryKey: ["integrations"],
    queryFn: ({ signal }) =>
      api.request<IntegrationView[]>("/api/v1/integrations", { signal }).then((r) => r.value),
    refetchInterval: 10000,
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const devices = (integrations.data ?? [])
    .flatMap((source) =>
      source.inventory.devices.map((device) => ({ ...device, source: source.name })),
    )
    .filter((device) =>
      [device.address, device.name, device.mac, device.source]
        .join(" ")
        .toLowerCase()
        .includes(search.toLowerCase()),
    );
  const last = Math.max(0, Math.ceil(devices.length / 25) - 1);
  const current = Math.min(page, last);
  async function refresh(name: string) {
    setBusy(name);
    setError(null);
    try {
      await api.request(`/api/v1/integrations/${encodeURIComponent(name)}/refresh`, {
        method: "POST",
      });
      await integrations.refetch();
    } catch (error) {
      setError(error);
    } finally {
      setBusy(null);
    }
  }
  return (
    <Panel
      title="Homelab integrations"
      detail="Inventory is advisory. Discovered devices never grant DNS admission or change policy."
    >
      <ErrorNotice error={error ?? integrations.error} />
      {!integrations.data?.length && (
        <p className="body-copy">
          Configure optional dnsmasq lease files, UniFi or OPNsense inventory in the appliance
          configuration. Peer policy copying is available in the migration workbench. Keep router
          DHCP when it already serves your network.
        </p>
      )}
      {integrations.data?.map((source) => (
        <article className="endpoint" key={source.name}>
          <header>
            <strong>{source.name}</strong>
            <Badge>{source.kind}</Badge>
          </header>
          {source.kind === "peer" ? (
            <p>
              Reviewed policy source. <Link to="/policies?section=migration">Open migration</Link>
            </p>
          ) : (
            <>
              <p>
                {source.inventory.refreshed_at
                  ? `Last success: ${new Date(source.inventory.refreshed_at * 1000).toLocaleString()}`
                  : "No snapshot yet"}{" "}
                · {source.inventory.devices.length} devices
              </p>
              {source.inventory.error && (
                <output className="notice notice-warning">
                  {source.inventory.error}. Last successful snapshot retained.
                </output>
              )}
              <button
                disabled={busy !== null || !api.canWrite}
                onClick={() => {
                  void refresh(source.name);
                }}
              >
                {busy === source.name ? "Refreshing…" : `Refresh ${source.name}`}
              </button>
            </>
          )}
        </article>
      ))}
      {!!devices.length && (
        <>
          <label className="field">
            <span>Search discovered devices</span>
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
            />
          </label>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Name</th>
                  <th>MAC</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {devices.slice(current * 25, (current + 1) * 25).map((device, index) => (
                  <tr key={`${device.source}-${device.address}-${index}`}>
                    <td className="mono">{device.address}</td>
                    <td>{device.name ?? "—"}</td>
                    <td className="mono">{device.mac ?? "—"}</td>
                    <td>{device.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button disabled={current === 0} onClick={() => setPage(current - 1)}>
              Previous devices
            </button>
            <span>
              Page {current + 1} of {last + 1}
            </span>
            <button disabled={current === last} onClick={() => setPage(current + 1)}>
              Next devices
            </button>
          </div>
        </>
      )}
    </Panel>
  );
}
