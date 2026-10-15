import { useState } from "react";

import { useApi } from "@/hooks/use-api";
import { Network } from "lucide-react";
import { Api } from "@/lib/api";
import type { Configuration } from "@/lib/api";
import { Badge, Empty, ErrorNotice, Field, Loading, Panel } from "@/components/common";
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
    [binding.name, binding.network, binding.policy, ...Object.values(binding.metadata ?? {}).flat()]
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
      <Panel title="Client admission" detail="Only these source networks may use recursive DNS.">
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
            Generation {clients.data.generation} · Unbound clients use {clients.data.default_policy}
            .
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
                {matches.slice(currentPage * 20, currentPage * 20 + 20).map((binding) => (
                  <tr key={binding.network}>
                    <td className="client-name">
                      <span>{binding.name}</span>
                      <small className="table-secondary">
                        {binding.network.endsWith("/32") || binding.network.endsWith("/128")
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
                              binding.metadata.vlan ? `VLAN ${binding.metadata.vlan}` : undefined,
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
              <button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>
                Previous clients
              </button>
              <span className="panel-note">
                {matches.length} matches · Page {currentPage + 1} of {lastPage + 1}
              </span>
              <button disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)}>
                Next clients
              </button>
            </div>
          </div>
        )}
        <p className="panel-note">
          Edit networks and annotations in the policy workbench. VLAN labels describe source
          subnets; they do not detect or enforce VLAN membership.
        </p>
      </Panel>
    </>
  );
}
