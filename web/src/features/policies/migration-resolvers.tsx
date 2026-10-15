import { useState } from "react";
import type { Configuration } from "@/lib/api";

export function MigrationResolvers({ config }: { config: Configuration }) {
  const [page, setPage] = useState(0);
  const profiles = new Map(config.upstreams.map((profile) => [profile.name, profile]));
  function resolver(name: string) {
    const profile = profiles.get(name);
    return (
      <>
        <strong>{name}</strong>
        {profile && (
          <p>
            {(profile.transport?.kind ?? "udp").toUpperCase()} · {profile.addresses.join(", ")}
          </p>
        )}
      </>
    );
  }
  return (
    <details>
      <summary>Resolver assignments · {config.policies.length} policies</summary>
      <p className="body-copy">
        Review client scope, default resolvers and conditional routes. Client bindings do not grant
        network admission; admitted networks remain listed in the translated configuration.
      </p>
      <div className="table-wrap">
        <table className="migration-resolvers" aria-label="Imported resolver assignments">
          <thead>
            <tr>
              <th scope="col">Policy and client scope</th>
              <th scope="col">Default resolver</th>
              <th scope="col">Conditional routes</th>
            </tr>
          </thead>
          <tbody>
            {config.policies.slice(page * 25, page * 25 + 25).map((policy) => {
              const bindings = config.bindings.filter((binding) => binding.policy === policy.name);
              return (
                <tr key={policy.name}>
                  <td>
                    <strong>{policy.name}</strong>
                    {policy.name === config.default_policy && <p>Default for admitted clients</p>}
                    {bindings.slice(0, 4).map((binding) => (
                      <p key={binding.network}>
                        {binding.name} · {binding.network}
                      </p>
                    ))}
                    {bindings.length > 4 && <p>+{bindings.length - 4} more bindings</p>}
                    {!bindings.length && policy.name !== config.default_policy && (
                      <p>No source-IP binding</p>
                    )}
                  </td>
                  <td>{resolver(policy.upstream)}</td>
                  <td>
                    <p>DS: {policy.ds_routing === "parent" ? "parent name" : "question name"}</p>
                    {!policy.routes?.length ? (
                      "No conditional routes"
                    ) : (
                      <details>
                        <summary>{policy.routes.length} suffix routes</summary>
                        {policy.routes.slice(0, 8).map((route) => (
                          <p key={route.domain}>
                            {route.domain} → {route.upstream}
                          </p>
                        ))}
                        {policy.routes.length > 8 && (
                          <p>
                            +{policy.routes.length - 8} more; inspect the full configuration below.
                          </p>
                        )}
                      </details>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {config.policies.length > 25 && (
        <div className="button-row">
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>
            Previous resolver assignments
          </button>
          <span>
            Page {page + 1} of {Math.ceil(config.policies.length / 25)}
          </span>
          <button
            disabled={(page + 1) * 25 >= config.policies.length}
            onClick={() => setPage(page + 1)}
          >
            Next resolver assignments
          </button>
        </div>
      )}
    </details>
  );
}
