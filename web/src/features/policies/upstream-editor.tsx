import { Plus, Trash2 } from "lucide-react";
import type { Configuration } from "@/lib/api";
import { Field, Panel, TextList } from "@/components/common";
import type { EditorProps } from "./editor-types";

export function UpstreamsEditor({ draft, edit }: EditorProps) {
  function patch(index: number, value: Partial<Configuration["upstreams"][number]>) {
    edit({
      ...draft,
      upstreams: draft.upstreams.map((item, i) => (i === index ? { ...item, ...value } : item)),
    });
  }
  return (
    <>
      {draft.upstreams.map((profile, u) => (
        <Panel
          key={u}
          title={profile.name || "Unnamed upstream"}
          detail="Servers are tried in order. No default multi-provider query racing."
        >
          <div className="form-grid">
            <Field label={`Upstream ${u + 1} name`}>
              <input
                value={profile.name}
                onChange={(e) =>
                  edit({
                    ...draft,
                    upstreams: draft.upstreams.map((item, i) =>
                      i === u ? { ...item, name: e.target.value } : item,
                    ),
                  })
                }
              />
            </Field>
            <Field label={`Upstream ${u + 1} timeout (ms)`}>
              <input
                type="number"
                min="1"
                value={profile.timeout_ms}
                onChange={(e) =>
                  edit({
                    ...draft,
                    upstreams: draft.upstreams.map((item, i) =>
                      i === u ? { ...item, timeout_ms: Number(e.target.value) } : item,
                    ),
                  })
                }
              />
            </Field>
          </div>
          <Field label={`Upstream ${u + 1} transport`}>
            <select
              value={profile.transport?.kind ?? "udp"}
              onChange={(e) => {
                const previous = profile.transport;
                const common =
                  previous && previous.kind !== "udp"
                    ? {
                        server_name: previous.server_name,
                        ca_pem: previous.ca_pem,
                        max_connections: previous.max_connections,
                      }
                    : { server_name: "", ca_pem: null, max_connections: 2 };
                patch(u, {
                  transport:
                    e.target.value === "https"
                      ? { kind: "https", path: "/dns-query", ...common }
                      : e.target.value === "tls"
                        ? { kind: "tls", ...common }
                        : undefined,
                });
              }}
            >
              <option value="udp">UDP with TCP fallback</option>
              <option value="tls">DNS over TLS</option>
              <option value="https">DNS over HTTPS (HTTP/2)</option>
            </select>
          </Field>
          {(profile.transport?.kind === "tls" || profile.transport?.kind === "https") &&
            (() => {
              const tls = profile.transport;
              return (
                <>
                  <div className="form-grid">
                    <Field
                      label={`Upstream ${u + 1} TLS server name`}
                      hint="Certificate name shared by these addresses. Encrypted profiles never fall back to plaintext."
                    >
                      <input
                        value={tls.server_name}
                        onChange={(e) =>
                          patch(u, {
                            transport: { ...tls, server_name: e.target.value },
                          })
                        }
                      />
                    </Field>
                    <Field label={`Upstream ${u + 1} TLS connections per address`}>
                      <input
                        type="number"
                        min="1"
                        max="8"
                        value={tls.max_connections}
                        onChange={(e) =>
                          patch(u, {
                            transport: {
                              ...tls,
                              max_connections: Number(e.target.value),
                            },
                          })
                        }
                      />
                    </Field>
                  </div>
                  {tls.kind === "https" && (
                    <Field
                      label={`Upstream ${u + 1} HTTPS path`}
                      hint="POST endpoint path, normally /dns-query. Redirects are refused."
                    >
                      <input
                        value={tls.path}
                        onChange={(e) =>
                          patch(u, {
                            transport: { ...tls, path: e.target.value },
                          })
                        }
                      />
                    </Field>
                  )}
                  <Field
                    label={`Upstream ${u + 1} private CA certificates (PEM)`}
                    hint="Leave empty for bundled public roots. Private certificates replace public roots; never paste a private key."
                  >
                    <textarea
                      value={tls.ca_pem ?? ""}
                      onChange={(e) =>
                        patch(u, {
                          transport: { ...tls, ca_pem: e.target.value || null },
                        })
                      }
                      rows={4}
                    />
                  </Field>
                </>
              );
            })()}
          <Field
            label={`Upstream ${u + 1} addresses`}
            hint="One IP:port per line; use [IPv6]:port for IPv6."
          >
            <TextList
              multiline
              values={profile.addresses}
              commit={(addresses) =>
                edit({
                  ...draft,
                  upstreams: draft.upstreams.map((item, i) =>
                    i === u ? { ...item, addresses } : item,
                  ),
                })
              }
            />
          </Field>
          <button
            className="text-button"
            disabled={draft.upstreams.length <= 1}
            onClick={() =>
              edit({
                ...draft,
                upstreams: draft.upstreams.filter((_, i) => i !== u),
              })
            }
          >
            <Trash2 size={14} /> Remove profile
          </button>
        </Panel>
      ))}
      <button
        onClick={() =>
          edit({
            ...draft,
            upstreams: [
              ...draft.upstreams,
              {
                name: `upstream-${draft.upstreams.length + 1}`,
                addresses: [],
                timeout_ms: 1500,
              },
            ],
          })
        }
      >
        <Plus size={16} /> Add upstream profile
      </button>
    </>
  );
}
