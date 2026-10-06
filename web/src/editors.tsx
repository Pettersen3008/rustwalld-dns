import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import type { BindingMetadata, Configuration } from "./api";
import { Field, Panel, TextList } from "./components";
type EditorProps = {
  draft: Configuration;
  edit: (value: Configuration) => void;
};

export function PoliciesEditor({ draft, edit }: EditorProps) {
  function patchPolicy(
    index: number,
    value: Partial<Configuration["policies"][number]>,
  ) {
    edit({
      ...draft,
      policies: draft.policies.map((p, i) =>
        i === index ? { ...p, ...value } : p,
      ),
    });
  }
  return (
    <>
      <Panel
        title="Default policy"
        detail="Applies to admitted clients with no matching binding."
      >
        <Field label="Default policy">
          <select
            value={draft.default_policy}
            onChange={(e) => edit({ ...draft, default_policy: e.target.value })}
          >
            {draft.policies.map((p, i) => (
              <option key={i}>{p.name}</option>
            ))}
          </select>
        </Field>
      </Panel>
      {draft.policies.map((policy, p) => (
        <Panel
          key={p}
          title={policy.name || "Unnamed policy"}
          detail="Allow rules take precedence. Suffix rules cover subdomains; prefix = for an exact rule."
          action={
            <button
              className="icon-button"
              aria-label={`Remove policy ${policy.name}`}
              disabled={draft.policies.length <= 1}
              onClick={() =>
                edit({
                  ...draft,
                  policies: draft.policies.filter((_, i) => i !== p),
                })
              }
            >
              <Trash2 size={16} />
            </button>
          }
        >
          <div className="form-grid">
            <Field label={`Policy ${p + 1} name`}>
              <input
                value={policy.name}
                onChange={(e) => patchPolicy(p, { name: e.target.value })}
              />
            </Field>
            <Field label={`Policy ${p + 1} upstream`}>
              <select
                value={policy.upstream}
                onChange={(e) => patchPolicy(p, { upstream: e.target.value })}
              >
                {draft.upstreams.map((u, i) => (
                  <option key={i}>{u.name}</option>
                ))}
              </select>
            </Field>
          </div>
          {policy.lists.map((list, l) => (
            <div className="rule-editor" key={l}>
              <div className="form-grid">
                <Field label={`List ${l + 1} name`}>
                  <input
                    value={list.name}
                    onChange={(e) =>
                      patchPolicy(p, {
                        lists: policy.lists.map((item, i) =>
                          i === l ? { ...item, name: e.target.value } : item,
                        ),
                      })
                    }
                  />
                </Field>
                <Field label={`List ${l + 1} action`}>
                  <select
                    value={list.action}
                    onChange={(e) =>
                      patchPolicy(p, {
                        lists: policy.lists.map((item, i) =>
                          i === l
                            ? {
                                ...item,
                                action: e.target.value as "allow" | "block",
                              }
                            : item,
                        ),
                      })
                    }
                  >
                    <option value="block">Block</option>
                    <option value="allow">Allow</option>
                  </select>
                </Field>
              </div>
              <Field
                label={`Rules for ${list.name || `list ${l + 1}`}`}
                hint="One domain or supported hosts/Adblock-style rule per line. Compilation rejects invalid data."
              >
                <textarea
                  className="mono"
                  rows={5}
                  value={list.rules}
                  spellCheck={false}
                  onChange={(e) =>
                    patchPolicy(p, {
                      lists: policy.lists.map((item, i) =>
                        i === l ? { ...item, rules: e.target.value } : item,
                      ),
                    })
                  }
                />
              </Field>
              <button
                className="text-button"
                onClick={() =>
                  patchPolicy(p, {
                    lists: policy.lists.filter((_, i) => i !== l),
                  })
                }
              >
                <Trash2 size={14} /> Remove list
              </button>
            </div>
          ))}
          <button
            onClick={() =>
              patchPolicy(p, {
                lists: [
                  ...policy.lists,
                  {
                    name: `list-${policy.lists.length + 1}`,
                    action: "block",
                    rules: "",
                  },
                ],
              })
            }
          >
            <Plus size={16} /> Add filter list
          </button>
          <h3 className="subheading">Local rewrites</h3>
          {policy.rewrites.map((rewrite, r) => (
            <div className="rewrite-row" key={r}>
              <Field label={`Rewrite ${r + 1} domain`}>
                <input
                  value={rewrite.domain}
                  onChange={(e) =>
                    patchPolicy(p, {
                      rewrites: policy.rewrites.map((item, i) =>
                        i === r ? { ...item, domain: e.target.value } : item,
                      ),
                    })
                  }
                />
              </Field>
              <Field label={`Rewrite ${r + 1} addresses`}>
                <TextList
                  values={rewrite.addresses}
                  commit={(addresses) =>
                    patchPolicy(p, {
                      rewrites: policy.rewrites.map((item, i) =>
                        i === r ? { ...item, addresses } : item,
                      ),
                    })
                  }
                />
              </Field>
              <Field label={`Rewrite ${r + 1} TTL`}>
                <input
                  type="number"
                  min="0"
                  max="4294967295"
                  value={rewrite.ttl}
                  onChange={(e) =>
                    patchPolicy(p, {
                      rewrites: policy.rewrites.map((item, i) =>
                        i === r
                          ? { ...item, ttl: Number(e.target.value) }
                          : item,
                      ),
                    })
                  }
                />
              </Field>
              <button
                aria-label={`Remove rewrite ${r + 1}`}
                className="icon-button"
                onClick={() =>
                  patchPolicy(p, {
                    rewrites: policy.rewrites.filter((_, i) => i !== r),
                  })
                }
              >
                <Trash2 size={16} />
              </button>
            </div>
          ))}
          <button
            onClick={() =>
              patchPolicy(p, {
                rewrites: [
                  ...policy.rewrites,
                  { domain: "", addresses: ["127.0.0.1"], ttl: 60 },
                ],
              })
            }
          >
            <Plus size={16} /> Add rewrite
          </button>
        </Panel>
      ))}
      <button
        onClick={() =>
          edit({
            ...draft,
            policies: [
              ...draft.policies,
              {
                name: `policy-${draft.policies.length + 1}`,
                upstream: draft.upstreams[0]?.name ?? "",
                lists: [],
                rewrites: [],
              },
            ],
          })
        }
      >
        <Plus size={16} /> Add policy
      </button>
    </>
  );
}

export function NetworksEditor({ draft, edit }: EditorProps) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const matches = draft.bindings
    .map((binding, index) => ({ binding, index }))
    .filter(({ binding }) =>
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
  const lastPage = Math.max(0, Math.ceil(matches.length / 10) - 1);
  const currentPage = Math.min(page, lastPage);
  function patchMetadata(index: number, value: Partial<BindingMetadata>) {
    const binding = draft.bindings[index];
    if (!binding) return;
    const metadata = Object.fromEntries(
      Object.entries({ ...binding.metadata, ...value }).filter(
        ([, value]) =>
          value !== undefined &&
          value !== "" &&
          (!Array.isArray(value) || value.length > 0),
      ),
    ) as BindingMetadata;
    edit({
      ...draft,
      bindings: draft.bindings.map((item, i) =>
        i === index
          ? {
              ...item,
              metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
            }
          : item,
      ),
    });
  }
  return (
    <>
      <Panel
        title="DNS admission"
        detail="A binding alone does not grant access. Use explicit, narrow client CIDRs."
      >
        <Field
          label="Allowed client networks"
          hint="One IPv4 or IPv6 CIDR per line."
        >
          <TextList
            multiline
            rows={4}
            values={draft.allowed_clients}
            commit={(allowed_clients) => edit({ ...draft, allowed_clients })}
          />
        </Field>
      </Panel>
      <Panel
        title="Client and subnet bindings"
        detail="Use /32 or /128 for a device. Longest matching prefix wins."
      >
        <Field
          label="Find draft binding"
          hint="Search names, IP networks, policies or annotations."
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
        {matches
          .slice(currentPage * 10, currentPage * 10 + 10)
          .map(({ binding, index: b }) => (
            <article className="binding-editor" key={b}>
              <div className="binding-row">
                {(["name", "network", "policy"] as const).map((key) => (
                  <Field key={key} label={`Binding ${b + 1} ${key}`}>
                    {key === "policy" ? (
                      <select
                        value={binding.policy}
                        onChange={(e) =>
                          edit({
                            ...draft,
                            bindings: draft.bindings.map((item, i) =>
                              i === b
                                ? { ...item, policy: e.target.value }
                                : item,
                            ),
                          })
                        }
                      >
                        {draft.policies.map((p, i) => (
                          <option key={i}>{p.name}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        value={binding[key]}
                        onChange={(e) =>
                          edit({
                            ...draft,
                            bindings: draft.bindings.map((item, i) =>
                              i === b
                                ? { ...item, [key]: e.target.value }
                                : item,
                            ),
                          })
                        }
                      />
                    )}
                  </Field>
                ))}
                <button
                  className="icon-button"
                  aria-label={`Remove binding ${b + 1}`}
                  onClick={() =>
                    edit({
                      ...draft,
                      bindings: draft.bindings.filter((_, i) => i !== b),
                    })
                  }
                >
                  <Trash2 size={16} />
                </button>
              </div>
              <details className="binding-annotations">
                <summary>
                  Annotations for {binding.name || `binding ${b + 1}`}
                </summary>
                <p className="panel-note">
                  Descriptive only. VLAN and group labels do not grant access or
                  change policy. More-specific bindings use their own
                  annotations.
                </p>
                <div className="form-grid">
                  {(["group", "owner"] as const).map((key) => (
                    <Field key={key} label={`Binding ${b + 1} ${key}`}>
                      <input
                        maxLength={128}
                        value={binding.metadata?.[key] ?? ""}
                        onChange={(e) =>
                          patchMetadata(b, { [key]: e.target.value })
                        }
                      />
                    </Field>
                  ))}
                  <Field
                    label={`Binding ${b + 1} VLAN label`}
                    hint="Optional: 1–4094. Identity comes from the source subnet."
                  >
                    <input
                      type="number"
                      min={1}
                      max={4094}
                      step={1}
                      value={binding.metadata?.vlan ?? ""}
                      onChange={(e) =>
                        patchMetadata(b, {
                          vlan:
                            e.target.value === ""
                              ? undefined
                              : Number(e.target.value),
                        })
                      }
                    />
                  </Field>
                  <Field
                    label={`Binding ${b + 1} tags`}
                    hint="Up to 16 unique tags: lowercase ASCII letters, digits, hyphens or underscores."
                  >
                    <TextList
                      values={binding.metadata?.tags ?? []}
                      commit={(tags) => patchMetadata(b, { tags })}
                    />
                  </Field>
                </div>
                <Field
                  label={`Binding ${b + 1} note`}
                  hint="Optional single-line note, up to 1024 UTF-8 bytes."
                >
                  <input
                    maxLength={1024}
                    value={binding.metadata?.note ?? ""}
                    onChange={(e) => patchMetadata(b, { note: e.target.value })}
                  />
                </Field>
              </details>
            </article>
          ))}
        {matches.length === 0 && (
          <p className="panel-note">No bindings match this search.</p>
        )}
        <div className="button-row">
          <button
            disabled={currentPage === 0}
            onClick={() => setPage(currentPage - 1)}
          >
            Previous bindings
          </button>
          <span className="panel-note">
            {matches.length} bindings · Page {currentPage + 1} of {lastPage + 1}
          </span>
          <button
            disabled={currentPage === lastPage}
            onClick={() => setPage(currentPage + 1)}
          >
            Next bindings
          </button>
        </div>
        <button
          disabled={draft.bindings.length >= 65536}
          onClick={() => {
            setSearch("");
            setPage(Math.floor(draft.bindings.length / 10));
            edit({
              ...draft,
              bindings: [
                ...draft.bindings,
                {
                  name: "",
                  network: "127.0.0.1/32",
                  policy: draft.default_policy,
                },
              ],
            });
          }}
        >
          <Plus size={16} /> Add binding
        </button>
      </Panel>
    </>
  );
}

export function UpstreamsEditor({ draft, edit }: EditorProps) {
  function patch(
    index: number,
    value: Partial<Configuration["upstreams"][number]>,
  ) {
    edit({
      ...draft,
      upstreams: draft.upstreams.map((item, i) =>
        i === index ? { ...item, ...value } : item,
      ),
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
                      i === u
                        ? { ...item, timeout_ms: Number(e.target.value) }
                        : item,
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
          {(profile.transport?.kind === "tls" ||
            profile.transport?.kind === "https") &&
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
                    <Field
                      label={`Upstream ${u + 1} TLS connections per address`}
                    >
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

export function AssertionsEditor({ draft, edit }: EditorProps) {
  return (
    <Panel
      title="Required policy assertions"
      detail="Every assertion must pass before a candidate can be staged, promoted or rolled back."
    >
      {draft.assertions.map((assertion, a) => (
        <div className="assertion-row" key={a}>
          <Field label={`Assertion ${a + 1} client`}>
            <input
              value={assertion.client}
              onChange={(e) =>
                edit({
                  ...draft,
                  assertions: draft.assertions.map((item, i) =>
                    i === a ? { ...item, client: e.target.value } : item,
                  ),
                })
              }
            />
          </Field>
          <Field label={`Assertion ${a + 1} domain`}>
            <input
              value={assertion.domain}
              onChange={(e) =>
                edit({
                  ...draft,
                  assertions: draft.assertions.map((item, i) =>
                    i === a ? { ...item, domain: e.target.value } : item,
                  ),
                })
              }
            />
          </Field>
          <Field label={`Assertion ${a + 1} expected`}>
            <select
              value={assertion.expected}
              onChange={(e) =>
                edit({
                  ...draft,
                  assertions: draft.assertions.map((item, i) =>
                    i === a
                      ? {
                          ...item,
                          expected: e.target.value as "allow" | "block",
                        }
                      : item,
                  ),
                })
              }
            >
              <option value="allow">Allow</option>
              <option value="block">Block</option>
            </select>
          </Field>
          <button
            className="icon-button"
            aria-label={`Remove assertion ${a + 1}`}
            onClick={() =>
              edit({
                ...draft,
                assertions: draft.assertions.filter((_, i) => i !== a),
              })
            }
          >
            <Trash2 size={16} />
          </button>
        </div>
      ))}
      <button
        onClick={() =>
          edit({
            ...draft,
            assertions: [
              ...draft.assertions,
              { client: "127.0.0.1", domain: "", expected: "allow" },
            ],
          })
        }
      >
        <Plus size={16} /> Add assertion
      </button>
    </Panel>
  );
}
