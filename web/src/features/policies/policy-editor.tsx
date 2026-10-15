import { Plus, Trash2 } from "lucide-react";
import type { Configuration } from "@/lib/api";
import { Field, Panel, TextList } from "@/components/common";
import type { EditorProps } from "./editor-types";

export function PoliciesEditor({ draft, edit }: EditorProps) {
  function patchPolicy(index: number, value: Partial<Configuration["policies"][number]>) {
    edit({
      ...draft,
      policies: draft.policies.map((p, i) => (i === index ? { ...p, ...value } : p)),
    });
  }
  return (
    <>
      <Panel title="Default policy" detail="Applies to admitted clients with no matching binding.">
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
                label={`List ${l + 1} syntax`}
                hint={
                  list.syntax === "adguard_v6"
                    ? "V6 adds ctag=device_phone|~user_admin. Only explicit binding filtering tags apply; descriptive tags do not. V5 client, type and domain scopes remain available."
                    : list.syntax === "adguard_v5"
                      ? "V5 adds $client=IP|CIDR|named client, with ~ exclusions. Names match explicit bindings exactly; discovered labels do not apply. Escape commas, pipes, quotes and $ in names. Combine client with dnstype and denyallow; other modifiers remain unsupported."
                      : list.syntax === "adguard_v4"
                        ? "V4 adds $dnstype=A|AAAA or ~A|~CNAME, optionally combined with $denyallow. CNAME targets use CNAME; address values and HTTPS hints use their response type. Exclusions skip only this rule. Sole $badfilter is supported; other combinations fail validation."
                        : list.syntax === "adguard_v3"
                          ? "V3 adds $denyallow=domain|domain to a mask or regex. Excluded domains and subdomains skip only this rule; other rules can still block them. Sole $badfilter is supported. Type selectors require V4."
                          : list.syntax === "adguard_v2"
                            ? "V2 supports sole $badfilter on a mask or regex, disabling identical pattern text and action across V2/V3/V4 lists. Comments occupy their own line. Other modifiers require a newer syntax."
                            : list.syntax === "adguard"
                              ? "AdGuard bare domains and hosts entries match exactly; ||domain^ includes subdomains. Modifiers require a newer syntax."
                              : "Native bare domains include subdomains. Prefix = for an exact match or @@ for an allow rule. Regexes use /pattern/."
                }
              >
                <select
                  value={list.syntax ?? "native"}
                  onChange={(e) =>
                    patchPolicy(p, {
                      lists: policy.lists.map((item, i) =>
                        i === l
                          ? {
                              ...item,
                              syntax: e.target.value as NonNullable<
                                Configuration["policies"][number]["lists"][number]["syntax"]
                              >,
                            }
                          : item,
                      ),
                    })
                  }
                >
                  <option value="native">Native / Pi-hole translation</option>
                  <option value="adguard">AdGuard legacy rules</option>
                  <option value="adguard_v2">AdGuard V2 · rule cancellation</option>
                  <option value="adguard_v3">AdGuard V3 · per-rule exclusions</option>
                  <option value="adguard_v4">AdGuard V4 · question & response types</option>
                  <option value="adguard_v6">AdGuard V6 · client filtering tags</option>
                  <option value="adguard_v5">AdGuard V5 · per-client rule scope</option>
                </select>
              </Field>
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
                        i === r ? { ...item, ttl: Number(e.target.value) } : item,
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
                rewrites: [...policy.rewrites, { domain: "", addresses: ["127.0.0.1"], ttl: 60 }],
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
