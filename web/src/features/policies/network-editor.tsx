import { useState } from "react";
import { clientFilteringTags } from "@/lib/dns-types";
import { Plus, Trash2 } from "lucide-react";
import type { BindingMetadata } from "@/lib/api";
import { Field, Panel, TextList } from "@/components/common";
import type { EditorProps } from "./editor-types";

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
        ...(binding.filter_tags ?? []),
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
          value !== undefined && value !== "" && (!Array.isArray(value) || value.length > 0),
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
        <Field label="Allowed client networks" hint="One IPv4 or IPv6 CIDR per line.">
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
        detail="Use /32 or /128 for a device. Longest matching prefix wins. Binding names are exact identities for V5 client rules; renaming one can change filtering."
      >
        <Field
          label="Find draft binding"
          hint="Search names, IP networks, policies, filtering tags or annotations."
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
        {matches.slice(currentPage * 10, currentPage * 10 + 10).map(({ binding, index: b }) => (
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
                            i === b ? { ...item, policy: e.target.value } : item,
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
                            i === b ? { ...item, [key]: e.target.value } : item,
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
            <Field
              label={`Binding ${b + 1} filtering tags`}
              hint="Explicit tags used by V6 ctag rules. Editing these changes DNS decisions; descriptive annotations below stay advisory."
            >
              <TextList
                values={binding.filter_tags ?? []}
                commit={(filter_tags) =>
                  edit({
                    ...draft,
                    bindings: draft.bindings.map((item, i) =>
                      i === b ? { ...item, filter_tags } : item,
                    ),
                  })
                }
              />
            </Field>
            <details className="binding-annotations">
              <summary>Choose filtering tags for {binding.name || `binding ${b + 1}`}</summary>
              <div className="form-grid">
                {clientFilteringTags.map((tag) => (
                  <button
                    type="button"
                    className="button secondary"
                    key={tag}
                    aria-pressed={(binding.filter_tags ?? []).includes(tag)}
                    onClick={() =>
                      edit({
                        ...draft,
                        bindings: draft.bindings.map((item, i) =>
                          i === b
                            ? {
                                ...item,
                                filter_tags: ((item.filter_tags ?? []).includes(tag)
                                  ? (item.filter_tags ?? []).filter((value) => value !== tag)
                                  : [...(item.filter_tags ?? []), tag]
                                ).sort(),
                              }
                            : item,
                        ),
                      })
                    }
                  >
                    {tag}
                    {(binding.filter_tags ?? []).includes(tag) ? " · selected" : ""}
                  </button>
                ))}
              </div>
            </details>
            <details className="binding-annotations">
              <summary>Annotations for {binding.name || `binding ${b + 1}`}</summary>
              <p className="panel-note">
                Descriptive only. VLAN and group labels do not grant access or change policy.
                More-specific bindings use their own annotations.
              </p>
              <div className="form-grid">
                {(["group", "owner"] as const).map((key) => (
                  <Field key={key} label={`Binding ${b + 1} ${key}`}>
                    <input
                      maxLength={128}
                      value={binding.metadata?.[key] ?? ""}
                      onChange={(e) => patchMetadata(b, { [key]: e.target.value })}
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
                        vlan: e.target.value === "" ? undefined : Number(e.target.value),
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
        {matches.length === 0 && <p className="panel-note">No bindings match this search.</p>}
        <div className="button-row">
          <button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>
            Previous bindings
          </button>
          <span className="panel-note">
            {matches.length} bindings · Page {currentPage + 1} of {lastPage + 1}
          </span>
          <button disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)}>
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
