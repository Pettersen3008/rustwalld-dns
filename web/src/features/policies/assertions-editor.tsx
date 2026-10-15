import { dnsTypeName } from "@/lib/dns-types";
import { Plus, Trash2 } from "lucide-react";
import { Field, Panel } from "@/components/common";
import type { EditorProps } from "./editor-types";

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
          <Field label={`Assertion ${a + 1} type`}>
            <select
              value={assertion.qtype ?? 1}
              onChange={(e) =>
                edit({
                  ...draft,
                  assertions: draft.assertions.map((item, i) =>
                    i === a ? { ...item, qtype: Number(e.target.value) } : item,
                  ),
                })
              }
            >
              {[...new Set([1, 28, 5, 65, 15, 16, 33, 12, 2, 6, 43, assertion.qtype ?? 1])].map(
                (kind) => (
                  <option key={kind} value={kind}>
                    {dnsTypeName(kind)}
                  </option>
                ),
              )}
            </select>
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
