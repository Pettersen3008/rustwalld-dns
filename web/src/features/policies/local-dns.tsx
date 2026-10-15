import { useEffect, useRef, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import type { Configuration, LocalRecord } from "@/lib/api";
import { Field, Panel } from "@/components/common";

type Data = LocalRecord["data"];
const defaults: Record<Data["type"], Data> = {
  PASSTHROUGH: { type: "PASSTHROUGH", family: "A" },
  A: { type: "A", address: "" },
  AAAA: { type: "AAAA", address: "" },
  CNAME: { type: "CNAME", target: "" },
  PTR: { type: "PTR", target: "" },
  TXT: { type: "TXT", text: "" },
  MX: { type: "MX", preference: 10, exchange: "" },
  SRV: { type: "SRV", priority: 0, weight: 0, port: 0, target: "" },
  HTTPS: { type: "HTTPS", priority: 1, target: "." },
  SVCB: { type: "SVCB", priority: 1, target: "." },
};
export function LocalDnsEditor({
  draft,
  edit,
}: {
  draft: Configuration;
  edit: (value: Configuration) => void;
}) {
  const [selection, setSelection] = useState(0);
  const [page, setPage] = useState(0);
  const [addition, setAddition] = useState<{ policy: number; row: number } | null>(null);
  const addedDomain = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (addition) addedDomain.current?.focus();
  }, [addition]);
  const index = Math.min(selection, draft.policies.length - 1);
  const policy = draft.policies[index];
  if (!policy) return null;
  const records = policy.dns_records ?? [];
  const routes = policy.routes ?? [];
  const currentPage = Math.min(page, Math.max(0, Math.ceil(records.length / 25) - 1));
  function patch(value: Partial<typeof policy>) {
    edit({
      ...draft,
      policies: draft.policies.map((p, i) => (i === index ? { ...p, ...value } : p)),
    });
  }
  function record(row: number, value: Partial<LocalRecord>) {
    patch({ dns_records: records.map((r, i) => (i === row ? { ...r, ...value } : r)) });
  }
  return (
    <div className="local-dns-editor">
      <Panel
        title="Local DNS & routes"
        detail={`Policy: ${policy.name}`}
        action={
          <button
            disabled={records.length >= 10000}
            onClick={() => {
              patch({
                dns_records: [
                  ...records,
                  { domain: "", ttl: 60, data: { type: "A", address: "" } },
                ],
              });
              setPage(Math.floor(records.length / 25));
              setAddition({ policy: index, row: records.length });
            }}
          >
            <Plus size={16} /> Add DNS record
          </button>
        }
      >
        <div className="form-grid">
          <Field label="Local DNS policy">
            <select
              value={index}
              onChange={(e) => {
                setSelection(Number(e.target.value));
                setPage(0);
              }}
            >
              {draft.policies.map((p, i) => (
                <option key={i} value={i}>
                  {p.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Blocked reply mode">
            <select
              value={policy.block_mode ?? "nx_domain"}
              onChange={(e) => patch({ block_mode: e.target.value as typeof policy.block_mode })}
            >
              <option value="nx_domain">NXDOMAIN</option>
              <option value="no_data">No data</option>
              <option value="null_ip">Null address (0.0.0.0 / ::)</option>
            </select>
          </Field>
        </div>
        <p className="body-copy">Local records override filtering for their owner.</p>
        <details className="body-copy">
          <summary>Local record behavior and wildcard limits</summary>
          <p>
            Validation rejects CNAME loops, conflicting records and unknown profiles. CNAME targets
            resolve through local records or the selected upstream. Existing address rewrites remain
            editable under Policies & rules. Family passthrough resumes normal filtering and
            upstream resolution for A or AAAA at the exact name. It never allowlists the name; other
            types keep their local answers or NODATA.
          </p>
          <p>
            Use *.home.arpa for A/AAAA/TXT/PTR/MX/SRV/HTTPS/SVCB answers shared by descendants, such
            as nas.home.arpa and apps.nas.home.arpa. The apex home.arpa needs its own record.
            Wildcards support one address per family and up to 32 records per other type.
            Address-only owners fall back by family to the nearest matching wildcard. An owner with
            other record types overrides all types; missing types return NODATA. Edit apex and
            descendant records separately. Wildcard CNAMEs, family passthrough and CNAME targets
            covered by wildcards are rejected during validation.
          </p>
        </details>
        <details className="body-copy">
          <summary>HTTPS/SVCB service records</summary>
          <p>
            Priority 0 aliases this service to another hostname; clients follow that target. Use one
            alias per name and type, without mixing service priorities. At priority 0, target . is
            advisory unavailability and clients may fall back. Priorities 1–65535 describe an
            endpoint, where target . uses the record’s name. ServiceMode supports an optional
            service port, from 0 to 65535. Leave it blank to keep the client’s original service
            port; 0 is an explicit port. Other parameters are unsupported. These records do not
            configure encrypted DNS, listeners or firewall rules.
          </p>
        </details>
        {records.slice(currentPage * 25, currentPage * 25 + 25).map((item, offset) => {
          const row = currentPage * 25 + offset;
          return (
            <div key={row} className="rule-editor">
              <div className="form-grid">
                <Field label={`Record ${row + 1} domain`}>
                  <input
                    ref={
                      addition?.policy === index && row === addition.row ? addedDomain : undefined
                    }
                    value={item.domain}
                    placeholder="nas.home.arpa or *.home.arpa"
                    onChange={(e) => record(row, { domain: e.target.value })}
                  />
                </Field>
                <Field label={`Record ${row + 1} type`}>
                  <select
                    value={item.data.type}
                    onChange={(e) =>
                      record(row, { data: { ...defaults[e.target.value as Data["type"]] } })
                    }
                  >
                    {Object.keys(defaults).map((type) => (
                      <option key={type} value={type}>
                        {type === "PASSTHROUGH" ? "Family passthrough" : type}
                      </option>
                    ))}
                  </select>
                </Field>
                {item.data.type !== "PASSTHROUGH" && (
                  <Field label={`Record ${row + 1} TTL`}>
                    <input
                      type="number"
                      min={0}
                      max={86400}
                      value={item.ttl}
                      onChange={(e) => record(row, { ttl: Number(e.target.value) })}
                    />
                  </Field>
                )}
                {Object.entries(item.data)
                  .filter(
                    (entry): entry is [string, string | number] =>
                      entry[0] !== "type" &&
                      entry[0] !== "params" &&
                      (typeof entry[1] === "string" || typeof entry[1] === "number"),
                  )
                  .map(([key, value]) => (
                    <Field key={key} label={`Record ${row + 1} ${key}`}>
                      {key === "family" ? (
                        <select
                          value={value}
                          onChange={(e) =>
                            record(row, {
                              data: { type: "PASSTHROUGH", family: e.target.value as "A" | "AAAA" },
                            })
                          }
                        >
                          <option value="A">A · IPv4</option>
                          <option value="AAAA">AAAA · IPv6</option>
                        </select>
                      ) : (
                        <input
                          type={typeof value === "number" ? "number" : "text"}
                          min={typeof value === "number" ? 0 : undefined}
                          max={typeof value === "number" ? 65535 : undefined}
                          value={value}
                          onChange={(e) =>
                            record(row, {
                              data: {
                                ...item.data,
                                [key]:
                                  typeof value === "number"
                                    ? Number(e.target.value)
                                    : e.target.value,
                              },
                            })
                          }
                        />
                      )}
                    </Field>
                  ))}
                {(item.data.type === "HTTPS" || item.data.type === "SVCB") && (
                  <Field label={`Record ${row + 1} service port`}>
                    <input
                      type="number"
                      min={0}
                      max={65535}
                      placeholder="Client default"
                      value={item.data.params?.port ?? ""}
                      onChange={(e) => {
                        if (item.data.type !== "HTTPS" && item.data.type !== "SVCB") return;
                        const { params: previousParams, ...data } = item.data;
                        record(row, {
                          data:
                            e.target.value === ""
                              ? data
                              : {
                                  ...data,
                                  params: { ...previousParams, port: Number(e.target.value) },
                                },
                        });
                      }}
                    />
                  </Field>
                )}
              </div>
              <button onClick={() => patch({ dns_records: records.filter((_, i) => i !== row) })}>
                <Trash2 size={14} /> Remove record {row + 1}
              </button>
            </div>
          );
        })}
        <div className="button-row">
          <button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>
            Previous records
          </button>
          <span>
            {records.length} records · page {currentPage + 1} of{" "}
            {Math.max(1, Math.ceil(records.length / 25))}
          </span>
          <button
            disabled={(currentPage + 1) * 25 >= records.length}
            onClick={() => setPage(currentPage + 1)}
          >
            Next records
          </button>
        </div>
      </Panel>
      <Panel
        title="Conditional forwarding"
        detail="The longest matching DNS suffix chooses a profile. A route for home.arpa also covers its subdomains, never another label ending in that text."
      >
        <Field label="DS resolver selection">
          <select
            value={policy.ds_routing ?? "question"}
            onChange={(event) => patch({ ds_routing: event.target.value as "question" | "parent" })}
          >
            <option value="question">Question name (native default)</option>
            <option value="parent">Parent name for DS (AdGuard)</option>
          </select>
        </Field>
        <p className="body-copy">
          DS records describe a child delegation in its parent zone. Parent mode changes only
          resolver selection for type DS; filtering and the forwarded question keep the original
          name. DNSSEC validation still requires a validating resolver such as Unbound.
        </p>
        {routes.map((route, row) => (
          <div className="form-grid rule-editor" key={row}>
            <Field label={`Route ${row + 1} domain`}>
              <input
                value={route.domain}
                onChange={(e) =>
                  patch({
                    routes: routes.map((r, i) =>
                      i === row ? { ...r, domain: e.target.value } : r,
                    ),
                  })
                }
              />
            </Field>
            <Field label={`Route ${row + 1} upstream`}>
              <select
                value={route.upstream}
                onChange={(e) =>
                  patch({
                    routes: routes.map((r, i) =>
                      i === row ? { ...r, upstream: e.target.value } : r,
                    ),
                  })
                }
              >
                {draft.upstreams.map((u) => (
                  <option key={u.name}>{u.name}</option>
                ))}
              </select>
            </Field>
            <button onClick={() => patch({ routes: routes.filter((_, i) => i !== row) })}>
              <Trash2 size={14} /> Remove route {row + 1}
            </button>
          </div>
        ))}
        <button
          disabled={routes.length >= 256 || draft.upstreams.length === 0}
          onClick={() =>
            patch({ routes: [...routes, { domain: "", upstream: draft.upstreams[0]!.name }] })
          }
        >
          <Plus size={16} /> Add domain route
        </button>
      </Panel>
    </div>
  );
}
