import { useState } from "react";
import type { Configuration } from "@/lib/api";
import { Badge, Field, Panel } from "@/components/common";

export function SafeSearchEditor({
  draft,
  edit,
}: {
  draft: Configuration;
  edit: (value: Configuration) => void;
}) {
  const [selection, setSelection] = useState(0);
  const index = Math.min(selection, draft.policies.length - 1);
  const policy = draft.policies[index];
  if (!policy) return null;
  const settings = policy.safe_search ?? {
    catalog_version: 1 as const,
    google: false,
    bing: false,
    duckduckgo: false,
    youtube: "off" as const,
  };
  const enabled =
    settings.google || settings.bing || settings.duckduckgo || settings.youtube !== "off";
  function update(patch: Partial<typeof settings>) {
    const next = { ...settings, ...patch };
    const enabled = next.google || next.bing || next.duckduckgo || next.youtube !== "off";
    edit({
      ...draft,
      policies: draft.policies.map((p, i) =>
        i === index ? { ...p, safe_search: enabled ? next : undefined } : p,
      ),
    });
  }
  return (
    <Panel
      title="SafeSearch & YouTube"
      detail="Choose provider restrictions for the devices bound to this policy. Changes stay in the draft until reviewed promotion."
      action={
        <Badge tone={enabled ? "green" : "neutral"}>{enabled ? "ENABLED IN DRAFT" : "OFF"}</Badge>
      }
    >
      <div className="form-grid">
        <Field label="SafeSearch policy">
          <select value={index} onChange={(e) => setSelection(Number(e.target.value))}>
            {draft.policies.map((p, i) => (
              <option key={i} value={i}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="YouTube restricted mode">
          <select
            value={settings.youtube}
            onChange={(e) => update({ youtube: e.target.value as "off" | "moderate" | "strict" })}
          >
            <option value="off">Off</option>
            <option value="moderate">Moderate</option>
            <option value="strict">Strict</option>
          </select>
        </Field>
      </div>
      <div className="form-grid">
        <Field
          label="Enforce Google SafeSearch"
          hint="Google Search country domains in catalog v1."
        >
          <input
            type="checkbox"
            checked={settings.google}
            onChange={(e) => update({ google: e.target.checked })}
          />
        </Field>
        <Field label="Enforce Bing SafeSearch" hint="Bing Search and the Microsoft Edge sidebar.">
          <input
            type="checkbox"
            checked={settings.bing}
            onChange={(e) => update({ bing: e.target.checked })}
          />
        </Field>
        <Field label="Enforce DuckDuckGo SafeSearch" hint="DuckDuckGo Search, www and start.">
          <input
            type="checkbox"
            checked={settings.duckduckgo}
            onChange={(e) => update({ duckduckgo: e.target.checked })}
          />
        </Field>
      </div>
      <p className="body-copy">
        Blocked names stay blocked. SafeSearch follows provider restrictions after filtering; allow
        rules and temporary filtering pauses keep it enabled. Devices must use this appliance’s DNS.
      </p>
      <details>
        <summary>Coverage and limits</summary>
        <p className="body-copy">
          Catalog v1 covers 194 exact Google www country names, two Bing names, three DuckDuckGo
          names and the five documented YouTube names. YouTube selects Strict or Moderate
          independently. Provider IPs resolve through this policy’s configured resolver.
        </p>
        <p className="body-copy">
          Conflicting local DNS records are rejected during validation. A provider DNS failure does
          not fall back to the unrestricted name. Other resolvers, VPNs and hardcoded addresses can
          bypass DNS policy; this is not a filter for all explicit content. Client DNS caches can
          delay policy changes until existing answers expire.
        </p>
      </details>
    </Panel>
  );
}
