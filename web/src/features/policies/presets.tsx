import { useState } from "react";
import type { Configuration } from "@/lib/api";
import { ErrorNotice, Field, Modal, Panel } from "@/components/common";
const profiles = {
  encrypted: {
    label: "Encrypted DNS",
    name: "cloudflare-dot",
    addresses: ["1.1.1.1:853", "1.0.0.1:853"],
    server_name: "cloudflare-dns.com",
  },
  security: {
    label: "Malware-filtering DNS",
    name: "cloudflare-security-dot",
    addresses: ["1.1.1.2:853", "1.0.0.2:853"],
    server_name: "security.cloudflare-dns.com",
  },
  family: {
    label: "Family DNS",
    name: "cloudflare-family-dot",
    addresses: ["1.1.1.3:853", "1.0.0.3:853"],
    server_name: "family.cloudflare-dns.com",
  },
} as const;
export function ResolverPresets({
  draft,
  edit,
}: {
  draft: Configuration;
  edit: (value: Configuration) => void;
}) {
  const [mode, setMode] = useState<keyof typeof profiles | "unbound">("encrypted");
  const [policy, setPolicy] = useState(draft.default_policy);
  const [address, setAddress] = useState("127.0.0.1:5335");
  const [review, setReview] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const selected = policy || draft.default_policy;
  const provider = mode === "unbound" ? null : profiles[mode];
  const name = provider?.name ?? "local-unbound";
  function apply() {
    setError(null);
    if (!draft.policies.some((p) => p.name === selected)) {
      setError(new Error("Choose an existing policy."));
      return;
    }
    const candidate: Configuration["upstreams"][number] = provider
      ? {
          name,
          addresses: [...provider.addresses],
          timeout_ms: 1500,
          transport: {
            kind: "tls",
            server_name: provider.server_name,
            ca_pem: null,
            max_connections: 2,
          },
        }
      : { name, addresses: [address], timeout_ms: 1500, transport: { kind: "udp" } };
    edit({
      ...draft,
      upstreams: [...draft.upstreams.filter((p) => p.name !== name), candidate],
      policies: draft.policies.map((p) => (p.name === selected ? { ...p, upstream: name } : p)),
    });
    setReview(false);
  }
  return (
    <>
      <Panel
        title="Resolver profiles"
        detail="Choose a starting configuration; validate and publish it through the normal policy workflow."
      >
        <ErrorNotice error={error} />
        <div className="form-grid">
          <Field label="Resolver mode">
            <select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
              {Object.entries(profiles).map(([key, p]) => (
                <option key={key} value={key}>
                  {p.label}
                </option>
              ))}
              <option value="unbound">Local validating Unbound</option>
            </select>
          </Field>
          <Field label="Apply resolver to policy">
            <select value={selected} onChange={(e) => setPolicy(e.target.value)}>
              {draft.policies.map((p) => (
                <option key={p.name}>{p.name}</option>
              ))}
            </select>
          </Field>
          {mode === "unbound" && (
            <Field label="Unbound address and port">
              <input value={address} onChange={(e) => setAddress(e.target.value)} />
            </Field>
          )}
        </div>
        <p className="body-copy">
          {provider
            ? "Cloudflare receives forwarded queries. Malware/family categories are maintained by that provider; local allow rules cannot override a provider’s block. TLS identity and bootstrap addresses are explicit, with no plaintext fallback."
            : "Install and verify Unbound separately before publishing. In containers, use the reachable host/sidecar address; container loopback is isolated. Encryption between this engine and Unbound is disabled in this local profile."}
        </p>
        <p className="muted">
          DNSSEC validation is delegated. A profile does not prove resolver availability. Client
          bypass prevention and content filtering require separate network or application controls.
        </p>
        <button onClick={() => setReview(true)}>Review resolver profile</button>
      </Panel>
      <Modal
        open={review}
        onClose={() => setReview(false)}
        title="Apply resolver profile to draft"
        description={`Policy ${selected} will use ${name}. An existing profile with this name will be replaced for every policy that references it. Live DNS changes only after promotion.`}
      >
        <p className="mono">{provider?.addresses.join(", ") ?? address}</p>
        <div className="dialog-actions">
          <button onClick={() => setReview(false)}>Cancel</button>
          <button className="primary" onClick={apply}>
            Apply profile to draft
          </button>
        </div>
      </Modal>
    </>
  );
}
