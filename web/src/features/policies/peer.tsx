import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { configSchema } from "@/lib/api";
import type { Api, Configuration, Versioned } from "@/lib/api";
import type { IntegrationView } from "@/features/setup/setup";
import { ErrorNotice, Field, Modal, Panel } from "@/components/common";
export function PeerEditor({
  api,
  base,
  edit,
}: {
  api: Api;
  base: Versioned<Configuration>;
  edit: (value: Configuration) => void;
}) {
  const peers = useQuery({
    queryKey: ["integrations"],
    queryFn: ({ signal }) =>
      api.request<IntegrationView[]>("/api/v1/integrations", { signal }).then((r) => r.value),
  });
  const [name, setName] = useState("");
  const [candidate, setCandidate] = useState<Versioned<Configuration> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function preview() {
    setBusy(true);
    setCandidate(null);
    setError(null);
    try {
      const result = await api.request<{ config: unknown }>(
        `/api/v1/integrations/${encodeURIComponent(name)}/preview`,
        { method: "POST", etag: base.etag },
      );
      setCandidate({ value: configSchema.parse(result.value.config), etag: result.etag });
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  const choices = peers.data?.filter((source) => source.kind === "peer") ?? [];
  return (
    <>
      <Panel
        title="Copy policy from a second node"
        detail="Download a validated draft over authenticated HTTPS. Each node publishes its own generation."
      >
        <ErrorNotice error={error ?? peers.error} />
        <p className="body-copy">
          This replaces the whole policy draft, including admission, upstreams and required
          assertions. Process listeners, secrets, sessions, query history and privacy preferences
          stay local. This operation does not activate the downloaded configuration.
        </p>
        {!choices.length ? (
          <p>
            Configure a peer integration with a read-only token and trusted certificate in the
            appliance configuration.
          </p>
        ) : (
          <>
            <Field label="Policy peer">
              <select value={name} onChange={(e) => setName(e.target.value)} disabled={busy}>
                <option value="">Choose a peer</option>
                {choices.map((peer) => (
                  <option key={peer.name}>{peer.name}</option>
                ))}
              </select>
            </Field>
            <button
              disabled={!name || busy || !api.canWrite}
              onClick={() => {
                void preview();
              }}
            >
              {busy ? "Downloading…" : "Preview peer policy"}
            </button>
          </>
        )}
      </Panel>
      <Modal
        open={candidate !== null}
        onClose={() => setCandidate(null)}
        title="Replace draft with peer policy"
        description="Existing unsaved edits in this tab will be replaced. Validate and review before publishing."
      >
        {candidate && (
          <>
            <p>
              {candidate.value.policies.length} policies · {candidate.value.bindings.length} client
              bindings · {candidate.value.assertions.length} assertions
            </p>
            <p>
              Allowed sources:{" "}
              <span className="mono">{candidate.value.allowed_clients.join(", ")}</span>
            </p>
            <div className="dialog-actions">
              <button onClick={() => setCandidate(null)}>Cancel</button>
              <button
                className="primary"
                disabled={!api.canWrite || candidate.etag !== base.etag}
                onClick={() => {
                  edit(candidate.value);
                  setCandidate(null);
                }}
              >
                Replace draft
              </button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
