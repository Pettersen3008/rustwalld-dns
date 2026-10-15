import { useState } from "react";

import { useApi } from "@/hooks/use-api";

import { Api, formatTime, countRules, pretty } from "@/lib/api";
import type { Configuration, Revision, Status, Versioned } from "@/lib/api";
import { Badge, ErrorNotice, Field, Loading, Modal, Panel } from "@/components/common";
export function Revisions({ api, published }: { api: Api; published: () => Promise<void> }) {
  const revisions = useApi<Revision[]>(api, "revisions", "/api/v1/revisions");
  const status = useApi<Status>(api, "status", "/api/v1/status");
  const [selected, setSelected] = useState<Revision | null>(null);
  const [review, setReview] = useState<{
    candidate: Configuration;
    active: Versioned<Configuration>;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function inspect(revision: Revision) {
    setSelected(revision);
    setReview(null);
    setError(null);
    setBusy(true);
    try {
      const [candidate, active] = await Promise.all([
        api.request<{ id: number; config: Configuration }>(`/api/v1/revisions/${revision.id}`),
        api.configuration(),
      ]);
      setReview({ candidate: candidate.value.config, active });
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function rollback() {
    if (!selected || !review) return;
    setBusy(true);
    setError(null);
    try {
      await api.request(`/api/v1/revisions/${selected.id}/rollback`, {
        method: "POST",
        etag: review.active.etag,
      });
      await published();
      setSelected(null);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Panel
        title="Durable revisions"
        detail="Rollback creates a fresh generation. It validates assertions before publication."
      >
        <ErrorNotice
          error={revisions.error}
          retry={() => {
            void revisions.refetch();
          }}
        />
        {revisions.isPending ? (
          <Loading />
        ) : (
          <div className="revision-list">
            {revisions.data?.map((revision) => (
              <div key={revision.id}>
                <div className="revision-number mono">G{revision.id}</div>
                <div>
                  <div className="revision-title">
                    <strong>{revision.actor}</strong>
                    <Badge
                      tone={
                        status.data?.generation === revision.id
                          ? "green"
                          : status.data?.shadow_generation === revision.id
                            ? "amber"
                            : "neutral"
                      }
                    >
                      {status.data?.generation === revision.id
                        ? "ACTIVE"
                        : status.data?.shadow_generation === revision.id
                          ? "SHADOW"
                          : revision.state.toUpperCase()}
                    </Badge>
                  </div>
                  <p>{revision.diff || "No configuration fields changed"}</p>
                  <small>{formatTime(revision.timestamp)}</small>
                </div>
                <button
                  onClick={() => {
                    void inspect(revision);
                  }}
                >
                  Inspect revision
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>
      <Modal
        open={selected !== null}
        onClose={() => {
          if (!busy) setSelected(null);
        }}
        title={`Inspect revision G${selected?.id ?? ""}`}
        description="Review the stored candidate and changed fields before creating a new active generation."
      >
        <ErrorNotice error={error} />
        {busy && !review && <Loading />}
        {review && (
          <>
            <div className="notice">
              Candidate: {review.candidate.policies.length} policies, {countRules(review.candidate)}{" "}
              raw rules, {review.candidate.assertions.length} assertions.
            </div>
            <Field label="Changed configuration fields">
              <div className="chips">
                {(Object.keys(review.candidate) as (keyof Configuration)[])
                  .filter(
                    (key) => pretty(review.candidate[key]) !== pretty(review.active.value[key]),
                  )
                  .map((key) => (
                    <Badge key={key}>{key}</Badge>
                  ))}
              </div>
            </Field>
            <details>
              <summary>Inspect complete stored configuration</summary>
              <pre>{pretty(review.candidate)}</pre>
            </details>
            <div className="dialog-actions">
              <button onClick={() => setSelected(null)} disabled={busy}>
                Close
              </button>
              <button className="danger" onClick={rollback} disabled={busy || !api.canWrite}>
                {busy ? "Publishing…" : "Validate and roll back to this revision"}
              </button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
