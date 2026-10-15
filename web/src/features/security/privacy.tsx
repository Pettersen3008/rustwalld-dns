import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Api, Versioned } from "@/lib/api";
import { Badge, ErrorNotice, Field, Modal, Panel } from "@/components/common";
type Mode = "full" | "no_client_identity" | "disabled";
type Privacy = { revision: number; mode: Mode; retention_rows: number; retained_rows: number };
export function PrivacySettings({ api }: { api: Api }) {
  const client = useQueryClient();
  const current = useQuery({
    queryKey: ["privacy"],
    queryFn: ({ signal }) => api.request<Privacy>("/api/v1/privacy", { signal }),
  });
  const [mode, setMode] = useState<Mode | null>(null);
  const [rows, setRows] = useState<string | null>(null);
  const [clear, setClear] = useState(false);
  const [review, setReview] = useState<Versioned<Privacy> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function prepare() {
    setBusy(true);
    setError(null);
    try {
      setReview(await api.request<Privacy>("/api/v1/privacy"));
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function apply() {
    if (!review) return;
    setBusy(true);
    setError(null);
    try {
      await api.request("/api/v1/privacy", {
        method: "PUT",
        etag: review.etag,
        body: {
          mode: mode ?? review.value.mode,
          retention_rows: Number(rows ?? review.value.retention_rows),
          clear_history: clear,
        },
      });
      setReview(null);
      setMode(null);
      setRows(null);
      setClear(false);
      await client.invalidateQueries();
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Panel
        title="Query-history privacy"
        detail="Preferences persist independently of DNS policies. Live counters and resolver health remain available."
        action={<Badge>P{current.data?.value.revision ?? "…"}</Badge>}
      >
        <ErrorNotice error={current.error} />
        <ErrorNotice error={error} />
        {current.data && (
          <>
            <p className="body-copy">
              {current.data.value.retained_rows.toLocaleString()} query rows retained. Masking
              applies to newly recorded history; configured client bindings remain visible. Existing
              history keeps its original identity unless you explicitly clear it.
            </p>
            <div className="form-grid">
              <Field label="Query logging mode">
                <select
                  disabled={busy || api.role !== "administrator"}
                  value={mode ?? current.data.value.mode}
                  onChange={(e) => setMode(e.target.value as Mode)}
                >
                  <option value="full">Full query history</option>
                  <option value="no_client_identity">Omit client identity</option>
                  <option value="disabled">Disable new query logging</option>
                </select>
              </Field>
              <Field
                label="Maximum retained rows"
                hint="1–1,000,000 rows. Lowering this limit trims the oldest entries."
              >
                <input
                  type="number"
                  min={1}
                  max={1000000}
                  disabled={busy || api.role !== "administrator"}
                  value={rows ?? current.data.value.retention_rows}
                  onChange={(e) => setRows(e.target.value)}
                />
              </Field>
            </div>
            <Field label="Clear retained query history">
              <input
                type="checkbox"
                checked={clear}
                disabled={busy || api.role !== "administrator"}
                onChange={(e) => setClear(e.target.checked)}
              />
            </Field>
            <p className="body-copy">
              Clearing removes rows from the application. Copies may remain in backups, snapshots,
              WAL or filesystem blocks.
            </p>
            <button disabled={busy || api.role !== "administrator"} onClick={() => void prepare()}>
              Review privacy change
            </button>
          </>
        )}
      </Panel>
      <Modal
        open={review !== null}
        onClose={() => {
          if (!busy) setReview(null);
        }}
        title="Apply query-history preferences?"
        description="This updates durable operational settings immediately. DNS policy, filtering and aggregate counters keep running."
      >
        <p>
          Mode: {mode ?? review?.value.mode} · retention: {rows ?? review?.value.retention_rows}{" "}
          rows.
        </p>
        {(clear || (rows !== null && Number(rows) < (review?.value.retained_rows ?? 0))) && (
          <p className="notice notice-warning">
            This removes retained history. Export or back up any records you need first.
          </p>
        )}
        <ErrorNotice error={error} />
        <div className="dialog-actions">
          <button disabled={busy} onClick={() => setReview(null)}>
            Keep current preferences
          </button>
          <button
            className={clear ? "danger" : "primary"}
            disabled={busy}
            onClick={() => void apply()}
          >
            Apply reviewed privacy preferences
          </button>
        </div>
      </Modal>
    </>
  );
}
