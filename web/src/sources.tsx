import { useState } from "react";
import { pretty } from "./api";
import type { Api, Configuration, FilterSource, RefreshStatus } from "./api";
import { useApi } from "./hooks";
import { Badge, ErrorNotice, Field, Panel } from "./components";

export function SourcesEditor({
  api,
  draft,
  edit,
  download,
  checkSchedule,
}: {
  api: Api;
  draft: Configuration;
  edit: (config: Configuration) => void;
  download: (index: number) => Promise<void>;
  checkSchedule: (index: number) => Promise<void>;
}) {
  const active = useApi<{ generation: number; sources: FilterSource[] }>(
    api,
    "filter-sources",
    "/api/v1/filter-sources",
  );
  const [policy, setPolicy] = useState(draft.policies[0]?.name ?? "");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [ips, setIps] = useState("");
  const [ca, setCa] = useState("");
  const [action, setAction] = useState<"allow" | "block">("block");
  const [scheduled, setScheduled] = useState(false);
  const [interval, setInterval] = useState("86400");
  const refresh = useApi<RefreshStatus>(
    api,
    "filter-refreshes",
    "/api/v1/filter-refreshes",
  );
  const [editing, setEditing] = useState<number | null>(null);
  const [formOpen, setFormOpen] = useState(!draft.filter_sources?.length);
  const [page, setPage] = useState(0);
  const sources = draft.filter_sources ?? [];
  const selected = draft.policies.find((p) => p.name === policy);
  const current = Math.min(
    page,
    Math.max(0, Math.ceil(sources.length / 10) - 1),
  );
  function replace(values: FilterSource[]) {
    const next = { ...draft };
    if (values.length) next.filter_sources = values;
    else delete next.filter_sources;
    edit(next);
  }
  function clear() {
    setFormOpen(false);
    setEditing(null);
    setName("");
    setUrl("");
    setIps("");
    setCa("");
    setScheduled(false);
    setInterval("86400");
  }
  function save() {
    const source: FilterSource = {
      policy,
      list: name.trim(),
      url: url.trim(),
      bootstrap_ips: ips.split(/[\s,;]+/).filter(Boolean),
      ...(ca.trim() ? { ca_pem: ca.trim() } : {}),
      ...(scheduled ? { refresh_interval_secs: Number(interval) } : {}),
    };
    const next = {
      ...draft,
      filter_sources:
        editing === null
          ? [...sources, source]
          : sources.map((old, index) => (index === editing ? source : old)),
      policies: draft.policies.map((p) =>
        p.name === policy && !p.lists.some((list) => list.name === source.list)
          ? {
              ...p,
              lists: [...p.lists, { name: source.list, action, rules: "" }],
            }
          : p,
      ),
    };
    edit(next);
    if (editing === null) setPage(Math.floor(sources.length / 10));
    clear();
  }
  return (
    <Panel
      title="Downloaded lists"
      detail="Fetch into a draft, inspect shadow impact, then promote."
    >
      <p className="body-copy">
        Live lists remain available during failed or stalled downloads. Only
        reviewed policy promotion changes production DNS. Opt-in schedules stage
        changed content in shadow and pause until it is promoted or dismissed.
      </p>
      <ErrorNotice
        error={active.error}
        retry={() => {
          void active.refetch();
        }}
      />
      <ErrorNotice
        error={refresh.error}
        retry={() => {
          void refresh.refetch();
        }}
      />
      {refresh.data?.paused === "shadow_review" && (
        <p className="notice notice-warning">
          Scheduled checks paused for shadow review. Use Review promotion or
          Stop shadow above.
        </p>
      )}
      {refresh.data?.running && (
        <p className="body-copy">
          Checking active source: {refresh.data.running.policy} /{" "}
          {refresh.data.running.list}.
        </p>
      )}
      {refresh.data?.queued && (
        <p className="body-copy">A scheduled check is queued.</p>
      )}
      <details
        className="source-form"
        open={formOpen}
        onToggle={(event) => setFormOpen(event.currentTarget.open)}
      >
        <summary>Configure a download source</summary>
        <div className="form-grid">
          <Field label="Download policy">
            <select value={policy} onChange={(e) => setPolicy(e.target.value)}>
              {draft.policies.map((p) => (
                <option key={p.name}>{p.name}</option>
              ))}
            </select>
          </Field>
          <Field label="Downloaded list name">
            <input
              value={name}
              maxLength={128}
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          <Field label="HTTPS list URL">
            <input
              value={url}
              maxLength={2048}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://lists.example/domains.txt"
            />
          </Field>
          <Field
            label="Bootstrap IPs"
            hint="Explicit destination IPs; HTTPS verifies the URL host. No bootstrap DNS lookup."
          >
            <textarea
              value={ips}
              rows={2}
              onChange={(e) => setIps(e.target.value)}
              placeholder="One IP per line"
            />
          </Field>
          <Field label="New list action">
            <select
              value={action}
              onChange={(e) => setAction(e.target.value as "allow" | "block")}
            >
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
          </Field>
          <Field label="Enable scheduled refresh">
            <input
              type="checkbox"
              checked={scheduled}
              onChange={(e) => setScheduled(e.target.checked)}
            />
          </Field>
          {scheduled && (
            <Field
              label="Check interval (seconds)"
              hint="300 through 2592000 seconds. 86400 is daily; 3600 is hourly."
            >
              <input
                type="number"
                min={300}
                max={2592000}
                step={1}
                value={interval}
                onChange={(e) => setInterval(e.target.value)}
              />
            </Field>
          )}
        </div>
        <details>
          <summary>Private HTTPS trust</summary>
          <Field
            label="Download CA PEM"
            hint="Optional private CA replaces public trust roots."
          >
            <textarea
              className="mono"
              rows={4}
              value={ca}
              onChange={(e) => setCa(e.target.value)}
            />
          </Field>
        </details>
        <p className="body-copy">
          Registering a source creates an empty list if needed. Attaching to an
          existing list keeps its contents and action until a successful
          download. Updating a source clears its download stamp; current text
          stays in the draft.
        </p>
        <div className="button-row">
          <button
            className="primary"
            onClick={save}
            disabled={
              !selected ||
              !name.trim() ||
              !url.trim() ||
              !ips.trim() ||
              (scheduled &&
                (!Number.isInteger(Number(interval)) ||
                  Number(interval) < 300 ||
                  Number(interval) > 2592000)) ||
              (editing === null && sources.length >= 64) ||
              sources.some(
                (s, index) =>
                  index !== editing &&
                  s.policy === policy &&
                  s.list === name.trim(),
              )
            }
          >
            {editing === null
              ? "Register source in draft"
              : "Save source in draft"}
          </button>
          {editing !== null && (
            <button onClick={clear}>Cancel source edit</button>
          )}
        </div>
      </details>
      {!sources.length && (
        <p className="muted source-empty">No download sources in this draft.</p>
      )}
      {sources.slice(current * 10, (current + 1) * 10).map((source, row) => {
        const index = current * 10 + row;
        const published = active.data?.sources.some(
          (item) => pretty(item) === pretty(source),
        );
        const activeIndex =
          active.data?.sources.findIndex(
            (item) => pretty(item) === pretty(source),
          ) ?? -1;
        const status = refresh.data?.entries.find(
          (entry) => entry.source === activeIndex,
        );
        return (
          <article className="source-row" key={index}>
            <div className="source-heading">
              <strong>
                {source.policy} / {source.list}
              </strong>
              <Badge tone={published ? "green" : "neutral"}>
                {published ? "ACTIVE" : "DRAFT"}
              </Badge>
            </div>
            <p className="mono source-url">{source.url}</p>
            {source.refresh_interval_secs ? (
              <p className="body-copy">
                Scheduled every {source.refresh_interval_secs.toLocaleString()}{" "}
                seconds · changed content requires shadow review.
              </p>
            ) : (
              <p className="muted">Manual refresh only.</p>
            )}
            {status && (
              <div className="refresh-result">
                <Badge
                  tone={
                    status.outcome === "failed"
                      ? "red"
                      : status.outcome === "staged"
                        ? "amber"
                        : "neutral"
                  }
                >
                  {status.outcome}
                </Badge>
                {status.last_http_status && (
                  <p className="body-copy">
                    HTTP {status.last_http_status} ·{" "}
                    {status.last_download_bytes?.toLocaleString()} body bytes
                    {status.last_http_status === 304
                      ? " · stored list retained"
                      : ""}
                    .
                  </p>
                )}
                {status.last_checked_at && (
                  <p className="body-copy">
                    Last check{" "}
                    {new Date(status.last_checked_at * 1000).toLocaleString()}{" "}
                    against G{status.checked_generation}.
                  </p>
                )}
                <p className="body-copy">
                  Next check{" "}
                  {refresh.data?.paused === "shadow_review"
                    ? "after shadow review"
                    : new Date(status.next_check_at * 1000).toLocaleString()}
                  .
                </p>
                {status.error && (
                  <p className="notice notice-error">{status.error}</p>
                )}
              </div>
            )}
            {source.download ? (
              <p className="body-copy">
                Retrieved{" "}
                {new Date(source.download.retrieved_at * 1000).toLocaleString()}{" "}
                · {source.download.bytes.toLocaleString()} bytes
              </p>
            ) : (
              <p className="muted">
                No matching download stamp. Fetch to validate this source.
              </p>
            )}
            {source.download && (
              <details>
                <summary>Content fingerprint</summary>
                <p className="mono source-url">
                  SHA-256 {source.download.sha256}
                </p>
              </details>
            )}
            <div className="button-row">
              <button
                className="primary"
                onClick={() => {
                  void download(index);
                }}
                aria-label={`Download ${source.list} into draft`}
              >
                Download into draft
              </button>
              <button
                onClick={() => {
                  setFormOpen(true);
                  setEditing(index);
                  setPolicy(source.policy);
                  setName(source.list);
                  setUrl(source.url);
                  setIps(source.bootstrap_ips.join("\n"));
                  setCa(source.ca_pem ?? "");
                  setScheduled(source.refresh_interval_secs !== undefined);
                  setInterval(String(source.refresh_interval_secs ?? 86400));
                }}
                aria-label={`Edit source ${source.list}`}
              >
                Edit source
              </button>
              {source.refresh_interval_secs && (
                <button
                  disabled={
                    !published ||
                    !!refresh.data?.paused ||
                    !!refresh.data?.running ||
                    !!refresh.data?.queued
                  }
                  onClick={() => {
                    void checkSchedule(activeIndex);
                  }}
                  aria-label={`Check active schedule ${source.list} now`}
                >
                  Check active source now
                </button>
              )}
              <button
                onClick={() => {
                  replace(sources.filter((_, i) => i !== index));
                  clear();
                }}
                aria-label={`Remove source ${source.list} from draft`}
              >
                Remove source
              </button>
            </div>
          </article>
        );
      })}
      {sources.length > 10 && (
        <div className="button-row">
          <button disabled={!current} onClick={() => setPage(current - 1)}>
            Previous sources
          </button>
          <span>
            Page {current + 1} of {Math.ceil(sources.length / 10)}
          </span>
          <button
            disabled={(current + 1) * 10 >= sources.length}
            onClick={() => setPage(current + 1)}
          >
            Next sources
          </button>
        </div>
      )}
      <p className="body-copy">
        Removing a source stops its download association; its current list text
        remains. Remove that list in Policies &amp; rules to stop filtering,
        then review and promote.
      </p>
    </Panel>
  );
}
