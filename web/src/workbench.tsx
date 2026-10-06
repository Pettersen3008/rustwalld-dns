import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  FlaskConical,
  Download,
  Code2,
  ArrowRight,
} from "lucide-react";
import {
  Api,
  checkReportSchema,
  failedCheckReport,
  configSchema,
  countRules,
  pretty,
} from "./api";
import type {
  CheckReport,
  Configuration,
  HistoryEvent,
  Shadow,
  Versioned,
} from "./api";
import {
  PoliciesEditor,
  NetworksEditor,
  UpstreamsEditor,
  AssertionsEditor,
} from "./editors";
import { TemporaryExceptionsEditor } from "./exceptions";
import { SourcesEditor } from "./sources";
import { Badge, ErrorNotice, Field, Modal, Panel } from "./components";
type Props = {
  api: Api;
  draft: Configuration;
  setDraft: (value: Configuration) => void;
  base: Versioned<Configuration>;
  setBase: (value: Versioned<Configuration>) => void;
  current?: Versioned<Configuration>;
  adopt: (value: Versioned<Configuration>) => void;
  published: (reset: boolean) => Promise<void>;
};
type Section =
  "rules" | "networks" | "upstreams" | "assertions" | "exceptions" | "sources";
export function Workbench({
  api,
  draft,
  setDraft,
  base,
  setBase,
  current,
  adopt,
  published,
}: Props) {
  const client = useQueryClient();
  const [section, setSection] = useState<Section>("rules");
  const [validated, setValidated] = useState<string | null>(null);
  const [report, setReport] = useState<CheckReport | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [modal, setModal] = useState<
    "json" | "reload" | "promote" | "clear" | null
  >(null);
  const [json, setJson] = useState("");
  const [jsonError, setJsonError] = useState<unknown>(null);
  const [candidate, setCandidate] = useState<Versioned<Shadow> | null>(null);
  const shadow = useQuery({
    queryKey: ["shadow"],
    queryFn: ({ signal }) => api.request<Shadow>("/api/v1/shadow", { signal }),
    refetchInterval: 5000,
  });
  const history = useQuery({
    queryKey: ["queries"],
    queryFn: ({ signal }) =>
      api
        .request<HistoryEvent[]>("/api/v1/queries?limit=500", { signal })
        .then((r) => r.value),
    refetchInterval: 5000,
  });
  const dirty = pretty(draft) !== pretty(base.value);
  const conflict = !!current && current.etag !== base.etag;
  const isValidated = validated === pretty(draft);
  function edit(value: Configuration) {
    const sources = value.filter_sources?.map((source) => {
      const old = draft.filter_sources?.find(
        (entry) => entry.policy === source.policy && entry.list === source.list,
      );
      const text = (config: Configuration) =>
        config.policies
          .find((p) => p.name === source.policy)
          ?.lists.find((list) => list.name === source.list)?.rules;
      if (
        source.download &&
        old?.download &&
        pretty(source.download) === pretty(old.download) &&
        text(value) !== text(draft)
      ) {
        const clean = { ...source };
        delete clean.download;
        return clean;
      }
      return source;
    });
    if (sources) value = { ...value, filter_sources: sources };
    setDraft(value);
    setValidated(null);
    setReport(null);
    setNotice("");
    setError(null);
  }
  async function validate() {
    const body = draft;
    setBusy(true);
    setError(null);
    setNotice("");
    setReport(null);
    try {
      const result = await api.request<unknown>("/api/v1/policy/test", {
        method: "POST",
        body,
      });
      const report = checkReportSchema.parse(result.value);
      if (!report.valid) throw new Error("The policy test did not pass.");
      setReport(report);
      setValidated(pretty(body));
      setNotice(
        `Validation passed: ${report.assertions} assertions, ${report.policies} policies. Nothing has been published.`,
      );
    } catch (error) {
      setError(error);
      setReport(failedCheckReport(error));
      setValidated(null);
    } finally {
      setBusy(false);
    }
  }
  async function download(index: number) {
    setBusy(true);
    setError(null);
    setNotice("");
    setReport(null);
    setValidated(null);
    try {
      const result = await api.request<{
        config: unknown;
        report: unknown;
        changed: boolean;
      }>("/api/v1/filter-sources/preview", {
        method: "POST",
        body: { config: draft, source: index },
        etag: base.etag,
      });
      const config = configSchema.parse(result.value.config);
      const report = checkReportSchema.parse(result.value.report);
      if (!report.valid)
        throw new Error("Downloaded candidate did not pass validation.");
      edit(config);
      setReport(report);
      setValidated(pretty(config));
      setNotice(
        `${result.value.changed ? "Downloaded new list contents" : "List contents are unchanged"}. Candidate validated; review in shadow before promotion. Nothing has been published.`,
      );
    } catch (error) {
      setError(error);
      setReport(failedCheckReport(error));
    } finally {
      setBusy(false);
    }
  }
  async function stage() {
    if (!isValidated) return;
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      const result = await api.request<{ generation: number }>(
        "/api/v1/shadow",
        { method: "POST", body: draft, etag: base.etag },
      );
      setBase({ ...base, etag: result.etag });
      setNotice(
        `Shadow G${result.value.generation} is evaluating live queries. Production answers are unchanged.`,
      );
      await client.invalidateQueries();
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function checkSchedule(index: number) {
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      await api.request("/api/v1/filter-refreshes/check", {
        method: "POST",
        body: { source: index },
        etag: base.etag,
      });
      setNotice(
        "Scheduled check queued for the active source. New content requires shadow review; your local draft is preserved.",
      );
      await client.invalidateQueries();
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function review(mode: "promote" | "clear") {
    setBusy(true);
    setError(null);
    try {
      const candidate = await api.request<Shadow>("/api/v1/shadow");
      if (!candidate.value.config)
        throw new Error("There is no shadow candidate to review.");
      setCandidate(candidate);
      setModal(mode);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function mutateCandidate(mode: "promote" | "clear") {
    if (!candidate) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.request<{ generation?: number }>(
        mode === "promote" ? "/api/v1/shadow/promote" : "/api/v1/shadow",
        {
          method: mode === "promote" ? "POST" : "DELETE",
          etag: candidate.etag,
        },
      );
      // An unrelated draft must survive promotion of a candidate from another editor.
      const matchesDraft = pretty(candidate.value.config) === pretty(draft);
      if (mode === "promote") await published(matchesDraft);
      else {
        const active = await api.configuration();
        if (pretty(active.value) === pretty(base.value))
          setBase({ ...base, etag: active.etag });
        await client.invalidateQueries();
      }
      setValidated(null);
      setReport(null);
      setModal(null);
      setNotice(
        mode === "promote"
          ? `Generation ${result.value.generation} is now active.`
          : "Shadow evaluation stopped.",
      );
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function reload() {
    setBusy(true);
    setError(null);
    try {
      adopt(await api.configuration());
      setValidated(null);
      setReport(null);
      setNotice("Loaded the current active configuration.");
      setModal(null);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  function exportDraft() {
    const url = URL.createObjectURL(
      new Blob([pretty(draft) + "\n"], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "rustwall-policy-draft.json";
    a.click();
    URL.revokeObjectURL(url);
  }
  const shadowEvents = (history.data ?? []).filter(
    (e) => e.shadow?.generation === shadow.data?.value.generation,
  );
  return (
    <>
      <div className="workbench-toolbar">
        <div>
          <Badge tone={dirty ? "amber" : "neutral"}>
            {dirty ? "LOCAL DRAFT" : "ACTIVE CONFIGURATION"}
          </Badge>
          {isValidated && (
            <Badge tone="green">
              <CheckCircle2 size={12} /> VALIDATED
            </Badge>
          )}
        </div>
        <div>
          <button onClick={exportDraft}>
            <Download size={15} /> Export draft
          </button>
          <button
            onClick={() => {
              setJson(pretty(draft));
              setJsonError(null);
              setModal("json");
            }}
            disabled={busy}
          >
            <Code2 size={15} /> JSON
          </button>
          <button
            onClick={() => (dirty ? setModal("reload") : void reload())}
            disabled={busy}
          >
            Reload active
          </button>
        </div>
      </div>
      {conflict && (
        <div className="notice notice-warning" role="status">
          A newer active or shadow revision exists. Your draft is preserved.
          Reload and review before staging it.
        </div>
      )}
      <ErrorNotice error={error} />
      {notice && (
        <div className="notice notice-success" role="status">
          <CheckCircle2 size={17} />
          {notice}
        </div>
      )}
      <ErrorNotice
        error={shadow.error}
        retry={() => {
          void shadow.refetch();
        }}
      />
      <ErrorNotice
        error={history.error}
        retry={() => {
          void history.refetch();
        }}
      />
      <div className="two-col">
        <Panel
          title="Draft → validated candidate"
          detail={`${draft.policies.length} policies · ${countRules(draft)} raw rules · ${draft.assertions.length} required assertions`}
        >
          <p className="body-copy">
            Required assertions are checked by the same compiler that publishes
            a revision. They test permanent policy, excluding temporary
            exceptions. Failed validation leaves production untouched.
          </p>
          <div className="button-row">
            <button className="primary" onClick={validate} disabled={busy}>
              <CheckCircle2 size={16} /> {busy ? "Working…" : "Validate draft"}
            </button>
            <button onClick={stage} disabled={busy || !isValidated || conflict}>
              <FlaskConical size={16} /> Stage in shadow
            </button>
          </div>
        </Panel>
        <Panel
          title="Shadow candidate"
          detail="Observe real traffic without enforcing the candidate."
          action={
            shadow.data?.value.generation ? (
              <Badge tone="amber">G{shadow.data.value.generation}</Badge>
            ) : (
              <Badge>NONE</Badge>
            )
          }
        >
          {shadow.data?.value.config ? (
            <>
              <p className="body-copy">
                {shadowEvents.filter((e) => e.shadow?.differs).length} differing
                decisions / {shadowEvents.length} candidate events in the latest
                500 retained queries.
              </p>
              <small className="muted">
                This is a retained sample, not a complete traffic impact
                estimate.
              </small>
              <div className="button-row">
                <button
                  className="primary"
                  disabled={busy}
                  onClick={() => {
                    void review("promote");
                  }}
                >
                  Review promotion <ArrowRight size={15} />
                </button>
                <button
                  disabled={busy}
                  onClick={() => {
                    void review("clear");
                  }}
                >
                  Stop shadow
                </button>
              </div>
            </>
          ) : (
            <p className="body-copy">
              Validate a draft and stage it to start collecting differences.
            </p>
          )}
        </Panel>
      </div>
      {report && <AssertionResults report={report} />}
      <div className="tabs" role="tablist" aria-label="Policy editor sections">
        {(
          [
            "rules",
            "networks",
            "upstreams",
            "assertions",
            "exceptions",
            "sources",
          ] as const
        ).map((id) => (
          <button
            role="tab"
            aria-selected={section === id}
            aria-controls={`editor-${id}`}
            id={`tab-${id}`}
            key={id}
            onClick={() => setSection(id)}
          >
            {id === "rules"
              ? "Policies & rules"
              : id === "networks"
                ? "Clients & networks"
                : id === "upstreams"
                  ? "Upstream profiles"
                  : id === "assertions"
                    ? "Assertions"
                    : id === "exceptions"
                      ? "Temporary exceptions"
                      : "Downloaded lists"}
          </button>
        ))}
      </div>
      <fieldset disabled={busy} className="editor-fieldset">
        <div
          role="tabpanel"
          id={`editor-${section}`}
          aria-labelledby={`tab-${section}`}
        >
          {section === "rules" && <PoliciesEditor draft={draft} edit={edit} />}
          {section === "networks" && (
            <NetworksEditor draft={draft} edit={edit} />
          )}
          {section === "upstreams" && (
            <UpstreamsEditor draft={draft} edit={edit} />
          )}
          {section === "assertions" && (
            <AssertionsEditor draft={draft} edit={edit} />
          )}
          {section === "exceptions" && (
            <TemporaryExceptionsEditor api={api} draft={draft} edit={edit} />
          )}
          {section === "sources" && (
            <SourcesEditor
              api={api}
              draft={draft}
              edit={edit}
              download={download}
              checkSchedule={checkSchedule}
            />
          )}
        </div>
      </fieldset>
      <Modal
        open={modal === "json"}
        onClose={() => setModal(null)}
        title="Inspect or import a draft"
        description="This edits only your local draft. The server must validate it before staging."
      >
        <Field label="Configuration JSON">
          <textarea
            rows={16}
            className="mono"
            value={json}
            onChange={(e) => setJson(e.target.value)}
            spellCheck={false}
          />
        </Field>
        <ErrorNotice error={jsonError} />
        <div className="dialog-actions">
          <button onClick={() => setModal(null)}>Cancel</button>
          <button
            className="primary"
            onClick={() => {
              try {
                edit(configSchema.parse(JSON.parse(json)));
                setModal(null);
              } catch (error) {
                setJsonError(error);
              }
            }}
          >
            Use this draft
          </button>
        </div>
      </Modal>
      <Modal
        open={modal === "reload"}
        onClose={() => setModal(null)}
        title="Discard your draft and reload?"
        description="The appliance’s current active configuration will replace your unsaved edits. Export your draft first if you want to keep a copy."
      >
        <ErrorNotice error={error} />
        <div className="dialog-actions">
          <button onClick={() => setModal(null)} disabled={busy}>
            Keep editing
          </button>
          <button className="danger" onClick={reload} disabled={busy}>
            Discard draft and reload
          </button>
        </div>
      </Modal>
      <Modal
        open={modal === "promote" || modal === "clear"}
        onClose={() => {
          if (!busy) setModal(null);
        }}
        title={
          modal === "clear"
            ? `Stop shadow G${candidate?.value.generation}?`
            : `Promote shadow G${candidate?.value.generation}?`
        }
        description={
          modal === "clear"
            ? "This stops candidate evaluation and leaves the active policy in place."
            : "Review this exact candidate. It will be recompiled, tested and durably recorded before atomic publication."
        }
      >
        <ErrorNotice error={error} />
        {candidate?.value.config && (
          <>
            <div className="notice">
              {candidate.value.config.policies.length} policies ·{" "}
              {countRules(candidate.value.config)} raw rules ·{" "}
              {candidate.value.config.assertions.length} required assertions
            </div>
            <Field label="Candidate differs from the draft base in">
              <div className="chips">
                {(
                  Object.keys(candidate.value.config) as (keyof Configuration)[]
                )
                  .filter(
                    (key) =>
                      pretty(candidate.value.config?.[key]) !==
                      pretty(base.value[key]),
                  )
                  .map((key) => (
                    <Badge key={key}>{key}</Badge>
                  ))}
              </div>
            </Field>
            <details>
              <summary>Inspect complete candidate</summary>
              <pre>{pretty(candidate.value.config)}</pre>
            </details>
            <div className="dialog-actions">
              <button onClick={() => setModal(null)} disabled={busy}>
                Cancel
              </button>
              <button
                className={modal === "clear" ? "danger" : "primary"}
                onClick={() => {
                  void mutateCandidate(modal === "clear" ? "clear" : "promote");
                }}
                disabled={busy}
              >
                {busy
                  ? "Publishing…"
                  : modal === "clear"
                    ? "Stop this shadow"
                    : "Promote this candidate"}
              </button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}

function AssertionResults({ report }: { report: CheckReport }) {
  const [showAll, setShowAll] = useState(false);
  const [page, setPage] = useState(0);
  const results =
    report.valid || showAll
      ? report.results
      : report.results.filter((result) => result.failure !== null);
  const pages = Math.max(1, Math.ceil(results.length / 10));
  const current = Math.min(page, pages - 1);
  return (
    <details className="assertion-results" open={!report.valid || undefined}>
      <summary>
        Assertion results: {report.failed} failed ·{" "}
        {report.assertions - report.failed} passed
      </summary>
      <p className="body-copy">
        These are configured decisions. Upstream connectivity and live DNS
        replies are not tested.
      </p>
      {!report.assertions && (
        <p className="notice notice-warning">
          No required assertions configured. Only structural validation was
          performed.
        </p>
      )}
      {!!report.failed && (
        <button
          onClick={() => {
            setShowAll(!showAll);
            setPage(0);
          }}
        >
          {showAll ? "Show failures only" : "Include passing assertions"}
        </button>
      )}
      {results.slice(current * 10, (current + 1) * 10).map((result, index) => (
        <article className="assertion-result" key={`${current}-${index}`}>
          <div className="assertion-heading">
            <Badge tone={result.failure ? "red" : "green"}>
              {result.failure ? "FAIL" : "PASS"}
            </Badge>
            <strong>
              {result.assertion.client} + {result.assertion.domain}
            </strong>
          </div>
          <p>
            Expected {result.assertion.expected.toUpperCase()} ·{" "}
            {result.trace
              ? `Configured ${result.trace.decision.action.toUpperCase()}${result.trace.rewrite ? " (local rewrite)" : ""}`
              : "No decision"}
          </p>
          {result.failure && (
            <p className="body-copy">
              {result.failure.kind === "invalid_domain"
                ? "Invalid domain."
                : result.failure.kind === "client_not_permitted"
                  ? "Client is outside allowed networks. The trace is hypothetical; this client cannot query DNS."
                  : "The configured decision differs from the assertion."}
            </p>
          )}
          {result.trace && (
            <details>
              <summary>Decision trace</summary>
              <dl className="assertion-trace">
                <dt>Normalized domain</dt>
                <dd>{result.trace.domain}</dd>
                <dt>Policy</dt>
                <dd>{result.trace.policy}</dd>
                <dt>Client / network</dt>
                <dd>
                  {result.trace.client_name ?? "Default client"} /{" "}
                  {result.trace.network ?? "Default policy"}
                </dd>
                <dt>Client admitted</dt>
                <dd>{result.permitted ? "Yes" : "No"}</dd>
                {result.trace.binding_metadata && (
                  <>
                    <dt>Binding annotations</dt>
                    <dd>
                      {[
                        result.trace.binding_metadata.group,
                        result.trace.binding_metadata.owner,
                        result.trace.binding_metadata.vlan
                          ? `VLAN ${result.trace.binding_metadata.vlan}`
                          : undefined,
                        ...(result.trace.binding_metadata.tags ?? []),
                        result.trace.binding_metadata.note,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </dd>
                  </>
                )}
                <dt>Upstream profile</dt>
                <dd>{result.trace.upstream}</dd>
                <dt>Matcher / rule</dt>
                <dd>
                  {result.trace.rule
                    ? `${result.trace.rule.matcher} / ${result.trace.rule.domain}`
                    : result.trace.rewrite
                      ? "Local rewrite"
                      : "Default allow"}
                </dd>
              </dl>
              {result.trace.rule && (
                <>
                  <ul>
                    {result.trace.rule.sources.map((source, index) => (
                      <li key={index}>
                        {source.list} · line {source.line}
                      </li>
                    ))}
                  </ul>
                  {result.trace.rule.total_sources >
                    result.trace.rule.sources.length && (
                    <p className="muted">
                      {result.trace.rule.sources.length} of{" "}
                      {result.trace.rule.total_sources} sources shown.
                    </p>
                  )}
                </>
              )}
            </details>
          )}
        </article>
      ))}
      {results.length > 10 && (
        <div className="pagination">
          <button disabled={current === 0} onClick={() => setPage(current - 1)}>
            Previous assertions
          </button>
          <span>
            Page {current + 1} of {pages}
          </span>
          <button
            disabled={current + 1 >= pages}
            onClick={() => setPage(current + 1)}
          >
            Next assertions
          </button>
        </div>
      )}
    </details>
  );
}
