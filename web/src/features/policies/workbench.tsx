import { PublicationPanel } from "./publication";
import { EditorSections, sections, type Section } from "./editor-sections";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Download, Code2 } from "lucide-react";
import { checkReportSchema, failedCheckReport, configSchema, countRules, pretty } from "@/lib/api";
import type { Api, CheckReport, Configuration, HistoryEvent, Shadow, Versioned } from "@/lib/api";
import {
  PoliciesEditor,
  NetworksEditor,
  UpstreamsEditor,
  AssertionsEditor,
} from "@/features/policies/editors";
import { TemporaryExceptionsEditor } from "@/features/policies/exceptions";
import { SourcesEditor } from "@/features/policies/sources";
import { LocalDnsEditor } from "@/features/policies/local-dns";
import { ServicesEditor } from "@/features/policies/services";
import { SafeSearchEditor } from "@/features/policies/safe-search";
import { ResolverPresets } from "@/features/policies/presets";
import { MigrationEditor } from "@/features/policies/migration";
import { Badge, ErrorNotice, Field, Modal } from "@/components/common";
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
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedSection = searchParams.get("section");
  const requested: Section = sections.includes(requestedSection as Section)
    ? (requestedSection as Section)
    : "rules";
  const [selection, setSelection] = useState({ requested, section: requested });
  if (selection.requested !== requested) setSelection({ requested, section: requested });
  const section = selection.requested === requested ? selection.section : requested;
  function setSection(value: Section) {
    setSelection({ requested, section: value });
    const next = new URLSearchParams(searchParams);
    if (value === "rules") next.delete("section");
    else next.set("section", value);
    setSearchParams(next, { replace: true });
  }
  const [validated, setValidated] = useState<string | null>(null);
  const [report, setReport] = useState<CheckReport | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [modal, setModal] = useState<"json" | "reload" | "promote" | "clear" | null>(null);
  const [json, setJson] = useState("");
  const [jsonError, setJsonError] = useState<unknown>(null);
  const [candidate, setCandidate] = useState<Versioned<Shadow> | null>(null);
  const [reviewOrigin, setReviewOrigin] = useState<HTMLElement | null>(null);
  const shadow = useQuery({
    queryKey: ["shadow"],
    queryFn: ({ signal }) => api.request<Shadow>("/api/v1/shadow", { signal }),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  const history = useQuery({
    queryKey: ["queries"],
    queryFn: ({ signal }) =>
      api.request<HistoryEvent[]>("/api/v1/queries?limit=500", { signal }).then((r) => r.value),
    refetchInterval: 5000,
  });
  const draftText = useMemo(() => pretty(draft), [draft]);
  const baseText = useMemo(() => pretty(base.value), [base.value]);
  const dirty = draftText !== baseText;
  const conflict = !!current && current.etag !== base.etag;
  const isValidated = validated === draftText;
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
      if (!report.valid) throw new Error("Downloaded candidate did not pass validation.");
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
      const result = await api.request<{ generation: number }>("/api/v1/shadow", {
        method: "POST",
        body: draft,
        etag: base.etag,
      });
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
  async function review(mode: "promote" | "clear", origin: HTMLElement) {
    setReviewOrigin(origin);
    setBusy(true);
    setError(null);
    try {
      const candidate = await api.request<Shadow>("/api/v1/shadow");
      if (!candidate.value.config) throw new Error("There is no shadow candidate to review.");
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
        if (pretty(active.value) === pretty(base.value)) setBase({ ...base, etag: active.etag });
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
    const url = URL.createObjectURL(new Blob([pretty(draft) + "\n"], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "rustwall-policy-draft.json";
    a.click();
    URL.revokeObjectURL(url);
  }
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
          <button onClick={() => (dirty ? setModal("reload") : void reload())} disabled={busy}>
            Reload active
          </button>
        </div>
      </div>
      {conflict && (
        <output className="notice notice-warning">
          A newer active or shadow revision exists. Your draft is preserved. Reload and review
          before staging it.
        </output>
      )}
      <ErrorNotice error={error} />
      {notice && (
        <output className="notice notice-success">
          <CheckCircle2 size={17} />
          {notice}
        </output>
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
      <PublicationPanel
        draft={draft}
        shadow={shadow.data}
        events={history.data}
        report={report}
        busy={busy}
        canWrite={api.canWrite}
        validated={isValidated}
        conflict={conflict}
        validate={validate}
        stage={stage}
        review={review}
      />
      <EditorSections section={section} select={setSection} />
      <fieldset disabled={busy || !api.canWrite} className="editor-fieldset">
        <div
          role="tabpanel"
          tabIndex={0}
          id={`editor-${section}`}
          aria-labelledby={`tab-${section}`}
        >
          {section === "rules" && <PoliciesEditor draft={draft} edit={edit} />}
          {section === "local-dns" && <LocalDnsEditor draft={draft} edit={edit} />}
          {section === "services" && <ServicesEditor api={api} draft={draft} edit={edit} />}
          {section === "safe-search" && <SafeSearchEditor draft={draft} edit={edit} />}
          {section === "migration" && <MigrationEditor api={api} base={base} edit={edit} />}
          {section === "networks" && <NetworksEditor draft={draft} edit={edit} />}
          {section === "upstreams" && (
            <>
              <ResolverPresets draft={draft} edit={edit} />
              <UpstreamsEditor draft={draft} edit={edit} />
            </>
          )}
          {section === "assertions" && <AssertionsEditor draft={draft} edit={edit} />}
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
            disabled={!api.canWrite}
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
        returnFocus={reviewOrigin}
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
                {(Object.keys(candidate.value.config) as (keyof Configuration)[])
                  .filter(
                    (key) => pretty(candidate.value.config?.[key]) !== pretty(base.value[key]),
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
                disabled={busy || !api.canWrite}
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
