import { MigrationResolvers } from "@/features/policies/migration-resolvers";
import { PeerEditor } from "@/features/policies/peer";
import { useEffect, useRef, useState } from "react";
import { z } from "zod";
import { Upload } from "lucide-react";
import { checkReportSchema, configSchema } from "@/lib/api";
import type { Api, Configuration, Versioned } from "@/lib/api";
import { Badge, ErrorNotice, Field, Modal, Panel } from "@/components/common";

const reportSchema = z.object({
  source: z.enum(["pihole", "adguard"]),
  config: configSchema,
  issues: z
    .array(
      z.object({
        field: z.string(),
        severity: z.enum(["blocker", "warning", "info"]),
        message: z.string(),
      }),
    )
    .max(200),
  total_issues: z.number().int().nonnegative(),
  blockers: z.number().int().nonnegative(),
  translated_rules: z.number().int().nonnegative(),
  ready: z.boolean(),
  validation: checkReportSchema.nullable().optional(),
  publishers: z.array(
    z.object({
      policy: z.string(),
      list: z.string(),
      url: z.string(),
      action: z.enum(["allow", "block"]),
      needs_download: z.boolean(),
    }),
  ),
});
type Report = z.infer<typeof reportSchema>;
export function MigrationEditor({
  api,
  base,
  edit,
}: {
  api: Api;
  base: Versioned<Configuration>;
  edit: (value: Configuration) => void;
}) {
  const [source, setSource] = useState<"pihole" | "adguard">("pihole");
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<Versioned<Report> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [confirm, setConfirm] = useState(false);
  const [page, setPage] = useState(0);
  const controller = useRef<AbortController | null>(null);
  const sourceInput = useRef<HTMLInputElement | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  const stale = !!report && report.etag !== base.etag;
  async function preview() {
    if (!file) return;
    setError(null);
    setReport(null);
    setBusy(true);
    setPage(0);
    const abort = new AbortController();
    controller.current = abort;
    try {
      if (file.size === 0 || file.size > 16 * 1024 * 1024)
        throw new Error("Choose a non-empty backup up to 16 MiB.");
      const result = await api.request<unknown>(`/api/v1/migrations/preview?source=${source}`, {
        method: "POST",
        rawBody: file,
        etag: base.etag,
        signal: abort.signal,
      });
      if (!abort.signal.aborted) setReport({ ...result, value: reportSchema.parse(result.value) });
    } catch (error) {
      if (!abort.signal.aborted) setError(error);
    } finally {
      if (!abort.signal.aborted) {
        setBusy(false);
        setFile(null);
        if (sourceInput.current) sourceInput.current.value = "";
      }
    }
  }
  return (
    <>
      <Panel
        title="Migrate from Pi-hole or AdGuard Home"
        detail="Preview a translated draft and inspect compatibility before changing DNS."
      >
        <p className="body-copy">
          Pi-hole: v5 Teleporter tar.gz, v6 Teleporter ZIP or gravity.db. AdGuard Home:
          AdGuardHome.yaml / JSON, or a ZIP containing that file and filters. Missing publisher
          contents, unsupported settings and identity differences appear in the report.
        </p>
        <p className="body-copy">
          Import keeps destination admission, assertions and resolver configuration unless an
          equivalent source setting is supported. Source passwords, tokens and history are excluded.
          Publisher URLs are never fetched during import.
        </p>
        <details>
          <summary>AdGuard DNS rewrite imports</summary>
          <p className="body-copy">
            Supported $dnsrewrite rules from custom rules and enabled block feeds bundled in an
            AdGuard ZIP become editable local DNS records. A suffix rule includes both its apex and
            descendants. Review surviving answers under Local DNS &amp; routes.
          </p>
          <ul className="body-copy list-disc space-y-2 pl-5">
            <li>
              Exact and suffix TXT/PTR/MX/SRV rewrites are supported alongside A/AAAA, with up to 32
              records per type. Suffix addresses allow one per family. Source TTL is retained.
            </li>
            <li>
              TXT imports use one plain ASCII string up to 255 bytes. Quoted or escaped payloads,
              CNAME/RCODE effects and MX/SRV value exceptions still require review.
            </li>
            <li>
              Same-pattern rewrite exceptions remove matching answers during import and do not allow
              ordinary blocked domains. Exceptions are resolved once, not kept as live rules.
              Partial exceptions, overlapping patterns, CNAME aliases and scopes still require
              review.
            </li>
            <li>Protection pause keeps these answers; filtering disable omits them.</li>
            <li>
              HTTPS/SVCB imports accept priority 0 aliases or ServiceMode priorities 1–65535, with
              an optional port=0..65535 for ServiceMode. Other parameters remain blockers. One alias
              per name and type; no mixed modes or self aliases. Target . is advisory unavailability
              at priority 0 and the record’s name otherwise. Value exceptions remain blockers; a
              whole same-pattern exception can remove these records.
            </li>
          </ul>
          <p className="body-copy">
            Bundled rewrite feeds are a frozen snapshot. Reimport the complete backup to update or
            remove their answers; ordinary list downloads cannot refresh converted rewrites. Missing
            or ambiguous active feed files remain blockers. Import never fetches publisher URLs or
            configures automatic downloads.
          </p>
        </details>
        <details>
          <summary>Encrypted AdGuard resolver requirements</summary>
          <p className="body-copy">
            For AdGuard DoT/DoH, configure a destination resolver profile with the same server name,
            port and HTTPS path before previewing. Import reuses its pinned IP addresses and trust.
            Bootstrap DNS servers are not resolver endpoint addresses. Domain-specific routes with
            literal IP resolvers are translated with parent-name resolver selection for DS. Client
            resolvers are imported independently of filtering inheritance; cache and resolver
            selection differences require review.
          </p>
        </details>
        <div className="form-grid">
          <Field label="Migration source">
            <select
              disabled={busy}
              value={source}
              onChange={(e) => {
                setSource(e.target.value as typeof source);
                setReport(null);
                setError(null);
              }}
            >
              <option value="pihole">Pi-hole</option>
              <option value="adguard">AdGuard Home</option>
            </select>
          </Field>
          <Field
            label="Source backup"
            hint="Maximum 16 MiB. The authenticated appliance parses the upload; it is not saved as a backup."
          >
            <input
              ref={sourceInput}
              type="file"
              disabled={busy}
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
                setReport(null);
                setError(null);
              }}
            />
          </Field>
        </div>
        <ErrorNotice error={error} />
        <button className="primary" disabled={busy || !file} onClick={() => void preview()}>
          <Upload size={16} />
          {busy ? "Inspecting backup…" : "Preview migration"}
        </button>
      </Panel>
      {report && (
        <Panel
          title="Compatibility report"
          detail={`${report.value.translated_rules} translated input lines · ${report.value.total_issues} diagnostics`}
          action={
            <Badge tone={report.value.ready ? "green" : "amber"}>
              {report.value.blockers} BLOCKERS
            </Badge>
          }
        >
          <p className="body-copy">
            {report.value.ready
              ? "The translated draft passed destination checks. Review its policy and resolver choices before activation."
              : "Resolve compatibility blockers before treating this draft as a replacement for the source. You can load it for further editing."}
          </p>
          {report.value.validation?.list_stats?.some((policy) =>
            policy.lists.some((list) => (list.badfilters ?? 0) > 0),
          ) && (
            <output className="notice">
              Rule cancellation:{" "}
              {report.value.validation.list_stats.reduce(
                (n, policy) =>
                  n + policy.lists.reduce((sum, list) => sum + (list.badfilters ?? 0), 0),
                0,
              )}{" "}
              declarations disable{" "}
              {report.value.validation.list_stats.reduce(
                (n, policy) =>
                  n + policy.lists.reduce((sum, list) => sum + (list.disabled ?? 0), 0),
                0,
              )}{" "}
              input lines across imported policies. Removing an exception can expose a block. Review
              the imported lists before activation; the Filters page shows source details after
              promotion.
            </output>
          )}
          {stale && (
            <output className="notice notice-warning">
              The draft base changed after this preview. Preview again before loading the imported
              draft.
            </output>
          )}
          <ol className="compatibility-list">
            {report.value.issues.slice(page * 25, page * 25 + 25).map((issue, i) => (
              <li key={i}>
                <Badge
                  tone={
                    issue.severity === "blocker"
                      ? "red"
                      : issue.severity === "warning"
                        ? "amber"
                        : "neutral"
                  }
                >
                  {issue.severity}
                </Badge>
                <strong>{issue.field}</strong>
                <p>{issue.message}</p>
              </li>
            ))}
          </ol>
          {report.value.total_issues > report.value.issues.length && (
            <p className="notice notice-warning">
              Showing the first {report.value.issues.length} diagnostics. {report.value.blockers}{" "}
              includes blockers beyond the detailed report; split or simplify the source
              configuration before migration.
            </p>
          )}
          <div className="button-row">
            <button disabled={page === 0} onClick={() => setPage(page - 1)}>
              Previous diagnostics
            </button>
            <span>
              Page {page + 1} of {Math.max(1, Math.ceil(report.value.issues.length / 25))}
            </span>
            <button
              disabled={(page + 1) * 25 >= report.value.issues.length}
              onClick={() => setPage(page + 1)}
            >
              Next diagnostics
            </button>
          </div>
          {report.value.publishers.length > 0 && (
            <details>
              <summary>
                {report.value.publishers.length} publisher references requiring review
              </summary>
              <p className="body-copy">
                Configure bootstrap IPs under Downloaded lists before downloading. Missing contents
                remain a migration blocker until their rules are reviewed. Converted rewrite feeds
                require a complete reimport to update their native answers; generic list downloads
                do not refresh these effects.
              </p>
              <pre>{JSON.stringify(report.value.publishers, null, 2)}</pre>
            </details>
          )}
          <MigrationResolvers config={report.value.config} />
          <details>
            <summary>Inspect translated configuration</summary>
            <pre>{JSON.stringify(report.value.config, null, 2)}</pre>
          </details>
          <button disabled={stale || busy} onClick={() => setConfirm(true)}>
            Review replacing local draft
          </button>
        </Panel>
      )}
      <PeerEditor api={api} base={base} edit={edit} />
      <Modal
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Replace your local draft?"
        description="This replaces unsaved draft edits with the translated configuration. Export your current draft first to keep it. Active DNS changes only after validation, shadow review and promotion."
      >
        <p>{report?.value.blockers ?? 0} migration blockers still require review.</p>
        <div className="dialog-actions">
          <button onClick={() => setConfirm(false)}>Keep current draft</button>
          <button
            className="primary"
            disabled={stale || !report}
            onClick={() => {
              if (report && !stale) {
                edit(report.value.config);
                setConfirm(false);
              }
            }}
          >
            Load imported draft
          </button>
        </div>
      </Modal>
    </>
  );
}
