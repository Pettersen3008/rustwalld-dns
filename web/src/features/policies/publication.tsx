import { ArrowRight, CheckCircle2, FlaskConical } from "lucide-react";
import { Badge, Panel } from "@/components/common";
import { countRules } from "@/lib/api";
import type { Configuration, HistoryEvent, Shadow, Versioned, CheckReport } from "@/lib/api";
import { AssertionResults } from "./assertion-results";

type Props = {
  draft: Configuration;
  shadow?: Versioned<Shadow>;
  events?: HistoryEvent[];
  report: CheckReport | null;
  busy: boolean;
  canWrite: boolean;
  validated: boolean;
  conflict: boolean;
  validate: () => Promise<void>;
  stage: () => Promise<void>;
  review: (mode: "promote" | "clear", origin: HTMLElement) => Promise<void>;
};

export function PublicationPanel({
  draft,
  shadow,
  events,
  report,
  busy,
  canWrite,
  validated,
  conflict,
  validate,
  stage,
  review,
}: Props) {
  const shadowEvents = (events ?? []).filter(
    (e) => e.shadow?.generation === shadow?.value.generation,
  );
  return (
    <>
      <Panel
        title="Validate & publish"
        detail={`${draft.policies.length} policies · ${countRules(draft)} raw rules · ${draft.assertions.length} required assertions`}
      >
        <div className="publication-actions">
          <div className="button-row">
            <button className="primary" onClick={validate} disabled={busy || !canWrite}>
              <CheckCircle2 size={16} /> {busy ? "Working…" : "Validate draft"}
            </button>
            <button onClick={stage} disabled={busy || !validated || conflict || !canWrite}>
              <FlaskConical size={16} /> Stage in shadow
            </button>
          </div>
          <div className="publication-shadow">
            {shadow?.value.config ? (
              <>
                <div className="button-row">
                  <Badge tone="amber">Shadow G{shadow.value.generation}</Badge>
                  <button
                    className="primary"
                    disabled={busy || !canWrite}
                    onClick={(event) => {
                      void review("promote", event.currentTarget);
                    }}
                  >
                    Review promotion <ArrowRight size={15} />
                  </button>
                  <button
                    disabled={busy || !canWrite}
                    onClick={(event) => {
                      void review("clear", event.currentTarget);
                    }}
                  >
                    Stop shadow
                  </button>
                </div>
                <p className="body-copy">
                  {shadowEvents.filter((e) => e.shadow?.differs).length} differing decisions /{" "}
                  {shadowEvents.length} candidate events in the latest 500 retained queries.
                </p>
                <small className="muted">
                  This is a retained sample, not a complete traffic impact estimate.
                </small>
              </>
            ) : (
              <p className="body-copy">No shadow candidate. Validate and stage a draft.</p>
            )}
          </div>
          <details className="body-copy publication-guidance">
            <summary>Validation and shadow guidance</summary>
            <p>
              Required assertions are checked by the same compiler that publishes a revision. They
              test permanent policy, excluding temporary exceptions and weekly schedules. Failed
              validation leaves production untouched.
            </p>
            <p>
              Shadow observes real traffic without enforcing the candidate. Review the candidate
              before promotion.
            </p>
          </details>
        </div>
      </Panel>
      {report?.list_stats?.some((policy) =>
        policy.lists.some((list) => (list.badfilters ?? 0) > 0),
      ) && (
        <output className="notice">
          Rule cancellation:{" "}
          {report.list_stats.reduce(
            (n, policy) => n + policy.lists.reduce((sum, list) => sum + (list.badfilters ?? 0), 0),
            0,
          )}{" "}
          declarations disable{" "}
          {report.list_stats.reduce(
            (n, policy) => n + policy.lists.reduce((sum, list) => sum + (list.disabled ?? 0), 0),
            0,
          )}{" "}
          input lines. Removing an exception can expose a block. Inspect the list text before
          promotion.
        </output>
      )}
      {report && <AssertionResults report={report} />}
    </>
  );
}
