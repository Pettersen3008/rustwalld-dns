import { useState } from "react";
import { dnsTypeName, typeScopeText, clientScopeText } from "@/lib/dns-types";
import type { CheckReport } from "@/lib/api";
import { Badge } from "@/components/common";

export function AssertionResults({ report }: { report: CheckReport }) {
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
        Assertion results: {report.failed} failed · {report.assertions - report.failed} passed
      </summary>
      <p className="body-copy">
        These are configured decisions. Upstream connectivity and live DNS replies are not tested.
      </p>
      {!report.assertions && (
        <p className="notice notice-warning">
          No required assertions configured. Only structural validation was performed.
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
              {result.assertion.client} + {result.assertion.domain} ·{" "}
              {dnsTypeName(result.assertion.qtype ?? 1)}
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
                {result.trace.rule?.denyallow && (
                  <>
                    <dt>Excluded from this rule</dt>
                    <dd>{result.trace.rule.denyallow.join(", ")}. Other rules can still apply.</dd>
                  </>
                )}
                {(result.trace.rule?.ctag || result.trace.filter_tags?.length) && (
                  <>
                    <dt>Filtering tags</dt>
                    <dd>{result.trace.filter_tags?.join(", ") || "Unassigned"}</dd>
                  </>
                )}
                {result.trace.rule?.ctag && (
                  <>
                    <dt>Rule tag scope</dt>
                    <dd>{clientScopeText(result.trace.rule.ctag)}</dd>
                  </>
                )}
                {result.trace.rule?.client && (
                  <>
                    <dt>Rule client scope</dt>
                    <dd>{clientScopeText(result.trace.rule.client)}</dd>
                  </>
                )}
                {result.trace.rule?.dnstype && (
                  <>
                    <dt>Rule type scope</dt>
                    <dd>{typeScopeText(result.trace.rule.dnstype)}</dd>
                  </>
                )}
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
                  {result.trace.rule.total_sources > result.trace.rule.sources.length && (
                    <p className="muted">
                      {result.trace.rule.sources.length} of {result.trace.rule.total_sources}{" "}
                      sources shown.
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
          <button disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>
            Next assertions
          </button>
        </div>
      )}
    </details>
  );
}
