import { useState } from "react";
import type { Api, Configuration, TemporaryState } from "./api";
import { useApi } from "./hooks";
import { Badge, ErrorNotice, Field, Panel } from "./components";

export function TemporaryExceptionsEditor({
  api,
  draft,
  edit,
}: {
  api: Api;
  draft: Configuration;
  edit: (value: Configuration) => void;
}) {
  const state = useApi<TemporaryState>(
    api,
    "temporary-exceptions",
    "/api/v1/temporary-exceptions",
  );
  const [policyIndex, setPolicyIndex] = useState(0);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [duration, setDuration] = useState("3600");
  const [page, setPage] = useState(0);
  const index = Math.min(policyIndex, draft.policies.length - 1);
  const policy = draft.policies[index];
  const exceptions = policy?.temporary_exceptions ?? [];
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(exceptions.length / 10) - 1),
  );
  function replace(
    values: NonNullable<
      Configuration["policies"][number]["temporary_exceptions"]
    >,
  ) {
    edit({
      ...draft,
      policies: draft.policies.map((policy, p) =>
        p === index
          ? (() => {
              const next = { ...policy };
              if (values.length) next.temporary_exceptions = values;
              else delete next.temporary_exceptions;
              return next;
            })()
          : policy,
      ),
    });
  }
  return (
    <Panel
      title="Temporary allows"
      detail="One exact domain, for every admitted client using the selected policy."
    >
      <p className="body-copy">
        Changes follow the validation and shadow workflow. Expiry continues if
        management or history storage is unavailable. Answers already used by
        applications cannot be withdrawn.
      </p>
      <ErrorNotice
        error={state.error}
        retry={() => {
          void state.refetch();
        }}
      />
      {state.data && (
        <p className="muted exception-status">
          Active G{state.data.generation}:{" "}
          {state.data.exceptions.filter((e) => e.active).length} active
          temporary allows. Draft entries below are not automatically applied.
        </p>
      )}
      <Field label="Exception policy">
        <select
          value={index}
          onChange={(e) => {
            setPolicyIndex(Number(e.target.value));
            setPage(0);
          }}
        >
          {draft.policies.map((policy, index) => (
            <option key={index} value={index}>
              {policy.name}
            </option>
          ))}
        </select>
      </Field>
      <div className="form-grid exception-form">
        <Field label="Exception name">
          <input
            value={name}
            maxLength={128}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label="Exact domain">
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="service.example"
          />
        </Field>
        <Field label="Allow for">
          <select
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
          >
            <option value="900">15 minutes</option>
            <option value="3600">1 hour</option>
            <option value="28800">8 hours</option>
            <option value="86400">24 hours</option>
          </select>
        </Field>
      </div>
      <button
        className="primary"
        disabled={
          !policy || !name.trim() || !domain.trim() || exceptions.length >= 1024
        }
        onClick={() => {
          replace([
            ...exceptions,
            {
              name: name.trim(),
              domain: domain.trim(),
              expires_at: Math.floor(Date.now() / 1000) + Number(duration),
            },
          ]);
          setName("");
          setDomain("");
          setPage(Math.floor(exceptions.length / 10));
        }}
      >
        Add temporary allow to draft
      </button>
      <div className="exception-list">
        {!exceptions.length && (
          <p className="muted">No temporary allows in this policy draft.</p>
        )}
        {exceptions
          .slice(currentPage * 10, (currentPage + 1) * 10)
          .map((exception, row) => {
            const position = currentPage * 10 + row;
            const published = state.data?.exceptions.find(
              (active) =>
                active.policy === policy?.name &&
                active.name === exception.name &&
                active.expires_at === exception.expires_at &&
                active.configured_domain === exception.domain,
            );
            return (
              <article className="exception-row" key={position}>
                <div>
                  <strong>{exception.name}</strong>
                  <p className="mono">{exception.domain}</p>
                  <p className="muted">
                    Expires{" "}
                    {new Date(exception.expires_at * 1000).toLocaleString()}
                  </p>
                </div>
                <Badge tone={published?.active ? "green" : "neutral"}>
                  {published
                    ? published.active
                      ? "ACTIVE"
                      : "EXPIRED"
                    : Date.now() / 1000 >= exception.expires_at
                      ? "EXPIRED DRAFT"
                      : "DRAFT"}
                </Badge>
                <button
                  onClick={() =>
                    replace(exceptions.filter((_, i) => i !== position))
                  }
                  aria-label={`Remove exception ${exception.name} from draft`}
                >
                  Remove from draft
                </button>
              </article>
            );
          })}
      </div>
      {exceptions.length > 10 && (
        <div className="button-row">
          <button
            disabled={!currentPage}
            onClick={() => setPage(currentPage - 1)}
          >
            Previous exceptions
          </button>
          <span>
            Page {currentPage + 1} of {Math.ceil(exceptions.length / 10)}
          </span>
          <button
            disabled={(currentPage + 1) * 10 >= exceptions.length}
            onClick={() => setPage(currentPage + 1)}
          >
            Next exceptions
          </button>
        </div>
      )}
      <p className="body-copy">
        Removing an entry edits this draft. Apply the reviewed candidate to
        revoke it. Rollback preserves its original expiry.
      </p>
    </Panel>
  );
}
