import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { serviceCatalogSchema, SERVICE_IDS_V1 } from "@/lib/api";
import type { Api, Configuration } from "@/lib/api";
import { ServiceScheduleEditor } from "@/features/policies/service-schedule";
import { Badge, ErrorNotice, Field, Panel } from "@/components/common";

export function ServicesEditor({
  api,
  draft,
  edit,
}: {
  api: Api;
  draft: Configuration;
  edit: (value: Configuration) => void;
}) {
  const catalogHint = useId();
  const [selection, setSelection] = useState(0);
  const [catalogSelection, setCatalogSelection] = useState<Record<string, 1 | 2>>({});
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const index = Math.min(selection, draft.policies.length - 1);
  const policy = draft.policies[index];
  const version =
    policy?.blocked_services?.catalog_version ?? catalogSelection[policy?.name ?? ""] ?? 1;
  const catalog = useQuery({
    queryKey: ["service-catalog", version],
    queryFn: async ({ signal }) => {
      const result = serviceCatalogSchema.parse(
        (await api.request(`/api/v1/service-catalog?version=${version}`, { signal })).value,
      );
      if (result.catalog_version !== version)
        throw new Error("Service catalog version does not match the requested draft.");
      return result;
    },
    staleTime: Infinity,
  });
  if (!policy) return null;
  const selected = policy.blocked_services?.ids ?? [];
  const canUseV1 = selected.every((id) => SERVICE_IDS_V1.some((old) => old === id));
  function chooseVersion(value: 1 | 2) {
    if (value === 1 && !canUseV1) return;
    setCategory("");
    setCatalogSelection((previous) => ({ ...previous, [policy.name]: value }));
    const settings = policy.blocked_services;
    if (settings)
      edit({
        ...draft,
        policies: draft.policies.map((entry, i) =>
          i === index
            ? {
                ...entry,
                blocked_services: { ...settings, catalog_version: value },
              }
            : entry,
        ),
      });
  }
  const categories = [...new Set(catalog.data?.services.map((service) => service.category))].sort();
  const visible =
    catalog.data?.services
      .filter(
        (service) =>
          (!category || service.category === category) &&
          [service.name, service.id, service.category, ...service.suffixes, ...service.exact_names]
            .join(" ")
            .toLowerCase()
            .includes(search.trim().toLowerCase()),
      )
      .sort((a, b) => a.name.localeCompare(b.name)) ?? [];
  function toggle(id: (typeof selected)[number], enabled: boolean) {
    const ids = enabled ? [...selected, id] : selected.filter((value) => value !== id);
    edit({
      ...draft,
      policies: draft.policies.map((entry, i) =>
        i === index
          ? {
              ...entry,
              blocked_services: ids.length
                ? { ...policy.blocked_services, catalog_version: version, ids }
                : undefined,
            }
          : entry,
      ),
    });
  }
  return (
    <Panel
      title="Service domain blocking"
      detail="Choose services for devices bound to this policy. Review the listed domain coverage before promoting the draft."
      action={
        <Badge tone={selected.length ? "amber" : "neutral"}>
          {selected.length ? `${selected.length} SELECTED IN DRAFT` : "OFF"}
        </Badge>
      }
    >
      <Field label="Service blocking policy">
        <select
          value={index}
          onChange={(event) => {
            setSelection(Number(event.target.value));
            setCategory("");
          }}
        >
          {draft.policies.map((entry, i) => (
            <option key={i} value={i}>
              {entry.name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Service catalog">
        <select
          value={version}
          aria-describedby={catalogHint}
          onChange={(event) => chooseVersion(Number(event.target.value) === 2 ? 2 : 1)}
        >
          <option value="1" disabled={!canUseV1}>
            Catalog v1 · 4 services
          </option>
          <option value="2">Catalog v2 · 12 services</option>
        </select>
      </Field>
      <p id={catalogHint} className="body-copy">
        Catalog changes stay in the draft and preserve selected services and weekly windows. Remove
        services unavailable in v1 before downgrading.
      </p>
      <div className="form-grid">
        <Field label="Search services">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Name, category or domain"
          />
        </Field>
        <Field label="Service category">
          <select value={category} onChange={(event) => setCategory(event.target.value)}>
            <option value="">All categories</option>
            {categories.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {catalog.data && (
        <output>
          {visible.length} of {catalog.data.services.length} services shown · {selected.length}{" "}
          selected in this policy
        </output>
      )}
      <ErrorNotice error={catalog.error} retry={() => void catalog.refetch()} />
      {catalog.isPending && <output>Loading service coverage…</output>}
      <div className="service-list">
        {visible.map((service) => (
          <div className="service-row" key={service.id}>
            <label className="service-choice">
              <input
                type="checkbox"
                aria-label={`Block ${service.name}`}
                checked={selected.includes(service.id)}
                onChange={(event) => toggle(service.id, event.target.checked)}
              />
              <span>
                <strong>{service.name}</strong>
                <small>{service.category}</small>
              </span>
            </label>
            <details>
              <summary>
                {service.name} coverage · catalog v{version}
              </summary>
              <div className="body-copy">
                {service.suffixes.length > 0 && (
                  <p>
                    Apex and subdomains: <span className="mono">{service.suffixes.join(", ")}</span>
                  </p>
                )}
                {service.exact_names.length > 0 && (
                  <p>
                    Exact names only: <span className="mono">{service.exact_names.join(", ")}</span>
                  </p>
                )}
                {service.limitations?.map((note) => (
                  <p key={note}>{note}</p>
                ))}
                {service.references?.map((url, reference) => (
                  <p key={url}>
                    <a href={url} target="_blank" rel="noreferrer">
                      {service.name} provider reference {reference + 1}
                    </a>
                  </p>
                ))}
              </div>
            </details>
          </div>
        ))}
      </div>
      {catalog.data && !visible.length && (
        <p className="body-copy">No services match these filters. Your selections are preserved.</p>
      )}
      <ServiceScheduleEditor api={api} draft={draft} index={index} edit={edit} />
      <p className="body-copy">
        Blocks the listed domains and their content, not just ads. Allow rules, temporary filtering
        pauses and explicit local DNS retain their overrides. Blocking a YouTube name takes
        precedence over SafeSearch unless a filter override applies.
      </p>
      <details>
        <summary>Limits and extending coverage</summary>
        <p className="body-copy">
          Catalogs contain explicit first-party domain groups; categories organize the list.
          Media/CDN endpoints outside the listed names may still work; add reviewed custom filter
          rules when needed. It does not promise to block every app connection. Client caches, other
          resolvers, VPNs and hardcoded IPs can bypass or delay DNS policy.
        </p>
      </details>
    </Panel>
  );
}
