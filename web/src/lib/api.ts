import { z } from "zod";
const action = z.enum(["allow", "block"]);
const list = z
  .object({
    name: z.string(),
    action,
    rules: z.string(),
    syntax: z
      .enum([
        "native",
        "adguard",
        "adguard_v2",
        "adguard_v3",
        "adguard_v4",
        "adguard_v5",
        "adguard_v6",
      ])
      .optional(),
  })
  .strict();
const rewrite = z
  .object({
    domain: z.string(),
    addresses: z.array(z.string()),
    ttl: z.number().int().nonnegative(),
  })
  .strict();
export const localRecordSchema = z
  .object({
    domain: z.string(),
    ttl: z.number().int().min(0).max(86400),
    data: z.discriminatedUnion("type", [
      z.object({ type: z.literal("PASSTHROUGH"), family: z.enum(["A", "AAAA"]) }).strict(),
      z.object({ type: z.literal("A"), address: z.string() }).strict(),
      z.object({ type: z.literal("AAAA"), address: z.string() }).strict(),
      z.object({ type: z.literal("CNAME"), target: z.string() }).strict(),
      z.object({ type: z.literal("PTR"), target: z.string() }).strict(),
      z.object({ type: z.literal("TXT"), text: z.string() }).strict(),
      z
        .object({
          type: z.literal("HTTPS"),
          params: z
            .object({ port: z.number().int().min(0).max(65535).optional() })
            .strict()
            .optional(),
          priority: z.number().int().min(0).max(65535),
          target: z.string(),
        })
        .strict(),
      z
        .object({
          type: z.literal("SVCB"),
          params: z
            .object({ port: z.number().int().min(0).max(65535).optional() })
            .strict()
            .optional(),
          priority: z.number().int().min(0).max(65535),
          target: z.string(),
        })
        .strict(),
      z
        .object({ type: z.literal("MX"), preference: z.number().int(), exchange: z.string() })
        .strict(),
      z
        .object({
          type: z.literal("SRV"),
          priority: z.number().int(),
          weight: z.number().int(),
          port: z.number().int(),
          target: z.string(),
        })
        .strict(),
    ]),
  })
  .strict();
export type LocalRecord = z.infer<typeof localRecordSchema>;
const source = z
  .object({
    policy: z.string(),
    list: z.string(),
    url: z.string(),
    bootstrap_ips: z.array(z.string()),
    ca_pem: z.string().optional(),
    refresh_interval_secs: z.number().int().min(300).max(2592000).optional(),
    download: z
      .object({
        retrieved_at: z.number().int().positive(),
        sha256: z.string(),
        bytes: z.number().int().positive(),
      })
      .strict()
      .optional(),
  })
  .strict();
export const bindingMetadataSchema = z
  .object({
    group: z.string().optional(),
    owner: z.string().optional(),
    vlan: z.number().int().min(1).max(4094).optional(),
    tags: z.array(z.string()).max(16).optional(),
    note: z.string().optional(),
  })
  .strict();
export type BindingMetadata = z.infer<typeof bindingMetadataSchema>;
export const SERVICE_IDS_V1 = ["discord", "reddit", "tiktok", "youtube"] as const;
export const SERVICE_IDS = [
  ...SERVICE_IDS_V1,
  "netflix",
  "spotify",
  "twitch",
  "steam",
  "roblox",
  "whatsapp",
  "telegram",
  "signal",
] as const;
export const configSchema = z
  .object({
    default_policy: z.string(),
    policies: z.array(
      z
        .object({
          name: z.string(),
          upstream: z.string(),
          lists: z.array(list),
          rewrites: z.array(rewrite),
          dns_records: z.array(localRecordSchema).optional(),
          routes: z
            .array(z.object({ domain: z.string(), upstream: z.string() }).strict())
            .optional(),
          ds_routing: z.enum(["question", "parent"]).optional(),
          block_mode: z.enum(["nx_domain", "no_data", "null_ip"]).optional(),
          blocked_services: z
            .object({
              catalog_version: z.union([z.literal(1), z.literal(2)]).default(1),
              schedule: z
                .object({
                  time_zone: z.string(),
                  mode: z.enum(["block", "allow"]).default("block"),
                  windows: z
                    .array(
                      z
                        .object({
                          days: z
                            .array(z.enum(["mon", "tue", "wed", "thu", "fri", "sat", "sun"]))
                            .min(1)
                            .max(7),
                          start: z.string(),
                          end: z.string(),
                        })
                        .strict(),
                    )
                    .max(32),
                })
                .strict()
                .optional(),
              ids: z.array(z.enum(SERVICE_IDS)).max(12).default([]),
            })
            .strict()
            .optional(),
          safe_search: z
            .object({
              catalog_version: z.literal(1).default(1),
              google: z.boolean().default(false),
              bing: z.boolean().default(false),
              duckduckgo: z.boolean().default(false),
              youtube: z.enum(["off", "moderate", "strict"]).default("off"),
            })
            .strict()
            .optional(),
          temporary_exceptions: z
            .array(
              z
                .object({
                  name: z.string(),
                  domain: z.string(),
                  expires_at: z.number().int().positive().max(253402300799),
                  clients: z.array(z.string()).max(64).optional(),
                  include_subdomains: z.boolean().optional(),
                })
                .strict(),
            )
            .optional(),
        })
        .strict()
        .transform((policy) => {
          if (policy.blocked_services?.ids.length === 0 && !policy.blocked_services.schedule)
            delete policy.blocked_services;
          if (policy.temporary_exceptions?.length === 0) delete policy.temporary_exceptions;
          if (policy.dns_records?.length === 0) delete policy.dns_records;
          if (policy.routes?.length === 0) delete policy.routes;
          if (policy.block_mode === "nx_domain") delete policy.block_mode;
          if (
            policy.safe_search &&
            !policy.safe_search.google &&
            !policy.safe_search.bing &&
            !policy.safe_search.duckduckgo &&
            policy.safe_search.youtube === "off"
          )
            delete policy.safe_search;
          for (const exception of policy.temporary_exceptions ?? []) {
            if (!exception.clients?.length) delete exception.clients;
            if (!exception.include_subdomains) delete exception.include_subdomains;
          }
          for (const list of policy.lists) if (list.syntax === "native") delete list.syntax;
          return policy;
        }),
    ),
    upstreams: z.array(
      z
        .object({
          name: z.string(),
          addresses: z.array(z.string()),
          timeout_ms: z.number().int().positive(),
          transport: z
            .discriminatedUnion("kind", [
              z.object({ kind: z.literal("udp") }).strict(),
              z
                .object({
                  kind: z.literal("tls"),
                  server_name: z.string(),
                  ca_pem: z.string().nullable().default(null),
                  max_connections: z.number().int().positive().default(2),
                })
                .strict(),
              z
                .object({
                  kind: z.literal("https"),
                  server_name: z.string(),
                  path: z.string().default("/dns-query"),
                  ca_pem: z.string().nullable().default(null),
                  max_connections: z.number().int().positive().default(2),
                })
                .strict(),
            ])
            .optional(),
        })
        .strict(),
    ),
    bindings: z.array(
      z
        .object({
          name: z.string(),
          network: z.string(),
          policy: z.string(),
          filter_tags: z.array(z.string()).max(21).optional(),
          metadata: bindingMetadataSchema.optional(),
        })
        .strict()
        .transform((binding) => {
          if (binding.metadata?.tags?.length === 0) delete binding.metadata.tags;
          if (binding.metadata && Object.keys(binding.metadata).length === 0)
            delete binding.metadata;
          return binding;
        }),
    ),
    allowed_clients: z.array(z.string()),
    assertions: z.array(
      z
        .object({
          client: z.string(),
          domain: z.string(),
          qtype: z.number().int().min(1).max(65535).optional(),
          expected: action,
        })
        .strict(),
    ),
    filter_sources: z.array(source).optional(),
  })
  .strict()
  .transform((config) => {
    if (config.filter_sources?.length === 0) delete config.filter_sources;
    return config;
  });
export type Configuration = z.infer<typeof configSchema>;
export type FilterSource = z.infer<typeof source>;
export type RefreshStatus = {
  generation: number;
  paused: "shadow_review" | "policy_mutation" | null;
  running: {
    generation: number;
    source: number;
    policy: string;
    list: string;
  } | null;
  queued: { generation: number; source: number } | null;
  entries: {
    source: number;
    policy: string;
    list: string;
    interval_secs: number;
    next_check_at: number;
    last_checked_at: number | null;
    checked_generation: number | null;
    last_http_status: number | null;
    last_download_bytes: number | null;
    outcome: "waiting" | "unchanged" | "staged" | "failed" | "deferred" | "cancelled";
    error: string | null;
  }[];
};
export type Versioned<T> = { value: T; etag: string };
export type Status = {
  version: string;
  generation: number;
  shadow_generation: number | null;
  policies: number;
  cache_entries: number;
  inflight: number;
  dns_listen: string;
};
export type Decision = {
  action: "allow" | "block";
  matcher: "exact" | "suffix" | "regex" | null;
  rule: number | null;
};
export const checkReportSchema = z.object({
  basis: z.literal("permanent_policy"),
  valid: z.boolean(),
  assertions: z.number().int().nonnegative(),
  failed: z.number().int().nonnegative(),
  policies: z.number().int().positive(),
  list_stats: z
    .array(
      z.object({
        policy: z.string(),
        lists: z.array(
          z.object({
            name: z.string(),
            raw: z.number(),
            unique: z.number(),
            duplicates: z.number(),
            invalid: z.number(),
            redundant: z.number(),
            badfilters: z.number().int().nonnegative().optional(),
            disabled: z.number().int().nonnegative().optional(),
          }),
        ),
      }),
    )
    .optional(),
  results: z
    .array(
      z.object({
        assertion: z.object({
          client: z.string(),
          domain: z.string(),
          expected: action,
          qtype: z.number().int().min(1).max(65535).optional(),
        }),
        permitted: z.boolean(),
        failure: z
          .object({
            kind: z.enum(["client_not_permitted", "invalid_domain", "unexpected_decision"]),
          })
          .nullable(),
        trace: z
          .object({
            domain: z.string(),
            client_name: z.string().nullable(),
            network: z.string().nullable(),
            binding_metadata: bindingMetadataSchema.optional(),
            filter_tags: z.array(z.string()).max(21).optional(),
            policy: z.string(),
            decision: z.object({
              action,
              matcher: z.enum(["exact", "suffix", "regex"]).nullable(),
              rule: z.number().int().nonnegative().nullable(),
            }),
            rewrite: z.boolean(),
            upstream: z.string(),
            rule: z
              .object({
                domain: z.string(),
                matcher: z.enum(["exact", "suffix", "regex"]),
                denyallow: z.array(z.string()).max(64).optional(),
                client: z
                  .object({
                    include: z.array(z.string()).max(64),
                    exclude: z.array(z.string()).max(64),
                  })
                  .optional(),
                ctag: z
                  .object({
                    include: z.array(z.string()).max(21),
                    exclude: z.array(z.string()).max(21),
                  })
                  .optional(),
                dnstype: z
                  .object({
                    include: z.array(z.number().int().min(1).max(65535)).max(64),
                    exclude: z.array(z.number().int().min(1).max(65535)).max(64),
                  })
                  .optional(),
                sources: z
                  .array(
                    z.object({
                      list: z.string(),
                      line: z.number().int().positive(),
                    }),
                  )
                  .max(16),
                total_sources: z.number().int().positive(),
              })
              .nullable(),
          })
          .nullable(),
      }),
    )
    .max(10000),
});
export type CheckReport = z.infer<typeof checkReportSchema>;
export function failedCheckReport(error: unknown): CheckReport | null {
  if (!(error instanceof ApiError)) return null;
  const result = z.object({ report: checkReportSchema }).safeParse(error.body);
  return result.success ? result.data.report : null;
}
export type HistoryEvent = {
  client_masked?: boolean;
  id: number;
  timestamp: string;
  client: string;
  domain: string;
  matched_domain?: string | null;
  matched_type?: number | null;
  qtype: number;
  generation: number;
  policy_id: number;
  action: "allow" | "block";
  rule_id: number | null;
  decision_cached: boolean;
  temporary_exception?: number | null;
  response_code: number;
  source: string;
  latency_us: number;
  shadow: {
    generation: number;
    policy_id: number;
    decision: Decision;
    rewrite: boolean;
    differs: boolean;
    temporary_exception?: number | null;
  } | null;
  service_schedule?: "active" | "inactive" | "invalid_clock" | null;
};
export type Explanation = {
  generation: number;
  client: string;
  /** False when allowed_clients does not admit the client; DNS drops its queries. */
  permitted: boolean;
  client_name: string | null;
  network: string | null;
  binding_metadata?: BindingMetadata;
  filter_tags?: string[];
  policy: string;
  decision: Decision;
  rule: {
    domain: string;
    matcher: string;
    denyallow?: string[];
    dnstype?: { include: number[]; exclude: number[] };
    client?: { include: string[]; exclude: string[] };
    ctag?: { include: string[]; exclude: string[] };
    sources: { list: string; line: number }[];
  } | null;
  rewrite: boolean;
  safe_search?: SafeSearchMatch | null;
  service_schedule?: {
    time_zone: string;
    state: "active" | "inactive" | "invalid_clock";
    ttl_cap: number;
  } | null;
  upstream: string;
  temporary_exception?: {
    name: string;
    domain: string;
    expires_at: number;
  } | null;
};
export type SafeSearchMatch = {
  provider: "google" | "bing" | "duckduckgo" | "youtube";
  target: string;
  catalog_version: number;
};
export type TemporaryState = {
  generation: number;
  exceptions: {
    policy: string;
    index: number;
    name: string;
    domain: string;
    configured_domain: string;
    expires_at: number;
    active: boolean;
    clients?: string[];
    include_subdomains?: boolean;
  }[];
};
export type Shadow = {
  generation: number | null;
  config: Configuration | null;
};
export type Revision = {
  id: number;
  timestamp: string;
  actor: string;
  state: string;
  diff: string;
};
export type Filter = {
  policy: string;
  generation: number;
  effective_rules: number;
  payload_bytes_estimate: number;
  lists: {
    name: string;
    raw: number;
    unique: number;
    duplicates: number;
    invalid: number;
    redundant: number;
    badfilters?: number;
    disabled?: number;
  }[];
  cancellation_targets?: number;
  cancellations?: {
    action: "allow" | "block";
    pattern: string;
    directives: number;
    directive_sources: { list: string; line: number }[];
    disabled: number;
    disabled_sources: { list: string; line: number }[];
  }[];
};
export type UpstreamFailure =
  | "deadline"
  | "connection"
  | "tls_authentication"
  | "tls_protocol"
  | "http_protocol"
  | "http_status"
  | "http_envelope"
  | "dns_response"
  | "servfail"
  | "refused"
  | "cancelled"
  | "local_error";
export type Upstream = {
  generation: number;
  name: string;
  transport: "udp" | "tls" | "https";
  path: string | null;
  server_name: string | null;
  servers: {
    address: string;
    attempts: number;
    successes: number;
    inflight: number;
    failures: Record<UpstreamFailure, number>;
    ewma_us: number;
    backoff_skips: number;
    recovery_probes: number;
    admission: {
      state: "ready" | "cooldown" | "probing";
      retry_after_ms: number;
    };
  }[];
};
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: unknown,
  ) {
    super(message);
  }
}
export class Api {
  private readonly lifetime = new AbortController();
  role: "read_only" | "operator" | "administrator" = "administrator";
  constructor(
    private token: string,
    private csrf: string | null = null,
  ) {}
  get canWrite() {
    return this.role !== "read_only";
  }
  async loadIdentity() {
    const result = await this.request<{ role: "read_only" | "operator" | "administrator" }>(
      "/api/v1/auth/session",
    );
    this.role = result.value.role;
  }
  async logout() {
    if (this.csrf) {
      try {
        await this.request("/api/v1/auth/logout", {
          method: "POST",
          signal: AbortSignal.timeout(5000),
        });
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 401)) throw error;
      }
    }
  }
  disconnect() {
    this.token = "";
    this.csrf = null;
    this.lifetime.abort();
  }
  async request<T>(
    path: string,
    options: {
      method?: string;
      body?: unknown;
      rawBody?: BodyInit;
      etag?: string;
      signal?: AbortSignal;
    } = {},
  ): Promise<Versioned<T>> {
    const response = await fetch(path, {
      method: options.method ?? "GET",
      signal: AbortSignal.any([this.lifetime.signal, ...(options.signal ? [options.signal] : [])]),
      redirect: "error",
      cache: "no-store",
      headers: {
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(this.csrf ? { "X-CSRF-Token": this.csrf } : {}),
        ...(options.rawBody === undefined
          ? options.body === undefined
            ? {}
            : { "Content-Type": "application/json" }
          : { "Content-Type": "application/octet-stream" }),
        ...(options.etag ? { "If-Match": options.etag } : {}),
      },
      body:
        options.rawBody ?? (options.body === undefined ? undefined : JSON.stringify(options.body)),
    });
    const text = await response.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    if (!response.ok) {
      const detail =
        typeof body === "object" && body !== null && "error" in body
          ? String(body.error)
          : String(body);
      throw new ApiError(response.status, detail || `Request failed (${response.status})`, body);
    }
    return { value: body as T, etag: response.headers.get("etag") ?? "" };
  }
  async configuration(signal?: AbortSignal) {
    const result = await this.request<unknown>("/api/v1/config", { signal });
    return { ...result, value: configSchema.parse(result.value) };
  }
}
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 412 && /privacy/i.test(error.message))
    return "Privacy preferences changed. Reload the current preferences and review your changes before retrying.";
  if (error instanceof ApiError && error.status === 412)
    return "The active or shadow revision changed. Your draft is preserved. Reload the active configuration and review your changes before retrying.";
  return error instanceof Error ? error.message : String(error);
}
export function lines(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}
export function pretty(value: unknown): string {
  return JSON.stringify(
    value,
    (_key, current: unknown) => {
      if (typeof current === "object" && current !== null && !Array.isArray(current)) {
        return Object.fromEntries(
          Object.entries(current).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        );
      }
      return current;
    },
    2,
  );
}
export function countRules(config: Configuration): number {
  return config.policies.reduce(
    (n, p) =>
      n +
      p.lists.reduce(
        (sum, l) =>
          sum + l.rules.split("\n").filter((s) => s.trim() && !s.trim().startsWith("#")).length,
        0,
      ),
    0,
  );
}
export function formatTime(timestamp: string): string {
  return new Date(
    timestamp.includes("T") ? timestamp : timestamp.replace(" ", "T") + "Z",
  ).toLocaleString();
}

export const serviceCatalogSchema = z
  .object({
    catalog_version: z.union([z.literal(1), z.literal(2)]),
    services: z
      .array(
        z
          .object({
            id: z.enum(SERVICE_IDS),
            name: z.string(),
            category: z.string(),
            suffixes: z.array(z.string()),
            exact_names: z.array(z.string()),
            limitations: z.array(z.string()).optional(),
            references: z.array(z.url().startsWith("https://")).optional(),
          })
          .strict(),
      )
      .max(12),
  })
  .strict();
