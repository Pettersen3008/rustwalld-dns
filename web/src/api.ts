import { z } from "zod";
const action = z.enum(["allow", "block"]);
const list = z.object({ name: z.string(), action, rules: z.string() }).strict();
const rewrite = z
  .object({
    domain: z.string(),
    addresses: z.array(z.string()),
    ttl: z.number().int().nonnegative(),
  })
  .strict();
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
          temporary_exceptions: z
            .array(
              z
                .object({
                  name: z.string(),
                  domain: z.string(),
                  expires_at: z.number().int().positive().max(253402300799),
                })
                .strict(),
            )
            .optional(),
        })
        .strict()
        .transform((policy) => {
          if (policy.temporary_exceptions?.length === 0)
            delete policy.temporary_exceptions;
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
          metadata: bindingMetadataSchema.optional(),
        })
        .strict()
        .transform((binding) => {
          if (binding.metadata?.tags?.length === 0)
            delete binding.metadata.tags;
          if (binding.metadata && Object.keys(binding.metadata).length === 0)
            delete binding.metadata;
          return binding;
        }),
    ),
    allowed_clients: z.array(z.string()),
    assertions: z.array(
      z
        .object({ client: z.string(), domain: z.string(), expected: action })
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
    outcome:
      "waiting" | "unchanged" | "staged" | "failed" | "deferred" | "cancelled";
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
  matcher: "exact" | "suffix" | null;
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
        }),
        permitted: z.boolean(),
        failure: z
          .object({
            kind: z.enum([
              "client_not_permitted",
              "invalid_domain",
              "unexpected_decision",
            ]),
          })
          .nullable(),
        trace: z
          .object({
            domain: z.string(),
            client_name: z.string().nullable(),
            network: z.string().nullable(),
            binding_metadata: bindingMetadataSchema.optional(),
            policy: z.string(),
            decision: z.object({
              action,
              matcher: z.enum(["exact", "suffix"]).nullable(),
              rule: z.number().int().nonnegative().nullable(),
            }),
            rewrite: z.boolean(),
            upstream: z.string(),
            rule: z
              .object({
                domain: z.string(),
                matcher: z.enum(["exact", "suffix"]),
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
  id: number;
  timestamp: string;
  client: string;
  domain: string;
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
};
export type Explanation = {
  generation: number;
  client: string;
  client_name: string | null;
  network: string | null;
  binding_metadata?: BindingMetadata;
  policy: string;
  decision: Decision;
  rule: {
    domain: string;
    matcher: string;
    sources: { list: string; line: number }[];
  } | null;
  rewrite: boolean;
  upstream: string;
  temporary_exception?: {
    name: string;
    domain: string;
    expires_at: number;
  } | null;
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
  constructor(private token: string) {}
  async request<T>(
    path: string,
    options: {
      method?: string;
      body?: unknown;
      etag?: string;
      signal?: AbortSignal;
    } = {},
  ): Promise<Versioned<T>> {
    const response = await fetch(path, {
      method: options.method ?? "GET",
      signal: options.signal,
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(options.body === undefined
          ? {}
          : { "Content-Type": "application/json" }),
        ...(options.etag ? { "If-Match": options.etag } : {}),
      },
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
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
      throw new ApiError(
        response.status,
        detail || `Request failed (${response.status})`,
        body,
      );
    }
    return { value: body as T, etag: response.headers.get("etag") ?? "" };
  }
  async configuration(signal?: AbortSignal) {
    const result = await this.request<unknown>("/api/v1/config", { signal });
    return { ...result, value: configSchema.parse(result.value) };
  }
}
export function errorMessage(error: unknown): string {
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
      if (
        typeof current === "object" &&
        current !== null &&
        !Array.isArray(current)
      ) {
        return Object.fromEntries(
          Object.entries(current).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
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
          sum +
          l.rules
            .split("\n")
            .filter((s) => s.trim() && !s.trim().startsWith("#")).length,
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
