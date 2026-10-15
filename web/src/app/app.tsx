import { useState, useEffect, useMemo, lazy } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router";
import { Button } from "@/components/ui/button";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  LayoutDashboard,
  ListFilter,
  SlidersHorizontal,
  Network,
  Layers,
  Radio,
  History,
  LogOut,
  ArrowRight,
  RotateCw,
  Sun,
  Moon,
} from "lucide-react";
import type { FormEvent } from "react";
import { Api, pretty } from "@/lib/api";
import type { Configuration, Status, Versioned } from "@/lib/api";
import { Badge, ErrorNotice, Loading, Modal, DeferredView } from "@/components/common";
import { Overview } from "@/features/overview/overview";
import { Clients } from "@/features/clients/clients";
const Filters = lazy(() =>
  import("@/features/filters/filters").then((module) => ({ default: module.Filters })),
);
import { Upstreams } from "@/features/upstreams/upstreams";
import { Revisions } from "@/features/revisions/revisions";
const Security = lazy(() =>
  import("@/features/security/security").then((module) => ({ default: module.Security })),
);
const Workbench = lazy(() =>
  import("@/features/policies/workbench").then((module) => ({ default: module.Workbench })),
);
const Queries = lazy(() =>
  import("@/features/queries/queries").then((module) => ({ default: module.Queries })),
);
const Setup = lazy(() =>
  import("@/features/setup/setup").then((module) => ({ default: module.Setup })),
);
import "@/styles/globals.css";
const navigation = [
  {
    id: "setup",
    label: "Setup & integrations",
    icon: Network,
    caption: "Appliance",
    title: "Setup & integrations",
    description: "Bring your network online and inspect optional integrations.",
  },
  {
    id: "overview",
    label: "Overview",
    icon: LayoutDashboard,
    caption: "DNS management",
    title: "Overview",
    description: "Live protection, traffic and the policy serving your network.",
  },
  {
    id: "queries",
    label: "Query log",
    icon: ListFilter,
    caption: "Observe & explain",
    title: "Query log",
    description: "Find a request and inspect the decision behind its answer.",
  },
  {
    id: "policies",
    label: "Policies",
    icon: SlidersHorizontal,
    caption: "Policy workbench",
    title: "Policy workbench",
    description: "Validate, observe in shadow, then promote a reviewed change.",
  },
  {
    id: "clients",
    label: "Clients & networks",
    icon: Network,
    caption: "Client identity",
    title: "Clients & networks",
    description: "Control admission and assign policies by source network.",
  },
  {
    id: "filters",
    label: "Filter lists",
    icon: Layers,
    caption: "Filter intelligence",
    title: "Filter lists",
    description: "Inspect rule quality and what each policy actually enforces.",
  },
  {
    id: "upstreams",
    label: "Upstreams",
    icon: Radio,
    caption: "Resolver health",
    title: "Upstreams",
    description: "Resolver availability, sequential fallback and recovery.",
  },
  {
    id: "history",
    label: "Revision history",
    icon: History,
    caption: "Configuration history",
    title: "Revisions",
    description: "Inspect a saved configuration or return to a validated revision.",
  },
  {
    id: "security",
    label: "Access & sessions",
    icon: ShieldCheck,
    caption: "Administration",
    title: "Access & sessions",
    description: "Local sign-in, 2FA and scoped automation tokens.",
  },
] as const;
type View = (typeof navigation)[number]["id"];
export function App() {
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  const toggleTheme = () => setTheme((value) => (value === "light" ? "dark" : "light"));
  const [session, setSession] = useState<{
    api: Api;
    initial: Versioned<Configuration>;
    client: QueryClient;
  } | null>(null);
  const [token, setToken] = useState("");
  const [mode, setMode] = useState<"token" | "password">("token");
  const [authInfo, setAuthInfo] = useState<{
    password_enabled: boolean;
    totp_enabled: boolean;
  } | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/v1/auth/info", {
      signal: controller.signal,
      cache: "no-store",
      redirect: "error",
    })
      .then(async (response) => {
        if (!response.ok) return;
        const value = (await response.json()) as {
          password_enabled: boolean;
          totp_enabled: boolean;
        };
        if (!controller.signal.aborted) {
          setAuthInfo(value);
          if (value.password_enabled) setMode("password");
        }
      })
      .catch(() => {});
    return () => controller.abort();
  }, []);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  async function login(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      let api: Api;
      if (mode === "password") {
        if (window.location.protocol !== "https:")
          throw new Error("Password login requires HTTPS.");
        const response = await fetch("/api/v1/auth/login", {
          method: "POST",
          redirect: "error",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, ...(authInfo?.totp_enabled ? { totp } : {}) }),
          signal: AbortSignal.timeout(15000),
        });
        const result = (await response.json()) as { error?: string; csrf_token?: string };
        if (!response.ok || !result.csrf_token) throw new Error(result.error ?? "Sign-in failed.");
        api = new Api("", result.csrf_token);
      } else api = new Api(token);
      await api.loadIdentity();
      const initial = await api.configuration();
      setSession({
        api,
        initial,
        client: new QueryClient({
          defaultOptions: {
            queries: { retry: 1, staleTime: 2000, refetchOnWindowFocus: true },
          },
        }),
      });
      setToken("");
      setPassword("");
      setTotp("");
    } catch (error) {
      setError(error);
    } finally {
      setPassword("");
      setTotp("");
      setBusy(false);
    }
  }
  if (session)
    return (
      <QueryClientProvider client={session.client}>
        <Session
          api={session.api}
          initial={session.initial}
          theme={theme}
          toggleTheme={toggleTheme}
          sessionError={error}
          onLogout={() => {
            void session.api
              .logout()
              .then(() => {
                session.api.disconnect();
                session.client.clear();
                setSession(null);
                setError(null);
              })
              .catch((error) => setError(error));
          }}
        />
      </QueryClientProvider>
    );
  return (
    <main className="login">
      <ThemeToggle theme={theme} toggle={toggleTheme} />
      <section className="login-form">
        <Brand />
        <h1>Sign in to DNS management</h1>
        <p>
          {mode === "password"
            ? "Sign in with your local administrator account."
            : "Enter your appliance’s management token."}
        </p>
        {authInfo?.password_enabled && (
          <div className="button-row">
            <button disabled={busy} onClick={() => setMode("password")}>
              Password & 2FA
            </button>
            <button disabled={busy} onClick={() => setMode("token")}>
              API token
            </button>
          </div>
        )}
        <form onSubmit={login}>
          {mode === "password" ? (
            <>
              <label className="field">
                <span>Username</span>
                <input
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  maxLength={128}
                />
              </label>
              <label className="field">
                <span>Password</span>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  maxLength={1024}
                />
              </label>
              {authInfo?.totp_enabled && (
                <label className="field">
                  <span>Authenticator code</span>
                  <input
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={totp}
                    onChange={(e) => setTotp(e.target.value)}
                    required
                  />
                </label>
              )}
            </>
          ) : (
            <label className="field">
              <span>Management token</span>
              <input
                name="token"
                aria-label="Management token"
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
              />
            </label>
          )}
          <ErrorNotice error={error} />
          <Button
            className="primary"
            type="submit"
            disabled={busy || (mode === "token" ? !token.trim() : !username.trim() || !password)}
          >
            {busy ? "Connecting…" : mode === "password" ? "Sign in" : "Connect"}
            <ArrowRight size={17} />
          </Button>
        </form>
        <p className="fine-print">
          {mode === "token"
            ? "Your token stays in this tab’s memory. Refreshing or disconnecting ends your session."
            : "Sessions use a secure HttpOnly cookie. Disconnect signs out on the appliance; sessions also expire automatically."}
        </p>
      </section>
    </main>
  );
}
function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <ShieldCheck size={23} />
      </span>
      <span>
        rustwall<span className="brand-sub">DNS POLICY ENGINE</span>
      </span>
    </div>
  );
}
function ThemeToggle({ theme, toggle }: { theme: "light" | "dark"; toggle: () => void }) {
  return (
    <button
      className="icon-button theme-toggle"
      aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`}
      onClick={toggle}
    >
      {theme === "light" ? <Moon size={17} /> : <Sun size={17} />}
    </button>
  );
}
function Session({
  api,
  initial,
  onLogout,
  theme,
  toggleTheme,
  sessionError,
}: {
  api: Api;
  initial: Versioned<Configuration>;
  onLogout: () => void;
  theme: "light" | "dark";
  toggleTheme: () => void;
  sessionError: unknown;
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const view = location.pathname.slice(1) as View;
  const [draft, setDraft] = useState(initial.value);
  const [base, setBase] = useState(initial);
  const [disconnect, setDisconnect] = useState(false);
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["status"],
    queryFn: ({ signal }) => api.request<Status>("/api/v1/status", { signal }).then((r) => r.value),
    refetchInterval: 5000,
  });
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api.configuration(signal),
    initialData: initial,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  // Poll the small version summary; fetch full list text only on revision changes.
  useEffect(() => {
    if (!status.data) return;
    const tag = `"g${status.data.generation}-s${status.data.shadow_generation ?? 0}"`;
    if (config.data?.etag !== tag) {
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      void queryClient.invalidateQueries({ queryKey: ["shadow"] });
    }
  }, [status.data, config.data?.etag, queryClient]);
  const dirty = useMemo(() => pretty(draft) !== pretty(base.value), [draft, base.value]);
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [view]);
  useEffect(() => {
    if (!dirty) return;
    const handler = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty]);
  const selected = navigation.find((v) => v.id === view) ?? navigation[0];
  async function refresh() {
    await queryClient.invalidateQueries();
  }
  function adopt(value: Versioned<Configuration>) {
    setBase(value);
    setDraft(value.value);
    queryClient.setQueryData(["config"], value);
  }
  async function published(reset: boolean) {
    const current = await api.configuration();
    if (reset || !dirty) adopt(current);
    await refresh();
  }
  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <Brand />
        <div className="sidebar-label">MANAGEMENT</div>
        <nav aria-label="Management navigation">
          {navigation.map((item) => (
            <NavLink
              to={`/${item.id}`}
              onClick={() => window.scrollTo(0, 0)}
              key={item.id}
              className={view === item.id ? "active" : ""}
              aria-current={view === item.id ? "page" : undefined}
            >
              <item.icon size={18} />
              {item.label}
              {item.id === "policies" && dirty && (
                <span className="draft-dot" title="Unsaved draft" />
              )}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-note">
            <ShieldCheck size={19} />
            <div>
              Local by design<small>Configuration and history stay here.</small>
            </div>
          </div>
          <button onClick={() => (dirty ? setDisconnect(true) : onLogout())}>
            <LogOut size={16} /> Disconnect
          </button>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span>
            <span className="topbar-name">APPLIANCE</span>
            <span className="mono listener-address">
              {status.data?.dns_listen ?? "Connecting…"}
            </span>
          </span>
          <div>
            {status.isError ? (
              <Badge tone="red">Status unavailable</Badge>
            ) : status.data ? (
              <Badge tone="green">
                <i /> DNS service online
              </Badge>
            ) : (
              <Badge>Connecting</Badge>
            )}
            <span className="mono">G{status.data?.generation ?? "—"}</span>
            <ThemeToggle theme={theme} toggle={toggleTheme} />
            <button
              className="icon-button"
              aria-label="Disconnect session"
              onClick={() => (dirty ? setDisconnect(true) : onLogout())}
            >
              <LogOut size={16} />
            </button>
            <button className="icon-button" aria-label="Refresh live data" onClick={refresh}>
              <RotateCw size={17} />
            </button>
          </div>
        </header>
        <main id="main-content" tabIndex={-1} className={`content view-${view}`}>
          <div className="page-title">
            <span className="eyebrow">{selected.caption}</span>
            <h1>{selected.title}</h1>
            <p>{selected.description}</p>
            <ErrorNotice error={sessionError} />
          </div>
          <ErrorNotice error={status.error} retry={refresh} />
          <ErrorNotice error={config.error} retry={refresh} />
          {!api.canWrite && (
            <output className="notice">
              Read-only credential. Configuration actions are unavailable.
            </output>
          )}
          {!status.data && !status.error && <Loading />}
          <Routes>
            <Route
              path="/setup"
              element={
                <DeferredView>
                  <Setup api={api} />
                </DeferredView>
              }
            />
            <Route
              path="/overview"
              element={
                <Overview api={api} status={status.data} navigate={(id) => navigate(`/${id}`)} />
              }
            />
            <Route
              path="/queries"
              element={
                <DeferredView key="queries">
                  <Queries api={api} published={() => published(false)} />
                </DeferredView>
              }
            />
            <Route
              path="/policies"
              element={
                <DeferredView key="policies">
                  <Workbench
                    api={api}
                    draft={draft}
                    setDraft={setDraft}
                    base={base}
                    setBase={setBase}
                    current={config.data}
                    adopt={adopt}
                    published={published}
                  />
                </DeferredView>
              }
            />
            <Route path="/clients" element={<Clients api={api} />} />
            <Route path="/filters" element={<Filters api={api} />} />
            <Route path="/upstreams" element={<Upstreams api={api} />} />
            <Route
              path="/history"
              element={<Revisions api={api} published={() => published(false)} />}
            />
            <Route
              path="/security"
              element={
                <DeferredView>
                  <Security api={api} />
                </DeferredView>
              }
            />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Routes>
          <footer className="page-footer">
            <span>rustwall / {status.data?.version ?? "…"}</span>
            <span>Local DNS management</span>
          </footer>
        </main>
      </div>
      <Modal
        open={disconnect}
        onClose={() => setDisconnect(false)}
        title="Disconnect and discard your draft?"
        description="Your unsaved changes exist only in this tab. Export the draft in the policy workbench if you want to keep it."
      >
        <div className="dialog-actions">
          <button onClick={() => setDisconnect(false)}>Keep editing</button>
          <button className="danger" onClick={onLogout}>
            Discard and disconnect
          </button>
        </div>
      </Modal>
    </div>
  );
}
