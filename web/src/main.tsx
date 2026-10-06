import { StrictMode, useState, useEffect, lazy } from "react";
import { createRoot } from "react-dom/client";
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
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
import { Api, pretty } from "./api";
import type { Configuration, Status, Versioned } from "./api";
import { Badge, ErrorNotice, Loading, Modal, DeferredView } from "./components";
import { Overview, Clients, Filters, Upstreams, Revisions } from "./views";
const Workbench = lazy(() =>
  import("./workbench").then((module) => ({ default: module.Workbench })),
);
const Queries = lazy(() =>
  import("./queries").then((module) => ({ default: module.Queries })),
);
import "./style.css";
const navigation = [
  {
    id: "overview",
    label: "Overview",
    icon: LayoutDashboard,
    caption: "Your network, at a glance",
    title: "Overview",
    description:
      "Live protection, traffic and the policy serving your network.",
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
    description:
      "Inspect a saved configuration or return to a validated revision.",
  },
] as const;
type View = (typeof navigation)[number]["id"];
function viewFromHash(): View {
  const id = location.hash.slice(1);
  return navigation.some((v) => v.id === id) ? (id as View) : "overview";
}
function App() {
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  const toggleTheme = () =>
    setTheme((value) => (value === "light" ? "dark" : "light"));
  const [session, setSession] = useState<{
    api: Api;
    initial: Versioned<Configuration>;
    client: QueryClient;
  } | null>(null);
  const [token, setToken] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  async function login(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const api = new Api(token);
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
    } catch (error) {
      setError(error);
    } finally {
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
          onLogout={() => {
            session.client.clear();
            setSession(null);
            setError(null);
          }}
        />
      </QueryClientProvider>
    );
  return (
    <main className="login">
      <ThemeToggle theme={theme} toggle={toggleTheme} />
      <div className="login-story">
        <Brand />
        <div>
          <span className="eyebrow">YOUR NETWORK. YOUR RULES.</span>
          <h1>
            Local control.
            <br />
            Clear decisions.
          </h1>
          <p>
            DNS policy, explanations and safe configuration changes. All on your
            own infrastructure.
          </p>
          <div
            className="login-path"
            aria-label="DNS flows through client identification, policy, cache and upstream resolution"
          >
            {["Client", "Policy", "Cache", "Upstream"].map((step, i) => (
              <span key={step}>
                <small>0{i + 1}</small>
                {step}
              </span>
            ))}
          </div>
        </div>
        <span className="login-footer">
          <ShieldCheck size={16} /> Built for the network you trust.
        </span>
      </div>
      <section className="login-form">
        <Badge tone="green">RUSTWALL DNS</Badge>
        <h2>Connect to your appliance</h2>
        <p>
          Enter the management token configured in{" "}
          <code>RUSTWALLD_API_TOKEN</code>.
        </p>
        <form onSubmit={login}>
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
          <ErrorNotice error={error} />
          <button
            className="primary"
            type="submit"
            disabled={busy || !token.trim()}
          >
            {busy ? "Connecting…" : "Connect securely"}
            <ArrowRight size={17} />
          </button>
        </form>
        <p className="fine-print">
          Your token stays in this tab’s memory. Refreshing or disconnecting
          ends your session.
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
function ThemeToggle({
  theme,
  toggle,
}: {
  theme: "light" | "dark";
  toggle: () => void;
}) {
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
}: {
  api: Api;
  initial: Versioned<Configuration>;
  onLogout: () => void;
  theme: "light" | "dark";
  toggleTheme: () => void;
}) {
  const [view, setView] = useState<View>(viewFromHash);
  const [draft, setDraft] = useState(initial.value);
  const [base, setBase] = useState(initial);
  const [disconnect, setDisconnect] = useState(false);
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["status"],
    queryFn: ({ signal }) =>
      api.request<Status>("/api/v1/status", { signal }).then((r) => r.value),
    refetchInterval: 5000,
  });
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api.configuration(signal),
    initialData: initial,
    refetchInterval: 5000,
  });
  const dirty = pretty(draft) !== pretty(base.value);
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [view]);
  useEffect(() => {
    const handler = () => setView(viewFromHash());
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
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
      <aside className="sidebar">
        <Brand />
        <div className="sidebar-label">WORKSPACE</div>
        <nav aria-label="Management navigation">
          {navigation.map((item) => (
            <a
              href={`#${item.id}`}
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
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-note">
            <ShieldCheck size={19} />
            <div>
              Local by design<small>Management stays on your appliance.</small>
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
            <button
              className="icon-button"
              aria-label="Refresh live data"
              onClick={refresh}
            >
              <RotateCw size={17} />
            </button>
          </div>
        </header>
        <main className={`content view-${view}`}>
          <div className="page-title">
            <span className="eyebrow">{selected.caption}</span>
            <h1>{selected.title}</h1>
            <p>{selected.description}</p>
          </div>
          <ErrorNotice error={status.error} retry={refresh} />
          <ErrorNotice error={config.error} retry={refresh} />
          {!status.data && !status.error && <Loading />}
          {view === "overview" && (
            <Overview
              api={api}
              status={status.data}
              navigate={(id) => {
                location.hash = id;
              }}
            />
          )}
          {view === "queries" && (
            <DeferredView key="queries">
              <Queries api={api} />
            </DeferredView>
          )}
          {view === "policies" && (
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
          )}
          {view === "clients" && <Clients api={api} />}
          {view === "filters" && <Filters api={api} />}
          {view === "upstreams" && <Upstreams api={api} />}
          {view === "history" && (
            <Revisions api={api} published={() => published(false)} />
          )}
          <footer className="page-footer">
            <span>rustwall / {status.data?.version ?? "…"}</span>
            <span>Independent DNS. Deliberate policy.</span>
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
const root = document.getElementById("root");
if (root)
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
