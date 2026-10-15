import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Api } from "@/lib/api";
import { Badge, ErrorNotice, Field, Modal, Panel } from "@/components/common";
import { PrivacySettings } from "@/features/security/privacy";
type Role = "read_only" | "operator" | "administrator";
type Token = { id: string; name: string; role: Role; expires_at: number };
export function Security({ api }: { api: Api }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const client = useQueryClient();
  const info = useQuery({
    queryKey: ["auth-info"],
    queryFn: ({ signal }) =>
      api
        .request<{ password_enabled: boolean; totp_enabled: boolean }>("/api/v1/auth/info", {
          signal,
        })
        .then((result) => result.value),
  });
  const tokens = useQuery({
    queryKey: ["auth-tokens"],
    enabled: api.role === "administrator" && !!info.data?.password_enabled,
    queryFn: ({ signal }) =>
      api.request<Token[]>("/api/v1/auth/tokens", { signal }).then((result) => result.value),
  });
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("read_only");
  const [duration, setDuration] = useState("86400");
  const [secret, setSecret] = useState<string | null>(null);
  const [revoke, setRevoke] = useState<Token | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  async function create() {
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      const result = await api.request<{ token: string }>("/api/v1/auth/tokens", {
        method: "POST",
        body: { name, role, duration_secs: Number(duration) },
      });
      setSecret(result.value.token);
      setName("");
      await client.invalidateQueries({ queryKey: ["auth-tokens"] });
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    if (!revoke) return;
    setBusy(true);
    setError(null);
    try {
      await api.request(`/api/v1/auth/tokens/${encodeURIComponent(revoke.id)}`, {
        method: "DELETE",
      });
      setNotice(`Revoked ${revoke.name}.`);
      setRevoke(null);
      await client.invalidateQueries({ queryKey: ["auth-tokens"] });
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PrivacySettings api={api} />
      <Panel
        title="Administration access"
        detail="Local identity and automation credentials stay separate from DNS policy and imports."
      >
        <div className="chips">
          <Badge>{api.role.replaceAll("_", " ").toUpperCase()}</Badge>
          <Badge tone={info.data?.totp_enabled ? "green" : "neutral"}>
            {info.data?.totp_enabled ? "PASSWORD 2FA ENABLED" : "PASSWORD 2FA NOT CONFIGURED"}
          </Badge>
        </div>
        <ErrorNotice error={info.error} />
        <p className="body-copy">
          Password sessions require HTTPS, use HttpOnly cookies and expire after eight hours or
          thirty minutes idle. Disconnect revokes the current session. 2FA protects password
          sign-in; scoped automation tokens and the emergency environment token authenticate
          independently.
        </p>
        {!info.data?.password_enabled && (
          <details open>
            <summary>Enable local password administration</summary>
            <p className="body-copy">
              Configure HTTPS first, then initialize a private credential file with a password from
              stdin. Add its path as auth_file in the appliance configuration and restart. The
              command prints a one-time authenticator provisioning URI. Keep credentials and TLS
              keys in your private recovery backup.
            </p>
            <pre>
              sudo -u rustwalld-dns /opt/rustwalld-dns/current/bin/rustwalld-dns auth init --output
              /var/lib/rustwalld-dns/auth.json --username admin --password-stdin
            </pre>
          </details>
        )}
      </Panel>
      {api.role !== "administrator" ? (
        <Panel
          title="API tokens"
          detail="An administrator credential is required to manage tokens."
        >
          <p className="body-copy">
            Your current scope can use the allowed DNS management views. Token creation and
            revocation require administrator access.
          </p>
        </Panel>
      ) : (
        info.data?.password_enabled && (
          <Panel
            title="API tokens"
            detail="Create a separate short-lived credential for each integration. Token values are shown once."
          >
            <ErrorNotice error={error} />
            <ErrorNotice error={tokens.error} />
            {notice && <output className="notice notice-success">{notice}</output>}
            <div className="form-grid">
              <Field label="Token name">
                <input
                  maxLength={128}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={busy}
                />
              </Field>
              <Field label="Token scope">
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as Role)}
                  disabled={busy}
                >
                  <option value="read_only">Read only</option>
                  <option value="operator">Policy operator</option>
                  <option value="administrator">Administrator</option>
                </select>
              </Field>
              <Field label="Token lifetime">
                <select
                  value={duration}
                  onChange={(e) => setDuration(e.target.value)}
                  disabled={busy}
                >
                  <option value="3600">1 hour</option>
                  <option value="86400">1 day</option>
                  <option value="604800">7 days</option>
                  <option value="2592000">30 days</option>
                </select>
              </Field>
            </div>
            <button
              className="primary"
              disabled={busy || !name.trim() || (tokens.data?.length ?? 0) >= 64}
              onClick={() => void create()}
            >
              Create scoped token
            </button>
            <div className="exception-list">
              {tokens.data?.map((token) => (
                <article className="exception-row" key={token.id}>
                  <div>
                    <strong>{token.name}</strong>
                    <p>
                      {token.role.replaceAll("_", " ")} · expires{" "}
                      {new Date(token.expires_at * 1000).toLocaleString()}
                    </p>
                  </div>
                  <Badge tone={token.expires_at * 1000 > now ? "green" : "neutral"}>
                    {token.expires_at * 1000 > now ? "ACTIVE" : "EXPIRED"}
                  </Badge>
                  <button
                    disabled={busy}
                    onClick={() => {
                      setError(null);
                      setRevoke(token);
                    }}
                  >
                    Revoke {token.name}
                  </button>
                </article>
              ))}
            </div>
            {!tokens.data?.length && <p className="muted">No scoped tokens configured.</p>}
          </Panel>
        )
      )}
      <Modal
        open={secret !== null}
        onClose={() => setSecret(null)}
        title="Save this token now"
        description="This value is shown once. Store it in your integration’s private credential settings. It will not appear in the token list."
      >
        <Field label="New token value">
          <textarea className="mono" rows={3} readOnly value={secret ?? ""} />
        </Field>
        <ErrorNotice error={error} />
        <div className="dialog-actions">
          <button
            onClick={() =>
              void navigator.clipboard.writeText(secret ?? "").catch((error) => setError(error))
            }
          >
            Copy token
          </button>
          <button className="primary" onClick={() => setSecret(null)}>
            I saved the token
          </button>
        </div>
      </Modal>
      <Modal
        open={revoke !== null}
        onClose={() => {
          if (!busy) setRevoke(null);
        }}
        title={`Revoke ${revoke?.name ?? "token"}?`}
        description="Requests using this token will stop authenticating after the durable update. DNS policy and other credentials remain in place."
      >
        <ErrorNotice error={error} />
        <div className="dialog-actions">
          <button disabled={busy} onClick={() => setRevoke(null)}>
            Keep token
          </button>
          <button className="danger" disabled={busy} onClick={() => void remove()}>
            Revoke reviewed token
          </button>
        </div>
      </Modal>
    </>
  );
}
