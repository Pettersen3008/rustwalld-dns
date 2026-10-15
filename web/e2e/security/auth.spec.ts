import { test, expect } from "@playwright/test";
import { readFile, writeFile } from "node:fs/promises";
import { createHmac } from "node:crypto";
import { authorization, reset } from "../helpers";
let fixtureSecret = "12345678901234567890";
function code() {
  const step = Math.floor(Date.now() / 30000);
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", fixtureSecret).update(bytes).digest();
  const offset = digest[19]! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}
test.beforeEach(async ({ request }, info) => {
  await reset(request);
  const fixture = JSON.parse(
    await readFile(new URL("../../../target/auth-ui-fixture.json", import.meta.url), "utf8"),
  ) as { authPath: string };
  const file = JSON.parse(await readFile(fixture.authPath, "utf8"));
  file.user.last_totp_step = null;
  const mobile = info.project.name === "mobile";
  fixtureSecret = mobile ? "ABCDEFGHIJKLMNOPQRST" : "12345678901234567890";
  file.user.totp_secret = mobile
    ? "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U"
    : "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  file.tokens = [];
  await writeFile(fixture.authPath, JSON.stringify(file), { mode: 0o600 });
  expect((await request.post("/api/v1/auth/recover", { headers: authorization })).status()).toBe(
    204,
  );
  const privacy = await request.get("/api/v1/privacy", { headers: authorization });
  expect(
    (
      await request.put("/api/v1/privacy", {
        headers: { ...authorization, "If-Match": privacy.headers()["etag"]! },
        data: { mode: "full", retention_rows: 100000, clear_history: true },
      })
    ).status(),
  ).toBe(200);
});
test("HTTPS password/TOTP, one-time scoped token, read-only UI and durable revoke", async ({
  page,
  request,
}, info) => {
  await page.goto("/");
  await expect(page.getByLabel("Authenticator code")).toBeVisible();
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("wrong-password");
  await page.getByLabel("Authenticator code").fill(code());
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Invalid credentials");
  await expect(page.getByLabel("Password", { exact: true })).toHaveValue("");
  await page.getByLabel("Password", { exact: true }).fill("fixture-password-16");
  await page.getByLabel("Authenticator code").fill(code());
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  const cookies = await page.context().cookies();
  const session = cookies.find((cookie) => cookie.name === "__Host-rustwall");
  expect(session?.secure).toBe(true);
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  await page.getByRole("link", { name: "Access & sessions", exact: true }).click();
  await expect(page.getByText("PASSWORD 2FA ENABLED", { exact: true })).toBeVisible();
  await page.getByLabel("Query logging mode").selectOption("no_client_identity");
  await page.getByLabel("Clear retained query history").check();
  await page.getByRole("button", { name: "Review privacy change" }).click();
  await expect(page.getByRole("dialog")).toContainText("removes retained history");
  await page.getByRole("button", { name: "Apply reviewed privacy preferences" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByRole("button", { name: "ads.test", exact: true }).first().click();
  await expect(page.getByRole("dialog")).toContainText("anonymous");
  await expect(
    page.getByRole("button", { name: "Temporarily allow for this client" }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.getByRole("link", { name: "Access & sessions", exact: true }).click();
  await page.getByLabel("Token name").fill("dashboard-reader");
  await page.getByLabel("Token scope").selectOption("read_only");
  await page.getByRole("button", { name: "Create scoped token" }).click();
  await expect(page.getByRole("dialog")).toContainText("shown once");
  const token = await page.getByLabel("New token value").inputValue();
  expect(token).toMatch(/^[a-f0-9]{64}$/);
  await page.getByRole("button", { name: "I saved the token" }).click();
  await expect(page.getByLabel("New token value")).toHaveCount(0);
  await page.getByRole("button", { name: "Disconnect session", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sign in to DNS management" })).toBeVisible();
  expect((await page.context().cookies()).some((cookie) => cookie.name === "__Host-rustwall")).toBe(
    false,
  );
  await page.getByRole("button", { name: "API token", exact: true }).click();
  await page.getByLabel("Management token").fill(token);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Read-only credential");
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(page.getByRole("button", { name: "Validate draft", exact: true })).toBeDisabled();
  await expect(page.getByLabel("Rules for baseline")).toBeDisabled();
  expect(
    (
      await request.post("/api/v1/policy/test", {
        headers: { Authorization: `Bearer ${token}` },
        data: {},
      })
    ).status(),
  ).toBe(403);
  await page.getByRole("link", { name: "Access & sessions", exact: true }).click();
  await expect(page.getByLabel("Query logging mode")).toBeDisabled();
  await expect(
    page.getByText("An administrator credential is required to manage tokens.", { exact: true }),
  ).toBeVisible();
  await page.screenshot({ path: info.outputPath("scoped-access.png"), fullPage: true });
  const tokens = (await (
    await request.get("/api/v1/auth/tokens", { headers: authorization })
  ).json()) as { id: string; name: string }[];
  const id = tokens.find((item) => item.name === "dashboard-reader")!.id;
  expect(
    (await request.delete(`/api/v1/auth/tokens/${id}`, { headers: authorization })).status(),
  ).toBe(204);
  expect(
    (
      await request.get("/api/v1/config", { headers: { Authorization: `Bearer ${token}` } })
    ).status(),
  ).toBe(401);
});
