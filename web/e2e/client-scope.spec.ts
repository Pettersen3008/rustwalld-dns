import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
test("V5 client-scoped rules separate real clients and retain original provenance", async ({
  page,
  request,
}, info) => {
  const longName = "named-" + "z".repeat(122);
  const config = await (await request.get("/api/v1/config", { headers: authorization })).json();
  config.allowed_clients = ["127.0.0.0/24"];
  config.bindings = [{ name: "Kids", network: "127.0.0.1/32", policy: "default" }];
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("List 1 syntax").selectOption("adguard_v4");
  await page
    .getByLabel("Rules for baseline")
    .fill(`ads.test\n||client.test^$client=Kids|${longName},dnstype=A,denyallow=safe.client.test`);
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  await page.getByLabel("List 1 syntax").selectOption("adguard_v5");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("client.test", 1, "127.0.0.1")).toBe(3);
  expect(await dns("client.test", 1, "127.0.0.2")).toBe(0);
  expect(await dns("safe.client.test", 1, "127.0.0.1")).toBe(0);
  expect(await dns("client.test", 28, "127.0.0.1")).toBe(0);
  expect(await dns("client.test", 1, "127.0.0.1")).toBe(3);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("client.test");
  await page.getByRole("button", { name: "client.test", exact: true }).first().click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  await expect(page.getByText("Rule client scope", { exact: true })).toBeVisible();
  await expect(page.getByText("Rule client scope: Kids", { exact: false })).toBeVisible();
  expect(
    await page.getByRole("dialog").evaluate((el) => el.scrollWidth <= el.clientWidth),
  ).toBeTruthy();
  await page.screenshot({ path: info.outputPath("client-scopes.png"), fullPage: true });
});
test("client modifier imports preserve names and IPv6 prefixes in V5", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354']}\nclients: {persistent: [{name: Kids, ids: [127.0.0.1]}]}\nuser_rules: [ads.test, '||client.test^$client=Kids|2001:db8::/32,dnstype=AAAA']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Policies & rules", exact: true }).click();
  await expect(page.getByLabel("List 1 syntax")).toHaveCount(2);
  await expect(page.getByLabel("List 1 syntax").first()).toHaveValue("adguard_v6");
  await expect(page.getByLabel("List 1 syntax").last()).toHaveValue("adguard_v6");
  await expect(page.getByLabel("Rules for adguard/user-rules").first()).toHaveValue(
    /\$client=Kids/,
  );
});
