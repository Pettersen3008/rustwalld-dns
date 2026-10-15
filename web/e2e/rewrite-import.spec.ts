import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
test("disabled AdGuard rewrites stay absent through reviewed promotion", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354'], rewrites: [{domain: active.home.arpa, answer: 192.0.2.10, enabled: true}, {domain: disabled.home.arpa, answer: 192.0.2.11, enabled: false}]}\nuser_rules: [ads.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Disabled source rewrite was not activated", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain")).toHaveValue("active.home.arpa");
  await expect(page.getByLabel("Record 2 domain")).toHaveCount(0);
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("active.home.arpa")).toBe(0);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(
    current.policies[0].dns_records.map((record: { domain: string }) => record.domain),
  ).toEqual(["active.home.arpa"]);
  const disabled = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=disabled.home.arpa", {
      headers: authorization,
    })
  ).json();
  expect(disabled.rewrite).toBe(false);
});

test("the global AdGuard rewrite switch stays off through reviewed promotion", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "schema_version: 34\ndns: {rewrites: [{domain: ignored.home.arpa, answer: 192.0.2.10}]}\nuser_rules: [ads.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("1 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Source schemas 26 and later store rewrite entries under filtering", {
      exact: false,
    }),
  ).toBeVisible();
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "schema_version: 34\ndns: {upstream_dns: ['127.0.0.1:15354']}\nfiltering: {rewrites_enabled: false, rewrites: [{domain: globally-off.home.arpa, answer: 192.0.2.10, enabled: true}, {domain: privacy.test, answer: 192.0.2.11}, {domain: privacy.test, answer: AAAA}]}\nuser_rules: [ads.test, privacy.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Source DNS rewrites are globally disabled", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain")).toHaveCount(0);
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("privacy.test", 1)).toBe(3);
  expect(await dns("privacy.test", 28)).toBe(3);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records ?? []).toEqual([]);
  const explanation = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=globally-off.home.arpa", {
      headers: authorization,
    })
  ).json();
  expect(explanation.rewrite).toBe(false);
});
