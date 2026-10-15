import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
test("historical DNS-container family passthrough imports, edits and promotes without allowlisting", async ({
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
      "schema_version: 25\ndns: {upstream_dns: ['127.0.0.1:15354'], rewrites: [{domain: privacy.test, answer: 192.0.2.10}, {domain: privacy.test, answer: AAAA}]}\nuser_rules: [ads.test, privacy.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 2 type")).toHaveValue("PASSTHROUGH");
  await expect(page.getByLabel("Record 2 family")).toHaveValue("AAAA");
  await expect(page.getByLabel("Record 2 TTL")).toHaveCount(0);
  await page.getByText("Local record behavior and wildcard limits", { exact: true }).click();
  await expect(page.getByText("It never allowlists the name", { exact: false })).toBeVisible();
  await page.getByLabel("Record 2 family").selectOption("A");
  await page.getByLabel("Record 2 family").selectOption("AAAA");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("privacy.test", 1)).toBe(0);
  expect(await dns("privacy.test", 28)).toBe(3);
  const explanation = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=privacy.test&qtype=28", {
      headers: authorization,
    })
  ).json();
  expect(explanation.rewrite).toBe(false);
  expect(explanation.decision.action).toBe("block");
  await page.reload();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 2 family")).toHaveValue("AAAA");
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records[1].data).toEqual({ type: "PASSTHROUGH", family: "AAAA" });
});
