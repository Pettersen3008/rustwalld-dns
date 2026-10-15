import { test, expect } from "@playwright/test";
import { dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));

test("V3 exclusions preserve other blocks through reviewed publication", async ({
  page,
  request,
}, info) => {
  const longDomain = [63, 63, 63, 61].map((length) => "z".repeat(length)).join(".");
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("List 1 syntax").selectOption("adguard_v2");
  await page
    .getByLabel("Rules for baseline")
    .fill(`ads.test\n||test^$denyallow=safe.test|${longDomain}\n||ads.safe.test^`);
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  await page.getByLabel("List 1 syntax").selectOption("adguard_v3");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("safe.test")).toBe(0);
  expect(await dns("ads.safe.test")).toBe(3);
  expect(await dns("blocked.test")).toBe(3);
  const response = await request.get("/api/v1/explain?client=127.0.0.1&domain=blocked.test", {
    headers: await revisionHeaders(request),
  });
  expect((await response.json()).rule.denyallow).toEqual(["safe.test", longDomain]);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("blocked.test");
  await page.getByRole("button", { name: "blocked.test", exact: true }).first().click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  await expect(page.getByText("Excluded from this rule", { exact: true })).toBeVisible();
  await expect(page.getByText("Other rules can still apply.", { exact: true })).toBeVisible();
  expect(
    await page.getByRole("dialog").evaluate((el) => el.scrollWidth <= el.clientWidth),
  ).toBeTruthy();
  await page.screenshot({ path: info.outputPath("denyallow-long-domains.png"), fullPage: true });
});

test("AdGuard exclusion import is V5 and mixed modifiers remain blockers", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354']}\nuser_rules: ['||test^$denyallow=safe.test', '||ads.safe.test^']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Policies & rules", exact: true }).click();
  await expect(page.getByLabel("List 1 syntax")).toHaveValue("adguard_v6");
  await expect(page.getByLabel("Rules for adguard/user-rules")).toHaveValue(/\$denyallow/);
  await page
    .getByLabel("Rules for adguard/user-rules")
    .fill("||test^$denyallow=safe.test,badfilter");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
});
