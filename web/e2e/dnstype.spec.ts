import { test, expect } from "@playwright/test";
import { dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));

test("V4 typed assertions and decisions survive reviewed publication", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("List 1 syntax").selectOption("adguard_v3");
  await page.getByLabel("Rules for baseline").fill("ads.test\n||typed.test^$dnstype=AAAA");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  await page.getByLabel("List 1 syntax").selectOption("adguard_v4");
  await page.getByRole("tab", { name: "Assertions", exact: true }).click();
  await page.getByLabel("Assertion 1 type").selectOption("28");
  await page.getByLabel("Assertion 1 domain").fill("typed.test");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByText("Assertion results: 0 failed · 1 passed", { exact: true }).click();
  await page.getByText("Decision trace", { exact: true }).click();
  await expect(page.getByText("Rule type scope", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("typed.test", 1)).toBe(0);
  expect(await dns("typed.test", 28)).toBe(3);
  const current = await request.get("/api/v1/config", { headers: await revisionHeaders(request) });
  expect((await current.json()).assertions[0].qtype).toBe(28);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("typed.test");
  await page.getByRole("button", { name: "typed.test", exact: true }).first().click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  await expect(page.getByText("Rule type scope", { exact: true }).last()).toBeVisible();
  expect(
    await page.getByRole("dialog").evaluate((el) => el.scrollWidth <= el.clientWidth),
  ).toBeTruthy();
  await page.screenshot({ path: info.outputPath("typed-decision.png"), fullPage: true });
});

test("response comparisons retain original question and actual response type", async ({
  page,
  request,
}, info) => {
  const current = await request.get("/api/v1/config", { headers: await revisionHeaders(request) });
  const config = await current.json();
  config.policies[0].lists.push({
    name: "address",
    action: "block",
    syntax: "adguard_v4",
    rules: "/^192\\.0\\.2\\.(10|20)$/$dnstype=A",
  });
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  expect(await dns("value.test", 28)).toBe(3); // Fixture returns A even to AAAA questions.
  await login(page);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("value.test");
  await page.getByRole("button", { name: "value.test", exact: true }).first().click();
  await expect(page.getByText("Matched response value", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  const comparison = page.waitForRequest((req) => req.url().includes("answer_type=1"));
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  const url = new URL((await comparison).url());
  expect(url.searchParams.get("domain")).toBe("value.test");
  expect(url.searchParams.get("qtype")).toBe("28");
  await expect(page.getByText("Rule type scope", { exact: true }).last()).toBeVisible();
  expect(
    await page.getByRole("dialog").evaluate((el) => el.scrollWidth <= el.clientWidth),
  ).toBeTruthy();
  await page.screenshot({ path: info.outputPath("response-type.png"), fullPage: true });
});

test("new imports accept type scopes and reject unknown record types", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  for (const kind of ["AAAA", "UNKNOWN"]) {
    await page.getByLabel("Source backup").setInputFiles({
      name: "AdGuardHome.yaml",
      mimeType: "application/yaml",
      buffer: Buffer.from(
        `dns: {upstream_dns: ['127.0.0.1:15354']}\nuser_rules: [ads.test, '||typed.test^$dnstype=${kind},denyallow=safe.typed.test']\n`,
      ),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(
      page.getByText(kind === "AAAA" ? "0 BLOCKERS" : "1 BLOCKERS", { exact: true }),
    ).toBeVisible();
  }
});
