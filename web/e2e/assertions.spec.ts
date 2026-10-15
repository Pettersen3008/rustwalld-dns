import { test, expect } from "@playwright/test";
import { authorization, baseline, dns, login, reset } from "./helpers";

test.beforeEach(async ({ request }) => {
  await reset(request);
});

test("complete assertion reports paginate failures, explain rules and preserve strict staging", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  const initial = (await (await request.get("/api/v1/status")).json()) as {
    generation: number;
  };
  const initialConfig = (await (
    await request.get("/api/v1/config", { headers: authorization })
  ).json()) as unknown;
  const draft = structuredClone(baseline);
  draft.assertions = [
    ...Array.from({ length: 12 }, (_, index) => ({
      client: "127.0.0.1",
      domain: `x${index}.ads.test`,
      expected: "allow" as const,
    })),
    { client: "127.0.0.1", domain: "nas.home.arpa", expected: "allow" },
    { client: "192.0.2.1", domain: "allowed.test", expected: "allow" },
    { client: "127.0.0.1", domain: "bad..domain", expected: "allow" },
  ];
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  await page.getByLabel("Configuration JSON").fill(JSON.stringify(draft));
  await page.getByRole("button", { name: "Use this draft" }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("14 of 15");
  const report = page.locator(".assertion-results");
  await expect(report).toContainText("Assertion results: 14 failed · 1 passed");
  await expect(report.locator(".assertion-result")).toHaveCount(10);
  await expect(page.getByRole("button", { name: "Stage in shadow" })).toBeDisabled();
  const first = report.locator(".assertion-result").first();
  await first.getByText("Decision trace", { exact: true }).click();
  await expect(first).toContainText("suffix / ads.test");
  await expect(first).toContainText("baseline · line 1");
  await expect(first).toContainText("Expected ALLOW · Configured BLOCK");
  await report.getByRole("button", { name: "Next assertions" }).click();
  await expect(report.locator(".assertion-result")).toHaveCount(4);
  await expect(report).toContainText("trace is hypothetical");
  await expect(report).toContainText("Invalid domain.");
  await expect(report).not.toContainText("nas.home.arpa");
  await report.getByRole("button", { name: "Include passing assertions" }).click();
  await expect(report).toContainText("Page 1 of 2");
  await report.getByRole("button", { name: "Next assertions" }).click();
  await expect(report.locator(".assertion-result")).toHaveCount(5);
  const rewrite = report.locator(".assertion-result").filter({ hasText: "nas.home.arpa" });
  await expect(rewrite).toContainText("PASS");
  await expect(rewrite).toContainText("Configured ALLOW (local rewrite)");
  await rewrite.getByText("Decision trace", { exact: true }).click();
  await expect(rewrite).toContainText("Local rewrite");
  expect(await dns("x0.ads.test")).toBe(3);
  const status = (await (await request.get("/api/v1/status")).json()) as {
    generation: number;
  };
  expect(status.generation).toBe(initial.generation);
  const live = await request.get("/api/v1/config", { headers: authorization });
  expect((await live.json()) as unknown).toEqual(initialConfig);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  await page.screenshot({
    path: info.outputPath("assertion-report.png"),
    fullPage: true,
  });
  // Any edit discards the report's validity and details.
  await page.getByLabel("Rules for baseline").fill("ads.test\nextra.test");
  await expect(report).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Stage in shadow" })).toBeDisabled();
});

test("passing reports stay collapsed and editing clears their validation", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  const report = page.locator(".assertion-results");
  await expect(report).toContainText("Assertion results: 0 failed · 1 passed");
  await expect(report).not.toHaveAttribute("open", "");
  await expect(report.locator(".assertion-result")).not.toBeVisible();
  await report.locator("summary").first().click();
  await expect(report.locator(".assertion-result")).toBeVisible();
  await expect(page.getByRole("button", { name: "Stage in shadow" })).toBeEnabled();
  await page.getByLabel("Rules for baseline").fill("ads.test\nnew.test");
  await expect(report).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Stage in shadow" })).toBeDisabled();
});
