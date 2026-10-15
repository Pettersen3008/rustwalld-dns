import { test, expect } from "@playwright/test";
import { baseline, dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));

test("V2 cancellation is explicit, validated and explained after promotion", async ({
  page,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("List 1 syntax").selectOption("adguard");
  await page
    .getByLabel("Rules for baseline")
    .fill("ads.test\n||tracking.test^\n||tracking.test^$badfilter");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  await expect(page.getByRole("alert")).toContainText("invalid");
  await page.getByLabel("List 1 syntax").selectOption("adguard_v2");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByText("Rule cancellation:", { exact: false })).toContainText(
    "1 declarations disable 1 input lines",
  );
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("tracking.test")).toBe(0);
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("link", { name: "Filter lists", exact: true }).click();
  await page.getByText("Rule cancellation · 1 targets", { exact: true }).click();
  await expect(page.getByRole("cell", { name: "||tracking.test^", exact: true })).toBeVisible();
  await expect(page.getByText("baseline · line 3", { exact: true })).toBeVisible();
  await expect(page.getByText("baseline · line 2", { exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("badfilter-provenance.png"), fullPage: true });
});

test("bounded target review pages totals, unmatched patterns and source samples", async ({
  page,
  request,
}, info) => {
  const config = structuredClone(baseline);
  let rules = "ads.test\n";
  for (let i = 0; i < 205; i++) {
    for (let j = 0; j < 7; j++) {
      rules += `||tracking${i}.test^$badfilter\n`;
      if (i !== 0) rules += `||tracking${i}.test^\n`;
    }
  }
  config.policies[0]!.lists[0] = {
    name: "publisher",
    action: "block",
    syntax: "adguard_v2",
    rules,
  };
  config.policies.push({ ...structuredClone(config.policies[0]!), name: "other policy" });
  const updated = await request.put("/api/v1/config", {
    headers: await revisionHeaders(request),
    data: config,
  });
  expect(updated.ok()).toBeTruthy();
  const scopedRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/v1/filter-lists?policy=")) scopedRequests.push(request.url());
  });
  await login(page);
  await page.getByRole("link", { name: "Filter lists", exact: true }).click();
  const report = page.locator(".cancellation-review").nth(1);
  await expect(report.getByText("Rule cancellation · 205 targets", { exact: true })).toBeVisible();
  expect(scopedRequests).toHaveLength(0);
  const scoped = page.waitForResponse((response) =>
    response.url().includes("/api/v1/filter-lists?policy=other%20policy"),
  );
  await report.getByText("Rule cancellation · 205 targets", { exact: true }).click();
  expect((await scoped).ok()).toBeTruthy();
  await expect(
    report.getByText("Showing the first 200 of 205 targets.", { exact: false }),
  ).toBeVisible();
  await expect(report.getByText("No matching rule", { exact: true })).toBeVisible();
  await expect(
    report.getByText("+2 more in saved revision", { exact: true }).first(),
  ).toBeVisible();
  await expect(report.getByRole("cell", { name: "||tracking20.test^", exact: true })).toHaveCount(
    0,
  );
  await report.getByRole("button", { name: "Next targets", exact: true }).click();
  await expect(report.getByText("Page 2 of 10", { exact: true })).toBeVisible();
  await expect(report.getByRole("cell", { name: "||tracking20.test^", exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("badfilter-bounded.png"), fullPage: true });
});

for (const theme of ["light", "dark"] as const) {
  test(`${theme} cancellation guidance preserves native and V2–V6 validation`, async ({
    page,
  }, info) => {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await login(page);
    await page.getByRole("link", { name: "Policies", exact: true }).click();
    await page
      .getByLabel("Rules for baseline")
      .fill("ads.test\n||tracking.test^\n||tracking.test^$badfilter");
    for (const syntax of ["native", "adguard"]) {
      await page.getByLabel("List 1 syntax").selectOption(syntax);
      await page.getByRole("button", { name: "Validate draft", exact: true }).click();
      await expect(page.getByRole("alert")).toContainText("invalid");
      await expect(
        page.getByRole("button", { name: "Stage in shadow", exact: true }),
      ).toBeDisabled();
    }
    for (const syntax of ["adguard_v2", "adguard_v3", "adguard_v4", "adguard_v5", "adguard_v6"]) {
      await page.getByLabel("List 1 syntax").selectOption(syntax);
      await page.getByRole("button", { name: "Validate draft", exact: true }).click();
      const notice = page.getByText("Rule cancellation:", { exact: false });
      await expect(notice).toContainText("1 declarations disable 1 input lines");
      await expect(notice).toContainText("Removing an exception can expose a block.");
      await expect(notice).toContainText("Inspect the list text before promotion.");
      await expect(notice).not.toContainText("V2");
      await expect(
        page.getByRole("button", { name: "Stage in shadow", exact: true }),
      ).toBeEnabled();
    }
    await page.getByText("Rule cancellation:", { exact: false }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`${theme}-validation-guidance.png`) });
  });

  test(`${theme} AdGuard migration previews cancellation and preserves V6 in the draft`, async ({
    page,
  }, info) => {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await login(page);
    await page.getByRole("link", { name: "Policies", exact: true }).click();
    await page.getByRole("tab", { name: "Migration", exact: true }).click();
    await page.getByLabel("Migration source").selectOption("adguard");
    await page.getByLabel("Source backup").setInputFiles({
      name: "AdGuardHome.yaml",
      mimeType: "application/yaml",
      buffer: Buffer.from(
        "dns: {upstream_dns: ['127.0.0.1:15354']}\nuser_rules: [ads.test, '||tracking.test^', '||tracking.test^$badfilter']\n",
      ),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
    const notice = page.getByText("Rule cancellation:", { exact: false });
    await expect(notice).toContainText("1 declarations disable 1 input lines");
    await expect(notice).toContainText("Removing an exception can expose a block.");
    await expect(notice).toContainText("Review the imported lists before activation");
    await expect(notice).not.toContainText("V2");
    await notice.scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`${theme}-migration-guidance.png`) });
    await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
    await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
    await page.getByRole("tab", { name: "Policies & rules", exact: true }).click();
    await expect(page.getByLabel("List 1 syntax")).toHaveValue("adguard_v6");
    await expect(page.getByLabel("Rules for adguard/user-rules")).toHaveValue(/\$badfilter/);
    await page.getByRole("button", { name: "Validate draft", exact: true }).click();
    await expect(page.getByText("Rule cancellation:", { exact: false })).toContainText(
      "Inspect the list text before promotion.",
    );
  });
}
