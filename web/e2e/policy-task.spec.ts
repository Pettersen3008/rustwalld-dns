import { test, expect } from "@playwright/test";
import { writeFile } from "node:fs/promises";
import { baseline, dns, login, reset, revisionHeaders, authorization } from "./helpers";

test.beforeEach(async ({ request }) => reset(request));

for (const theme of ["light", "dark"] as const) {
  test(`policy task: ${theme} reaches, edits and publishes a local record`, async ({
    page,
    request,
  }, info) => {
    await page.setViewportSize(
      info.project.name === "mobile" ? { width: 390, height: 844 } : { width: 1280, height: 800 },
    );
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await login(page);
    await page.getByRole("link", { name: /^Policies/ }).click();
    await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
    await page.evaluate(() => window.scrollTo(0, 0));
    const add = page.getByRole("button", { name: "Add DNS record", exact: true });
    await expect(page.getByText("Policy: default", { exact: true })).toBeVisible();
    const distance = await add.evaluate((element) => {
      const r = element.getBoundingClientRect();
      return { y: r.y + scrollY, bottom: r.bottom + scrollY, viewport: innerHeight };
    });
    await info.attach("task-distance", {
      body: JSON.stringify(distance),
      contentType: "application/json",
    });
    await writeFile(info.outputPath("task-distance.json"), JSON.stringify({ theme, ...distance }));
    await page.screenshot({ path: info.outputPath(`${theme}-local-task.png`) });
    await page.screenshot({ path: info.outputPath(`${theme}-local-document.png`), fullPage: true });
    expect(distance.bottom).toBeLessThanOrEqual(distance.viewport);
    if (info.project.name === "mobile") expect(distance.y).toBeLessThan(1852 / 2);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    ).toBeTruthy();
    await add.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Record 1 domain", { exact: true })).toBeFocused();
    await page.getByLabel("Record 1 domain", { exact: true }).fill("task.home.arpa");
    await page.getByLabel("Record 1 address", { exact: true }).fill("192.0.2.77");
    const guidance = page.getByText("Local record behavior and wildcard limits", { exact: true });
    await guidance.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("Use *.home.arpa", { exact: false })).toBeVisible();
    await page.getByText("HTTPS/SVCB service records", { exact: true }).click();
    await expect(page.getByText("Priority 0 aliases this service", { exact: false })).toBeVisible();
    await page.getByRole("link", { name: "Query log", exact: true }).click();
    await page.getByRole("link", { name: /^Policies/ }).click();
    await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
    await expect(page.getByLabel("Record 1 domain", { exact: true })).toHaveValue("task.home.arpa");
    await page.getByRole("button", { name: "Validate draft", exact: true }).click();
    await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
    await page.getByRole("button", { name: "Review promotion", exact: true }).click();
    await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
    expect(await dns("task.home.arpa")).toBe(0);
    const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
    expect(current.policies[0].dns_records).toContainEqual({
      domain: "task.home.arpa",
      ttl: 60,
      data: { type: "A", address: "192.0.2.77" },
    });
  });
}

test("policy task: adding selects the new record page and preserves each policy", async ({
  page,
  request,
}) => {
  const config = structuredClone(baseline);
  config.policies[0]!.dns_records = Array.from({ length: 25 }, (_, i) => ({
    domain: `record${i}.home.arpa`,
    ttl: 60,
    data: { type: "A" as const, address: "192.0.2.10" },
  }));
  config.policies.push({
    ...structuredClone(baseline.policies[0]!),
    name: "second",
    dns_records: [],
  });
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  const add = page.getByRole("button", { name: "Add DNS record", exact: true });
  await add.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByLabel("Record 26 domain", { exact: true })).toBeFocused();
  await page.getByLabel("Record 26 domain", { exact: true }).fill("last.home.arpa");
  await page.getByRole("combobox", { name: "Local DNS policy", exact: true }).selectOption("1");
  await expect(page.getByText("Policy: second", { exact: true })).toBeVisible();
  await add.click();
  await expect(page.getByLabel("Record 1 domain", { exact: true })).toBeFocused();
  await page.getByRole("button", { name: "Remove record 1", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain", { exact: true })).toHaveCount(0);
  await page.getByRole("combobox", { name: "Local DNS policy", exact: true }).selectOption("0");
  await page.getByRole("button", { name: "Next records", exact: true }).click();
  await expect(page.getByLabel("Record 26 domain", { exact: true })).toHaveValue("last.home.arpa");
});
