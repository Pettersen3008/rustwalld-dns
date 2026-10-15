import { revisionHeaders } from "./helpers";
import { test, expect } from "@playwright/test";
import type { Configuration, TemporaryState } from "../src/lib/api";
import { authorization, baseline, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => {
  await reset(request);
});

test("temporary allow validates permanent policy, shadows, promotes, explains and revokes", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Temporary exceptions", exact: true }).click();
  await page.getByLabel("Exception name").fill("TV repair");
  await page.getByLabel("Exact domain").fill("ads.test");
  await page.getByLabel("Allow for").selectOption("900");
  await page.getByRole("button", { name: "Add temporary allow to draft" }).click();
  await expect(page.locator(".exception-row")).toContainText("TV repair");
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  expect(await dns("ads.test")).toBe(3);
  await expect
    .poll(async () => {
      const history = (await (
        await request.get("/api/v1/queries?limit=500", {
          headers: authorization,
        })
      ).json()) as {
        action: string;
        shadow: { temporary_exception?: number; differs: boolean } | null;
      }[];
      return history.some(
        (event) =>
          event.action === "block" &&
          event.shadow?.temporary_exception === 0 &&
          event.shadow.differs,
      );
    })
    .toBeTruthy();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect(page.getByRole("status")).toContainText("now active");
  expect(await dns("ads.test")).toBe(0);
  const active = (await (
    await request.get("/api/v1/temporary-exceptions", {
      headers: authorization,
    })
  ).json()) as TemporaryState;
  expect(active.exceptions[0]?.active).toBe(true);
  const expiry = active.exceptions[0]!.expires_at;
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("ads.test");
  await page
    .locator("tbody tr")
    .filter({
      has: page.getByText(`G${active.generation}`, { exact: true }),
    })
    .getByRole("button", { name: "ads.test", exact: true })
    .first()
    .click();
  await page.getByRole("button", { name: "Explain with current policy" }).click();
  await expect(page.getByRole("dialog")).toContainText("Temporary allow: TV repair");
  await expect(page.getByRole("dialog")).toContainText("Exception 1");
  await page.keyboard.press("Escape");
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Temporary exceptions", exact: true }).click();
  await expect(page.locator(".exception-row")).toContainText("ACTIVE");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: info.outputPath("temporary-allow.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Remove exception TV repair from draft" }).click();
  expect(await dns("ads.test")).toBe(0);
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect(page.getByRole("status")).toContainText("now active");
  expect(await dns("ads.test")).toBe(3);
  await expect(page.getByText("ACTIVE CONFIGURATION", { exact: true })).toBeVisible();
  const revisions = (await (
    await request.get("/api/v1/revisions", { headers: authorization })
  ).json()) as { id: number }[];
  const live = (await (
    await request.get(`/api/v1/revisions/${active.generation}`, {
      headers: authorization,
    })
  ).json()) as { config: Configuration };
  expect(live.config.policies[0]?.temporary_exceptions?.[0]?.expires_at).toBe(expiry);
  expect(revisions[0]!.id).toBeGreaterThan(active.generation);
});

test("unicode active labels and automatic expiry work without another revision", async ({
  page,
  request,
}) => {
  const draft = structuredClone(baseline);
  const expiry = Math.floor(Date.now() / 1000) + 4;
  draft.policies[0]!.lists[0]!.rules += "\nbücher.test";
  draft.policies[0]!.temporary_exceptions = [
    { name: "Unicode repair", domain: "BÜCHER.TEST.", expires_at: expiry },
  ];
  const promotion = await request.put("/api/v1/config", {
    headers: await revisionHeaders(request),
    data: draft,
  });
  expect(promotion.ok()).toBeTruthy();
  const { generation } = (await promotion.json()) as { generation: number };
  expect(await dns("xn--bcher-kva.test")).toBe(0);
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Temporary exceptions", exact: true }).click();
  await expect(page.locator(".exception-row")).toContainText("ACTIVE");
  await expect.poll(async () => await dns("xn--bcher-kva.test"), { timeout: 7000 }).toBe(3);
  await expect(page.locator(".exception-row")).toContainText("EXPIRED");
  const live = (await (
    await request.get("/api/v1/temporary-exceptions", {
      headers: authorization,
    })
  ).json()) as TemporaryState;
  expect(live.generation).toBe(generation);
  expect(live.exceptions[0]?.expires_at).toBe(expiry);
  expect(live.exceptions[0]?.active).toBe(false);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
});
