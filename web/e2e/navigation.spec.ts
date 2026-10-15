import { test, expect } from "@playwright/test";
import { baseline, login, reset, revisionHeaders, token } from "./helpers";

test.beforeEach(async ({ request }) => {
  await reset(request);
});

test("document routes preserve drafts, browser history and authenticated bookmarks", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(page).toHaveURL(/\/policies$/);
  await page.getByLabel("Rules for baseline").fill("ads.test\nnavigation.test");
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await expect(page).toHaveURL(/\/queries$/);
  await page.goBack();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue("ads.test\nnavigation.test");
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  // Refresh requires authentication but retains the document destination.
  page.once("dialog", (dialog) => dialog.accept());
  await page.reload();
  await expect(page.getByLabel("Management token")).toHaveValue("");
  await page.getByLabel("Management token").fill(token);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Traffic ledger", exact: true })).toBeVisible();
  await page.goto("/#upstreams");
  await expect(page).toHaveURL(/\/upstreams$/);
});

test("unchanged generations avoid configuration polling and changed versions preserve edits", async ({
  page,
  request,
}) => {
  let reads = 0;
  page.on("request", (req) => {
    if (new URL(req.url()).pathname === "/api/v1/config" && req.method() === "GET") reads++;
  });
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("Rules for baseline").fill("ads.test\nmy-local.test");
  // Wait through more than one ordinary five-second poll interval.
  await page.waitForTimeout(5500);
  expect(reads).toBe(1);
  const changed = structuredClone(baseline);
  changed.policies[0]!.lists[0]!.rules += "\nanother-editor.test";
  expect(
    (
      await request.put("/api/v1/config", {
        headers: await revisionHeaders(request),
        data: changed,
      })
    ).ok(),
  ).toBeTruthy();
  await expect(
    page.getByText("A newer active or shadow revision exists.", { exact: false }),
  ).toBeVisible();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue("ads.test\nmy-local.test");
  expect(reads).toBe(2);
});

test("query tables sort numeric latency, paginate and filter with the current Table API", async ({
  page,
}) => {
  const events = Array.from({ length: 45 }, (_, index) => ({
    id: index + 1,
    timestamp: new Date().toISOString(),
    client: "127.0.0.1",
    domain: `d${String(index).padStart(2, "0")}.fixture.test`,
    qtype: 1,
    generation: 1,
    policy_id: 0,
    action: "allow",
    rule_id: null,
    decision_cached: false,
    response_code: 0,
    source: "cache",
    latency_us: index === 0 ? 1000 : index,
    shadow: null,
  }));
  await page.route(/\/api\/v1\/queries\?/, (route) => route.fulfill({ json: events }));
  await login(page);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(20);
  const latency = page.getByRole("columnheader", { name: "Latency" });
  await latency.getByRole("button").click();
  if ((await latency.getAttribute("aria-sort")) === "descending")
    await latency.getByRole("button").click();
  await expect(latency).toHaveAttribute("aria-sort", "ascending");
  await expect(page.locator("tbody tr").first()).toContainText("d01.fixture.test");
  await page.getByRole("button", { name: "Next page", exact: true }).click();
  await expect(page.locator(".table-footer")).toContainText("Page 2 of 3");
  await page.getByLabel("Search queries").fill("d00.fixture.test");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("tbody tr")).toContainText("1000 µs");
  await expect(page.locator(".table-footer")).toContainText("Page 1 of 1");
});

test("policy section tabs support arrow navigation, wrapping and tabbing into their panel", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  const first = page.getByRole("tab", { name: "Policies & rules", exact: true });
  await first.focus();
  await page.keyboard.press("ArrowRight");
  const networks = page.getByRole("tab", { name: "Clients & networks", exact: true });
  await expect(networks).toBeFocused();
  await expect(networks).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("End");
  await expect(page.getByRole("tab", { name: "Migration", exact: true })).toBeFocused();
  await page.keyboard.press("ArrowRight");
  await expect(first).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("tabpanel")).toBeFocused();
});
