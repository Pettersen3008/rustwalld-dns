import { test, expect } from "@playwright/test";
import { authorization, baseline, dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));

async function promote(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
}
test("SafeSearch draft, conflict validation, reviewed promotion and original-generation history", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "SafeSearch", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "SafeSearch & YouTube", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("OFF", { exact: true })).toBeVisible();
  await page.getByLabel("Enforce Google SafeSearch").check();
  await page.getByLabel("YouTube restricted mode").selectOption("strict");
  const before = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(before.policies[0].safe_search).toBeUndefined();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await page.getByRole("button", { name: "Add DNS record", exact: true }).click();
  await page.getByLabel("Record 1 domain").fill("www.google.com");
  await page.getByLabel("Record 1 address").fill("192.0.2.99");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("SafeSearch owner/target conflicts");
  await page.getByRole("button", { name: "Remove record 1", exact: true }).click();
  await page.getByRole("tab", { name: "SafeSearch", exact: true }).click();
  await promote(page);
  expect(await dns("www.google.com")).toBe(0);
  expect(await dns("www.youtube.com")).toBe(0);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByRole("button", { name: "SafeSearch", exact: true }).click();
  await expect(page.getByRole("button", { name: "www.google.com", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "www.google.com", exact: true }).click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await expect(page.getByText("Recorded SafeSearch route:", { exact: false })).toContainText(
    "forcesafesearch.google.com",
  );
  const events = await (
    await request.get("/api/v1/queries?limit=500", { headers: authorization })
  ).json();
  const event = events.find(
    (row: { domain: string; source: string }) =>
      row.domain === "www.google.com" && row.source === "safe_search",
  );
  expect(event).toBeDefined();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  delete current.policies[0].safe_search;
  const saved = await request.put("/api/v1/config", {
    headers: await revisionHeaders(request),
    data: current,
  });
  expect(saved.ok()).toBeTruthy();
  const recorded = await (
    await request.get(`/api/v1/queries/${event.id}/explain`, { headers: authorization })
  ).json();
  expect(recorded.safe_search.target).toBe("forcesafesearch.google.com");
  const explanation = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=www.google.com", {
      headers: authorization,
    })
  ).json();
  expect(explanation.safe_search).toBeUndefined();
  await page.screenshot({ path: info.outputPath("safe-search-history.png"), fullPage: true });
});

test("SafeSearch choices stay inside the selected client policy", async ({
  page,
  request,
}, info) => {
  const child = { ...baseline.policies[0]!, name: "kids" };
  const config = {
    ...baseline,
    allowed_clients: ["127.0.0.0/8"],
    policies: [baseline.policies[0]!, child],
    bindings: [{ network: "127.0.0.2/32", policy: "kids", name: "Child device" }],
  };
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "SafeSearch", exact: true }).click();
  await page.getByLabel("SafeSearch policy").selectOption("1");
  await page.getByLabel("Enforce Bing SafeSearch").check();
  await promote(page);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].safe_search).toBeUndefined();
  expect(current.policies[1].safe_search.bing).toBe(true);
  const normal = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=www.bing.com", {
      headers: authorization,
    })
  ).json();
  const childTrace = await (
    await request.get("/api/v1/explain?client=127.0.0.2&domain=www.bing.com", {
      headers: authorization,
    })
  ).json();
  expect(normal.safe_search).toBeUndefined();
  expect(childTrace.safe_search.target).toBe("strict.bing.com");
  await page.screenshot({ path: info.outputPath("safe-search-policy.png"), fullPage: true });
});
