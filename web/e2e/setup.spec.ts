import { test, expect } from "@playwright/test";
import { login, reset, authorization } from "./helpers";
test.beforeEach(async ({ request }) => {
  await reset(request);
});
test("setup reports real listeners and inventory without creating admission", async ({
  page,
  request,
}) => {
  const before = await (await request.get("/api/v1/config", { headers: authorization })).json();
  await login(page);
  await page.getByRole("link", { name: "Setup & integrations", exact: true }).click();
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Bound listeners" })).toBeVisible();
  await expect(page.getByRole("main").getByText("127.0.0.1:15353", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Refresh dhcp-fixture", exact: true }).click();
  await expect(page.getByRole("cell", { name: "fixture-nas", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "192.0.2.20", exact: true })).toBeVisible();
  const after = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(after).toEqual(before);
});
test("peer policy replaces a reviewed draft and preserves live policy", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("Rules for baseline").fill("ads.test\nmy-unsaved.test");
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Policy peer").selectOption("peer-fixture");
  await page.getByRole("button", { name: "Preview peer policy", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Replace draft with peer policy" })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("tab", { name: "Policies & rules", exact: true }).click();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue("ads.test\nmy-unsaved.test");
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Policy peer").selectOption("peer-fixture");
  await page.getByRole("button", { name: "Preview peer policy", exact: true }).click();
  await page.getByRole("button", { name: "Replace draft", exact: true }).click();
  await page.getByRole("tab", { name: "Policies & rules", exact: true }).click();
  await expect(page.getByLabel("Rules for peer-list")).toHaveValue("ads.test\npeer.test");
  const live = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(live.policies[0].lists[0].name).toBe("baseline");
});
test("family resolver profiles stay in a reviewed draft with no public DNS calls", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Upstream profiles", exact: true }).click();
  await page.getByLabel("Resolver mode").selectOption("family");
  await page.getByRole("button", { name: "Review resolver profile", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Apply resolver profile to draft" })).toBeVisible();
  await page.getByRole("button", { name: "Apply profile to draft", exact: true }).click();
  await expect(page.getByLabel("Upstream 2 TLS server name")).toHaveValue(
    "family.cloudflare-dns.com",
  );
  const live = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(live.upstreams).toHaveLength(1);
  expect(live.upstreams[0].name).toBe("local-mock");
});
