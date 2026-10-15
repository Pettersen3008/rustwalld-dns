import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
test("V6 explicit filtering tags control DNS while descriptive tags stay advisory", async ({
  page,
  request,
}, info) => {
  const config = await (await request.get("/api/v1/config", { headers: authorization })).json();
  config.allowed_clients = ["127.0.0.0/24"];
  config.bindings = [
    {
      name: "Phone",
      network: "127.0.0.1/32",
      policy: "default",
      metadata: { tags: ["user_child"] },
    },
  ];
  config.policies[0].lists[0] = {
    name: "baseline",
    action: "block",
    syntax: "adguard_v6",
    rules: "ads.test\n||tag.test^$ctag=user_child|~user_admin,dnstype=A,denyallow=safe.tag.test",
  };
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  expect(await dns("tag.test", 1, "127.0.0.1")).toBe(0);
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Clients & networks", exact: true }).click();
  await page.getByLabel("Binding 1 filtering tags").fill("user_child");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("tag.test", 1, "127.0.0.1")).toBe(3);
  expect(await dns("tag.test", 1, "127.0.0.2")).toBe(0);
  expect(await dns("safe.tag.test", 1, "127.0.0.1")).toBe(0);
  expect(await dns("tag.test", 28, "127.0.0.1")).toBe(0);
  expect(await dns("tag.test", 1, "127.0.0.1")).toBe(3);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("tag.test");
  await page.getByRole("button", { name: "Blocked", exact: true }).click();
  await page.getByRole("button", { name: "tag.test", exact: true }).first().click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  await expect(page.getByText("Rule tag scope", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Rule tag scope: user_child; except user_admin", { exact: true }),
  ).toBeVisible();
  expect(
    await page.getByRole("dialog").evaluate((el) => el.scrollWidth <= el.clientWidth),
  ).toBeTruthy();
  await page.screenshot({ path: info.outputPath("tag-scopes.png"), fullPage: true });
});
test("AdGuard tag imports preserve explicit source tags", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354']}\nclients: {persistent: [{name: Phone, ids: [127.0.0.1], tags: [device_phone,user_child]}]}\nuser_rules: [ads.test, '||tag.test^$ctag=user_child']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Clients & networks", exact: true }).click();
  await page.getByLabel("Find draft binding").fill("user_child");
  await expect(page.getByLabel("Binding 1 filtering tags")).toHaveValue("device_phone, user_child");
});
