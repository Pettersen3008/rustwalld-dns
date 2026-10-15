import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
test("wildcard addresses import, explain apex limits, edit and promote on desktop and mobile", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "schema_version: 34\ndns: {upstream_dns: ['127.0.0.1:15354']}\nfiltering: {rewrites: [{domain: '*.private.home.arpa', answer: 192.0.2.10}, {domain: '*.deep.private.home.arpa', answer: 192.0.2.20}]}\nuser_rules: [ads.test, private.home.arpa]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain")).toHaveValue("*.private.home.arpa");
  await page.getByText("Local record behavior and wildcard limits", { exact: true }).click();
  await expect(
    page.getByText("The apex home.arpa needs its own record", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Record 2 address").fill("192.0.2.30");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(await dns("nas.deep.private.home.arpa")).toBe(0);
  expect(await dns("private.home.arpa")).toBe(3);
  expect(await dns("ads.test")).toBe(3);
  const child = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=nas.deep.private.home.arpa", {
      headers: authorization,
    })
  ).json();
  const apex = await (
    await request.get("/api/v1/explain?client=127.0.0.1&domain=private.home.arpa", {
      headers: authorization,
    })
  ).json();
  expect(child.rewrite).toBe(true);
  expect(apex.rewrite).toBe(false);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records[1].data.address).toBe("192.0.2.30");
  await page.reload();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 2 address")).toHaveValue("192.0.2.30");
});
