import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
test("literal pattern addresses import with source TTL, edited apex and descendant answers", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByText("AdGuard DNS rewrite imports", { exact: true }).click();
  await expect(
    page.getByText("A suffix rule includes both its apex and descendants", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "schema_version: 34\ndns: {upstream_dns: ['127.0.0.1:15354']}\nfiltering: {blocked_response_ttl: 18, rewrites_enabled: false}\nuser_rules: [ads.test, '||private.home.arpa^$dnsrewrite=192.0.2.10', '||private.home.arpa^$dnsrewrite=NOERROR;AAAA;2001:db8::a']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page
      .getByText("Literal address pattern rewrite became native local DNS records", {
        exact: false,
      })
      .first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain")).toHaveValue("private.home.arpa");
  await expect(page.getByLabel("Record 2 domain")).toHaveValue("*.private.home.arpa");
  await expect(page.getByLabel("Record 1 TTL")).toHaveValue("18");
  await page.getByLabel("Record 1 address").fill("192.0.2.30");
  await page.getByLabel("Record 2 address").fill("192.0.2.30");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  for (const domain of ["private.home.arpa", "nas.private.home.arpa"]) {
    expect(await dns(domain, 1)).toBe(0);
    expect(await dns(domain, 28)).toBe(0);
    const value = await (
      await request.get(`/api/v1/explain?client=127.0.0.1&domain=${domain}`, {
        headers: authorization,
      })
    ).json();
    expect(value.rewrite).toBe(true);
  }
  expect(await dns("ads.test")).toBe(3);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records[0].data.address).toBe("192.0.2.30");
  expect(current.policies[0].dns_records[1].ttl).toBe(18);
});

test("filtering-disabled legacy and pattern definitions stay absent in the imported draft", async ({
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
      "schema_version: 34\ndns: {upstream_dns: ['127.0.0.1:15354']}\nfiltering: {filtering_enabled: false, rewrites: [{domain: legacy.home.arpa, answer: 192.0.2.20}]}\nuser_rules: ['||private.home.arpa^$dnsrewrite=192.0.2.10']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  // Destination's permanent ads.test assertion deliberately prevents publishing
  // this fully disabled source. The preview still proves inactive record handling.
  await expect(
    page.getByText("Source filtering is disabled; legacy rewrite definitions", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByText("Source filtering is disabled; pattern rewrite rules", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByText("Resolve compatibility blockers before treating this draft as a replacement", {
      exact: false,
    }),
  ).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records ?? []).toEqual([]);
  expect(await dns("ads.test")).toBe(3);
});

test("mixed controls, whitespace owners and unknown paused feeds remain migration blockers", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  for (const [source, message] of [
    [
      "schema_version: 34\ndns: {filtering_enabled: false}\nuser_rules: [ads.test, '||private.home.arpa^$dnsrewrite=192.0.2.10']\n",
      "Pattern rules mix filtering control/TTL layouts",
    ],
    [
      "filtering: {rewrites: [{domain: ' legacy.home.arpa', answer: 192.0.2.20}]}\nuser_rules: [ads.test]\n",
      "Source rewrite owners with whitespace require review",
    ],
    [
      "filtering: {protection_enabled: false}\nfilters: [{id: 1, enabled: true, url: 'https://publisher.test/list'}]\n",
      "Paused protection does not prove an enabled downloaded list",
    ],
  ]) {
    await page.getByLabel("Source backup").setInputFiles({
      name: "AdGuardHome.yaml",
      mimeType: "application/yaml",
      buffer: Buffer.from(source!),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(page.getByText(message!, { exact: false })).toBeVisible();
    expect(await dns("ads.test")).toBe(3);
  }
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records ?? []).toEqual([]);
});

test("address sets and same-pattern exceptions import, edit and publish with ordinary blocking", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByText("AdGuard DNS rewrite imports", { exact: true }).click();
  await expect(
    page.getByText("Same-pattern rewrite exceptions remove matching answers", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "schema_version: 34\nfiltering: {blocked_response_ttl: 19}\nuser_rules: [ads.test, '|pool.home.arpa^$dnsrewrite=192.0.2.10', '|pool.home.arpa|$dnsrewrite=192.0.2.20', '|pool.home.arpa^$dnsrewrite=192.0.2.30', '@@|pool.home.arpa|$dnsrewrite=NOERROR;A;192.0.2.10', '|cancelled.test^$dnsrewrite=192.0.2.10', '@@|cancelled.test|$dnsrewrite', cancelled.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Same-pattern rewrite exception was resolved", { exact: false }).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain")).toHaveValue("pool.home.arpa");
  await expect(page.getByLabel("Record 2 domain")).toHaveValue("pool.home.arpa");
  await expect(page.getByLabel("Record 1 address")).toHaveValue("192.0.2.20");
  await expect(page.getByLabel("Record 2 address")).toHaveValue("192.0.2.30");
  await page.getByLabel("Record 2 address").fill("192.0.2.40");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(
    current.policies[0].dns_records.map((record: { data: { address: string }; ttl: number }) => [
      record.data.address,
      record.ttl,
    ]),
  ).toEqual([
    ["192.0.2.20", 19],
    ["192.0.2.40", 19],
  ]);
  expect(await dns("pool.home.arpa")).toBe(0);
  expect(await dns("cancelled.test")).toBe(3);
  expect(await dns("ads.test")).toBe(3);
});

test("partial rewrite exceptions remain blockers without changing active DNS", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "user_rules: [ads.test, '||pool.home.arpa^$dnsrewrite=192.0.2.10', '@@|pool.home.arpa^$dnsrewrite']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(
    page.getByText("Rewrite exceptions require identical pattern coverage", { exact: false }),
  ).toBeVisible();
  expect(await dns("ads.test")).toBe(3);
});
