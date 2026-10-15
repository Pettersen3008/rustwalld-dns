import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";

test.beforeEach(async ({ request }) => reset(request));
test("typed rewrite imports expose editable TXT PTR MX SRV fields and publish reviewed answers", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByText("AdGuard DNS rewrite imports", { exact: true }).click();
  await expect(
    page.getByText("Exact and suffix TXT/PTR/MX/SRV rewrites are supported", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      JSON.stringify({
        schema_version: 34,
        filtering: { blocked_response_ttl: 31 },
        user_rules: [
          "ads.test",
          "|typed.home.arpa^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture",
          "|typed.home.arpa^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.",
          "|typed.home.arpa^$dnsrewrite=NOERROR;MX;10 MAIL.home.arpa",
          "|typed.home.arpa^$dnsrewrite=NOERROR;SRV;1 2 8443 SERVICE.home.arpa",
          "|typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed",
          "@@|typed.home.arpa|$dnsrewrite=NOERROR;TXT;removed",
        ],
      }),
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page
      .getByText("Literal typed pattern rewrite became exact native local DNS records", {
        exact: false,
      })
      .first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 type")).toHaveValue("TXT");
  await expect(page.getByLabel("Record 1 text")).toHaveValue("v=spf1 -all;fixture");
  await expect(page.getByLabel("Record 1 TTL")).toHaveValue("31");
  await expect(page.getByLabel("Record 2 type")).toHaveValue("PTR");
  await expect(page.getByLabel("Record 2 target")).toHaveValue("nas.home.arpa");
  await expect(page.getByLabel("Record 3 type")).toHaveValue("MX");
  await expect(page.getByLabel("Record 3 exchange")).toHaveValue("mail.home.arpa");
  await expect(page.getByLabel("Record 4 type")).toHaveValue("SRV");
  await expect(page.getByLabel("Record 4 target")).toHaveValue("service.home.arpa");
  await page.getByLabel("Record 1 text").fill("edited TXT");
  await page.getByLabel("Record 2 target").fill("new-nas.home.arpa");
  await page.getByLabel("Record 3 preference").fill("20");
  await page.getByLabel("Record 4 port").fill("9443");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records.map((record: { data: unknown }) => record.data)).toEqual([
    { type: "TXT", text: "edited TXT" },
    { type: "PTR", target: "new-nas.home.arpa" },
    { type: "MX", preference: 20, exchange: "mail.home.arpa" },
    { type: "SRV", priority: 1, weight: 2, port: 9443, target: "service.home.arpa" },
  ]);
  for (const kind of [16, 12, 15, 33]) expect(await dns("typed.home.arpa", kind)).toBe(0);
  expect(await dns("ads.test")).toBe(3);
});

test("ambiguous TXT options and MX value exceptions remain blockers without value disclosure", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  for (const [rule, message] of [
    [
      "|typed.test^$dnsrewrite=NOERROR;TXT;private-fixture-secret,client=127.0.0.2",
      "TXT import supports one 0..255-byte",
    ],
    [
      "@@|typed.test^$dnsrewrite=NOERROR;MX;10 mail.test",
      "MX/SRV value exceptions require source-comparison review",
    ],
  ] as const) {
    await page.getByLabel("Source backup").setInputFiles({
      name: "AdGuardHome.yaml",
      mimeType: "application/yaml",
      buffer: Buffer.from(
        JSON.stringify({ user_rules: ["ads.test", "|safe.test^$dnsrewrite=192.0.2.10", rule] }),
      ),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(page.getByText(message, { exact: false })).toBeVisible();
    await expect(page.getByText("private-fixture-secret", { exact: false })).toHaveCount(0);
    expect(await dns("ads.test")).toBe(3);
  }
});

test("typed suffix imports keep apex and descendant edits independent after promotion", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByText("AdGuard DNS rewrite imports", { exact: true }).click();
  await expect(
    page.getByText("Exact and suffix TXT/PTR/MX/SRV rewrites are supported", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      JSON.stringify({
        schema_version: 34,
        filtering: { blocked_response_ttl: 31 },
        user_rules: [
          "ads.test",
          "||typed.home.arpa^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture",
          "||typed.home.arpa^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.",
          "||typed.home.arpa^$dnsrewrite=NOERROR;MX;10 MAIL.home.arpa",
          "||typed.home.arpa^$dnsrewrite=NOERROR;SRV;1 2 8443 SERVICE.home.arpa",
          "||typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed",
          "@@||typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed",
        ],
      }),
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page
      .getByText(
        "Literal typed pattern rewrite became apex and descendant native local DNS records",
        {
          exact: false,
        },
      )
      .first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 2 type")).toHaveValue("TXT");
  await expect(page.getByLabel("Record 2 text")).toHaveValue("v=spf1 -all;fixture");
  await expect(page.getByLabel("Record 2 TTL")).toHaveValue("31");
  await expect(page.getByLabel("Record 4 type")).toHaveValue("PTR");
  await expect(page.getByLabel("Record 4 target")).toHaveValue("nas.home.arpa");
  await expect(page.getByLabel("Record 6 type")).toHaveValue("MX");
  await expect(page.getByLabel("Record 6 exchange")).toHaveValue("mail.home.arpa");
  await expect(page.getByLabel("Record 8 type")).toHaveValue("SRV");
  await expect(page.getByLabel("Record 8 target")).toHaveValue("service.home.arpa");
  await expect(page.getByLabel("Record 1 domain")).toHaveValue("typed.home.arpa");
  await expect(page.getByLabel("Record 2 domain")).toHaveValue("*.typed.home.arpa");
  await page.getByText("Local record behavior and wildcard limits", { exact: true }).click();
  await expect(
    page.getByText("Edit apex and descendant records separately", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Record 2 text").fill("edited TXT");
  await page.getByLabel("Record 4 target").fill("new-nas.home.arpa");
  await page.getByLabel("Record 6 preference").fill("20");
  await page.getByLabel("Record 8 port").fill("9443");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records.map((record: { data: unknown }) => record.data)).toEqual([
    { type: "TXT", text: "v=spf1 -all;fixture" },
    { type: "TXT", text: "edited TXT" },
    { type: "PTR", target: "nas.home.arpa" },
    { type: "PTR", target: "new-nas.home.arpa" },
    { type: "MX", preference: 10, exchange: "mail.home.arpa" },
    { type: "MX", preference: 20, exchange: "mail.home.arpa" },
    { type: "SRV", priority: 1, weight: 2, port: 8443, target: "service.home.arpa" },
    { type: "SRV", priority: 1, weight: 2, port: 9443, target: "service.home.arpa" },
  ]);
  for (const name of ["typed.home.arpa", "child.typed.home.arpa", "a.b.typed.home.arpa"]) {
    for (const kind of [16, 12, 15, 33]) expect(await dns(name, kind)).toBe(0);
  }
  await page.reload();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 text")).toHaveValue("v=spf1 -all;fixture");
  await expect(page.getByLabel("Record 2 text")).toHaveValue("edited TXT");
  expect(await dns("ads.test")).toBe(3);
});

test("partial typed suffix exceptions report blockers without activating answers", async ({
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
      JSON.stringify({
        user_rules: [
          "ads.test",
          "||typed.test^$dnsrewrite=NOERROR;TXT;fixture",
          "@@|child.typed.test^$dnsrewrite",
        ],
      }),
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(
    page.getByText("Rewrite exceptions require identical pattern coverage", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Review replacing local draft", exact: true }),
  ).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records ?? []).toEqual([]);
  expect(await dns("ads.test")).toBe(3);
});
