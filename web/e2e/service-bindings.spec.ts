import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";

test.beforeEach(async ({ request }) => reset(request));
test("service binding imports expose root targets and publish independent descendant edits", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByText("AdGuard DNS rewrite imports", { exact: true }).click();
  await expect(
    page.getByText("HTTPS/SVCB imports accept priority 0 aliases", { exact: false }),
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
          "||binding.home.arpa^$dnsrewrite=NOERROR;HTTPS;1 . port=8443",
          "||binding.home.arpa^$dnsrewrite=NOERROR;SVCB;0 ENDPOINT.home.arpa",
          "|cancelled.test^$dnsrewrite=NOERROR;HTTPS;1 .",
          "@@|cancelled.test^$dnsrewrite",
        ],
      }),
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await page.getByText("HTTPS/SVCB service records", { exact: true }).click();
  await expect(page.getByText("These records do not configure", { exact: false })).toBeVisible();
  await expect(page.getByLabel("Record 1 type")).toHaveValue("HTTPS");
  await expect(page.getByLabel("Record 1 target")).toHaveValue(".");
  await expect(page.getByLabel("Record 1 priority")).toHaveValue("1");
  await expect(page.getByLabel("Record 2 domain")).toHaveValue("*.binding.home.arpa");
  await expect(page.getByLabel("Record 2 TTL")).toHaveValue("31");
  await expect(page.getByLabel("Record 3 type")).toHaveValue("SVCB");
  await expect(page.getByLabel("Record 3 priority")).toHaveValue("0");
  await expect(page.getByLabel("Record 3 target")).toHaveValue("endpoint.home.arpa");
  await expect(page.getByLabel("Record 1 service port")).toHaveValue("8443");
  await page.getByLabel("Record 2 service port").fill("443");
  await page.getByLabel("Record 2 priority").fill("2");
  await page.getByLabel("Record 2 target").fill("edited.home.arpa");
  await page.getByRole("button", { name: "Add DNS record", exact: true }).click();
  await page.getByLabel("Record 5 domain").fill("manual.home.arpa");
  await page.getByLabel("Record 5 type").selectOption("HTTPS");
  await expect(page.getByLabel("Record 5 priority")).toHaveValue("1");
  await expect(page.getByLabel("Record 5 target")).toHaveValue(".");
  await expect(page.getByLabel("Record 5 priority")).toHaveAttribute("min", "0");
  await page.getByLabel("Record 5 priority").fill("0");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records.map((record: { data: unknown }) => record.data)).toEqual([
    { type: "HTTPS", priority: 1, target: ".", params: { port: 8443 } },
    { type: "HTTPS", priority: 2, target: "edited.home.arpa", params: { port: 443 } },
    { type: "SVCB", priority: 0, target: "endpoint.home.arpa" },
    { type: "SVCB", priority: 0, target: "endpoint.home.arpa" },
    { type: "HTTPS", priority: 0, target: "." },
  ]);
  for (const name of ["binding.home.arpa", "child.binding.home.arpa", "a.b.binding.home.arpa"])
    for (const kind of [64, 65]) expect(await dns(name, kind)).toBe(0);
  expect(await dns("manual.home.arpa", 65)).toBe(0);
  expect(await dns("ads.test")).toBe(3);
  await page.reload();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 target")).toHaveValue(".");
  await expect(page.getByLabel("Record 2 target")).toHaveValue("edited.home.arpa");
  await expect(page.getByLabel("Record 3 priority")).toHaveValue("0");
  await expect(page.getByLabel("Record 5 priority")).toHaveValue("0");
  await expect(page.getByLabel("Record 1 service port")).toHaveValue("8443");
  await expect(page.getByLabel("Record 2 service port")).toHaveValue("443");
});

test("service binding mixed modes parameters and value exceptions block import without disclosure", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  for (const [rule, message] of [
    [
      "||binding.test^$dnsrewrite=NOERROR;HTTPS;0 .",
      "HTTPS/SVCB AliasMode requires one record per owner/type",
    ],
    [
      "||binding.test^$dnsrewrite=NOERROR;HTTPS;1 . ech=private-fixture-secret",
      "HTTPS/SVCB parameters are unsupported",
    ],
    [
      "@@||binding.test^$dnsrewrite=NOERROR;SVCB;1 .",
      "HTTPS/SVCB value exceptions require source-comparison review",
    ],
  ] as const) {
    await page.getByLabel("Source backup").setInputFiles({
      name: "AdGuardHome.yaml",
      mimeType: "application/yaml",
      buffer: Buffer.from(
        JSON.stringify({
          user_rules: ["ads.test", "||binding.test^$dnsrewrite=NOERROR;HTTPS;1 .", rule],
        }),
      ),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(page.getByText(message, { exact: false })).toBeVisible();
    await expect(page.getByText("private-fixture-secret", { exact: false })).toHaveCount(0);
    expect(await dns("ads.test")).toBe(3);
  }
});

test("manual service binding validation rejects mixed modes and preserves the active policy", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await page.getByRole("button", { name: "Add DNS record", exact: true }).click();
  await page.getByLabel("Record 1 domain").fill("manual.home.arpa");
  await page.getByLabel("Record 1 type").selectOption("SVCB");
  await expect(page.getByLabel("Record 1 target")).toHaveValue(".");
  await page.getByLabel("Record 1 priority").fill("0");
  await page.getByRole("button", { name: "Add DNS record", exact: true }).click();
  await page.getByLabel("Record 2 domain").fill("manual.home.arpa");
  await page.getByLabel("Record 2 type").selectOption("SVCB");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(
    page.getByText("HTTPS/SVCB AliasMode requires one record per owner/type", { exact: false }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].dns_records ?? []).toEqual([]);
  expect(await dns("ads.test")).toBe(3);
});

test("optional service port preserves explicit zero removes cleanly and rejects AliasMode parameters", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await page.getByRole("button", { name: "Add DNS record", exact: true }).click();
  await page.getByLabel("Record 1 domain").fill("port.home.arpa");
  await page.getByLabel("Record 1 type").selectOption("SVCB");
  await expect(page.getByLabel("Record 1 service port")).toHaveValue("");
  await page.getByLabel("Record 1 service port").fill("0");
  for (const removing of [false, true]) {
    if (removing) await page.getByLabel("Record 1 service port").fill("");
    await page.getByRole("button", { name: "Validate draft", exact: true }).click();
    await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
    await page.getByRole("button", { name: "Review promotion", exact: true }).click();
    await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
    const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
    expect(active.policies[0].dns_records[0].data).toEqual(
      removing
        ? { type: "SVCB", priority: 1, target: "." }
        : { type: "SVCB", priority: 1, target: ".", params: { port: 0 } },
    );
    expect(await dns("port.home.arpa", 64)).toBe(0);
    await page.reload();
    await login(page);
    await page.getByRole("link", { name: "Policies", exact: true }).click();
    await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
    await expect(page.getByLabel("Record 1 service port")).toHaveValue(removing ? "" : "0");
  }
  await page.getByLabel("Record 1 priority").fill("0");
  await page.getByLabel("Record 1 service port").fill("8443");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(
    page.getByText("HTTPS/SVCB AliasMode does not support service parameters", { exact: false }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(active.policies[0].dns_records[0].data).toEqual({
    type: "SVCB",
    priority: 1,
    target: ".",
  });
});
