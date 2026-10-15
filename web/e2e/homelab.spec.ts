import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";
import { readFileSync } from "node:fs";
test.beforeEach(async ({ request }) => reset(request));

test("Pi-hole v5 archive becomes a checked draft and retains local DNS after promotion", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await expect(page.getByText("Pi-hole: v5 Teleporter tar.gz", { exact: false })).toBeVisible();
  await page.getByLabel("Source backup").setInputFiles({
    name: "pihole-v5.tar.gz",
    mimeType: "application/gzip",
    buffer: readFileSync(new URL("./fixtures/pihole-v5.tar.gz", import.meta.url)),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Source backup")).toHaveValue("");
  await expect(page.locator("body")).not.toContainText("PUBLIC_TEST_SENTINEL_DO_NOT_COPY");
  const before = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(before.policies[0].name).toBe("default");
  await page.getByRole("button", { name: "Review replacing local draft" }).click();
  await page.getByRole("button", { name: "Load imported draft" }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const after = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(after.policies[0].name).toBe("pi-hole/groups-0");
  expect(after.policies[0].dns_records).toContainEqual({
    domain: "storage.home.arpa",
    ttl: 40,
    data: { type: "CNAME", target: "nas.home.arpa" },
  });
  expect(await dns("ads.test")).toBe(3);
  expect(await dns("nas.home.arpa")).toBe(0);
});

test("AdGuard route import preserves every resolver and missing TLS pins stay blocked", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354', '[/home.arpa/]127.0.0.1:15355']}\nuser_rules: [ads.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft" }).click();
  await page.getByRole("button", { name: "Load imported draft" }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: "DS resolver selection", exact: true }),
  ).toHaveValue("parent");
  await expect(page.getByLabel("Route 1 domain")).toHaveValue("home.arpa");
  await expect(page.getByLabel("Route 1 upstream")).toHaveValue("adguard/upstreams/route-0");
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['tls://unconfigured.test'], bootstrap_dns: ['192.0.2.99']}\nuser_rules: [ads.test]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("1 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Source bootstrap servers were not used as endpoint addresses", {
      exact: false,
    }),
  ).toBeVisible();
  const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(active.policies[0].name).toBe("default");
  expect(await dns("ads.test")).toBe(3);
});

test("migration preview, compatibility and replacement preserve active DNS until promotion", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByLabel("Rules for baseline").fill("ads.test\nunsaved.test");
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: [127.0.0.1:15354]}\nuser_rules: [ads.test, '||tracking.test^']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Stage in shadow" })).toBeDisabled();
  const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(active.policies[0].lists[0].rules).toBe("ads.test");
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("button", { name: "Review replacing local draft" }).click();
  await expect(page.getByRole("dialog")).toContainText("unsaved draft edits");
  await page.getByRole("button", { name: "Keep current draft" }).click();
  await page.getByRole("tab", { name: "Policies & rules" }).click();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue("ads.test\nunsaved.test");
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  // Leaving the import panel clears its sensitive source/report state.
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "user_rules: [ads.test]\nfilters: [{id: 1, enabled: true, url: 'https://publisher.test/list'}]\nusers: [{name: admin, password: MUST_NOT_DISPLAY}]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("1 BLOCKERS", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Enabled downloaded list contents are absent.", { exact: false }),
  ).toBeVisible();
  await expect(page.locator("body")).not.toContainText("MUST_NOT_DISPLAY");
  await page.getByRole("button", { name: "Review replacing local draft" }).click();
  await page.getByRole("button", { name: "Load imported draft" }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow" })).toBeDisabled();
  await page.getByRole("tab", { name: "Policies & rules" }).click();
  await expect(page.getByLabel("List 1 syntax")).toHaveValue("adguard_v6");
  expect(await dns("ads.test")).toBe(3);
  await page.screenshot({ path: info.outputPath("migration-draft.png"), fullPage: true });
});

test("local records, alias validation, routes and modes are editable and publish atomically", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await page.getByRole("button", { name: "Add DNS record" }).click();
  await page.getByLabel("Record 1 domain").fill("storage.home.arpa");
  await page.getByLabel("Record 1 type").selectOption("CNAME");
  await page.getByLabel("Record 1 target").fill("storage.home.arpa");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("loop");
  await page.getByLabel("Record 1 target").fill("nas.home.arpa");
  await page.getByLabel("Record 1 TTL").fill("45");
  await page.getByRole("button", { name: "Add domain route" }).click();
  await page.getByLabel("Route 1 domain").fill("home.arpa");
  await page.getByLabel("Blocked reply mode").selectOption("null_ip");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect(page.getByRole("status")).toContainText("now active");
  await expect(page.locator(".skip-link")).not.toBeFocused();
  expect(await dns("ads.test")).toBe(0);
  expect(await dns("storage.home.arpa")).toBe(0);
  const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(active.policies[0].dns_records[0].data).toEqual({
    type: "CNAME",
    target: "nas.home.arpa",
  });
  expect(active.policies[0].block_mode).toBe("null_ip");
  await page.screenshot({ path: info.outputPath("local-dns.png"), fullPage: true });
});

test("query repair confirms a client-specific expiring action and preserves local drafts", async ({
  page,
  request,
}, info) => {
  expect(await dns("ads.test")).toBe(3);
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByLabel("Rules for baseline").fill("ads.test\nunsaved.test");
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByRole("button", { name: "ads.test", exact: true }).first().click();
  await page.getByRole("button", { name: "Explain recorded decision" }).click();
  await expect(page.getByRole("heading", { name: /Recorded policy provenance/ })).toBeVisible();
  await page.getByText("Original rule sources (up to 100)", { exact: true }).click();
  await expect(page.getByText("baseline · line 1", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Temporarily allow for this client" }).click();
  await expect(page.getByRole("heading", { name: "Review temporary client action" })).toBeVisible();
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("button", { name: "Apply to this client" }).click();
  await expect(page.getByRole("status")).toContainText("applied to 127.0.0.1");
  expect(await dns("ads.test")).toBe(0);
  const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(active.policies[0].temporary_exceptions[0].clients).toEqual(["127.0.0.1/32"]);
  expect(active.policies[0].temporary_exceptions[0].expires_at).toBeLessThanOrEqual(
    Math.floor(Date.now() / 1000) + 300,
  );
  await page.getByRole("link", { name: /^Policies/ }).click();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue("ads.test\nunsaved.test");
  await expect(
    page.getByText("A newer active or shadow revision exists.", { exact: false }),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("client-repair-draft-preserved.png"),
    fullPage: true,
  });
});

test("client resolver migration shows assignments and publishes only after review", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354']}\nclients: {persistent: [{name: Work, ids: [127.0.0.2], use_global_settings: true, upstreams: ['127.0.0.1:15355']}, {name: Shared, ids: [127.0.0.3], upstreams: ['127.0.0.1:15355']}, {name: Inherited, ids: [127.0.0.4], upstreams: []}]}\nuser_rules: [ads.test]\nusers: [{password: PRIVATE_SENTINEL}]\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByText("Resolver assignments · 4 policies", { exact: true }).click();
  const table = page.getByRole("table", { name: "Imported resolver assignments" });
  await expect(table.getByRole("row")).toHaveCount(5);
  expect(await table.evaluate((element) => element.scrollWidth)).toBeLessThanOrEqual(
    await table.evaluate((element) => element.clientWidth),
  );
  await expect(table).toContainText("Work · 127.0.0.2/32");
  await expect(table.getByRole("row").filter({ hasText: "Work ·" })).toContainText(
    "127.0.0.1:15355",
  );
  await expect(table.getByRole("row").filter({ hasText: "Inherited ·" })).toContainText(
    "127.0.0.1:15354",
  );
  await expect(page.locator("body")).not.toContainText("PRIVATE_SENTINEL");
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies,
  ).toHaveLength(1);
  expect(await dns("ads.test")).toBe(3);
  await page.screenshot({ path: info.outputPath("client-resolvers.png"), fullPage: true });
  await page.getByRole("button", { name: "Review replacing local draft" }).click();
  await page.getByRole("button", { name: "Load imported draft" }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const active = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(active.policies).toHaveLength(4);
  expect(active.policies[1].upstream).toBe(active.policies[2].upstream);
  expect(active.policies[1].upstream).not.toBe(active.policies[0].upstream);
  expect(active.allowed_clients).toEqual(["127.0.0.1/32", "::1/128"]);
  expect(await dns("ads.test")).toBe(3);
});

test("resolver assignment pages retain scope and reset on a new preview", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: /^Policies/ }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  async function upload(count: number) {
    await page.getByLabel("Source backup").setInputFiles({
      name: "AdGuardHome.json",
      mimeType: "application/json",
      buffer: Buffer.from(
        JSON.stringify({
          clients: {
            persistent: Array.from({ length: count }, (_, i) => ({
              name: `Client ${i}`,
              ids: [`127.0.0.${i + 2}`],
              upstreams: ["127.0.0.1:15355"],
            })),
          },
          user_rules: ["ads.test"],
        }),
      ),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  }
  await upload(30);
  await page.getByText("Resolver assignments · 31 policies", { exact: true }).click();
  await page.getByRole("button", { name: "Next resolver assignments", exact: true }).click();
  await expect(page.getByRole("table", { name: "Imported resolver assignments" })).toContainText(
    "Client 29 · 127.0.0.31/32",
  );
  await upload(1);
  const summary = page.getByText("Resolver assignments · 2 policies", { exact: true });
  // A fresh preview remounts the table and resets pagination.
  await summary.click();
  await expect(page.getByRole("table", { name: "Imported resolver assignments" })).toContainText(
    "Client 0 · 127.0.0.2/32",
  );
});

test("DS routing imports remain ready and query-log explanations send the recorded type", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: "DS resolver selection", exact: true }),
  ).toHaveValue("question");
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "AdGuardHome.yaml",
    mimeType: "application/yaml",
    buffer: Buffer.from(
      "dns: {upstream_dns: ['127.0.0.1:15354', '[/test/]127.0.0.1:15354', '[/child.test/]127.0.0.1:15355']}\nclients: {persistent: [{name: Work, ids: [127.0.0.2], upstreams: ['127.0.0.1:15355']}]}\nuser_rules: [ads.test, '||child.test^']\n",
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: "DS resolver selection", exact: true }),
  ).toHaveValue("parent");
  await page.screenshot({ path: info.outputPath("ds-route-editor.png"), fullPage: true });
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies[0]
      .ds_routing,
  ).toBe("parent");
  expect(await dns("child.test", 43)).toBe(3);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("child.test");
  await page.getByRole("button", { name: "child.test", exact: true }).first().click();
  await expect(page.getByRole("dialog")).toContainText("DS · delegation");
  const trace = page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/api/v1/explain",
  );
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  const response = await trace;
  expect(new URL(response.url()).searchParams.get("qtype")).toBe("43");
  expect((await response.json()).upstream).toBe("adguard/upstreams/route-1");
  await page.keyboard.press("Escape");
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await page.getByRole("combobox", { name: "Local DNS policy", exact: true }).selectOption("1");
  await expect(
    page.getByRole("combobox", { name: "DS resolver selection", exact: true }),
  ).toHaveValue("parent");
  await page
    .getByRole("combobox", { name: "DS resolver selection", exact: true })
    .selectOption("question");
  await page.getByRole("combobox", { name: "Local DNS policy", exact: true }).selectOption("0");
  await expect(
    page.getByRole("combobox", { name: "DS resolver selection", exact: true }),
  ).toHaveValue("parent");
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies[0]
      .ds_routing,
  ).toBe("parent");
});
