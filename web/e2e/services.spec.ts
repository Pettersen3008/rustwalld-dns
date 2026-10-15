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
test("service draft promotion and historical provenance survive current disable", async ({
  page,
  request,
}, info) => {
  const domain = `service-review-${info.project.name}.youtube.com`;
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Services", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Service domain blocking", exact: true }),
  ).toBeVisible();
  await page.getByLabel("Block YouTube", { exact: true }).check();
  await page.getByText("YouTube coverage · catalog v1", { exact: true }).click();
  await expect(
    page.getByText("youtube.com, youtu.be, youtube-nocookie.com", { exact: true }),
  ).toBeVisible();
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies[0]
      .blocked_services,
  ).toBeUndefined();
  await promote(page);
  expect(await dns(domain)).toBe(3);
  expect(await dns("youtubei.googleapis.com")).toBe(3);
  expect(await dns("google.com")).toBe(0);
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill(domain);
  await expect(page.getByRole("button", { name: domain, exact: true })).toBeVisible();
  await page.getByRole("button", { name: domain, exact: true }).click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await expect(page.getByText("Recorded service block:", { exact: false })).toContainText(
    "@service/v1/youtube",
  );
  const events = await (
    await request.get("/api/v1/queries?limit=500", { headers: authorization })
  ).json();
  const event = events.find((entry: { domain: string }) => entry.domain === domain);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  delete current.policies[0].blocked_services;
  expect(
    (
      await request.put("/api/v1/config", {
        headers: await revisionHeaders(request),
        data: current,
      })
    ).ok(),
  ).toBeTruthy();
  const recorded = await (
    await request.get(`/api/v1/queries/${event.id}/explain`, { headers: authorization })
  ).json();
  expect(recorded.rule.sources[0].list).toContain("@service/v1/youtube");
  const now = await (
    await request.get(`/api/v1/explain?client=127.0.0.1&domain=${domain}`, {
      headers: authorization,
    })
  ).json();
  expect(now.decision.action).toBe("allow");
  await page.screenshot({ path: info.outputPath("services-history.png"), fullPage: true });
});

test("service choices remain scoped to the selected policy and respect native allows", async ({
  page,
  request,
}, info) => {
  const config = {
    ...baseline,
    allowed_clients: ["127.0.0.0/8"],
    policies: [
      baseline.policies[0]!,
      {
        ...baseline.policies[0]!,
        name: "kids",
        lists: [
          ...baseline.policies[0]!.lists,
          { name: "support allow", action: "allow", rules: "=support.tiktok.com" },
        ],
      },
    ],
    bindings: [{ network: "127.0.0.2/32", policy: "kids", name: "Child device" }],
  };
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Services", exact: true }).click();
  await page.getByLabel("Service blocking policy").selectOption("1");
  await page.getByLabel("Block TikTok", { exact: true }).check();
  await promote(page);
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.policies[0].blocked_services).toBeUndefined();
  expect(current.policies[1].blocked_services.ids).toEqual(["tiktok"]);
  for (const [client, domain, action] of [
    ["127.0.0.1", "www.tiktok.com", "allow"],
    ["127.0.0.2", "www.tiktok.com", "block"],
    ["127.0.0.2", "support.tiktok.com", "allow"],
  ]) {
    const trace = await (
      await request.get(`/api/v1/explain?client=${client}&domain=${domain}`, {
        headers: authorization,
      })
    ).json();
    expect(trace.decision.action).toBe(action);
  }
  await page.screenshot({ path: info.outputPath("services-policy.png"), fullPage: true });
});

test("catalog upgrade preserves weekly windows, filters selections and retains v2 history", async ({
  page,
  request,
}, info) => {
  const schedule = {
    time_zone: "UTC",
    mode: "block",
    windows: [
      { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], start: "00:00", end: "24:00" },
    ],
  };
  const config = structuredClone(baseline);
  config.policies[0]!.blocked_services = {
    catalog_version: 1,
    ids: ["youtube"],
    schedule,
  } as (typeof config.policies)[0]["blocked_services"];
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).ok(),
  ).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Services", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Service catalog", exact: true })).toHaveValue(
    "1",
  );
  await page.getByRole("combobox", { name: "Service catalog", exact: true }).selectOption("2");
  await page.getByLabel("Search services").fill("netflix");
  await page.getByLabel("Block Netflix", { exact: true }).check();
  await page.getByText("Netflix coverage · catalog v2", { exact: true }).click();
  await expect(page.getByText("Separate streaming CDNs", { exact: false })).toBeVisible();
  await expect(page.getByRole("link", { name: "Netflix provider reference 1" })).toHaveAttribute(
    "href",
    "https://help.netflix.com/en/node/114701/",
  );
  await expect(
    page
      .getByRole("combobox", { name: "Service catalog", exact: true })
      .locator('option[value="1"]'),
  ).toHaveAttribute("disabled", "");
  await page
    .getByRole("combobox", { name: "Service category", exact: true })
    .selectOption("Gaming");
  await expect(page.getByText("No services match", { exact: false })).toBeVisible();
  await page.getByLabel("Search services").fill("");
  await expect(page.getByLabel("Block Steam", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Block Roblox", { exact: true })).toBeVisible();
  const live = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(live.policies[0].blocked_services).toEqual({
    catalog_version: 1,
    ids: ["youtube"],
    schedule,
  });
  await promote(page);
  const domain = `expanded-review-${info.project.name}.netflix.com`;
  expect(await dns(domain)).toBe(3);
  const published = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(published.policies[0].blocked_services).toEqual({
    catalog_version: 2,
    ids: ["youtube", "netflix"],
    schedule,
  });
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill(domain);
  await page.getByRole("button", { name: domain, exact: true }).click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await expect(page.getByText("Recorded service block:", { exact: false })).toContainText(
    "@service/v2/netflix",
  );
  const events = await (
    await request.get("/api/v1/queries?limit=500", { headers: authorization })
  ).json();
  const event = events.find((entry: { domain: string }) => entry.domain === domain);
  published.policies[0].blocked_services.catalog_version = 1;
  published.policies[0].blocked_services.ids = ["youtube"];
  expect(
    (
      await request.put("/api/v1/config", {
        headers: await revisionHeaders(request),
        data: published,
      })
    ).ok(),
  ).toBeTruthy();
  const recorded = await (
    await request.get(`/api/v1/queries/${event.id}/explain`, { headers: authorization })
  ).json();
  expect(recorded.rule.sources[0].list).toContain("@service/v2/netflix");
});

test("new catalog view supports domain search and safe reviewed downgrade without dropping selections", async ({
  page,
  request,
}, info) => {
  const configured = structuredClone(baseline);
  configured.policies.push({
    ...structuredClone(baseline.policies[0]!),
    name: "legacy",
    blocked_services: { catalog_version: 1, ids: ["youtube"] },
  });
  expect(
    (
      await request.put("/api/v1/config", {
        headers: await revisionHeaders(request),
        data: configured,
      })
    ).ok(),
  ).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Services", exact: true }).click();
  await page.getByRole("combobox", { name: "Service catalog", exact: true }).selectOption("2");
  await page.getByLabel("Search services").fill("whatsapp.net");
  await page.getByLabel("Block WhatsApp", { exact: true }).check();
  await page.getByText("WhatsApp coverage · catalog v2", { exact: true }).click();
  await expect(page.getByText("whatsapp.com, whatsapp.net", { exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("expanded-services.png"), fullPage: true });
  await page.getByLabel("Search services").fill("");
  await page.getByLabel("Block YouTube", { exact: true }).check();
  await expect(
    page
      .getByRole("combobox", { name: "Service catalog", exact: true })
      .locator('option[value="1"]'),
  ).toHaveAttribute("disabled", "");
  await page
    .getByRole("combobox", { name: "Service category", exact: true })
    .selectOption("Gaming");
  await page.getByLabel("Service blocking policy").selectOption("1");
  await expect(page.getByRole("combobox", { name: "Service catalog", exact: true })).toHaveValue(
    "1",
  );
  await expect(page.getByRole("combobox", { name: "Service category", exact: true })).toHaveValue(
    "",
  );
  await expect(page.getByLabel("Block YouTube", { exact: true })).toBeChecked();
  await page.getByLabel("Service blocking policy").selectOption("0");
  await expect(page.getByLabel("Block WhatsApp", { exact: true })).toBeChecked();
  await page.getByLabel("Block WhatsApp", { exact: true }).uncheck();
  await page.getByRole("combobox", { name: "Service catalog", exact: true }).selectOption("1");
  await expect(page.getByLabel("Block YouTube", { exact: true })).toBeChecked();
  await expect(page.getByLabel("Block WhatsApp", { exact: true })).toHaveCount(0);
  await promote(page);
  const live = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(live.policies[0].blocked_services).toEqual({ catalog_version: 1, ids: ["youtube"] });
});
