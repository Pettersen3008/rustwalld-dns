import { test, expect } from "@playwright/test";
import type { Configuration, Upstream } from "../src/api";
import { authorization, dns, login, reset, token } from "./helpers";
test.beforeEach(async ({ request }) => {
  await reset(request);
});
test("authentication, live views, provenance and memory-only session", async ({
  page,
}, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByLabel("Management token").fill("incorrect-token-value");
  await page.getByRole("button", { name: "Connect securely" }).click();
  await expect(page.getByRole("alert")).toContainText("bearer token required");
  await login(page);
  await expect(page.getByText("DNS service online")).toBeVisible();
  await page.screenshot({
    path: `test-results/${info.project.name}-overview.png`,
    fullPage: true,
  });
  for (const [link, heading] of [
    ["Clients & networks", "Client admission"],
    ["Filter lists", "default"],
    ["Upstreams", "local-mock"],
    ["Revision history", "Durable revisions"],
  ] as const) {
    await page.getByRole("link", { name: link, exact: true }).click();
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
  }
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("ads.test");
  await page
    .getByRole("button", { name: "ads.test", exact: true })
    .first()
    .click();
  await expect(page.getByRole("dialog")).toContainText("Recorded decision");
  await page
    .getByRole("button", { name: "Explain with current policy" })
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Source: baseline · line 1",
  );
  await expect(page.getByRole("dialog")).toContainText("suffix / ads.test");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
  expect(page.url()).not.toContain(token);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.reload();
  await expect(page.getByLabel("Management token")).toHaveValue("");
  expect(errors).toEqual([]);
});
test("validate, shadow, inspect, promote and durable rollback with real DNS", async ({
  page,
  request,
}, info) => {
  const { generation: initialGeneration } = (await (
    await request.get("/api/v1/status", { headers: authorization })
  ).json()) as { generation: number };
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("Rules for baseline").fill("ads.test\nnew.test");
  await page.getByRole("tab", { name: "Assertions", exact: true }).click();
  await page.getByLabel("Assertion 1 expected").selectOption("allow");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("assertion");
  await expect(
    page.getByRole("button", { name: "Stage in shadow" }),
  ).toBeDisabled();
  await page.getByLabel("Assertion 1 expected").selectOption("block");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await expect(
    page.getByRole("button", { name: "Review promotion" }),
  ).toBeVisible();
  expect(await dns("new.test")).toBe(0);
  await expect
    .poll(async () => {
      const events = (await (
        await request.get("/api/v1/queries?limit=500", {
          headers: authorization,
        })
      ).json()) as { domain: string; shadow: { differs: boolean } | null }[];
      return events.some(
        (event) => event.domain === "new.test" && event.shadow?.differs,
      );
    })
    .toBeTruthy();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByText("Inspect complete candidate", { exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("new.test");
  await page.screenshot({
    path: `test-results/${info.project.name}-promotion.png`,
    fullPage: true,
  });
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(page.getByRole("status")).toContainText("now active");
  await expect(
    page.getByText("A newer active or shadow revision exists.", {
      exact: false,
    }),
  ).not.toBeVisible();
  await expect(
    page.getByText("ACTIVE CONFIGURATION", { exact: true }),
  ).toBeVisible();
  expect(await dns("new.test")).toBe(3);
  await page
    .getByRole("link", { name: "Revision history", exact: true })
    .click();
  const initial = page.locator(".revision-list > div").filter({
    has: page.getByText(`G${initialGeneration}`, { exact: true }),
  });
  await initial.getByRole("button", { name: "Inspect revision" }).click();
  await expect(page.getByRole("dialog")).toContainText("1 raw rules");
  await page
    .getByRole("button", { name: "Validate and roll back to this revision" })
    .click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  expect(await dns("new.test")).toBe(0);
  expect(await dns("ads.test")).toBe(3);
});
test("a conflicting administrator preserves the validated draft", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByLabel("Rules for baseline").fill("ads.test\nmy-draft.test");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.route("**/api/v1/shadow", async (route) => {
    if (route.request().method() === "POST") {
      const current = await request.get("/api/v1/config", {
        headers: authorization,
      });
      const config = (await current.json()) as Configuration;
      config.policies[0]!.lists[0]!.rules = "ads.test\nother-admin.test";
      const update = await request.put("/api/v1/config", {
        headers: authorization,
        data: config,
      });
      expect(update.ok()).toBeTruthy();
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "Your draft is preserved",
  );
  await expect(page.getByLabel("Rules for baseline")).toHaveValue(
    "ads.test\nmy-draft.test",
  );
  const response = await request.get("/api/v1/shadow", {
    headers: authorization,
  });
  expect(((await response.json()) as { config: unknown }).config).toBeNull();
  await page
    .getByRole("button", { name: "Reload active", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toContainText("Discard your draft");
  await page.getByRole("button", { name: "Discard draft and reload" }).click();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue(
    "ads.test\nother-admin.test",
  );
});
test("errors are visible and multiline network editing survives separators", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page
    .getByRole("tab", { name: "Clients & networks", exact: true })
    .click();
  const networks = page.getByLabel("Allowed client networks");
  await networks.fill("127.0.0.1/32");
  await networks.press("End");
  await networks.press("Enter");
  await networks.pressSequentially("::1/128");
  await expect(networks).toHaveValue("127.0.0.1/32\n::1/128");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.route("**/api/v1/queries?*", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: '{"error":"history unavailable"}',
    }),
  );
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("history unavailable");
  await page.unroute("**/api/v1/queries?*");
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByRole("alert")).not.toBeVisible();
  await expect(
    page.getByRole("button", { name: "ads.test", exact: true }).first(),
  ).toBeVisible();
});

test("stopping another editor’s candidate keeps an older draft stale", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page
    .getByLabel("Rules for baseline")
    .fill("ads.test\nlocal-draft.test");
  const active = await request.get("/api/v1/config", {
    headers: authorization,
  });
  const config = (await active.json()) as Configuration;
  config.policies[0]!.lists[0]!.rules = "ads.test\nexternal-active.test";
  expect(
    (
      await request.put("/api/v1/config", {
        headers: authorization,
        data: config,
      })
    ).ok(),
  ).toBeTruthy();
  config.policies[0]!.lists[0]!.rules += "\nexternal-shadow.test";
  expect(
    (
      await request.post("/api/v1/shadow", {
        headers: authorization,
        data: config,
      })
    ).ok(),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Refresh live data" }).click();
  await page.getByRole("button", { name: "Stop shadow", exact: true }).click();
  await page.getByRole("button", { name: "Stop this shadow" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(page.getByLabel("Rules for baseline")).toHaveValue(
    "ads.test\nlocal-draft.test",
  );
  await expect(
    page.getByText("A newer active or shadow revision exists.", {
      exact: false,
    }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Stage in shadow" }),
  ).toBeDisabled();
  expect(
    (
      (await (
        await request.get("/api/v1/config", { headers: authorization })
      ).json()) as Configuration
    ).policies[0]!.lists[0]!.rules,
  ).toBe("ads.test\nexternal-active.test");
  await page.getByRole("button", { name: "Disconnect session" }).click();
  await page.getByRole("button", { name: "Discard and disconnect" }).click();
  await expect(page.getByLabel("Management token")).toHaveValue("");
});

test("TLS profile edits validate and survive staging without changing live DNS", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page
    .getByRole("tab", { name: "Upstream profiles", exact: true })
    .click();
  await page.getByLabel("Upstream 1 transport").selectOption("tls");
  await page.getByLabel("Upstream 1 TLS server name").fill("resolver.test");
  await page.getByLabel("Upstream 1 TLS connections per address").fill("3");
  await page
    .getByLabel("Upstream 1 private CA certificates (PEM)")
    .fill("invalid CA");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("TLS CA PEM");
  await expect(
    page.getByRole("button", { name: "Stage in shadow" }),
  ).toBeDisabled();
  await page.getByLabel("Upstream 1 private CA certificates (PEM)").fill("");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await expect(
    page.getByRole("button", { name: "Review promotion" }),
  ).toBeVisible();
  const shadow = await (
    await request.get("/api/v1/shadow", { headers: authorization })
  ).json();
  expect(shadow.config.upstreams[0].transport).toEqual({
    kind: "tls",
    server_name: "resolver.test",
    ca_pem: null,
    max_connections: 3,
  });
  expect(await dns("ads.test")).toBe(3);
  await page.reload();
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Review promotion" }),
  ).toBeVisible();
});

test("HTTPS endpoint validation and shadow staging preserve the explicit profile", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page
    .getByRole("tab", { name: "Upstream profiles", exact: true })
    .click();
  await page.getByLabel("Upstream 1 transport").selectOption("https");
  await page.getByLabel("Upstream 1 TLS server name").fill("resolver.test");
  await page.getByLabel("Upstream 1 TLS connections per address").fill("3");
  await page
    .getByLabel("Upstream 1 HTTPS path")
    .fill("http://other.test/dns-query");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("HTTPS path");
  await expect(
    page.getByRole("button", { name: "Stage in shadow" }),
  ).toBeDisabled();
  await page.getByLabel("Upstream 1 HTTPS path").fill("/dns-query");
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await expect(
    page.getByRole("button", { name: "Review promotion" }),
  ).toBeVisible();
  const shadow = await (
    await request.get("/api/v1/shadow", { headers: authorization })
  ).json();
  expect(shadow.config.upstreams[0].transport).toEqual({
    kind: "https",
    server_name: "resolver.test",
    path: "/dns-query",
    ca_pem: null,
    max_connections: 3,
  });
  expect(await dns("ads.test")).toBe(3);
  // Switching encrypted transports keeps trust/identity while changing the protocol.
  await page.getByLabel("Upstream 1 transport").selectOption("tls");
  await expect(page.getByLabel("Upstream 1 TLS server name")).toHaveValue(
    "resolver.test",
  );
  await expect(
    page.getByLabel("Upstream 1 TLS connections per address"),
  ).toHaveValue("3");
});

test("upstream failure reasons, recovery and generation reset use real DNS", async ({
  page,
  request,
}, info) => {
  expect(await dns("servfail.test")).toBe(2);
  expect(await dns("recovery.test")).toBe(0);
  const health = (await (
    await request.get("/api/v1/upstreams", { headers: authorization })
  ).json()) as Upstream[];
  expect(health[0]!.servers[0]!.failures.servfail).toBe(1);
  expect(health[0]!.servers[0]!.successes).toBe(1);
  expect(health[0]!.servers[1]!.failures.servfail).toBe(1);
  await login(page);
  await page.getByRole("link", { name: "Upstreams", exact: true }).click();
  await expect(page.getByRole("list").first()).toContainText(
    "Upstream SERVFAIL: 1",
  );
  await expect(page.getByText("Upstream SERVFAIL: 1").first()).toBeInViewport();
  await expect(
    page.getByText("Failures are historical", { exact: false }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.screenshot({
    path: info.outputPath("upstream-failure-recovery.png"),
    fullPage: true,
  });
  await reset(request);
  await page.getByRole("button", { name: "Refresh live data" }).click();
  await expect(page.getByRole("list")).toHaveCount(0);
  const fresh = (await (
    await request.get("/api/v1/upstreams", { headers: authorization })
  ).json()) as Upstream[];
  expect(fresh[0]!.generation).toBeGreaterThan(health[0]!.generation);
  expect(
    fresh[0]!.servers.every((s) => s.attempts === 0 && s.inflight === 0),
  ).toBeTruthy();
});
