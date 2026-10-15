import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset, revisionHeaders } from "./helpers";
test.beforeEach(async ({ request }) => reset(request));
async function promote(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
}
test("weekly service draft validates, publishes, disables windows and keeps recorded state", async ({
  page,
  request,
}, info) => {
  const domain = `schedule-review-${info.project.name}.youtube.com`;
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Services", exact: true }).click();
  await expect(page.getByLabel("Use weekly service schedule")).toBeDisabled();
  await page.getByLabel("Block YouTube", { exact: true }).check();
  await page.getByLabel("Use weekly service schedule").check();
  await page.getByLabel("Schedule time zone").fill("Local");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("explicit IANA");
  await page.getByLabel("Schedule time zone").fill("UTC");
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies[0]
      .blocked_services,
  ).toBeUndefined();
  await promote(page);
  expect(await dns(domain)).toBe(3);
  await expect(page.getByText("Published policy: active · UTC", { exact: false })).toBeVisible();
  const live = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(live.policies[0].blocked_services.schedule.windows[0].end).toBe("24:00");
  await page.getByRole("button", { name: "Remove schedule window 1" }).click();
  await expect(page.getByText("No windows:", { exact: false })).toContainText("never blocked");
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies[0]
      .blocked_services.schedule.windows,
  ).toHaveLength(1);
  await promote(page);
  expect(await dns(`off-${domain}`)).toBe(0);
  await expect(page.getByText("Published policy: inactive · UTC", { exact: false })).toBeVisible();
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill(domain);
  // Search excludes the new off-event by its distinct full hostname after matching the row.
  const row = page.getByRole("button", { name: domain, exact: true });
  await expect(row).toBeVisible();
  await row.click();
  await page.getByRole("button", { name: "Explain recorded decision", exact: true }).click();
  await expect(
    page.getByText("Recorded service schedule: active · UTC", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  await expect(
    page.getByText("Current service schedule: inactive · UTC", { exact: false }),
  ).toBeVisible();
  await page.screenshot({ path: info.outputPath("weekly-history.png"), fullPage: true });
});
test("allow mode, overnight day choices and disabling schedules remain reviewed drafts", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Services", exact: true }).click();
  await page.getByLabel("Block TikTok", { exact: true }).check();
  await page.getByLabel("Use weekly service schedule").check();
  await page.getByLabel("Schedule mode").selectOption("allow");
  await promote(page);
  expect(await dns("www.tiktok.com")).toBe(0);
  await page.getByLabel("Window 1 start").fill("22:00");
  await page.getByLabel("Window 1 end").fill("07:00");
  await page.getByLabel("Window 1 Sunday").uncheck();
  const before = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(before.policies[0].blocked_services.schedule.windows[0].start).toBe("00:00");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeEnabled();
  await page.screenshot({ path: info.outputPath("weekly-draft.png"), fullPage: true });
  await page.getByLabel("Use weekly service schedule").uncheck();
  await promote(page);
  expect(await dns("www.tiktok.com")).toBe(3);
  expect(
    (await (await request.get("/api/v1/config", { headers: authorization })).json()).policies[0]
      .blocked_services.schedule,
  ).toBeUndefined();
  // An invalid native time is rejected by the server as well as the editor's validation flow.
  const config = await (await request.get("/api/v1/config", { headers: authorization })).json();
  config.policies[0].blocked_services.schedule = {
    time_zone: "UTC",
    mode: "block",
    windows: [{ days: ["mon"], start: "24:00", end: "07:00" }],
  };
  expect(
    (
      await request.put("/api/v1/config", { headers: await revisionHeaders(request), data: config })
    ).status(),
  ).toBe(422);
  config.policies[0].blocked_services.ids = [];
  config.policies[0].blocked_services.schedule = { time_zone: "UTC", mode: "block", windows: [] };
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  await page.getByLabel("Configuration JSON").fill(JSON.stringify(config));
  await page.getByRole("button", { name: "Use this draft", exact: true }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("select a service");
});
