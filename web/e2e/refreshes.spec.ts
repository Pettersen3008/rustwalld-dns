import { readFile } from "node:fs/promises";
import { test, expect } from "@playwright/test";
import { authorization, dns, login, reset } from "./helpers";

test.beforeEach(async ({ request }) => {
  await reset(request);
});

test("scheduled lists require review, expose unchanged and failed checks, and can be disabled", async ({
  page,
  request,
}, info) => {
  const ca = await readFile(new URL("./fixtures/download-cert.pem", import.meta.url), "utf8");
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Downloaded lists", exact: true }).click();
  await page.getByLabel("Downloaded list name").fill("baseline");
  await page.getByLabel("HTTPS list URL").fill("https://lists.test:15356/list");
  await page.getByLabel("Bootstrap IPs").fill("127.0.0.1");
  await page.getByText("Private HTTPS trust", { exact: true }).click();
  await page.getByLabel("Download CA PEM").fill(ca);
  await page.getByLabel("Enable scheduled refresh").check();
  await page.getByLabel("Check interval (seconds)").fill("299");
  await expect(page.getByRole("button", { name: "Register source in draft" })).toBeDisabled();
  await page.getByLabel("Check interval (seconds)").fill("300");
  await page.getByRole("button", { name: "Register source in draft" }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect
    .poll(
      async () =>
        (
          await (
            await request.get("/api/v1/filter-refreshes", {
              headers: authorization,
            })
          ).json()
        ).entries[0]?.outcome,
    )
    .toBe("staged");
  expect(await dns("downloaded.test")).toBe(0);
  await expect(page.getByText(/Scheduled checks paused for shadow review/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Check active schedule baseline now" }),
  ).toBeDisabled();
  await expect(page.getByRole("button", { name: "Review promotion" })).toBeVisible();
  await page.screenshot({
    path: info.outputPath("scheduled-review.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Review promotion" }).click();
  await expect(page.getByRole("dialog")).toContainText("=downloaded.test");
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect.poll(() => dns("downloaded.test")).toBe(3);
  // An unedited draft adopts the explicitly promoted candidate.
  const current = await (await request.get("/api/v1/status", { headers: authorization })).json();
  await page.getByRole("button", { name: "Check active schedule baseline now" }).click();
  await expect
    .poll(
      async () =>
        (
          await (
            await request.get("/api/v1/filter-refreshes", {
              headers: authorization,
            })
          ).json()
        ).entries[0]?.outcome,
    )
    .toBe("unchanged");
  expect(
    (await (await request.get("/api/v1/status", { headers: authorization })).json()).generation,
  ).toBe(current.generation);
  await expect(page.locator(".source-row")).toContainText("unchanged");
  await expect(page.locator(".source-row")).toContainText("HTTP 304 · 0 body bytes");
  await expect(page.locator(".source-row")).toContainText("stored list retained");
  const transfer = await (
    await request.get("/api/v1/filter-refreshes", { headers: authorization })
  ).json();
  expect(transfer.entries[0].last_http_status).toBe(304);
  expect(transfer.entries[0].last_download_bytes).toBe(0);
  await page.screenshot({
    path: info.outputPath("conditional-unchanged.png"),
    fullPage: true,
  });

  await page.getByRole("button", { name: "Edit source baseline" }).click();
  await page.getByLabel("HTTPS list URL").fill("https://lists.test:15356/invalid");
  await page.getByRole("button", { name: "Save source in draft" }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect
    .poll(
      async () =>
        (
          await (
            await request.get("/api/v1/filter-refreshes", {
              headers: authorization,
            })
          ).json()
        ).entries[0]?.outcome,
    )
    .toBe("failed");
  await expect(page.locator(".source-row")).toContainText("invalid filter rules");
  expect(await dns("downloaded.test")).toBe(3);
  expect(
    (await (await request.get("/api/v1/shadow", { headers: authorization })).json()).generation,
  ).toBeNull();
  await page.screenshot({
    path: info.outputPath("scheduled-failure.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Edit source baseline" }).click();
  await page.getByLabel("Enable scheduled refresh").uncheck();
  await page.getByRole("button", { name: "Save source in draft" }).click();
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect
    .poll(
      async () =>
        (
          await (
            await request.get("/api/v1/filter-refreshes", {
              headers: authorization,
            })
          ).json()
        ).entries.length,
    )
    .toBe(0);
  await expect(page.locator(".source-row")).toContainText("Manual refresh only");
  expect(await dns("downloaded.test")).toBe(3);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
});
