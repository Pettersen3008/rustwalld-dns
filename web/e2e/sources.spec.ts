import { readFile } from "node:fs/promises";
import { test, expect } from "@playwright/test";
import type { Configuration } from "../src/api";
import { authorization, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => {
  await reset(request);
});

test("HTTPS lists preview, shadow, promote, retain fingerprints and survive failed refresh/removal", async ({
  page,
  request,
}, info) => {
  const ca = await readFile(
    new URL("./fixtures/download-cert.pem", import.meta.url),
    "utf8",
  );
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page
    .getByRole("tab", { name: "Downloaded lists", exact: true })
    .click();
  await page.getByLabel("Downloaded list name").fill("remote-download");
  await page.getByLabel("HTTPS list URL").fill("https://lists.test:15356/list");
  await page.getByLabel("Bootstrap IPs").fill("127.0.0.1");
  await page.getByText("Private HTTPS trust", { exact: true }).click();
  await page.getByLabel("Download CA PEM").fill(ca);
  await page.getByRole("button", { name: "Register source in draft" }).click();
  expect(await dns("downloaded.test")).toBe(0);
  await page
    .getByRole("button", { name: "Download remote-download into draft" })
    .click();
  await expect(page.getByRole("status")).toContainText("Candidate validated");
  await expect(page.locator(".source-row")).toContainText("Retrieved");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await expect(page.getByRole("status")).toContainText(
    "evaluating live queries",
  );
  expect(await dns("downloaded.test")).toBe(0);
  const shadow = (await (
    await request.get("/api/v1/shadow", { headers: authorization })
  ).json()) as { config: Configuration };
  const fingerprint = shadow.config.filter_sources![0]!.download!.sha256;
  expect(fingerprint).toMatch(/^[a-f0-9]{64}$/);
  expect(shadow.config.policies[0]!.lists[1]!.rules).toContain(
    "=downloaded.test",
  );
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect(page.getByRole("status")).toContainText("now active");
  expect(await dns("downloaded.test")).toBe(3);
  await expect(page.locator(".source-row")).toContainText("ACTIVE");
  await page
    .locator(".source-row")
    .getByText("Content fingerprint", { exact: true })
    .click();
  await expect(page.locator(".source-row")).toContainText(fingerprint);
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect.poll(async () => page.evaluate(() => window.scrollY)).toBe(0);
  await page.screenshot({
    path: info.outputPath("downloaded-lists.png"),
    fullPage: true,
  });
  const explanation = (await (
    await request.get(
      "/api/v1/explain?client=127.0.0.1&domain=downloaded.test",
      { headers: authorization },
    )
  ).json()) as { rule: { sources: { list: string; line: number }[] } };
  expect(explanation.rule.sources[0]).toEqual({
    list: "remote-download",
    line: 2,
  });

  await page
    .getByRole("tab", { name: "Policies & rules", exact: true })
    .click();
  await page
    .getByLabel("Rules for remote-download")
    .fill(shadow.config.policies[0]!.lists[1]!.rules + "manual.test\n");
  await page
    .getByRole("tab", { name: "Downloaded lists", exact: true })
    .click();
  await expect(page.locator(".source-row")).toContainText(
    "No matching download stamp",
  );
  await page
    .getByRole("button", { name: "Edit source remote-download" })
    .click();
  await page
    .getByLabel("HTTPS list URL")
    .fill("https://lists.test:15356/invalid");
  await page.getByRole("button", { name: "Save source in draft" }).click();
  await page
    .getByRole("button", { name: "Download remote-download into draft" })
    .click();
  await expect(page.getByRole("alert")).toContainText("invalid filter rules");
  expect(await dns("downloaded.test")).toBe(3);
  await page
    .getByRole("tab", { name: "Policies & rules", exact: true })
    .click();
  await expect(page.getByLabel("Rules for remote-download")).toHaveValue(
    /manual\.test/,
  );
  const active = (await (
    await request.get("/api/v1/config", { headers: authorization })
  ).json()) as Configuration;
  expect(active.filter_sources![0]!.download!.sha256).toBe(fingerprint);
  await page
    .getByRole("tab", { name: "Downloaded lists", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Remove source remote-download from draft" })
    .click();
  await page
    .getByRole("button", { name: "Validate draft", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow" }).click();
  await page.getByRole("button", { name: "Review promotion" }).click();
  await page.getByRole("button", { name: "Promote this candidate" }).click();
  await expect(
    page.getByText("ACTIVE CONFIGURATION", { exact: true }),
  ).toBeVisible();
  expect(await dns("downloaded.test")).toBe(3);
  const removed = (await (
    await request.get("/api/v1/config", { headers: authorization })
  ).json()) as Configuration;
  expect(removed.filter_sources).toBeUndefined();
  expect(removed.policies[0]!.lists[1]!.rules).toContain("manual.test");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
});
