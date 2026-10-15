import { revisionHeaders } from "./helpers";
import { test, expect } from "@playwright/test";
import { baseline, dns, login } from "./helpers";
for (const theme of ["light", "dark"] as const) {
  test(`design system: ${theme} layouts, keyboard, contrast and local assets`, async ({
    page,
    request,
  }, info) => {
    const config = structuredClone(baseline);
    config.allowed_clients.push("192.0.2.0/24");
    config.bindings.push({
      name: "Loopback devices",
      network: "127.0.0.0/8",
      policy: "default",
    });
    expect(
      (
        await request.put("/api/v1/config", {
          headers: await revisionHeaders(request),
          data: config,
        })
      ).ok(),
    ).toBeTruthy();
    await dns("ads.test");
    await dns("nas.home.arpa");
    await dns("allowed.test");
    const errors: string[] = [];
    const external: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (req) => {
      if (new URL(req.url()).origin !== "http://127.0.0.1:18081") external.push(req.url());
    });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await login(page);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const opposite = theme === "light" ? "dark" : "light";
    const toggle = page.getByRole("button", {
      name: `Switch to ${opposite} theme`,
    });
    await toggle.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("html")).toHaveAttribute("data-theme", opposite);
    await page.getByRole("button", { name: `Switch to ${theme} theme` }).click();
    await expect(page.getByRole("img", { name: /Recent query outcomes/ })).toBeVisible();
    await page.getByText("View counts as a table", { exact: true }).click();
    await expect(page.getByRole("table")).toContainText("Bucket start");
    await page.getByText("View counts as a table", { exact: true }).click();
    for (const [link, heading] of [
      ["Overview", "Overview"],
      ["Query log", "Query log"],
      ["Policies", "Policy workbench"],
      ["Clients & networks", "Clients & networks"],
      ["Filter lists", "Filter lists"],
      ["Upstreams", "Upstreams"],
      ["Revision history", "Revisions"],
    ]) {
      await page.getByRole("link", { name: link, exact: true }).click();
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
      await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
      if (link === "Query log")
        await expect(
          page.getByRole("heading", { name: "Traffic ledger", exact: true }),
        ).toBeVisible();
      if (link === "Policies") await expect(page.getByLabel("Rules for baseline")).toBeVisible();
      if (link === "Clients & networks")
        await expect(page.getByText("Loopback devices", { exact: true })).toBeVisible();
      if (link === "Filter lists")
        await expect(page.getByText("Subsumed", { exact: true })).toBeVisible();
      if (link === "Upstreams")
        await expect(page.getByText("Ready for queries").first()).toBeVisible();
      if (link === "Revision history")
        await expect(page.getByRole("button", { name: "Inspect revision" }).first()).toBeVisible();
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      ).toBeTruthy();
      await page.screenshot({
        path: info.outputPath(`${theme}-${link?.replaceAll(" ", "-")}.png`),
        fullPage: true,
      });
    }
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    await page.getByRole("link", { name: "Overview", exact: true }).click();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
    await page.getByRole("link", { name: "Query log", exact: true }).click();
    const outcomes = page.getByRole("group", { name: "Filter by outcome" });
    await outcomes.getByRole("button", { name: "Local", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "nas.home.arpa", exact: true }).first(),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "ads.test", exact: true })).toHaveCount(0);
    await outcomes.getByRole("button", { name: "Blocked", exact: true }).click();
    await expect(page.getByRole("button", { name: "nas.home.arpa", exact: true })).toHaveCount(0);
    await outcomes.getByRole("button", { name: "All", exact: true }).click();
    await page.getByLabel("Search queries").fill("ads.test");
    const query = page.getByRole("button", { name: "ads.test", exact: true }).first();
    await query.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByRole("button", { name: "Explain with current policy" }).click();
    await expect(page.getByRole("dialog")).toContainText("Source: baseline · line 1");
    await page.screenshot({
      path: info.outputPath(`${theme}-query-detail.png`),
      fullPage: true,
    });
    const contrast = await page.evaluate(() => {
      const rgb = (color: string) => (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);
      const luminance = (values: number[]) =>
        values.reduce((n, value, i) => {
          const v = value / 255;
          return (
            n +
            (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4) *
              ([0.2126, 0.7152, 0.0722][i] ?? 0)
          );
        }, 0);
      return [".dialog-popup", ".dialog-popup .primary", ".dialog-popup .icon-button"].map(
        (selector) => {
          const element = document.querySelector(selector);
          if (!element) throw new Error(`Missing contrast element ${selector}`);
          const style = getComputedStyle(element);
          const parent = element.closest(".dialog-popup");
          const background =
            style.backgroundColor === "rgba(0, 0, 0, 0)" && parent
              ? getComputedStyle(parent).backgroundColor
              : style.backgroundColor;
          const a = luminance(rgb(style.color));
          const b = luminance(rgb(background));
          return {
            selector,
            ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05),
          };
        },
      );
    });
    for (const result of contrast)
      expect(result.ratio, result.selector).toBeGreaterThanOrEqual(4.5);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).not.toBeVisible();
    await expect(query).toBeFocused();
    expect(errors).toEqual([]);
    expect(external).toEqual([]);
    expect(
      await page.evaluate(() => ({
        local: { ...localStorage },
        session: { ...sessionStorage },
      })),
    ).toEqual({ local: {}, session: {} });
  });
}

test("missing deferred assets leave navigation and the session usable", async ({
  page,
  request,
}) => {
  expect(
    (
      await request.put("/api/v1/config", {
        headers: await revisionHeaders(request),
        data: baseline,
      })
    ).ok(),
  ).toBeTruthy();
  await page.route("**/assets/workbench-*.js", (route) => route.abort());
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(page.getByText("This view could not load.", { exact: false })).toBeVisible();
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Traffic ledger", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Upstreams", exact: true }).click();
  await expect(page.getByRole("heading", { name: "local-mock", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.getByText("DNS service online", { exact: true })).toBeVisible();
});
