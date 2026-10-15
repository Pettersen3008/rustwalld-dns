import { test, expect } from "@playwright/test";
import type { Page, APIRequestContext } from "@playwright/test";
import { login, reset, revisionHeaders, baseline } from "./helpers";

async function stage(page: Page) {
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByText(/Validation passed:/)).toBeVisible();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await expect(page.getByRole("button", { name: "Review promotion", exact: true })).toBeEnabled();
}

async function prepare(page: Page, request: APIRequestContext, theme: "light" | "dark") {
  await reset(request);
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await stage(page);
}

for (const theme of ["light", "dark"] as const) {
  test(`async review: ${theme} dismissal returns to each initiating button`, async ({
    page,
    request,
  }, info) => {
    await prepare(page, request, theme);
    for (const name of ["Review promotion", "Stop shadow"]) {
      const trigger = page.getByRole("button", { name, exact: true });
      for (const close of ["Escape", "Cancel", "Close dialog"]) {
        // Hold a real candidate request to exercise the disabled/loading interval.
        let release = () => {};
        const held = new Promise<void>((resolve) => {
          release = resolve;
        });
        await page.route(
          "**/api/v1/shadow",
          async (route) => {
            await held;
            await route.continue();
          },
          { times: 1 },
        );
        await trigger.focus();
        await page.keyboard.press("Enter");
        await expect(trigger).toBeDisabled();
        await expect(page.getByRole("dialog")).not.toBeVisible();
        release();
        const dialog = page.getByRole("dialog");
        await expect(dialog).toBeVisible();
        // Tab and Shift+Tab must stay inside the modal.
        await dialog.getByRole("button", { name: "Close dialog", exact: true }).focus();
        await page.keyboard.press("Tab");
        await expect(dialog).toContainText(
          name === "Stop shadow" ? "stops candidate" : "exact candidate",
        );
        expect(
          await dialog.evaluate((element) => element.contains(document.activeElement)),
        ).toBeTruthy();
        await page.keyboard.press("Shift+Tab");
        expect(
          await dialog.evaluate((element) => element.contains(document.activeElement)),
        ).toBeTruthy();
        if (name === "Review promotion" && close === "Escape") {
          await page.screenshot({ path: info.outputPath(`${theme}-review.png`), fullPage: true });
          expect(
            await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          ).toBeTruthy();
        }
        if (close === "Escape") await page.keyboard.press("Escape");
        else await dialog.getByRole("button", { name: close, exact: true }).click();
        await expect(dialog).not.toBeVisible();
        await expect(trigger).toBeFocused();
        await page.keyboard.press("Tab");
        if (name === "Review promotion")
          await expect(
            page.getByRole("button", { name: "Stop shadow", exact: true }),
          ).toBeFocused();
        else
          await expect(
            page.getByText("Validation and shadow guidance", { exact: true }),
          ).toBeFocused();
      }
    }
  });

  for (const mode of ["promote", "stop"] as const) {
    test(`async review: ${theme} successful ${mode} focuses main when trigger disappears`, async ({
      page,
      request,
    }) => {
      await prepare(page, request, theme);
      await page
        .getByRole("button", {
          name: mode === "promote" ? "Review promotion" : "Stop shadow",
          exact: true,
        })
        .click();
      await page
        .getByRole("dialog")
        .getByRole("button", {
          name: mode === "promote" ? "Promote this candidate" : "Stop this shadow",
          exact: true,
        })
        .click();
      await expect(page.getByRole("dialog")).not.toBeVisible();
      await expect(page.getByRole("button", { name: "Review promotion", exact: true })).toHaveCount(
        0,
      );
      await expect(page.locator("#main-content")).toBeFocused();
    });
  }

  test(`async review: ${theme} stale publication preserves the dialog and return focus`, async ({
    page,
    request,
  }) => {
    await prepare(page, request, theme);
    const trigger = page.getByRole("button", { name: "Review promotion", exact: true });
    await trigger.click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    // A real competing editor changes the durable revision, invalidating review.
    const changed = await request.put("/api/v1/config", {
      headers: await revisionHeaders(request),
      data: baseline,
    });
    expect(changed.ok()).toBeTruthy();
    await dialog.getByRole("button", { name: "Promote this candidate", exact: true }).click();
    await expect(dialog.getByRole("alert")).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: "Promote this candidate", exact: true }),
    ).toBeEnabled();
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
    // The stale local shadow trigger may still exist until the next refresh.
    if (await trigger.count()) await expect(trigger).toBeFocused();
    else await expect(page.locator("#main-content")).toBeFocused();
  });

  test(`async review: ${theme} failed candidate fetch leaves the action usable`, async ({
    page,
    request,
  }) => {
    await prepare(page, request, theme);
    const trigger = page.getByRole("button", { name: "Review promotion", exact: true });
    await page.route("**/api/v1/shadow", (route) => route.abort(), { times: 1 });
    await trigger.click();
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.getByRole("dialog")).not.toBeVisible();
    await expect(trigger).toBeEnabled();
    await trigger.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(trigger).toBeFocused();
  });
}
