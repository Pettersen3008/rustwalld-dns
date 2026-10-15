import { revisionHeaders } from "./helpers";
import { test, expect } from "@playwright/test";
import type { Configuration } from "../src/lib/api";
import { authorization, baseline, dns, login, reset } from "./helpers";
test.beforeEach(async ({ request }) => {
  await reset(request);
});

test("binding annotations stay in drafts until promotion, appear in explanations and can be cleared", async ({
  page,
  request,
}, info) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Clients & networks", exact: true }).click();
  await page.getByRole("button", { name: "Add binding", exact: true }).click();
  await page.getByLabel("Binding 1 name", { exact: true }).fill("Work laptop");
  await page.getByText("Annotations for Work laptop", { exact: true }).click();
  await page.getByLabel("Binding 1 group", { exact: true }).fill("Work – 内部");
  await page.getByLabel("Binding 1 owner", { exact: true }).fill("Pettersen");
  await page.getByLabel("Binding 1 VLAN label").fill("20");
  await page.getByLabel("Binding 1 tags").fill("managed, laptop");
  await page.getByLabel("Binding 1 note").fill("Fixed DHCP reservation");
  const active = (await (
    await request.get("/api/v1/clients", { headers: authorization })
  ).json()) as { bindings: unknown[] };
  expect(active.bindings).toEqual([]);
  await page.getByLabel("Binding 1 tags").fill("managed, managed");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("invalid annotations");
  await expect(page.getByRole("button", { name: "Stage in shadow", exact: true })).toBeDisabled();
  await page.getByLabel("Binding 1 tags").fill("managed, laptop");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("evaluating live queries");
  expect(await dns("ads.test")).toBe(3);
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("now active");
  const explanation = (await (
    await request.get("/api/v1/explain?client=::ffff:127.0.0.1&domain=ads.test", {
      headers: authorization,
    })
  ).json()) as { binding_metadata: unknown };
  expect(explanation.binding_metadata).toEqual({
    group: "Work – 内部",
    owner: "Pettersen",
    vlan: 20,
    tags: ["managed", "laptop"],
    note: "Fixed DHCP reservation",
  });
  await page.getByRole("link", { name: "Clients & networks", exact: true }).click();
  await page.getByLabel("Find client or network").fill("managed");
  await expect(page.getByRole("row").filter({ hasText: "Work laptop" })).toContainText("VLAN 20");
  await expect(page.getByRole("row").filter({ hasText: "Work laptop" })).toContainText("Pettersen");
  await page.getByText("Note", { exact: true }).click();
  await expect(page.getByText("Fixed DHCP reservation", { exact: true })).toBeVisible();
  await page.screenshot({
    path: info.outputPath("client-metadata.png"),
    fullPage: true,
  });
  await page.getByLabel("Find client or network").fill("missing-client");
  await expect(
    page.getByText("No clients or networks match this search.", {
      exact: true,
    }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Query log", exact: true }).click();
  await page.getByLabel("Search queries").fill("ads.test");
  await page.getByRole("button", { name: "ads.test", exact: true }).first().click();
  await page.getByRole("button", { name: "Explain with current policy", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Binding annotations");
  await expect(page.getByRole("dialog")).toContainText("VLAN 20");
  await page.keyboard.press("Escape");
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Clients & networks", exact: true }).click();
  await page.getByText("Annotations for Work laptop", { exact: true }).click();
  for (const field of ["group", "owner", "VLAN label", "tags", "note"])
    await page.getByLabel(`Binding 1 ${field}`).fill("");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Validation passed");
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("evaluating live queries");
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("now active");
  const config = (await (
    await request.get("/api/v1/config", { headers: authorization })
  ).json()) as Configuration;
  expect(config.bindings[0]!.metadata).toBeUndefined();
  expect(await dns("ads.test")).toBe(3);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
});

test("client inventory and draft bindings paginate and search without rendering every row", async ({
  page,
  request,
}) => {
  const config: Configuration = {
    ...baseline,
    bindings: Array.from({ length: 45 }, (_, index) => ({
      name: `Device ${index + 1}`,
      network: `192.0.2.${index + 1}/32`,
      policy: "default",
      metadata: {
        group: index < 20 ? "IoT" : "Work",
        tags: ["managed"],
        owner: "Operator",
      },
    })),
  };
  const result = await request.put("/api/v1/config", {
    headers: await revisionHeaders(request),
    data: config,
  });
  expect(result.ok()).toBeTruthy();
  await login(page);
  await page.getByRole("link", { name: "Clients & networks", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(20);
  await page.getByRole("button", { name: "Next clients", exact: true }).click();
  await expect(page.locator("tbody tr").first()).toContainText("Device 21");
  await page.getByRole("button", { name: "Next clients", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(5);
  await page.getByLabel("Find client or network").fill("iot");
  await expect(page.locator("tbody tr")).toHaveCount(20);
  await expect(page.getByRole("button", { name: "Next clients", exact: true })).toBeDisabled();
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Clients & networks", exact: true }).click();
  await expect(page.locator(".binding-editor")).toHaveCount(10);
  await page.getByRole("button", { name: "Next bindings", exact: true }).click();
  await expect(page.getByLabel("Binding 11 name", { exact: true })).toHaveValue("Device 11");
  await page.getByLabel("Find draft binding").fill("Device 45");
  await expect(page.locator(".binding-editor")).toHaveCount(1);
  await expect(page.getByLabel("Binding 45 name", { exact: true })).toHaveValue("Device 45");
  await page.getByRole("button", { name: "Remove binding 45", exact: true }).click();
  await expect(page.getByText("No bindings match this search.", { exact: true })).toBeVisible();
  const active = (await (
    await request.get("/api/v1/config", { headers: authorization })
  ).json()) as Configuration;
  expect(active.bindings).toHaveLength(45);
  expect(await dns("ads.test")).toBe(3);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
});
