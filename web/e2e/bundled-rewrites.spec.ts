import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { authorization, dns, login, reset } from "./helpers";

// The repository's local verification requires Python; use its ZIP writer so
// browser fixtures exercise real bounded archive parsing without a dependency.
function backup(configuration: string, files: Record<string, string>): Buffer {
  return execFileSync(
    "python3",
    [
      "-c",
      "import io,json,sys,zipfile\nentries=json.load(sys.stdin);out=io.BytesIO()\nwith zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED) as z:\n for name,text in entries.items(): z.writestr(name,text)\nsys.stdout.buffer.write(out.getvalue())",
    ],
    {
      input: JSON.stringify({ "AdGuardHome.yaml": configuration, ...files }),
    },
  );
}

test.beforeEach(async ({ request }) => reset(request));
test("bundled rewrite feeds combine custom exceptions, show refresh limits and publish edited answers", async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByText("AdGuard DNS rewrite imports", { exact: true }).click();
  await expect(
    page.getByText("Bundled rewrite feeds are a frozen snapshot", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Migration source").selectOption("adguard");
  await page.getByLabel("Source backup").setInputFiles({
    name: "adguard-backup.zip",
    mimeType: "application/zip",
    buffer: backup(
      "schema_version: 34\nfiltering: {blocked_response_ttl: 29}\nfilters: [{id: 7, enabled: true, url: 'https://publisher.test/feed'}]\nuser_rules: [ads.test, '|pool.home.arpa^$dnsrewrite=192.0.2.10', '|cancelled.test^$dnsrewrite=192.0.2.10']\n",
      {
        "data/filters/7.txt":
          "! bundled fixture\n|pool.home.arpa^$dnsrewrite=192.0.2.20\n|pool.home.arpa^$dnsrewrite=192.0.2.30\n|pool.home.arpa^$dnsrewrite=2001:db8::20\n@@|pool.home.arpa|$dnsrewrite=192.0.2.10\n@@|cancelled.test|$dnsrewrite\ncancelled.test\n",
      },
    ),
  });
  await page.getByRole("button", { name: "Preview migration", exact: true }).click();
  await expect(page.getByText("0 BLOCKERS", { exact: true })).toBeVisible();
  await expect(page.getByText("filters[0].contents.lines[4]", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Bundled rewrite rules are a frozen import snapshot", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Review replacing local draft", exact: true }).click();
  await page.getByRole("button", { name: "Load imported draft", exact: true }).click();
  await page.getByRole("tab", { name: "Local DNS & routes", exact: true }).click();
  await expect(page.getByLabel("Record 1 domain")).toHaveValue("pool.home.arpa");
  await expect(page.getByLabel("Record 1 TTL")).toHaveValue("29");
  await expect(page.getByLabel("Record 1 address")).toHaveValue("192.0.2.20");
  await expect(page.getByLabel("Record 2 address")).toHaveValue("192.0.2.30");
  await expect(page.getByLabel("Record 3 address")).toHaveValue("2001:db8::20");
  await page.getByLabel("Record 1 address").fill("192.0.2.40");
  await page.getByRole("button", { name: "Validate draft", exact: true }).click();
  await page.getByRole("button", { name: "Stage in shadow", exact: true }).click();
  await page.getByRole("button", { name: "Review promotion", exact: true }).click();
  await page.getByRole("button", { name: "Promote this candidate", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "is now active" })).toBeVisible();
  const current = await (await request.get("/api/v1/config", { headers: authorization })).json();
  expect(current.filter_sources ?? []).toEqual([]);
  expect(current.policies[0].dns_records).toHaveLength(3);
  expect(current.policies[0].dns_records[0].data.address).toBe("192.0.2.40");
  expect(await dns("pool.home.arpa")).toBe(0);
  expect(await dns("pool.home.arpa", 28)).toBe(0);
  expect(await dns("cancelled.test")).toBe(3);
  expect(await dns("ads.test")).toBe(3);
});

test("ambiguous and unsupported bundled feeds remain blockers with active DNS unchanged", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page.getByRole("tab", { name: "Migration", exact: true }).click();
  await page.getByLabel("Migration source").selectOption("adguard");
  for (const [files, message] of [
    [
      {
        "filters/7.txt": "|pool.test^$dnsrewrite=192.0.2.10",
        "data/filters/7.txt": "|other.test^$dnsrewrite=192.0.2.20",
      },
      "Multiple archive files match this enabled filter ID",
    ],
    [
      { "filters/7.txt": "|pool.test^$dnsrewrite=NOERROR;NAPTR;private-fixture-secret" },
      "Unsupported rewrite response type",
    ],
  ] as const) {
    await page.getByLabel("Source backup").setInputFiles({
      name: "adguard-backup.zip",
      mimeType: "application/zip",
      buffer: backup(
        "filters: [{id: 7, enabled: true}]\nuser_rules: [ads.test, '|custom.test^$dnsrewrite=192.0.2.10']\n",
        files,
      ),
    });
    await page.getByRole("button", { name: "Preview migration", exact: true }).click();
    await expect(page.getByText(message, { exact: false })).toBeVisible();
    await expect(page.getByText("private-fixture-secret", { exact: false })).toHaveCount(0);
    expect(await dns("ads.test")).toBe(3);
  }
});
