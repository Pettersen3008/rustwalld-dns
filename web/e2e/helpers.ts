import { expect } from "@playwright/test";
import type { Page, APIRequestContext } from "@playwright/test";
import dgram from "node:dgram";
import type { Configuration } from "../src/api";
export const token = "browser-test-token-at-least-16";
export const authorization = { Authorization: `Bearer ${token}` };
// Independent of the appliance's bounded revision history and worker restarts.
export const baseline: Configuration = {
  default_policy: "default",
  allowed_clients: ["127.0.0.1/32", "::1/128"],
  bindings: [],
  upstreams: [
    {
      name: "local-mock",
      addresses: ["127.0.0.1:15354", "127.0.0.1:15355"],
      timeout_ms: 200,
      transport: { kind: "udp" },
    },
  ],
  policies: [
    {
      name: "default",
      upstream: "local-mock",
      lists: [{ name: "baseline", action: "block", rules: "ads.test" }],
      rewrites: [
        { domain: "nas.home.arpa", addresses: ["192.0.2.10"], ttl: 60 },
      ],
    },
  ],
  assertions: [{ client: "127.0.0.1", domain: "ads.test", expected: "block" }],
};
export async function reset(request: APIRequestContext) {
  const update = await request.put("/api/v1/config", {
    headers: authorization,
    data: baseline,
  });
  expect(update.ok()).toBeTruthy();
}
export async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("Management token").fill(token);
  await page.getByRole("button", { name: "Connect securely" }).click();
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
}
export async function dns(domain: string): Promise<number> {
  const socket = dgram.createSocket("udp4");
  const bytes = Buffer.concat([
    Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
    ...domain
      .split(".")
      .map((label) =>
        Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]),
      ),
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error("Loopback DNS timed out"));
    }, 2000);
    socket.once("message", (response) => {
      clearTimeout(timer);
      socket.close();
      resolve(response[3]! & 15);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      socket.close();
      reject(error);
    });
    socket.send(bytes, 15353, "127.0.0.1");
  });
}
