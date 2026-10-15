import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e/security",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  expect: { timeout: 10000 },
  // Browser UX fixture uses a self-signed public test certificate. Server/client
  // certificate validation is independently verified by Rust secure_ingress.
  use: { baseURL: "https://127.0.0.1:18081", ignoreHTTPSErrors: true, trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    {
      name: "mobile",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 393, height: 852 },
        isMobile: true,
        hasTouch: true,
      },
    },
  ],
  webServer: {
    command: "RUSTWALL_AUTH_UI=1 node e2e/server.mjs",
    url: "https://127.0.0.1:18081/healthz",
    ignoreHTTPSErrors: true,
    timeout: 30000,
    reuseExistingServer: false,
  },
});
