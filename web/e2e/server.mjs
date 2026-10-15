// A real appliance process, isolated database and loopback-only DNS fixture.
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import dgram from "node:dgram";
import https from "node:https";
const root = fileURLToPath(new URL("../../", import.meta.url));
const directory = await mkdtemp(path.join(root, "target", "ui-test-"));
const config = path.join(directory, "config.toml");
const apiPort = Number(process.env.RUSTWALL_UI_PORT ?? 18081);
if (!Number.isInteger(apiPort) || apiPort < 1024 || apiPort > 65535)
  throw new Error("Invalid fixture API port");
const authUi = process.env.RUSTWALL_AUTH_UI === "1";
let authSettings = "";
if (authUi) {
  const authPath = path.join(directory, "auth.json");
  const result = spawnSync(
    path.join(root, "target", "debug", "rustwalld-dns"),
    ["auth", "init", "--output", authPath, "--username", "admin", "--password-stdin"],
    { input: "fixture-password-16\n", encoding: "utf8" },
  );
  if (result.status !== 0) throw new Error("Fixture credential initialization failed");
  const auth = JSON.parse(await readFile(authPath, "utf8"));
  // RFC public fixture secret; never a deployment credential.
  auth.user.totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  await writeFile(authPath, JSON.stringify(auth), { mode: 0o600 });
  const certPath = path.join(directory, "cert.pem"),
    keyPath = path.join(directory, "key.pem");
  await writeFile(
    certPath,
    await readFile(new URL("./fixtures/download-cert.pem", import.meta.url)),
  );
  await writeFile(
    keyPath,
    await readFile(new URL("./fixtures/download-key.pem", import.meta.url)),
    { mode: 0o600 },
  );
  await writeFile(path.join(root, "target", "auth-ui-fixture.json"), JSON.stringify({ authPath }));
  authSettings = `auth_file = ${JSON.stringify(authPath)}\n[api_tls]\ncert_file = ${JSON.stringify(certPath)}\nkey_file = ${JSON.stringify(keyPath)}\n`;
}
const leasePath = path.join(directory, "dnsmasq.leases");
const peerTokenPath = path.join(directory, "peer.token");
await writeFile(leasePath, "0 aa:bb:cc:dd:ee:ff 192.0.2.20 fixture-nas *\n");
await writeFile(peerTokenPath, "fixture-peer-token-at-least16", { mode: 0o600 });
const peerConfig = {
  default_policy: "default",
  allowed_clients: ["127.0.0.1/32", "::1/128"],
  bindings: [],
  upstreams: [{ name: "local-mock", addresses: ["127.0.0.1:15354"], timeout_ms: 200 }],
  policies: [
    {
      name: "default",
      upstream: "local-mock",
      lists: [{ name: "peer-list", action: "block", rules: "ads.test\npeer.test" }],
      rewrites: [],
    },
  ],
  assertions: [{ client: "127.0.0.1", domain: "ads.test", expected: "block" }],
};
// Public test key/certificate, trusted only by explicit loopback fixture policies.
const lists = https.createServer(
  {
    cert: await readFile(new URL("./fixtures/download-cert.pem", import.meta.url)),
    key: await readFile(new URL("./fixtures/download-key.pem", import.meta.url)),
  },
  (request, response) => {
    if (request.url === "/api/v1/config") {
      if (request.headers.authorization !== "Bearer fixture-peer-token-at-least16") {
        response.writeHead(401);
        response.end();
        return;
      }
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(peerConfig));
      return;
    }
    if (request.headers.authorization || request.headers.cookie)
      throw new Error("credentials forwarded to list publisher");
    const rules =
      request.url === "/invalid" ? "bad..test\n" : "ads.test\n=downloaded.test\nads.test\n";
    const etag = request.url === "/invalid" ? '"invalid"' : '"list-v1"';
    if (request.headers["if-none-match"] === etag) {
      response.writeHead(304, {
        ETag: etag,
        "Content-Length": Buffer.byteLength(rules),
      });
      response.end();
      return;
    }
    response.writeHead(200, {
      ETag: etag,
      "Content-Type": "text/plain",
      "Content-Length": Buffer.byteLength(rules),
    });
    response.end(rules);
  },
);
lists.listen(15356, "127.0.0.1");
await writeFile(
  config,
  `dns_listen = "127.0.0.1:15353"
api_listen = "127.0.0.1:${apiPort}"
database = ${JSON.stringify(path.join(directory, "dns.sqlite"))}
web_root = ${JSON.stringify(path.join(root, "web", "dist"))}
${authSettings}
[[integrations]]
name = "dhcp-fixture"
[integrations.source]
kind = "dnsmasq"
lease_file = ${JSON.stringify(leasePath)}
[[integrations]]
name = "peer-fixture"
[integrations.source]
kind = "peer"
[integrations.source.endpoint]
url = "https://lists.test:15356"
bootstrap_ips = ["127.0.0.1"]
token_file = ${JSON.stringify(peerTokenPath)}
ca_pem = ${JSON.stringify(await readFile(new URL("./fixtures/download-cert.pem", import.meta.url), "utf8"))}
[policy]
default_policy = "default"
allowed_clients = ["127.0.0.1/32", "::1/128"]
bindings = []
[[policy.upstreams]]
name = "local-mock"
addresses = ["127.0.0.1:15354", "127.0.0.1:15355"]
timeout_ms = 200
[[policy.policies]]
name = "default"
upstream = "local-mock"
[[policy.policies.lists]]
name = "baseline"
action = "block"
rules = "ads.test"
[[policy.policies.rewrites]]
domain = "nas.home.arpa"
addresses = ["192.0.2.10"]
ttl = 60
[[policy.assertions]]
client = "127.0.0.1"
domain = "ads.test"
expected = "block"
`,
);
const processChild = spawn(
  path.join(root, "target", "debug", "rustwalld-dns"),
  ["--config", config],
  {
    env: {
      ...process.env,
      RUSTWALLD_API_TOKEN: "browser-test-token-at-least-16",
    },
    stdio: ["ignore", "pipe", "inherit"],
  },
);
processChild.stdout.on("data", () => {});
function packet(domain) {
  const header = Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
  const labels = domain
    .split(".")
    .map((s) => Buffer.concat([Buffer.from([s.length]), Buffer.from(s)]));
  return Buffer.concat([header, ...labels, Buffer.from([0, 0, 1, 0, 1])]);
}
// Answer the upstream fixture locally; never contact public resolvers.
const upstreams = [15354, 15355].map((port) => {
  const socket = dgram.createSocket("udp4");
  socket.on("message", (message, source) => {
    const response = Buffer.from(message);
    // Controlled fault names exercise the appliance's real failure accounting.
    const fault = message.subarray(13, 13 + message[12]).toString() === "servfail";
    response.writeUInt16BE(fault ? 0x8182 : 0x8180, 2);
    // A controlled A response to both question types proves the UI preserves
    // the original question and the actual matched response type separately.
    if (message.subarray(13, 13 + message[12]).toString() === "value") {
      let end = 12;
      while (message[end]) end += message[end] + 1;
      const valueResponse = Buffer.from(response.subarray(0, end + 5));
      valueResponse.writeUInt16BE(1, 6);
      valueResponse.writeUInt16BE(0, 10);
      socket.send(
        Buffer.concat([
          valueResponse,
          Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10]),
        ]),
        source.port,
        source.address,
      );
    } else socket.send(response, source.port, source.address);
  });
  socket.bind(port, "127.0.0.1");
  return socket;
});
const traffic = dgram.createSocket("udp4");
traffic.on("error", () => {});
const timer = setInterval(() => {
  for (const domain of ["ads.test", "nas.home.arpa"])
    traffic.send(packet(domain), 15353, "127.0.0.1");
}, 200);
let stopped = false;
async function stop() {
  if (stopped) return;
  stopped = true;
  clearInterval(timer);
  traffic.close();
  for (const socket of upstreams) socket.close();
  lists.closeAllConnections();
  lists.close();
  processChild.kill("SIGTERM");
  setTimeout(() => processChild.kill("SIGKILL"), 5000).unref();
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
processChild.on("exit", async (code) => {
  clearInterval(timer);
  await rm(directory, { recursive: true, force: true });
  process.exit(stopped ? 0 : (code ?? 1));
});
