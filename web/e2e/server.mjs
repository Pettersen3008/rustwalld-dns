// A real appliance process, isolated database and loopback-only DNS fixture.
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import dgram from "node:dgram";
import https from "node:https";
const root = fileURLToPath(new URL("../../", import.meta.url));
const directory = await mkdtemp(path.join(root, "target", "ui-test-"));
const config = path.join(directory, "config.toml");
// Public test key/certificate, trusted only by explicit loopback fixture policies.
const lists = https.createServer(
  {
    cert: await readFile(
      new URL("./fixtures/download-cert.pem", import.meta.url),
    ),
    key: await readFile(
      new URL("./fixtures/download-key.pem", import.meta.url),
    ),
  },
  (request, response) => {
    if (request.headers.authorization || request.headers.cookie)
      throw new Error("credentials forwarded to list publisher");
    const rules =
      request.url === "/invalid"
        ? "bad..test\n"
        : "ads.test\n=downloaded.test\nads.test\n";
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
api_listen = "127.0.0.1:18081"
database = ${JSON.stringify(path.join(directory, "dns.sqlite"))}
web_root = ${JSON.stringify(path.join(root, "web", "dist"))}
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
    const fault =
      message.subarray(13, 13 + message[12]).toString() === "servfail";
    response.writeUInt16BE(fault ? 0x8182 : 0x8180, 2);
    socket.send(response, source.port, source.address);
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
