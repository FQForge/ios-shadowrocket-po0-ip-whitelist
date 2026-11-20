"use strict";

const { execFileSync } = require("node:child_process");
const { once } = require("node:events");
const { mkdtempSync, readFileSync, rmSync } = require("node:fs");
const { createServer } = require("node:https");
const { isIP } = require("node:net");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const host = "127.0.0.1";
const defaultToken = "mock-token";

function send(res, status, body = "", contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, { "Content-Type": contentType, "Cache-Control": "no-store" });
  res.end(body);
}

async function readSubmission(req, url) {
  if (req.method === "GET") {
    return { ip: url.searchParams.get("ip"), family: Number(url.searchParams.get("family")) };
  }
  let body = "";
  req.setEncoding("utf8");
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 8192) throw new Error("Request body is too large");
  }
  return JSON.parse(body);
}

async function startMock({
  port = 0,
  token = defaultToken,
  ips = { 4: "8.8.8.8", 6: "2001:4860:4860::8888" },
  intercept = () => false
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), "shadowrocket-whitelist-mock-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "certificate.pem");
  const removeCertificate = () => rmSync(dir, { recursive: true, force: true });
  const entries = new Map();
  const submissions = [];
  let server;
  let cert;
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:" + host,
      "-keyout", keyPath, "-out", certPath
    ], { stdio: ["ignore", "ignore", "pipe"] });
    cert = readFileSync(certPath);
    server = createServer({ key: readFileSync(keyPath), cert }, (req, res) => {
      handle(req, res).catch(() => {
        if (!res.headersSent && !res.destroyed) send(res, 500);
        else res.destroy();
      });
    });
    server.listen(port, host);
    await once(server, "listening");
  } catch (error) {
    removeCertificate();
    throw error;
  }

  async function handle(req, res) {
    const url = new URL(req.url, "https://" + host);
    if (await intercept(req, res, url)) return;
    if (req.method === "GET" && url.pathname === "/ip4") return send(res, 200, ips[4]);
    if (req.method === "GET" && url.pathname === "/ip6") return send(res, 200, ips[6]);
    if (url.pathname !== "/whitelist" && url.pathname !== "/state") return send(res, 404);
    if (token && req.headers.authorization !== "Bearer " + token) return send(res, 401);
    if (req.method === "GET" && url.pathname === "/state") {
      return send(res, 200, JSON.stringify([...entries.values()]), "application/json");
    }
    if (url.pathname !== "/whitelist" || !["GET", "POST"].includes(req.method)) {
      return send(res, 405);
    }
    let payload;
    try {
      payload = await readSubmission(req, url);
    } catch {
      if (!res.destroyed) send(res, 400);
      return;
    }
    if (!payload || typeof payload.ip !== "string" ||
        ![4, 6].includes(payload.family) || isIP(payload.ip) !== payload.family) {
      return send(res, 400);
    }
    const { ip, family } = payload;
    entries.set(family + ":" + ip, { ip, family });
    submissions.push({ ip, family, method: req.method, query: Object.fromEntries(url.searchParams) });
    return send(res, 204);
  }

  return {
    url: "https://" + host + ":" + server.address().port,
    certPath,
    cert,
    ips,
    submissions,
    async close() {
      try {
        await new Promise((resolve, reject) => {
          server.close(error => error ? reject(error) : resolve());
        });
      } finally {
        removeCertificate();
      }
    }
  };
}

async function main() {
  const [requestedPort = "8443", ...rest] = process.argv.slice(2);
  const port = Number(requestedPort);
  if (rest.length || !/^\d+$/.test(requestedPort) || port > 65535) {
    throw new Error("用法：node mock/server.js [0–65535]");
  }
  const mock = await startMock({ port });
  console.log("Mock 地址：" + mock.url);
  console.log("TLS 证书：" + mock.certPath);
  console.log("测试 Token：" + defaultToken);
  const stop = () => mock.close().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (require.main === module) {
  main().catch(error => {
    console.error("Mock 启动失败：" + error.message);
    process.exitCode = 1;
  });
}

module.exports = { startMock, defaultToken };
