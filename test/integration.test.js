"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const https = require("node:https");
const { join } = require("node:path");
const { test } = require("node:test");
const { Script } = require("node:vm");
const { startMock, defaultToken } = require("../mock/server.js");

const filename = "shadowrocket/public-ip-whitelist.js";
const script = new Script(readFileSync(join(__dirname, "..", filename), "utf8"), { filename });
const defaultProbes = new Map([
  ["https://api.ipify.org/", "/ip4"],
  ["https://api6.ipify.org/", "/ip6"]
]);
const firstV4 = "8.8.8.8";
const nextV4 = "1.1.1.1";
const firstV6 = "2001:4860:4860::8888";
const expandedV6 = "2001:4860:4860:0000:0000:0000:0000:8888";
const po0Origin = "https://124.221.69.228";
const fakePo0Token = "pgnfw_" + "0123456789abcdef".repeat(4);
const po0StatusPath = "/api/firewall/" + fakePo0Token;
const po0AddPath = po0StatusPath + "/add";
const po0Confirmed = "[IP 加白] po0 已确认当前 IPv4 在白名单中";

async function fixture(t, { token = defaultToken, intercept } = {}) {
  const calls = [];
  const requests = [];
  const logs = [];
  const storage = new Map();
  const mock = await startMock({
    token,
    async intercept(req, res, url) {
      requests.push({
        method: req.method, path: url.pathname, authorization: req.headers.authorization
      });
      return intercept ? intercept(req, res, url) : false;
    }
  });
  t.after(() => mock.close());

  function httpRequest(method, rawOptions, callback) {
    const opts = typeof rawOptions === "string" ? { url: rawOptions } : rawOptions;
    const requestedUrl = new URL(opts.url);
    calls.push({ method, url: requestedUrl.href, body: opts.body, policy: opts.policy });
    let mappedPath = defaultProbes.get(requestedUrl.href);
    if (requestedUrl.origin === po0Origin && [po0StatusPath, po0AddPath].includes(requestedUrl.pathname)) {
      mappedPath = requestedUrl.pathname + requestedUrl.search;
    }
    const url = new URL(mappedPath ? mock.url + mappedPath : requestedUrl.href);
    if (url.origin !== mock.url) {
      callback(new Error("Simulator only allows the loopback HTTPS Mock"));
      return;
    }
    const request = https.request(url, {
      method, headers: opts.headers, ca: mock.cert, agent: false
    }, response => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", chunk => { body += chunk; });
      response.once("error", callback);
      response.on("end", () => callback(null, {
        status: response.statusCode, statusCode: response.statusCode, headers: response.headers
      }, body));
    });
    request.setTimeout(3000, () => request.destroy(new Error("Mock request timeout")));
    request.once("error", callback);
    request.end(opts.body);
  }

  function run(overrides = {}) {
    const args = {
      api: mock.url + "/whitelist",
      method: "POST",
      families: "46",
      token: token || "unset",
      probe4: "default",
      probe6: "default",
      ...overrides
    };
    const argument = Object.entries(args).map(([key, value]) => key + "=" + value).join("|");
    return runArgument(argument);
  }

  function runArgument(argument, globals = {}) {
    return new Promise((resolve, reject) => {
      const watchdog = setTimeout(() => reject(new Error("Script did not call $done")), 15000);
      const recordLog = (...args) => { logs.push(args.map(String).join(" ")); };
      try {
        script.runInNewContext({
          $argument: argument,
          $httpClient: {
            get: (options, callback) => httpRequest("GET", options, callback),
            post: (options, callback) => httpRequest("POST", options, callback)
          },
          $persistentStore: {
            read: key => storage.get(key) ?? null,
            write: (value, key) => { storage.set(key, value); return true; }
          },
          console: {
            log: recordLog, warn: recordLog, error: recordLog,
            info: recordLog, debug: recordLog
          },
          setTimeout,
          clearTimeout,
          $done: () => { clearTimeout(watchdog); resolve(); },
          ...globals
        }, { timeout: 1000 });
      } catch (error) {
        clearTimeout(watchdog);
        reject(error);
      }
    });
  }

  return {
    mock, run, runArgument, calls, requests, logs, storage,
    submissions: () => mock.submissions.map(({ ip, family }) => [ip, family]).sort()
  };
}

test("po0 sends its add request without script timers or persistent storage", async t => {
  const { runArgument, requests } = await fixture(t, {
    intercept(req, res, url) {
      if (req.method !== "POST" || url.pathname !== po0AddPath) return false;
      req.resume();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        enabled: true,
        currentIp: "8.8.8.0/24",
        whitelist: [{ ip: "8.8.8.0/24", slot: 0 }]
      }));
      return true;
    }
  });
  await runArgument('"po0Token=' + fakePo0Token + '"', {
    setTimeout: undefined,
    clearTimeout: undefined,
    $persistentStore: undefined
  });
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [["POST", po0AddPath]]);
});

test("po0 module posts on both triggers and repeated adds do not duplicate a subnet", async t => {
  const modulePath = join(__dirname, "..", "shadowrocket", "public-ip-whitelist.srmodule");
  const moduleText = readFileSync(modulePath, "utf8");
  assert.match(moduleText, /^IP-CIDR,124\.221\.69\.228\/32,DIRECT,no-resolve$/m);
  const scriptSection = moduleText.split(/^\[Script\]$/m)[1]?.split(/^\[/m)[0];
  assert.ok(scriptSection, "Missing [Script] section");
  const rules = scriptSection.split(/\r?\n/).map(line => line.slice(line.indexOf("=") + 1).trim());
  const event = rules.find(rule => rule.startsWith("type=event,"));
  const schedule = rules.find(rule => rule.startsWith("type=cron,"));
  assert.match(event, /^type=event,\s*event-name=network-changed,/);
  assert.match(schedule, /^type=cron,\s*cronexpr="\*\/5 \* \* \* \*",/);

  const argumentDefaults = moduleText.match(/^#!arguments=(.+)$/m)?.[1];
  assert.ok(argumentDefaults, "Missing module parameter defaults");
  const defaults = Object.fromEntries(argumentDefaults.split(/,\s*/).map(entry => entry.split(":", 2)));
  assert.deepEqual(defaults, { token: "unset" });

  function renderArgument(rule, settings) {
    const pathMatch = rule.match(/,\s*script-path=(https:\/\/[^,]+),/);
    assert.ok(pathMatch, "Missing absolute script URL");
    const scriptUrl = new URL(pathMatch[1]);
    assert.equal(scriptUrl.hostname, "raw.githubusercontent.com");
    assert.ok(scriptUrl.pathname.endsWith("/" + filename), "Unexpected script file");

    const argument = rule.match(/,\s*argument=([^,]+)$/)?.[1];
    assert.ok(argument, "Missing argument template");
    return argument.replace(/\{\{\{(\w+)\}\}\}/g, (_match, name) => {
      assert.ok(Object.hasOwn(settings, name), "Unknown module parameter: " + name);
      return settings[name];
    });
  }

  let currentSubnet = "8.8.8.0/24";
  const whitelist = new Set();
  const { runArgument, calls, requests, logs, storage } = await fixture(t, {
    intercept(req, res, url) {
      if (req.method === "POST" && url.pathname === po0AddPath) {
        req.resume();
        whitelist.add(currentSubnet);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({
          enabled: true,
          currentIp: currentSubnet,
          whitelist: [...whitelist].map(ip => ({ ip, slot: null }))
        }));
        return true;
      }
      return false;
    }
  });
  await runArgument(renderArgument(event, defaults));
  await runArgument(renderArgument(schedule, defaults));
  assert.deepEqual(calls, [], "A module with default settings should make no requests");

  const settings = { token: fakePo0Token };
  const eventArgument = renderArgument(event, settings);
  const scheduleArgument = renderArgument(schedule, settings);
  assert.equal(eventArgument, "po0NetworkToken=" + fakePo0Token);
  assert.equal(scheduleArgument, "po0Token=" + fakePo0Token);

  await runArgument(eventArgument);
  assert.deepEqual([...whitelist], ["8.8.8.0/24"]);
  assert.ok(logs.some(line => line.includes("检测到网络切换")));
  assert.ok(logs.includes(po0Confirmed));
  await runArgument(scheduleArgument);
  assert.deepEqual([...whitelist], ["8.8.8.0/24"]);

  currentSubnet = "1.1.1.0/24";
  await runArgument(scheduleArgument);
  assert.deepEqual([...whitelist], ["8.8.8.0/24", "1.1.1.0/24"]);

  whitelist.delete(currentSubnet);
  await runArgument(scheduleArgument);
  assert.ok(whitelist.has(currentSubnet), "A missing entry should be restored on the next check");
  assert.deepEqual(calls.map(({ method, url, body }) => [method, url, body]),
    Array.from({ length: 4 }, () => ["POST", po0Origin + po0AddPath, ""]));
  assert.equal(requests.length, 4);
  assert.equal(requests.every(request => request.authorization === undefined), true);
  assert.equal(logs.join("\n").includes(fakePo0Token), false);
  assert.equal(JSON.stringify([...storage]).includes(fakePo0Token), false);
});

test("po0 mode rejects missing tokens and malformed URL path content before sending requests", async t => {
  const { runArgument, calls } = await fixture(t);
  for (const value of ["", "{{{token}}}", "wrong_prefix", "pgnfw_", "pgnfw_fake/fake", "pgnfw_fake?slot=0"]) {
    await runArgument("po0Token=" + value);
  }
  assert.deepEqual(calls, []);
});

test("po0 mode does not retry a rejected add or report success without confirmed membership", async t => {
  let status = 401;
  let enabled = false;
  const { runArgument, requests, logs } = await fixture(t, {
    intercept(req, res, url) {
      if (req.method !== "POST" || url.pathname !== po0AddPath) return false;
      req.resume();
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ enabled, currentIp: firstV4, whitelist: ["8.8.8.40"] }));
      return true;
    }
  });
  const argument = "po0Token=" + fakePo0Token;
  await runArgument(argument);
  status = 403;
  await runArgument(argument);
  status = 200;
  await runArgument(argument);
  enabled = true;
  await runArgument(argument);
  assert.deepEqual(requests.map(({ method, path }) => [method, path]),
    Array.from({ length: 4 }, () => ["POST", po0AddPath]));
  assert.ok(logs.some(line => /未启用/.test(line)));
  assert.equal(logs.includes(po0Confirmed), false);
});

test("po0 retries while a switching network becomes available", async t => {
  const { runArgument, requests, logs } = await fixture(t, {
    intercept(req, res, url) {
      if (req.method === "POST" && url.pathname === po0AddPath) {
        req.resume();
        if (requests.length <= 2) {
          res.writeHead(503);
          res.end(fakePo0Token);
        } else {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            enabled: true, currentIp: "8.8.8.0/24", whitelist: [{ ip: "8.8.8.0/24", slot: null }]
          }));
        }
        return true;
      }
      return false;
    }
  });
  await runArgument("po0NetworkToken=" + fakePo0Token);
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [
    ["POST", po0AddPath], ["POST", po0AddPath], ["POST", po0AddPath]
  ]);
  assert.ok(logs.includes(po0Confirmed));
  assert.equal(logs.join("\n").includes(fakePo0Token), false);
});

test("sends each family on first run and only submits changed IPs on later runs", async t => {
  const token = "mock-token+/demo==";
  const { mock, run, requests, submissions } = await fixture(t, { token });
  await run();
  assert.deepEqual(submissions(), [[firstV6, 6], [firstV4, 4]]);
  assert.equal(mock.submissions.every(request => request.method === "POST"), true);
  assert.equal(requests.filter(request => request.path === "/whitelist")
    .every(request => request.authorization === "Bearer " + token), true);
  assert.equal(requests.filter(request => request.path.startsWith("/ip"))
    .every(request => request.authorization === undefined), true);

  mock.ips[6] = expandedV6;
  await run();
  assert.deepEqual(submissions(), [[firstV6, 6], [firstV4, 4]]);
  assert.equal(requests.filter(request => request.path.startsWith("/ip")).length, 4);

  mock.ips[4] = nextV4;
  await run();
  assert.deepEqual(submissions(), [[nextV4, 4], [firstV6, 6], [firstV4, 4]]);
});

test("GET keeps the existing query and can use a custom IPv6 probe without a token", async t => {
  const { mock, run, requests } = await fixture(t, { token: "" });
  await run({
    api: mock.url + "/whitelist?tenant=a%2Bb",
    method: "GET",
    families: "6",
    probe6: mock.url + "/ip6?custom=1"
  });
  assert.deepEqual(mock.submissions, [{
    ip: firstV6,
    family: 6,
    method: "GET",
    query: { tenant: "a+b", ip: firstV6, family: "6" }
  }]);
  assert.deepEqual(requests.map(({ path }) => path), ["/ip6", "/whitelist"]);
  assert.equal(requests[1].authorization, undefined);
});

test("retries transient HTTP failures and does not repeat a successful update", async t => {
  const failures = [503, 429];
  const { run, requests, submissions } = await fixture(t, {
    intercept(req, res, url) {
      if (url.pathname !== "/whitelist" || failures.length === 0) return false;
      req.resume();
      res.writeHead(failures.shift()).end();
      return true;
    }
  });
  await run({ families: "4" });
  await run({ families: "4" });
  assert.deepEqual(submissions(), [[firstV4, 4]]);
  assert.equal(requests.filter(request => request.path === "/whitelist").length, 3);
});

test("retries a dropped HTTPS connection", async t => {
  let drop = true;
  const { run, requests, submissions } = await fixture(t, {
    intercept(req, _res, url) {
      if (url.pathname !== "/whitelist" || !drop) return false;
      drop = false;
      req.socket.destroy();
      return true;
    }
  });
  await run({ families: "4" });
  assert.deepEqual(submissions(), [[firstV4, 4]]);
  assert.equal(requests.filter(request => request.path === "/whitelist").length, 2);
});

test("a rejected update does not suppress the next run and token is not in logs", async t => {
  let reject = true;
  const { run, requests, submissions, logs } = await fixture(t, {
    intercept(req, res, url) {
      if (url.pathname !== "/whitelist" || !reject) return false;
      req.resume();
      res.writeHead(403).end(defaultToken);
      return true;
    }
  });
  await run({ families: "4" });
  assert.deepEqual(submissions(), []);
  assert.equal(requests.filter(request => request.path === "/whitelist").length, 1);
  assert.equal(logs.join("\n").includes(defaultToken), false);

  reject = false;
  await run({ families: "4" });
  assert.deepEqual(submissions(), [[firstV4, 4]]);
});

test("submits IPv4 when IPv6 is unavailable and adds IPv6 once it becomes available", async t => {
  let ipv6Available = false;
  const { run, submissions } = await fixture(t, {
    intercept(_req, res, url) {
      if (url.pathname !== "/ip6" || ipv6Available) return false;
      res.writeHead(404).end();
      return true;
    }
  });
  await run();
  assert.deepEqual(submissions(), [[firstV4, 4]]);

  ipv6Available = true;
  await run();
  assert.deepEqual(submissions(), [[firstV6, 6], [firstV4, 4]]);
});

test("rejects a private or wrong-family address returned by the probes", async t => {
  const { mock, run, requests } = await fixture(t);
  mock.ips[4] = "192.168.1.1";
  mock.ips[6] = firstV4;
  await run();
  assert.deepEqual(requests.map(request => request.path).sort(), ["/ip4", "/ip6"]);
});

test("overlapping invocations share stored state and avoid duplicate submissions", async t => {
  let probeStarted;
  let finishProbe;
  let firstProbe = true;
  const started = new Promise(resolve => { probeStarted = resolve; });
  const release = new Promise(resolve => { finishProbe = resolve; });
  const { run, submissions } = await fixture(t, {
    async intercept(_req, _res, url) {
      if (url.pathname === "/ip4" && firstProbe) {
        firstProbe = false;
        probeStarted();
        await release;
      }
      return false;
    }
  });
  const firstRun = run({ families: "4" });
  try {
    await Promise.race([started, firstRun.then(() => {
      throw new Error("First invocation ended before its probe");
    })]);
    const secondRun = run({ families: "4" });
    finishProbe();
    await secondRun;
  } finally {
    finishProbe();
    await firstRun;
  }
  assert.deepEqual(submissions(), [[firstV4, 4]]);
});
