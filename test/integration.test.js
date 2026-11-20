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

async function fixture(t, { token = defaultToken, intercept } = {}) {
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
    const requestedUrl = new URL(opts.url).href;
    const mappedPath = defaultProbes.get(requestedUrl);
    const url = new URL(mappedPath ? mock.url + mappedPath : requestedUrl);
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

  function runArgument(argument) {
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
          $done: () => { clearTimeout(watchdog); resolve(); }
        }, { timeout: 1000 });
      } catch (error) {
        clearTimeout(watchdog);
        reject(error);
      }
    });
  }

  return {
    mock, run, runArgument, requests, logs,
    submissions: () => mock.submissions.map(({ ip, family }) => [ip, family]).sort()
  };
}

test("module event and five minute schedule share state and submit an IP change", async t => {
  const modulePath = join(__dirname, "..", "shadowrocket", "public-ip-whitelist.srmodule");
  const moduleText = readFileSync(modulePath, "utf8");
  const scriptSection = moduleText.split(/^\[Script\]$/m)[1]?.split(/^\[/m)[0];
  assert.ok(scriptSection, "Missing [Script] section");
  const rules = scriptSection.split(/\r?\n/).map(line => line.slice(line.indexOf("=") + 1).trim());
  const event = rules.find(rule => rule.startsWith("type=event,"));
  const schedule = rules.find(rule => rule.startsWith("type=cron,"));
  // Both forms are demonstrated by the community Cloudflare.DNS.srmodule.
  assert.match(event, /^type=event,\s*network-changed,/);
  assert.match(schedule, /^type=cron,\s*cronexp="\*\/5 \* \* \* \*",/);

  const argumentDefaults = moduleText.match(/^#!arguments=(.+)$/m)?.[1];
  assert.ok(argumentDefaults, "Missing module parameter defaults");
  const defaults = Object.fromEntries(argumentDefaults.split(/,\s*/).map(entry => entry.split(":", 2)));

  function renderArgument(rule, settings) {
    const pathMatch = rule.match(/,\s*script-path=(https:\/\/[^,]+),/);
    assert.ok(pathMatch, "Missing absolute script URL");
    const scriptUrl = new URL(pathMatch[1]);
    assert.equal(scriptUrl.hostname, "raw.githubusercontent.com");
    assert.ok(scriptUrl.pathname.endsWith("/" + filename), "Unexpected script file");

    const argument = rule.match(/,\s*argument=("[^"]+")$/)?.[1];
    assert.ok(argument, "Missing quoted argument template");
    return argument.replace(/\{\{\{(\w+)\}\}\}/g, (_match, name) => {
      assert.ok(Object.hasOwn(settings, name), "Unknown module parameter: " + name);
      return settings[name];
    });
  }

  const { mock, runArgument, requests, submissions } = await fixture(t);
  await runArgument(renderArgument(event, defaults));
  await runArgument(renderArgument(schedule, defaults));
  assert.deepEqual(requests, [], "A module with default settings should make no requests");

  const settings = { ...defaults, api: mock.url + "/whitelist", families: "4", token: defaultToken };
  await runArgument(renderArgument(event, settings));
  assert.deepEqual(submissions(), [[firstV4, 4]]);
  await runArgument(renderArgument(schedule, settings));
  assert.deepEqual(submissions(), [[firstV4, 4]]);

  mock.ips[4] = nextV4;
  await runArgument(renderArgument(schedule, settings));
  assert.deepEqual(submissions(), [[nextV4, 4], [firstV4, 4]]);
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
