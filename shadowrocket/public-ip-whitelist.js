(() => {
  'use strict';

  const PREFIX = 'sr-public-ip-whitelist/v1';
  const PROBE_URLS = {
    4: 'https://api.ipify.org/',
    6: 'https://api6.ipify.org/',
  };
  const PO0_API = 'https://124.221.69.228/api/firewall';
  const REQUEST_SECONDS = 5;
  const RETRY_DELAYS = [500, 1000];
  const LEASE_MS = 65000;
  const WAIT_FOR_LEASE_MS = 12000;
  const HTTPS_URL = /^https:\/\/(?:[a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(?::[0-9]{1,5})?(?:[/?][^\s"'#,\\|{}\u0000-\u001f\u007f]*)?$/i;

  const log = (message) => console.log(`[IP 加白] ${message}`);
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const isSuccess = (status) => status >= 200 && status < 300;

  function readConfig(argument) {
    const text = typeof argument === 'string' ? argument.trim().replace(/^"(.*)"$/, '$1') : '';
    if (text.startsWith('po0Token=')) {
      const po0Token = text.slice('po0Token='.length).trim();
      if (/^pgnfw_[A-Za-z0-9]+$/.test(po0Token)) return { po0Token };
      log('请在模块的「编辑参数」中填写 pgnfw_ 开头的 Token');
      return null;
    }

    const fields = Object.create(null);
    for (const entry of text.split('|')) {
      const separator = entry.indexOf('=');
      if (separator > 0) fields[entry.slice(0, separator)] = entry.slice(separator + 1).trim();
    }

    const { api, token, probe4, probe6 } = fields;
    const method = (fields.method || 'POST').toUpperCase();
    const families = fields.families || '46';

    if (!api || api === 'unset' || api === '{{{api}}}') {
      log('请在模块的「编辑参数」中填写 api');
      return null;
    }
    if (!HTTPS_URL.test(api)) {
      log('api 必须为 HTTPS URL。请检查主机名和参数格式');
      return null;
    }
    if (!['GET', 'POST'].includes(method) || !['4', '6', '46'].includes(families)) {
      log('method 须为 GET 或 POST，families 须为 4、6 或 46');
      return null;
    }

    const bearer = token && token !== 'unset' ? token : '';
    if (bearer && !/^[a-z0-9._~+/\-]+=*$/i.test(bearer)) {
      log('token 请填写 Bearer 后面的值');
      return null;
    }

    const probes = {
      4: !probe4 || probe4 === 'default' ? PROBE_URLS[4] : probe4,
      6: !probe6 || probe6 === 'default' ? PROBE_URLS[6] : probe6,
    };
    const enabled = Array.from(families, Number);
    if (!enabled.every((family) => HTTPS_URL.test(probes[family]))) {
      log('启用的 probe4 和 probe6 须为 HTTPS URL 或 default');
      return null;
    }

    if (method === 'GET' && hasAddressParameters(api)) {
      log('GET 接口地址中的 ip 和 family 由脚本填写，请移除已有值');
      return null;
    }

    return { api, bearer, method, enabled, probes };
  }

  function hasAddressParameters(url) {
    const queryStart = url.indexOf('?');
    if (queryStart === -1) return false;
    return url.slice(queryStart + 1).split('&').some((parameter) => {
      const name = parameter.split('=', 1)[0];
      try {
        return ['ip', 'family'].includes(decodeURIComponent(name));
      } catch {
        return true;
      }
    });
  }

  function normalizeV4(text) {
    const segments = text.split('.');
    if (segments.length !== 4 || !segments.every((part) => /^(0|[1-9]\d{0,2})$/.test(part))) {
      return null;
    }
    const [a, b, c, d] = segments.map(Number);
    if ([a, b, c, d].some((part) => part > 255)) return null;

    const nonPublic = a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0 && (c === 0 || c === 2))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113);
    return nonPublic ? null : text;
  }

  function normalizeV6(text) {
    const halves = text.split('::');
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
    if (![...left, ...right].every((part) => /^[a-f0-9]{1,4}$/i.test(part))) return null;

    const groups = [...left, ...Array(missing).fill('0'), ...right]
      .map((part) => parseInt(part, 16));
    if ((groups[0] & 0xe000) !== 0x2000
      || (groups[0] === 0x2001 && groups[1] === 0x0db8)
      || (groups[0] === 0x3fff && groups[1] <= 0x0fff)) return null;

    let bestStart = 0;
    let bestLength = 1;
    let runLength = 0;
    for (let i = 0; i < groups.length; i += 1) {
      runLength = groups[i] === 0 ? runLength + 1 : 0;
      if (runLength > bestLength) {
        bestStart = i - runLength + 1;
        bestLength = runLength;
      }
    }
    const hex = groups.map((part) => part.toString(16));
    if (bestLength === 1) return hex.join(':');
    return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
  }

  function request(method, options) {
    return new Promise((resolve) => {
      function finish(status = 0, body = '') {
        clearTimeout(timer);
        resolve({ status, body });
      }

      const timer = setTimeout(finish, REQUEST_SECONDS * 1000);
      try {
        $httpClient[method]({ timeout: REQUEST_SECONDS, 'auto-redirect': false, ...options },
          (error, response, body) => {
            const status = Number(response && (response.status || response.statusCode));
            finish(error || !Number.isInteger(status) ? 0 : status, body);
          });
      } catch {
        finish();
      }
    });
  }

  async function probe(family, url) {
    const { status, body } = await request('get', { url, policy: 'DIRECT' });
    const text = isSuccess(status) && typeof body === 'string' ? body.trim() : '';
    const ip = family === 4 ? normalizeV4(text) : normalizeV6(text);
    if (!ip) log(`IPv${family} 探测未获得可用地址`);
    return ip;
  }

  function readLease(key) {
    const value = $persistentStore.read(key);
    try {
      const lease = JSON.parse(value || 'null');
      return lease && typeof lease.id === 'string' && Number.isFinite(lease.expires) ? lease : null;
    } catch {
      return null;
    }
  }

  async function takeLease(key) {
    const id = `${Date.now()}:${Math.random()}`;
    const deadline = Date.now() + WAIT_FOR_LEASE_MS;
    do {
      const current = readLease(key);
      if (!current || current.expires <= Date.now()) {
        const written = $persistentStore.write(JSON.stringify({ id, expires: Date.now() + LEASE_MS }), key);
        if (written === false) throw new Error('无法写入脚本存储');
        // Give a concurrent invocation time to finish writing before we check ownership.
        await sleep(50);
        const next = readLease(key);
        if (next && next.id === id) return id;
      }
      await sleep(250);
    } while (Date.now() < deadline);
    return null;
  }

  function allowlistRequest(config, family, ip) {
    const { api, bearer, method } = config;
    const headers = { Accept: 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (method === 'GET') {
      let separator = '?';
      if (api.includes('?')) separator = /[?&]$/.test(api) ? '' : '&';
      const url = `${api}${separator}ip=${encodeURIComponent(ip)}&family=${family}`;
      return { url, headers };
    }

    headers['Content-Type'] = 'application/json';
    return { url: api, headers, body: JSON.stringify({ ip, family }) };
  }

  async function requestWithRetry(method, options, action) {
    let response;
    for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt += 1) {
      if (attempt > 0) await sleep(RETRY_DELAYS[attempt - 1]);
      response = await request(method, options);
      const { status } = response;
      if (isSuccess(status)) break;
      log(`${action}请求第 ${attempt + 1} 次失败（${status ? `HTTP ${status}` : '网络错误或超时'}）`);
      if (!(status === 0 || status === 408 || status === 429 || (status >= 500 && status <= 599))) {
        break;
      }
    }
    return response;
  }

  async function submit(config, family, ip) {
    const options = allowlistRequest(config, family, ip);
    const { status } = await requestWithRetry(config.method.toLowerCase(), options, `IPv${family} 加白`);
    return isSuccess(status);
  }

  function po0Subnet(value) {
    if (typeof value !== 'string') return null;
    const [address, prefix, ...extra] = value.trim().split('/');
    if (extra.length || (prefix !== undefined && prefix !== '24')) return null;
    const ip = normalizeV4(address);
    return ip ? ip.slice(0, ip.lastIndexOf('.')) : null;
  }

  function readPo0State(body) {
    let data;
    try {
      data = JSON.parse(body);
    } catch {
      return null;
    }
    if (!data || typeof data !== 'object') return null;
    if (data.enabled === false) return { enabled: false, listed: false };

    const currentSubnet = po0Subnet(data.currentIp);
    if (!currentSubnet || !Array.isArray(data.whitelist)) return null;
    const listed = data.whitelist.some((entry) => {
      const address = typeof entry === 'string' ? entry : entry && entry.ip;
      return po0Subnet(address) === currentSubnet;
    });
    return { enabled: data.enabled, listed };
  }

  async function ensurePo0(token) {
    const url = `${PO0_API}/${encodeURIComponent(token)}`;
    const options = { policy: 'DIRECT', headers: { Accept: 'application/json' } };
    const statusResponse = await request('get', { ...options, url });
    if (statusResponse.status === 401 || statusResponse.status === 403) {
      log(`po0 接口拒绝访问（HTTP ${statusResponse.status}），请检查 Token`);
      return;
    }

    const current = isSuccess(statusResponse.status) ? readPo0State(statusResponse.body) : null;
    if (current && current.enabled === false) {
      log('po0 防火墙尚未启用');
      return;
    }
    if (current && current.listed) {
      log('当前 IPv4 网段已在 po0 白名单中');
      return;
    }

    const added = await requestWithRetry('post', { ...options, url: `${url}/add` }, 'po0 加白');
    if (!isSuccess(added.status)) return;
    const result = readPo0State(added.body);
    if (result && result.enabled === true && result.listed) {
      log('当前 IPv4 网段已加入 po0 白名单');
    } else if (result && result.enabled === false) {
      log('po0 防火墙尚未启用');
    } else {
      log('po0 接口未确认当前 IPv4 网段已加白，下次触发时会重新检查');
    }
  }

  async function run() {
    const config = readConfig(typeof $argument === 'undefined' ? '' : $argument);
    if (!config) return;

    const key = config.po0Token ? `${PREFIX}:po0` : `${PREFIX}:${config.method}:${config.api}`;
    const leaseKey = `${key}:lease`;
    const lease = await takeLease(leaseKey);
    if (!lease) {
      log('另一次检查仍在运行，等待下次触发');
      return;
    }

    try {
      if (config.po0Token) {
        await ensurePo0(config.po0Token);
        return;
      }

      const addresses = await Promise.all(config.enabled.map((family) => probe(family, config.probes[family])));
      for (const [index, family] of config.enabled.entries()) {
        const ip = addresses[index];
        const stateKey = `${key}:IPv${family}`;
        if (!ip || ip === $persistentStore.read(stateKey)) continue;
        const current = readLease(leaseKey);
        if (!current || current.id !== lease || current.expires <= Date.now()) return;
        if (await submit(config, family, ip)) {
          const afterSubmit = readLease(leaseKey);
          if (!afterSubmit || afterSubmit.id !== lease || afterSubmit.expires <= Date.now()) return;
          if ($persistentStore.write(ip, stateKey) === false) {
            log(`IPv${family} 已加白，脚本存储写入失败，下次会再次检查`);
          } else {
            log(`IPv${family} 已加白`);
          }
        }
      }
    } finally {
      const current = readLease(leaseKey);
      if (current && current.id === lease) $persistentStore.write('null', leaseKey);
    }
  }

  run()
    .catch(() => log('脚本执行出错，请检查脚本存储和配置'))
    .finally(() => $done({}));
})();
