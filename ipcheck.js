/*!
 * IP 检测 · Surge 模块脚本（iOS / Mac 通用）
 * https://github.com/halo798/surge-ipcheck
 *
 * 检测内容：本地 IP、入口 IP（可多个）、落地 IP 的位置与运营商，执行策略路径；
 * 落地 IP 是否原生、是否家宽，以及多个数据库的风险评分与风险因子。
 *
 * 运行方式（由模块配置）：
 *   generic       信息面板；在脚本编辑器里手动运行时另发一条通知
 *   http-request  浏览器打开 http://ipcheck.surge 查看完整报告
 *   event         网络切换后发通知（模块参数 NOTIFY=1 时）
 */

const VERSION = '1.0.0';
const REPO = 'https://github.com/halo798/surge-ipcheck';
const REPORT_URL = 'http://ipcheck.surge/';
const CACHE_KEY = 'ipcheck.quality.v1';
const NOTIFY_KEY = 'ipcheck.notify.v1';
const IPAPI_FIELDS = 'status,message,country,countryCode,regionName,city,district,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query';
const START = Date.now();

const ARG = parseArgs(typeof $argument === 'string' ? $argument : '');
const OPT = {
  policy: ARG.policy || '',
  timeout: clampNum(ARG.timeout, 6, 2, 30),
  cache: clampNum(ARG.cache, 1800, 0, 86400),
  mask: isOn(ARG.mask),
  ipv6: isOn(ARG.ipv6),
  notify: isOn(ARG.notify),
  key: {
    ipqs: ARG.ipqs_key || '',
    abuseipdb: ARG.abuseipdb_key || '',
    ipapi: ARG.ipapi_key || '',
    ipregistry: ARG.ipregistry_key || '',
    ipdata: ARG.ipdata_key || '',
    ip2location: ARG.ip2location_key || '',
    proxycheck: ARG.proxycheck_key || '',
  },
};
// 落地与 IP 质量查询走的策略：留空时按规则分流，与日常上网一致
const PROXY = OPT.policy ? { policy: OPT.policy } : {};
const DIRECT = { policy: 'DIRECT' };

/* ───────────────────────── 参数与通用工具 ───────────────────────── */

function parseArgs(s) {
  const out = {};
  String(s).split('&').forEach(kv => {
    const i = kv.indexOf('=');
    if (i < 0) return;
    const k = kv.slice(0, i).trim().toLowerCase();
    let v = kv.slice(i + 1).trim();
    try { v = decodeURIComponent(v); } catch (e) { /* 原样使用 */ }
    // 未替换的 {{{参数}}} 与占位词都当作未填写
    if (/^\{\{\{.*\}\}\}$/.test(v) || /^(none|null|auto|-)$/i.test(v)) v = '';
    out[k] = v;
  });
  return out;
}

function clampNum(v, def, min, max) {
  const n = Number(v);
  if (v === '' || v == null || !isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

function isOn(v) {
  return /^(1|true|yes|on)$/i.test(String(v || ''));
}

function uniq(arr) {
  return arr.filter((x, i) => x && arr.indexOf(x) === i);
}

// 任一为 true 即 true；全部未知时返回 undefined
function any(...vals) {
  if (vals.some(v => v === true)) return true;
  if (vals.some(v => v === false)) return false;
  return undefined;
}

function bool(v) {
  if (typeof v === 'boolean') return v;
  if (v === 1 || v === '1' || v === 'yes' || v === 'true') return true;
  if (v === 0 || v === '0' || v === 'no' || v === 'false') return false;
  return undefined;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function clock(ts) {
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function dateTime(ts) {
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${clock(ts)}`;
}

function secs(ms) {
  return (ms / 1000).toFixed(1) + 's';
}

/* ───────────────────────── IP 与地区 ───────────────────────── */

const isIPv4 = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s || '');
const isIPv6 = s => /^[0-9a-f:.]+$/i.test(s || '') && String(s).includes(':');
const isIP = s => isIPv4(s) || isIPv6(s);

function isPrivate(ip) {
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 198 && (b === 18 || b === 19));
  }
  const s = String(ip).toLowerCase();
  return s === '::1' || s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80');
}

function maskIP(ip) {
  if (!ip) return ip;
  if (isIPv4(ip)) return ip.split('.').slice(0, 2).join('.') + '.*.*';
  if (isIPv6(ip)) return ip.split(':').slice(0, 2).join(':') + ':*';
  return ip;
}

function showIP(ip) {
  return OPT.mask ? maskIP(ip) : ip;
}

function flag(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map(c => 0x1F1A5 + c.charCodeAt(0)));
}

let REGION_NAMES = null;
try { REGION_NAMES = new Intl.DisplayNames(['zh-Hans'], { type: 'region' }); } catch (e) { REGION_NAMES = null; }

function ccName(cc) {
  if (!cc) return '';
  cc = cc.toUpperCase();
  const fixed = { HK: '香港', MO: '澳门', TW: '台湾' };
  if (fixed[cc]) return fixed[cc];
  try { return (REGION_NAMES && REGION_NAMES.of(cc)) || cc; } catch (e) { return cc; }
}

function surgeGeo(ip) {
  const out = { cc: '', asn: '', org: '' };
  if (typeof $utils === 'undefined' || !ip) return out;
  try { out.cc = String($utils.geoip(ip) || ''); } catch (e) { /* 无本地库 */ }
  try { const n = $utils.ipasn(ip); out.asn = n ? 'AS' + n : ''; } catch (e) { /* 无本地库 */ }
  try { out.org = String($utils.ipaso(ip) || ''); } catch (e) { /* 无本地库 */ }
  return out;
}

// 常见运营商与云厂商的中文名（按 ASN）
const ASN_NAMES = {
  4134: '中国电信', 4809: '中国电信 CN2', 4811: '中国电信', 4812: '中国电信', 23764: '中国电信国际 CTG',
  4837: '中国联通', 9929: '中国联通 A 网', 10099: '中国联通国际', 17621: '中国联通', 17622: '中国联通', 17816: '中国联通',
  9808: '中国移动', 56040: '中国移动', 56041: '中国移动', 56042: '中国移动', 56044: '中国移动', 56046: '中国移动',
  56047: '中国移动', 56048: '中国移动', 24400: '中国移动', 58453: '中国移动国际 CMI', 58807: '中国移动 CMIN2', 9231: '中国移动香港',
  9394: '中国铁通', 4538: '中国教育网', 7497: '中国科技网',
  45090: '腾讯云', 132203: '腾讯云', 37963: '阿里云', 45102: '阿里云', 55990: '华为云', 136907: '华为云', 38365: '百度云',
  4760: '香港电讯 HKT', 9269: '香港宽频 HKBN', 9304: '和记环球电讯 HGC', 3462: '中华电信',
  4713: 'NTT OCN', 2516: 'KDDI', 17676: '软银 SoftBank',
  16509: '亚马逊 AWS', 14618: '亚马逊 AWS', 15169: '谷歌', 396982: '谷歌云', 8075: '微软 Azure', 13335: 'Cloudflare',
  31898: '甲骨文云', 20473: 'Vultr', 14061: 'DigitalOcean', 63949: 'Akamai Linode', 24940: 'Hetzner', 16276: 'OVH',
};

function asnNum(asn) {
  const m = String(asn || '').match(/(\d+)/);
  return m ? Number(m[1]) : 0;
}

const CN_ISP = { 移动: '中国移动', 联通: '中国联通', 电信: '中国电信', 广电: '中国广电', 铁通: '中国铁通', 教育网: '中国教育网' };

function ispName(g) {
  const n = asnNum(g.asn);
  if (n && ASN_NAMES[n]) return ASN_NAMES[n];
  if (g.ispCN) return CN_ISP[g.ispCN] || g.ispCN;
  return g.isp || g.org || '';
}

function trimPlace(s) {
  return String(s || '').replace(/(省|市|特别行政区|自治区|壮族|回族|维吾尔)$/g, '');
}

// 面板用的短地址：国旗 + 省/州 + 城市（同名只留一个）
function placeShort(g) {
  if (!g) return '';
  const parts = [];
  [g.region, g.city].forEach(p => {
    if (p && !parts.some(x => trimPlace(x) === trimPlace(p)) && trimPlace(p) !== trimPlace(g.country)) parts.push(p);
  });
  if (!parts.length) parts.push(g.country || ccName(g.cc));
  return [flag(g.cc), parts.join(' ')].filter(Boolean).join(' ');
}

// 报告用的完整地址：国家 + 省/州 + 城市
function placeFull(g) {
  if (!g) return '';
  const parts = [g.country || ccName(g.cc)];
  [g.region, g.city].forEach(p => {
    if (p && !parts.some(x => trimPlace(x) === trimPlace(p))) parts.push(p);
  });
  return [flag(g.cc), parts.filter(Boolean).join(' ')].filter(Boolean).join(' ');
}

/* ───────────────────────── 网络请求 ───────────────────────── */

const SENT = []; // 未指定 DIRECT 的请求，用于在最近请求里找入口
let active = 0;
const waiting = [];

function http(opts) {
  return new Promise(resolve => {
    const run = () => {
      active++;
      const o = Object.assign({ timeout: OPT.timeout }, opts);
      const method = (o.method || 'get').toLowerCase();
      delete o.method;
      if (!o.policy) delete o.policy;
      if (o.policy !== 'DIRECT') SENT.push(o.url);
      const t0 = Date.now();
      let settled = false;
      const finish = (error, resp, body) => {
        if (settled) return;
        settled = true;
        active--;
        if (waiting.length) waiting.shift()();
        resolve({
          error: error ? String(error.message || error) : null,
          status: resp ? resp.status || resp.statusCode || 0 : 0,
          body: body == null ? '' : String(body),
          ms: Date.now() - t0,
        });
      };
      try { $httpClient[method](o, finish); } catch (e) { finish(e); }
    };
    if (active < 10) run(); else waiting.push(run);
  });
}

function httpError(r) {
  if (r.error) return /timeout|timed out/i.test(r.error) ? '超时' : r.error.slice(0, 80);
  if (r.status === 429) return '限流（429）';
  if (r.status === 401 || r.status === 403) return `拒绝访问（${r.status}）`;
  if (r.status >= 400) return `HTTP ${r.status}`;
  return '';
}

async function fetchText(opts) {
  const r = await http(opts);
  const err = httpError(r);
  if (err) throw new Error(err);
  return r.body;
}

async function fetchJSON(opts) {
  const t = await fetchText(opts);
  try { return JSON.parse(t); } catch (e) { throw new Error('返回内容不是 JSON'); }
}

// 调用 Surge 自身的 HTTP API（脚本内无需密钥）
function surgeAPI(method, path, body) {
  return new Promise(resolve => {
    if (typeof $httpAPI === 'undefined') return resolve(null);
    let done = false;
    const end = v => { if (!done) { done = true; resolve(v); } };
    setTimeout(() => end(null), 3000);
    try { $httpAPI(method, path, body || null, end); } catch (e) { end(null); }
  });
}

function readStore(key) {
  try { return JSON.parse($persistentStore.read(key) || '{}') || {}; } catch (e) { return {}; }
}

function writeStore(key, obj) {
  try { $persistentStore.write(JSON.stringify(obj), key); } catch (e) { /* 忽略 */ }
}

/* ───────────────────────── 本地 / 入口 / 落地 ───────────────────────── */

const RADIO = { NR: '5G', NRNSA: '5G', LTE: '4G', WCDMA: '3G', HSDPA: '3G', HSUPA: '3G', CDMAEVDORev0: '3G', CDMAEVDORevA: '3G', CDMAEVDORevB: '3G', eHRPD: '3G', GPRS: '2G', Edge: '2G', CDMA1x: '2G' };
const CARRIERS = { 46000: '中国移动', 46002: '中国移动', 46004: '中国移动', 46007: '中国移动', 46008: '中国移动', 46001: '中国联通', 46006: '中国联通', 46009: '中国联通', 46003: '中国电信', 46005: '中国电信', 46011: '中国电信', 46015: '中国广电', 45400: 'CSL', 45406: 'SmarTone', 45412: 'CMHK', 45416: 'PCCW' };

function envInfo() {
  const e = typeof $environment !== 'undefined' ? $environment : {};
  const sys = e.system === 'macOS' ? 'Mac' : (e.system || '');
  return { system: sys, version: e['surge-version'] || '', build: e['surge-build'] || '', model: e['device-model'] || '' };
}

function netInfo() {
  const n = typeof $network !== 'undefined' ? $network : {};
  const v4 = n.v4 || {};
  const v6 = n.v6 || {};
  const wifi = n.wifi || {};
  const cell = n['cellular-data'] || {};
  const out = { lan: v4.primaryAddress || '', lan6: v6.primaryAddress || '', router: v4.primaryRouter || '', iface: v4.primaryInterface || v6.primaryInterface || '', dns: n.dns || [] };
  if (wifi.ssid) {
    out.type = 'Wi-Fi';
    out.ssid = wifi.ssid;
  } else if (cell.radio || cell.carrier) {
    out.type = '蜂窝';
    const radio = String(cell.radio || '').replace(/^CTRadioAccessTechnology/, '');
    out.radio = RADIO[radio] || radio;
    out.carrier = CARRIERS[cell.carrier] || cell.carrier || '';
  } else {
    out.type = out.iface ? '有线/其他' : '';
  }
  return out;
}

function geoFromIpApi(a) {
  if (!a || a.status !== 'success') return null;
  return { ip: a.query, cc: a.countryCode, country: a.country, region: a.regionName, city: a.city, isp: a.isp, org: a.org, asn: String(a.as || '').split(' ')[0], lat: a.lat, lon: a.lon, tz: a.timezone, src: ['ip-api'] };
}

// 合并 ip-api 与 B 站数据：国内地址用 B 站中文库，国外用 ip-api
function mergeGeo(ip, a, b) {
  const g = Object.assign({ ip, cc: '', country: '', region: '', city: '', isp: '', org: '', asn: '', src: [] }, geoFromIpApi(a) || {});
  g.ip = ip;
  if (b && b.country) {
    if (b.country === '中国' || !g.cc) {
      g.country = b.country;
      if (b.province) g.region = b.province;
      if (b.city) g.city = b.city;
      if (!g.cc && b.country === '中国') g.cc = 'CN';
      if (b.latitude) { g.lat = Number(b.latitude); g.lon = Number(b.longitude); }
    }
    if (b.isp && !String(b.isp).includes('/')) g.ispCN = b.isp; // “电信/联通/移动”是机房泛称，不采用
    g.src = g.src.concat('bilibili');
  }
  const s = surgeGeo(ip);
  if (!g.cc) g.cc = s.cc;
  if (!g.asn) g.asn = s.asn;
  if (!g.isp && !g.org) g.org = s.org;
  if (!g.src.length && s.cc) g.src.push('Surge GeoIP');
  return g;
}

async function detectLocal() {
  const [b, a] = await Promise.all([
    fetchJSON(Object.assign({ url: 'https://api.bilibili.com/x/web-interface/zone' }, DIRECT)).then(j => j.data).catch(() => null),
    fetchJSON(Object.assign({ url: `http://ip-api.com/json/?fields=${IPAPI_FIELDS}&lang=zh-CN` }, DIRECT)).catch(() => null),
  ]);
  const ip = (b && b.addr) || (a && a.query) || '';
  if (!ip) return { error: '直连查询失败' };
  const g = mergeGeo(ip, a && a.query === ip ? a : null, b && b.addr === ip ? b : null);
  if (a && a.query && a.query !== ip) g.alt = a.query; // 多线宽带或分流时两个库看到的出口可能不同
  return g;
}

const PROBES = [
  {
    id: 'ip-api',
    url: `http://ip-api.com/json/?lang=zh-CN&fields=${IPAPI_FIELDS}`,
    parse(t) {
      const a = JSON.parse(t);
      if (a.status !== 'success') throw new Error(a.message || '查询失败');
      return { ip: a.query, geo: geoFromIpApi(a), raw: a };
    },
  },
  {
    id: 'IPinfo',
    url: 'https://ipinfo.io/json',
    parse(t) {
      const j = JSON.parse(t);
      if (!j.ip) throw new Error('无数据');
      return { ip: j.ip, geo: { ip: j.ip, cc: j.country, region: j.region, city: j.city, org: j.org, asn: String(j.org || '').split(' ')[0], tz: j.timezone, src: ['IPinfo'] }, raw: j };
    },
  },
  {
    id: 'Cloudflare',
    url: 'https://www.cloudflare.com/cdn-cgi/trace',
    parse(t) {
      const kv = {};
      t.split('\n').forEach(l => { const i = l.indexOf('='); if (i > 0) kv[l.slice(0, i)] = l.slice(i + 1).trim(); });
      if (!kv.ip) throw new Error('无数据');
      return { ip: kv.ip, geo: { ip: kv.ip, cc: kv.loc, src: ['Cloudflare'] }, raw: kv };
    },
  },
];

async function runProbe(p, extra) {
  const r = await http(Object.assign({ url: p.url }, PROXY, extra || {}));
  const err = httpError(r);
  if (err) return { id: p.id, error: err, ms: r.ms };
  try { return Object.assign({ id: p.id, ms: r.ms }, p.parse(r.body)); } catch (e) { return { id: p.id, error: e.message, ms: r.ms }; }
}

async function detectV6() {
  const r = await http(Object.assign({ url: 'https://api6.ipify.org?format=json', timeout: Math.min(OPT.timeout, 5) }, PROXY));
  if (httpError(r)) return { error: httpError(r) };
  try {
    const ip = JSON.parse(r.body).ip;
    return isIPv6(ip) ? { ip } : { error: '无 IPv6 出口' };
  } catch (e) { return { error: '无 IPv6 出口' }; }
}

function sameURL(a, b) {
  return a === b || a.startsWith(b) || b.startsWith(a);
}

// 从 Surge 最近请求里找本脚本发出的请求，读出入口 IP 与策略路径
async function readRoutes() {
  const res = await surgeAPI('GET', '/v1/requests/recent');
  if (!res) return null;
  const list = res.requests || [];
  const urls = SENT.slice();
  return list
    .filter(r => r && r.URL && urls.some(u => sameURL(u, r.URL)) && (!r.startDate || r.startDate * 1000 >= START - 3000))
    .map(r => {
      const remote = String(r.remoteAddress || '');
      const notes = (r.notes || []).map(String);
      const path = notes.map(n => n.match(/Policy decision path:\s*(.+)$/)).find(Boolean);
      const used = notes.map(n => n.match(/Use policy:\s*(.+)$/)).find(Boolean);
      return {
        url: r.URL,
        ip: remote.replace(/\s*\(.*?\)\s*$/, '').trim(),
        proxied: /\(proxy\)/i.test(remote),
        node: r.policyName || r.originalPolicyName || '',
        rule: r.rule || '',
        path: path ? path[1].split(/\s*->\s*/) : used ? [used[1].trim()] : [],
        failed: !!r.failed,
      };
    });
}

// 请求备注里没有决策路径时（Surge 对同一域名会缓存规则结果），按规则与策略组的当前选择推出来
async function resolvePath(rule, node) {
  let start = OPT.policy;
  if (!start && rule) {
    const res = await surgeAPI('GET', '/v1/rules');
    const line = ((res && res.rules) || []).find(l => typeof l === 'string' && (l === rule || l.startsWith(rule + ',')));
    if (line) start = line.slice(rule.length + 1).split(',')[0].trim().replace(/^"(.*)"$/, '$1');
  }
  if (!start) return [];
  const groups = (await surgeAPI('GET', '/v1/policy_groups')) || {};
  const path = [start];
  let cur = start;
  for (let i = 0; i < 6 && groups[cur] && cur !== node; i++) {
    const sel = await surgeAPI('GET', '/v1/policy_groups/select', { group_name: cur });
    const next = sel && sel.policy;
    if (!next || path.includes(next)) break;
    path.push(next);
    cur = next;
  }
  // 推出来的终点和实际节点对不上（负载均衡等），就只保留起点
  return path[path.length - 1] === node || !groups[cur] ? path : [start];
}

function collectEntries(routes, into) {
  const map = into || {};
  (routes || []).forEach(r => {
    if (!r.proxied || !isIP(r.ip)) return;
    const e = map[r.ip] || (map[r.ip] = { ip: r.ip, nodes: [], count: 0 });
    e.count++;
    if (r.node && !e.nodes.includes(r.node)) e.nodes.push(r.node);
  });
  return map;
}

// 节点域名解析出的其他地址：从 Surge DNS 缓存里找包含入口 IP 的记录
async function dnsCandidates(ips) {
  const out = {};
  if (!ips.length) return out;
  const res = await surgeAPI('GET', '/v1/dns');
  const cache = (res && res.dnsCache) || [];
  ips.forEach(ip => {
    const hit = cache.find(c => Array.isArray(c.data) && c.data.includes(ip));
    if (hit) out[ip] = { domain: hit.domain, ips: uniq(hit.data.filter(x => isIP(x) && x !== ip)) };
  });
  return out;
}

async function lookupIPs(ips) {
  const out = {};
  const pub = uniq(ips).filter(ip => isIP(ip) && !isPrivate(ip)).slice(0, 8);
  ips.filter(ip => isIP(ip) && isPrivate(ip)).forEach(ip => { out[ip] = { ip, private: true }; });
  if (!pub.length) return out;
  const [batch, bili] = await Promise.all([
    fetchJSON(Object.assign({ url: `http://ip-api.com/batch?lang=zh-CN&fields=${IPAPI_FIELDS}`, method: 'post', body: JSON.stringify(pub), headers: { 'Content-Type': 'application/json' } }, DIRECT)).catch(() => []),
    Promise.all(pub.map(ip => fetchJSON(Object.assign({ url: `https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip=${ip}` }, DIRECT)).then(j => j.data).catch(() => null))),
  ]);
  pub.forEach((ip, i) => {
    const a = Array.isArray(batch) ? batch.find(x => x && x.query === ip) : null;
    out[ip] = mergeGeo(ip, a, bili[i]);
  });
  return out;
}

/* ───────────────────────── IP 质量数据源 ───────────────────────── */

const USAGE_LABEL = { isp: '家宽', mobile: '手机', hosting: '机房', business: '商业', education: '教育', government: '政府', banking: '金融', cdn: 'CDN', crawler: '爬虫', reserved: '保留', other: '其他' };

function usageCode(raw) {
  if (raw == null || raw === '') return null;
  const s = String(raw).toLowerCase();
  if (/mobile|wireless|cellular|\bmob\b/.test(s)) return 'mobile';
  if (/cdn|content delivery/.test(s)) return 'cdn';
  if (/hosting|data ?cent(er|re)|\bdch\b|transit|cloud/.test(s)) return 'hosting';
  if (/residential|fixed line|\bisp\b|\bres\b/.test(s)) return 'isp';
  if (/business|commercial|corporate|\bcom\b|organi[sz]ation|\borg\b/.test(s)) return 'business';
  if (/education|university|college|school|\bedu\b/.test(s)) return 'education';
  if (/government|military|\bgov\b|\bmil\b/.test(s)) return 'government';
  if (/bank/.test(s)) return 'banking';
  if (/spider|crawler|\bses\b/.test(s)) return 'crawler';
  if (/reserved|\brsv\b|inactive/.test(s)) return 'reserved';
  return 'other';
}

const LEVELS = ['极低', '低', '中', '高', '极高'];

function band(v, a, b, c) {
  return v < a ? 1 : v < b ? 2 : v < c ? 3 : 4;
}

function textLevel(t) {
  const s = String(t || '').toLowerCase();
  if (/very low/.test(s)) return 0;
  if (/very high|extreme/.test(s)) return 4;
  if (/high/.test(s)) return 3;
  if (/medium|elevated|moderate/.test(s)) return 2;
  if (/low/.test(s)) return 1;
  return -1;
}

function riskScore(kind, raw, text) {
  if (kind === 'ipapiis') {
    const m = String(raw || '').match(/([\d.]+)\s*\(([^)]+)\)/);
    if (!m) return null;
    const pct = parseFloat(m[1]) * 100;
    const lv = textLevel(m[2]);
    return { value: pct, display: (pct < 1 ? pct.toFixed(2) : pct.toFixed(1)) + '%', level: lv < 0 ? band(pct, 25, 50, 75) : lv, bar: Math.min(100, pct) };
  }
  const v = Number(raw);
  if (raw === '' || raw == null || !isFinite(v)) return null;
  switch (kind) {
    case 'scamalytics': {
      const lv = textLevel(text);
      return { value: v, display: String(v), level: lv < 0 ? band(v, 25, 50, 75) : lv, bar: v };
    }
    case 'proxycheck': // 官方说明：0–33 低，34–66 高，67–100 危险
      return { value: v, display: String(v), level: v < 34 ? 1 : v < 67 ? 3 : 4, bar: v };
    case 'ipqs': // 官方说明：75 起可疑，85 起高风险，90 起极高
      return { value: v, display: String(v), level: v < 75 ? 1 : v < 85 ? 2 : v < 90 ? 3 : 4, bar: v };
    case 'ipdata': // trust_score 越高越可信
      return { value: v, display: '信任 ' + v, level: band(100 - v, 25, 50, 75), bar: 100 - v };
    default:
      return { value: v, display: String(v), level: band(v, 25, 50, 75), bar: v };
  }
}

function withKey(url, name, key) {
  return key ? `${url}${url.includes('?') ? '&' : '?'}${name}=${encodeURIComponent(key)}` : url;
}

const SOURCES = [
  {
    id: 'ipinfo', name: 'IPinfo',
    async run(ip) {
      let d;
      try {
        const j = await fetchJSON(Object.assign({ url: `https://ipinfo.io/widget/demo/${ip}` }, PROXY));
        d = j.data;
        if (!d || !d.country) throw new Error('无数据');
      } catch (e) {
        // 演示接口限流时退回基础接口，只有位置信息
        const b = await fetchJSON(Object.assign({ url: `https://ipinfo.io/${ip}/json` }, PROXY));
        return { cc: b.country, region: b.region, city: b.city, org: b.org, asn: String(b.org || '').split(' ')[0], note: '仅基础信息' };
      }
      const p = d.privacy || {};
      return {
        cc: d.country, region: d.region, city: d.city, org: d.org, asn: d.asn && d.asn.asn,
        usage: d.is_mobile ? 'mobile' : d.asn && d.asn.type, company: d.company && d.company.type,
        f: { proxy: any(p.proxy, p.relay), vpn: bool(p.vpn), tor: bool(p.tor), server: any(p.hosting, d.is_hosting) },
      };
    },
  },
  {
    id: 'iplocate', name: 'IPLocate',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://iplocate.io/api/lookup/${ip}` }, PROXY));
      if (d.error || !d.ip) throw new Error(d.error || '无数据');
      const p = d.privacy || {};
      const a = d.asn || {};
      return {
        cc: d.country_code, region: d.subdivision, city: d.city, org: a.name, asn: a.asn,
        usage: a.type, company: d.company && d.company.type, reg: a.country_code,
        f: { proxy: any(p.is_proxy, p.is_icloud_relay), vpn: bool(p.is_vpn), tor: bool(p.is_tor), server: bool(p.is_hosting), abuse: bool(p.is_abuser) },
      };
    },
  },
  {
    id: 'proxycheck', name: 'proxycheck',
    async run(ip) {
      const j = await fetchJSON(Object.assign({ url: withKey(`https://proxycheck.io/v3/${ip}`, 'key', OPT.key.proxycheck) }, PROXY));
      const d = j[ip];
      if (!d) throw new Error(j.message || j.status || '无数据');
      const n = d.network || {};
      const l = d.location || {};
      const x = d.detections || {};
      return {
        cc: l.country_code, region: l.region_name, city: l.city_name, org: n.organisation || n.provider, asn: n.asn, usage: n.type,
        f: { proxy: bool(x.proxy), vpn: bool(x.vpn), tor: bool(x.tor), server: bool(x.hosting), abuse: bool(x.compromised), bot: bool(x.scraper) },
        score: riskScore('proxycheck', x.risk),
      };
    },
  },
  {
    id: 'ip2location', name: 'IP2Location',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: withKey(`https://api.ip2location.io/?ip=${ip}`, 'key', OPT.key.ip2location) }, PROXY));
      if (d.error) throw new Error(d.error.error_message || '查询失败');
      const p = d.proxy || {};
      return {
        cc: d.country_code, region: d.region_name, city: d.city_name, org: d.as || d.isp, asn: d.asn ? 'AS' + d.asn : '',
        usage: d.usage_type || p.usage_type || null,
        f: {
          proxy: any(bool(d.is_proxy), p.is_public_proxy, p.is_web_proxy, p.is_residential_proxy), vpn: bool(p.is_vpn), tor: bool(p.is_tor),
          server: bool(p.is_data_center), abuse: any(p.is_spammer, p.is_scanner, p.is_botnet), bot: bool(p.is_web_crawler),
        },
        score: riskScore('generic', d.fraud_score),
      };
    },
  },
  {
    id: 'ipquery', name: 'ipquery',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://api.ipquery.io/${ip}` }, PROXY));
      if (!d.ip) throw new Error('无数据');
      const l = d.location || {};
      const i = d.isp || {};
      const r = d.risk || {};
      return {
        cc: l.country_code, region: l.state, city: l.city, org: i.isp || i.org, asn: i.asn,
        usage: r.is_datacenter ? 'hosting' : r.is_mobile ? 'mobile' : null,
        f: { proxy: bool(r.is_proxy), vpn: bool(r.is_vpn), tor: bool(r.is_tor), server: bool(r.is_datacenter) },
        score: riskScore('generic', r.risk_score),
      };
    },
  },
  {
    id: 'scamalytics', name: 'Scamalytics',
    async run(ip) {
      const html = await fetchText(Object.assign({ url: `https://scamalytics.com/ip/${ip}` }, PROXY));
      const m = html.match(/"score"\s*:\s*"?(\d+)"?/);
      if (!m) throw new Error(/Just a moment|cf-chl|challenge/i.test(html) ? '被 Cloudflare 拦截' : '页面格式已变化');
      const risk = (html.match(/"risk"\s*:\s*"([^"]+)"/) || [])[1];
      const row = name => {
        const r = html.match(new RegExp('<th>\\s*' + name + '\\s*</th>\\s*<td>\\s*<div class="risk (yes|no)', 'i'));
        return r ? r[1].toLowerCase() === 'yes' : undefined;
      };
      const black = (html.match(/"is_blacklisted_external"\s*:\s*(true|false)/) || [])[1];
      const isp = (html.match(/<title>[^(<]*\(\s*([^)<]+?)\s*\)/) || [])[1];
      return {
        org: isp,
        f: {
          proxy: any(row('Public Proxy'), row('Web Proxy'), row('Residential Proxy')), vpn: row('Anonymizing VPN'), tor: row('Tor Exit Node'),
          server: row('Server'), abuse: black == null ? undefined : black === 'true', bot: row('Search Engine Robot'),
        },
        score: riskScore('scamalytics', m[1], risk),
      };
    },
  },
  {
    id: 'dbip', name: 'DB-IP',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://api.db-ip.com/v2/free/${ip}` }, PROXY));
      if (d.error || !d.countryCode) throw new Error(d.error || '无数据');
      return { cc: d.countryCode, region: d.stateProv, city: d.city };
    },
  },
  {
    id: 'ipqs', name: 'IPQS', key: 'ipqs',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://www.ipqualityscore.com/api/json/ip/${encodeURIComponent(OPT.key.ipqs)}/${ip}?strictness=1&allow_public_access_points=true` }, PROXY));
      if (d.success === false) throw new Error(d.message || '查询失败');
      return {
        cc: d.country_code, region: d.region, city: d.city, org: d.ISP || d.organization, asn: d.ASN ? 'AS' + d.ASN : '', usage: d.connection_type,
        f: {
          proxy: bool(d.proxy), vpn: any(d.vpn, d.active_vpn), tor: any(d.tor, d.active_tor),
          server: d.connection_type ? /data center/i.test(d.connection_type) : undefined, abuse: bool(d.recent_abuse), bot: bool(d.bot_status),
        },
        score: riskScore('ipqs', d.fraud_score),
      };
    },
  },
  {
    id: 'abuseipdb', name: 'AbuseIPDB', key: 'abuseipdb',
    async run(ip) {
      const j = await fetchJSON(Object.assign({ url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, headers: { Key: OPT.key.abuseipdb, Accept: 'application/json' } }, PROXY));
      if (j.errors) throw new Error((j.errors[0] && j.errors[0].detail) || '查询失败');
      const d = j.data || {};
      return {
        cc: d.countryCode, org: d.isp, usage: d.usageType,
        f: { tor: bool(d.isTor), abuse: typeof d.totalReports === 'number' ? d.totalReports > 0 : undefined, server: d.usageType ? /data center|hosting/i.test(d.usageType) : undefined },
        score: riskScore('generic', d.abuseConfidenceScore),
        note: typeof d.totalReports === 'number' ? `90 天内被举报 ${d.totalReports} 次` : '',
      };
    },
  },
  {
    id: 'ipapiis', name: 'ipapi.is', key: 'ipapi',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://api.ipapi.is/?q=${ip}&key=${encodeURIComponent(OPT.key.ipapi)}` }, PROXY));
      if (d.error) throw new Error(d.error);
      const c = d.company || {};
      const a = d.asn || {};
      const l = d.location || {};
      return {
        cc: l.country_code, region: l.state, city: l.city, org: c.name || a.org, asn: a.asn ? 'AS' + a.asn : '',
        usage: d.is_mobile ? 'mobile' : a.type, company: c.type, reg: a.country,
        f: { proxy: bool(d.is_proxy), vpn: bool(d.is_vpn), tor: bool(d.is_tor), server: bool(d.is_datacenter), abuse: bool(d.is_abuser), bot: bool(d.is_crawler) },
        score: riskScore('ipapiis', c.abuser_score || a.abuser_score),
      };
    },
  },
  {
    id: 'ipregistry', name: 'ipregistry', key: 'ipregistry',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://api.ipregistry.co/${ip}?key=${encodeURIComponent(OPT.key.ipregistry)}` }, PROXY));
      if (d.code && d.message) throw new Error(d.message);
      const c = d.connection || {};
      const s = d.security || {};
      const l = d.location || {};
      return {
        cc: l.country && l.country.code, region: l.region && l.region.name, city: l.city, org: c.organization, asn: c.asn ? 'AS' + c.asn : '',
        usage: c.type, company: d.company && d.company.type,
        f: { proxy: any(s.is_proxy, s.is_relay), vpn: bool(s.is_vpn), tor: any(s.is_tor, s.is_tor_exit), server: bool(s.is_cloud_provider), abuse: any(s.is_abuser, s.is_attacker, s.is_threat) },
      };
    },
  },
  {
    id: 'ipdata', name: 'ipdata', key: 'ipdata',
    async run(ip) {
      const d = await fetchJSON(Object.assign({ url: `https://api.ipdata.co/${ip}?api-key=${encodeURIComponent(OPT.key.ipdata)}` }, PROXY));
      if (!d.ip) throw new Error(d.message || '查询失败');
      const t = d.threat || {};
      const a = d.asn || {};
      const sc = t.scores || {};
      return {
        cc: d.country_code, region: d.region, city: d.city, org: a.name, asn: a.asn, usage: a.type,
        f: { proxy: any(t.is_proxy, t.is_icloud_relay), vpn: bool(t.is_vpn), tor: bool(t.is_tor), server: bool(t.is_datacenter), abuse: any(t.is_known_abuser, t.is_known_attacker, t.is_threat) },
        score: riskScore('ipdata', sc.trust_score),
      };
    },
  },
];

async function runSource(s, ip) {
  const t0 = Date.now();
  try {
    const r = await s.run(ip);
    return normalizeRec(Object.assign({ id: s.id, name: s.name, ok: true, ms: Date.now() - t0 }, r));
  } catch (e) {
    return { id: s.id, name: s.name, ok: false, ms: Date.now() - t0, error: String(e && e.message || e).slice(0, 80) };
  }
}

function normalizeRec(r) {
  r.cc = r.cc ? String(r.cc).toUpperCase() : '';
  r.reg = r.reg ? String(r.reg).toUpperCase() : '';
  r.usageRaw = r.usage || '';
  r.companyRaw = r.company || '';
  r.usage = usageCode(r.usage);
  r.company = usageCode(r.company);
  r.f = r.f || {};
  r.score = r.score || null;
  return r;
}

// 注册地：RIPEstat 的 RIR 分配统计
async function registration(ip) {
  try {
    const j = await fetchJSON(Object.assign({ url: `https://stat.ripe.net/data/rir-stats-country/data.json?resource=${ip}&sourceapp=surge-ipcheck` }, PROXY));
    const r = j.data && j.data.located_resources && j.data.located_resources[0];
    if (r && r.location) return { cc: String(r.location).toUpperCase(), src: 'RIPEstat', block: r.resource };
  } catch (e) { /* 失败时用其他库的 ASN 国家兜底 */ }
  return null;
}

function tally(list) {
  const t = {};
  list.forEach(x => { if (x) t[x] = (t[x] || 0) + 1; });
  return t;
}

function topOf(t) {
  return Object.keys(t).sort((a, b) => t[b] - t[a])[0] || '';
}

const FACTORS = [['proxy', '代理'], ['vpn', 'VPN'], ['tor', 'Tor'], ['server', '机房'], ['abuse', '滥用'], ['bot', '机器人']];

function summarize(ip, recs, reg) {
  const ok = recs.filter(r => r.ok);
  const ccVotes = tally(ok.map(r => r.cc));
  const mm = ok.find(r => r.id === 'maxmind');
  const useCC = (mm && mm.cc) || topOf(ccVotes);
  const regFallback = ok.find(r => r.reg);
  const regInfo = reg || (regFallback ? { cc: regFallback.reg, src: regFallback.name + '（ASN 国家）' } : null);
  const native = regInfo && useCC ? (regInfo.cc === useCC ? '原生IP' : '广播IP') : '未知';

  const usageVotes = tally(ok.map(r => r.usage));
  const usageTotal = Object.values(usageVotes).reduce((a, b) => a + b, 0);
  const usageTop = topOf(usageVotes);

  const scores = ok.filter(r => r.score).map(r => Object.assign({ name: r.name }, r.score));
  const level = scores.length ? Math.max(...scores.map(s => s.level)) : -1;

  const factors = {};
  FACTORS.forEach(([k]) => {
    const vals = ok.filter(r => typeof r.f[k] === 'boolean');
    factors[k] = { hit: vals.filter(r => r.f[k]).length, total: vals.length, by: vals.filter(r => r.f[k]).map(r => r.name) };
  });

  return {
    ip,
    use: { cc: useCC, votes: ccVotes, src: mm && mm.cc ? 'Surge GeoIP' : '多库多数' },
    reg: regInfo,
    native,
    usage: { top: usageTop, votes: usageVotes, total: usageTotal },
    risk: { level, scores },
    factors,
    sources: recs,
  };
}

function qualitySig() {
  return Object.keys(OPT.key).filter(k => OPT.key[k]).join(',');
}

async function quality(ip, probeRec, noCache) {
  const cache = readStore(CACHE_KEY);
  const hit = cache[ip];
  if (!noCache && OPT.cache > 0 && hit && hit.v === VERSION && hit.sig === qualitySig() && Date.now() - hit.ts < OPT.cache * 1000) {
    return Object.assign({}, hit.q, { cachedAt: hit.ts });
  }
  const list = SOURCES.filter(s => !s.key || OPT.key[s.key]);
  const [recs, reg] = await Promise.all([Promise.all(list.map(s => runSource(s, ip))), registration(ip)]);
  if (probeRec) recs.unshift(probeRec);
  const sg = surgeGeo(ip);
  if (sg.cc) recs.unshift(normalizeRec({ id: 'maxmind', name: 'Surge GeoIP', ok: true, ms: 0, cc: sg.cc, asn: sg.asn, org: sg.org }));
  const q = summarize(ip, recs, reg);
  if (recs.some(r => r.ok && r.id !== 'maxmind' && r.id !== 'ipapi')) {
    cache[ip] = { ts: Date.now(), v: VERSION, sig: qualitySig(), q };
    Object.keys(cache).sort((a, b) => cache[b].ts - cache[a].ts).slice(10).forEach(k => delete cache[k]);
    writeStore(CACHE_KEY, cache);
  }
  return q;
}

// 落地探测里 ip-api 的结果直接当作一个质量数据源，不再重复请求
function ipApiRec(probe) {
  const a = probe && probe.raw;
  if (!a) return null;
  return normalizeRec({
    id: 'ipapi', name: 'ip-api', ok: true, ms: probe.ms, cc: a.countryCode, region: a.regionName, city: a.city, org: a.isp || a.org, asn: String(a.as || '').split(' ')[0],
    usage: a.hosting ? 'hosting' : a.mobile ? 'mobile' : null,
    f: { proxy: bool(a.proxy), server: bool(a.hosting) },
  });
}

/* ───────────────────────── 主流程 ───────────────────────── */

async function detect(opts) {
  opts = opts || {};
  const R = { ts: START, version: VERSION, env: envInfo(), net: netInfo(), policyArg: OPT.policy, mask: OPT.mask };

  // 第一轮：本地（直连）与落地（代理）同时查
  const [local, probes, v6] = await Promise.all([
    detectLocal(),
    Promise.all(PROBES.map(p => runProbe(p))),
    OPT.ipv6 ? detectV6() : Promise.resolve(null),
  ]);
  R.local = local;
  R.probes = probes.map(p => ({ id: p.id, ip: p.ip || '', error: p.error || '', ms: p.ms }));
  const okProbes = probes.filter(p => p.ip);
  const ipCount = tally(okProbes.map(p => p.ip));
  const primary = (probes[0] && probes[0].ip) || topOf(ipCount);
  const cf = probes.find(p => p.id === 'Cloudflare' && p.raw);
  R.landing = primary ? Object.assign({}, (okProbes.find(p => p.ip === primary && p.geo && p.geo.region) || okProbes.find(p => p.ip === primary)).geo, { ip: primary }) : null;
  if (R.landing && cf) { R.landing.colo = cf.raw.colo; R.landing.warp = cf.raw.warp; }
  R.landingAlt = uniq(okProbes.map(p => p.ip).filter(ip => ip !== primary));

  // 入口与执行策略
  const routes1 = await readRoutes();
  let routes = routes1;
  R.apiOK = routes !== null;
  const entryMap = collectEntries(routes);
  const entryIPs = Object.keys(entryMap);
  const dns = await dnsCandidates(entryIPs);
  const candIPs = uniq([].concat(...Object.values(dns).map(d => d.ips))).filter(ip => !entryMap[ip]).slice(0, 4);

  // 第二轮：入口位置、备选入口、其他出口、IPv6 与落地 IP 质量同时查
  const [geo, q] = await Promise.all([
    lookupIPs(entryIPs.concat(candIPs, R.landingAlt, v6 && v6.ip ? [v6.ip] : [])),
    primary ? quality(primary, probes[0] && probes[0].ip === primary ? ipApiRec(probes[0]) : null, opts.noCache) : Promise.resolve(null),
  ]);
  R.quality = q;

  // 第二轮的请求同样走代理，负载均衡时可能又多出入口
  const routes2 = await readRoutes();
  if (routes2) {
    collectEntries(routes2, entryMap);
    routes = routes2;
  }
  const extra = Object.keys(entryMap).filter(ip => !geo[ip]);
  if (extra.length) Object.assign(geo, await lookupIPs(extra));

  R.entries = Object.keys(entryMap)
    .sort((a, b) => entryMap[b].count - entryMap[a].count)
    .map(ip => Object.assign({}, geo[ip] || { ip }, entryMap[ip], { domain: dns[ip] && dns[ip].domain }));
  R.candidates = candIPs.map(ip => Object.assign({}, geo[ip] || { ip }, { domain: (Object.values(dns).find(d => d.ips.includes(ip)) || {}).domain }));
  R.landingAlt = R.landingAlt.map(ip => geo[ip] || { ip });
  R.v6 = v6 && v6.ip ? Object.assign({}, geo[v6.ip] || {}, { ip: v6.ip }) : v6;
  if (R.landing && q) {
    // 落地地址缺省省份时，用质量库里的信息补齐
    const best = q.sources.find(s => s.ok && s.cc === R.landing.cc && s.region);
    if (!R.landing.region && best) Object.assign(R.landing, { region: best.region, city: best.city });
    if (!R.landing.isp && !R.landing.org) R.landing.org = (q.sources.find(s => s.ok && s.org) || {}).org;
  }

  // 执行策略以落地探测请求为准；备注里没有决策路径时按规则与策略组推算
  const probeRoutes = (routes1 || []).filter(r => PROBES.some(p => sameURL(p.url, r.url)));
  const probeRoute = probeRoutes[0] || (routes || [])[0];
  const withPath = probeRoutes.find(r => r.path.length) || (routes || []).find(r => r.path.length && (!probeRoute || r.node === probeRoute.node));
  const rule = (probeRoutes.find(r => r.rule) || probeRoute || {}).rule || '';
  const node = probeRoute ? probeRoute.node : '';
  R.exec = {
    rule,
    path: withPath ? withPath.path : probeRoute && probeRoute.proxied ? await resolvePath(rule, node) : [],
    node,
    nodes: uniq((routes || []).filter(r => r.proxied).map(r => r.node)),
    direct: !!routes && routes.length > 0 && !routes.some(r => r.proxied),
  };
  R.ms = Date.now() - START;
  return R;
}

/* ───────────────────────── 文本输出 ───────────────────────── */

function geoLine(g) {
  if (!g) return '';
  if (g.private) return `${showIP(g.ip)} 内网/本机代理`;
  return [showIP(g.ip), placeShort(g), ispName(g)].filter(Boolean).join(' ');
}

function execText(R) {
  const e = R.exec || {};
  if (!R.apiOK) return '无法读取（需 Surge 的 $httpAPI）';
  if (e.direct) return `${e.rule ? e.rule + ' ➜ ' : ''}DIRECT（未经代理）`;
  const path = (e.path && e.path.length ? e.path.slice() : [R.policyArg].filter(Boolean));
  if (e.node && path[path.length - 1] !== e.node) path.push(e.node);
  const head = R.policyArg ? '指定' : e.rule;
  const s = [head].concat(path).filter(Boolean).join(' ➜ ');
  return (s || e.node || '未知') + (e.nodes.length > 1 ? `（共 ${e.nodes.length} 个节点）` : '');
}

function usageText(u) {
  if (!u || !u.total) return '类型未知';
  const keys = Object.keys(u.votes).sort((a, b) => u.votes[b] - u.votes[a]);
  if (u.votes[keys[0]] * 2 > u.total) return `${USAGE_LABEL[keys[0]]} ${u.votes[keys[0]]}/${u.total}`;
  return keys.map(k => USAGE_LABEL[k] + u.votes[k]).join('·');
}

function riskText(q) {
  if (!q || q.risk.level < 0) return '风险未知';
  return LEVELS[q.risk.level] + '风险';
}

function factorText(q) {
  const hits = FACTORS.filter(([k]) => q.factors[k].hit > 0).map(([k, n]) => `${n} ${q.factors[k].hit}/${q.factors[k].total}`);
  if (hits.length) return hits.join(' · ');
  const n = q.sources.filter(s => s.ok && Object.values(s.f).some(v => typeof v === 'boolean')).length;
  return `代理/VPN/Tor/机房/滥用/机器人 均未命中（${n} 库）`;
}

function lines(R) {
  const L = [];
  const n = R.net || {};
  const netDesc = n.type === '蜂窝' ? `蜂窝 ${[n.carrier, n.radio].filter(Boolean).join(' ')}` : n.type === 'Wi-Fi' ? 'Wi-Fi' : '';
  L.push(`本地：${R.local && R.local.ip ? geoLine(R.local) : R.local && R.local.error || '未知'}${netDesc ? ' · ' + netDesc : ''}`);
  if (!R.apiOK) L.push('入口：无法读取');
  else if (!R.entries.length) L.push(R.exec.direct ? '入口：无（直连，未经代理）' : '入口：未找到代理请求');
  R.entries.forEach((e, i) => {
    const more = i === 0 && R.candidates.length ? `（DNS 另有 ${R.candidates.length} 个）` : '';
    L.push(`${i ? '入口' + (i + 1) : '入口'}：${geoLine(e)}${more}`);
  });
  if (R.landing) {
    L.push(`落地：${geoLine(R.landing)}`);
    R.landingAlt.forEach((g, i) => L.push(`落地${i + 2}：${geoLine(g)}`));
  } else {
    L.push('落地：检测失败');
  }
  if (R.v6) L.push(`IPv6：${R.v6.ip ? geoLine(R.v6) : '无（' + R.v6.error.slice(0, 24) + '）'}`);
  L.push(`执行：${execText(R)}`);
  const q = R.quality;
  if (q) {
    const reg = q.reg ? `注册 ${q.reg.cc}` : '注册地未知';
    L.push(`类型：${q.native}（${reg}/使用 ${q.use.cc || '?'}）· ${usageText(q.usage)}`);
    const sc = q.risk.scores.map(s => `${s.name} ${s.display}`).join(' · ');
    L.push(`风险：${riskText(q)}${sc ? ' · ' + sc : ''}`);
    L.push(`因子：${factorText(q)}`);
  }
  return L;
}

function titleText(R) {
  const q = R.quality;
  if (!R.landing) return 'IP 检测 · 落地检测失败';
  if (!q) return `IP 检测 · ${flag(R.landing.cc)} ${showIP(R.landing.ip)}`;
  const u = q.usage.top ? USAGE_LABEL[q.usage.top] : '类型未知';
  return `${flag(q.use.cc || R.landing.cc)} ${q.native} · ${u} · ${riskText(q)}`;
}

function footText(R) {
  const env = R.env;
  const cached = R.quality && R.quality.cachedAt ? ` · 质量数据缓存于 ${clock(R.quality.cachedAt)}` : '';
  return `${clock(R.ts)} · 用时 ${secs(R.ms)} · Surge ${env.system} ${env.version}${cached}`;
}

function riskColor(level) {
  if (level < 0) return '#8E8E93';
  if (level <= 1) return '#34C759';
  if (level === 2) return '#FF9F0A';
  return '#FF453A';
}

/* ───────────────────────── 网页报告 ───────────────────────── */

const CHIP_CLASS = { isp: 'good', mobile: 'good', hosting: 'bad', cdn: 'bad', business: 'warn', education: 'info', government: 'info', banking: 'info', crawler: 'bad', reserved: 'muted', other: 'muted' };

function chip(text, cls) {
  return `<span class="chip ${cls || ''}">${esc(text)}</span>`;
}

function usageChip(code, raw) {
  if (!code) return '<span class="none">—</span>';
  return `<span class="chip ${CHIP_CLASS[code] || ''}" title="${esc(raw)}">${esc(USAGE_LABEL[code])}</span>`;
}

function flagCell(v) {
  if (v === true) return '<span class="chip bad">是</span>';
  if (v === false) return '<span class="chip good">否</span>';
  return '<span class="none">—</span>';
}

function geoCells(g) {
  if (!g) return '<td class="none">—</td>';
  if (g.private) return `<td><div class="mono">${esc(showIP(g.ip))}</div><div class="muted">内网 / 本机代理</div></td>`;
  const asn = g.asn ? ` <span class="muted">${esc(g.asn)}</span>` : '';
  return `<td><div class="mono">${esc(showIP(g.ip))}</div><div>${esc(placeFull(g))} · ${esc(ispName(g))}${asn}</div></td>`;
}

function renderHTML(R) {
  const q = R.quality;
  const n = R.net || {};
  const rows = [];
  const none = t => `<td class="none">${esc(t)}</td>`;
  const sub = t => `<tr class="sub"><th></th><td>${esc(t)}</td></tr>`;
  const netDesc = [n.type, n.ssid && !OPT.mask ? n.ssid : '', n.carrier, n.radio].filter(Boolean).join(' · ');
  rows.push(`<tr><th>本地</th>${R.local && R.local.ip ? geoCells(R.local) : none(R.local && R.local.error || '未知')}</tr>`);
  if (n.lan) rows.push(`<tr><th>内网</th><td><div class="mono">${esc(showIP(n.lan))}</div><div class="muted">${esc([netDesc || n.iface, n.router ? '网关 ' + showIP(n.router) : ''].filter(Boolean).join(' · '))}</div></td></tr>`);
  if (!R.entries.length) rows.push(`<tr><th>入口</th>${none(R.apiOK ? (R.exec.direct ? '无（直连，未经代理）' : '未找到代理请求') : '无法读取（需 Surge 的 $httpAPI）')}</tr>`);
  R.entries.forEach((e, i) => {
    rows.push(`<tr><th>入口${R.entries.length > 1 ? i + 1 : ''}</th>${geoCells(e)}</tr>`);
    const info = [e.nodes.length ? '节点：' + e.nodes.join('、') : '', e.domain && !OPT.mask ? '域名：' + e.domain : ''].filter(Boolean).join(' · ');
    if (info) rows.push(sub(info));
  });
  R.candidates.forEach((g, i) => rows.push(`<tr><th>备选入口${i + 1}</th>${geoCells(g)}</tr>` + sub('同一节点域名在 DNS 缓存里的其他地址，本次未使用')));
  rows.push(`<tr><th>落地</th>${R.landing ? geoCells(R.landing) : none('检测失败')}</tr>`);
  if (R.landing && R.landing.colo) rows.push(sub(`Cloudflare 节点 ${R.landing.colo}${R.landing.warp && R.landing.warp !== 'off' ? ' · WARP ' + R.landing.warp : ''}${R.landing.tz ? ' · 时区 ' + R.landing.tz : ''}`));
  R.landingAlt.forEach((g, i) => rows.push(`<tr><th>落地${i + 2}</th>${geoCells(g)}</tr>`));
  if (R.v6) rows.push(`<tr><th>IPv6</th>${R.v6.ip ? geoCells(R.v6) : none(R.v6.error)}</tr>`);
  rows.push(`<tr><th>执行</th><td>${esc(execText(R))}</td></tr>`);
  const env = R.env;
  rows.push(sub(`Surge ${env.system} ${env.version}（${env.build}）${env.model ? ' · ' + env.model : ''}`));

  let body = `<section><h2>网络路径</h2><table class="kv">${rows.join('')}</table></section>`;

  if (q) {
    const ok = q.sources.filter(s => s.ok);
    const nativeCls = q.native === '原生IP' ? 'good' : q.native === '广播IP' ? 'warn' : 'muted';
    const lv = q.risk.level;
    const lvCls = lv < 0 ? 'muted' : lv <= 1 ? 'good' : lv === 2 ? 'warn' : 'bad';
    const useVotes = Object.keys(q.use.votes).map(k => `${k} ${q.use.votes[k]}`).join('、');
    body += `<section><h2>基础信息（落地 IP）</h2><div class="badges">${chip(q.native, nativeCls)}${q.usage.top ? usageChip(q.usage.top) : ''}${chip(riskText(q), lvCls)}</div>
<table class="kv">
<tr><th>IP</th><td class="mono">${esc(showIP(q.ip))}</td></tr>
<tr><th>使用地</th><td>${esc(flag(q.use.cc))} ${esc(ccName(q.use.cc))} <span class="muted">（${esc(q.use.src)}；各库：${esc(useVotes)}）</span></td></tr>
<tr><th>注册地</th><td>${q.reg ? `${esc(flag(q.reg.cc))} ${esc(ccName(q.reg.cc))} <span class="muted">（${esc(q.reg.src)}${q.reg.block ? ' · ' + esc(q.reg.block) : ''}）</span>` : '<span class="none">未知</span>'}</td></tr>
<tr><th>判定</th><td>${esc(q.native)}${q.native === '广播IP' ? '：注册地与使用地不同，地址可能是从别国调来广播的' : q.native === '原生IP' ? '：注册地与使用地一致' : ''}</td></tr>
<tr><th>使用类型</th><td>${esc(usageText(q.usage))}</td></tr>
</table></section>`;

    const typed = ok.filter(s => s.usage || s.company);
    if (typed.length) {
      body += `<section><h2>IP 类型属性</h2><div class="scroll"><table class="grid"><tr><th>数据库</th>${typed.map(s => `<th>${esc(s.name)}</th>`).join('')}</tr>
<tr><th>使用类型</th>${typed.map(s => `<td>${usageChip(s.usage, s.usageRaw)}</td>`).join('')}</tr>
<tr><th>公司类型</th>${typed.map(s => `<td>${usageChip(s.company, s.companyRaw)}</td>`).join('')}</tr></table></div></section>`;
    }

    if (q.risk.scores.length) {
      body += `<section><h2>风险评分</h2><div class="scale"><span class="l0">极低</span><span class="l1">低</span><span class="l2">中</span><span class="l3">高</span><span class="l4">极高</span></div>
${q.risk.scores.map(s => `<div class="score"><span class="name">${esc(s.name)}</span><span class="bar"><i class="l${s.level}" style="width:${Math.max(3, Math.min(100, s.bar))}%"></i></span><span class="val">${esc(s.display)}</span><span class="chip l${s.level}">${esc(LEVELS[s.level])}风险</span></div>`).join('')}
<p class="muted small">综合等级取各库中最高的一项。</p></section>`;
    }

    const fdb = ok.filter(s => Object.values(s.f).some(v => typeof v === 'boolean') || s.cc);
    body += `<section><h2>风险因子</h2><div class="scroll"><table class="grid"><tr><th>库</th>${fdb.map(s => `<th>${esc(s.name)}</th>`).join('')}</tr>
<tr><th>地区</th>${fdb.map(s => `<td>${s.cc ? esc(flag(s.cc) + ' ' + s.cc) : '<span class="none">—</span>'}</td>`).join('')}</tr>
${FACTORS.map(([k, name]) => `<tr><th>${name}</th>${fdb.map(s => `<td>${flagCell(s.f[k])}</td>`).join('')}</tr>`).join('')}
</table></div></section>`;

    body += `<section><h2>数据源状态${q.cachedAt ? `<span class="muted small">（缓存于 ${clock(q.cachedAt)}）</span>` : ''}</h2><div class="scroll"><table class="grid status"><tr><th>数据库</th><th>状态</th><th>用时</th><th>说明</th></tr>
${q.sources.map(s => `<tr><th>${esc(s.name)}</th><td>${s.ok ? '<span class="chip good">成功</span>' : '<span class="chip bad">失败</span>'}</td><td>${s.ms ? s.ms + ' ms' : '—'}</td><td>${esc(s.ok ? [s.org, s.note].filter(Boolean).join(' · ') : s.error)}</td></tr>`).join('')}
${R.probes.map(p => `<tr><th>落地探测 · ${esc(p.id)}</th><td>${p.ip ? '<span class="chip good">成功</span>' : '<span class="chip bad">失败</span>'}</td><td>${p.ms} ms</td><td class="mono">${esc(p.ip ? showIP(p.ip) : p.error)}</td></tr>`).join('')}
</table></div>
<p class="muted small">没填 API Key 的数据库不会查询：IPQS、AbuseIPDB、ipapi.is、ipregistry、ipdata。在模块参数里填入 Key 即可启用。</p></section>`;
  }

  const style = `:root{--bg:#f5f6f8;--card:#fff;--text:#1c1e21;--muted:#6b7280;--line:#e6e8eb;--good:#15803d;--good-bg:#dcfce7;--warn:#b45309;--warn-bg:#fef3c7;--bad:#b91c1c;--bad-bg:#fee2e2;--info:#1d4ed8;--info-bg:#dbeafe;--l0:#16a34a;--l1:#65a30d;--l2:#f59e0b;--l3:#ef4444;--l4:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--card:#171a20;--text:#e5e7eb;--muted:#9ca3af;--line:#2a2e37;--good:#4ade80;--good-bg:#12321f;--warn:#fbbf24;--warn-bg:#3a2c0b;--bad:#f87171;--bad-bg:#3b1414;--info:#93c5fd;--info-bg:#132544}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Helvetica Neue",sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:16px}header h1{font-size:20px;margin:8px 0 4px}header p{margin:0;color:var(--muted);font-size:13px}
.actions{margin:10px 0 4px;display:flex;gap:8px;flex-wrap:wrap}.actions a{font-size:13px;padding:5px 12px;border-radius:999px;background:var(--card);border:1px solid var(--line);color:var(--text);text-decoration:none}
section{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;margin:14px 0}h2{font-size:16px;margin:0 0 10px}
table{border-collapse:collapse;width:100%}th,td{padding:6px 8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);font-size:14px}tr:last-child th,tr:last-child td{border-bottom:0}
.kv th{width:84px;color:var(--muted);font-weight:500;white-space:nowrap}.kv tr.sub td{color:var(--muted);font-size:12.5px;padding-top:0}.kv tr.sub th,.kv tr.sub td{border-bottom:1px solid var(--line)}
.grid th{color:var(--muted);font-weight:500;white-space:nowrap}.grid td{white-space:nowrap}.status td:last-child{white-space:normal;color:var(--muted);font-size:13px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px;white-space:nowrap}.kv .mono{white-space:normal;word-break:break-all}
.muted{color:var(--muted)}.small{font-size:12.5px;font-weight:400}.none{color:var(--muted)}
.chip{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12.5px;font-weight:600;background:var(--line);color:var(--text)}
.chip.good{background:var(--good-bg);color:var(--good)}.chip.warn{background:var(--warn-bg);color:var(--warn)}.chip.bad{background:var(--bad-bg);color:var(--bad)}.chip.info{background:var(--info-bg);color:var(--info)}.chip.muted{color:var(--muted)}
.badges{display:flex;gap:6px;margin-bottom:8px}.badges .chip{font-size:14px;padding:3px 10px}
.scale{display:flex;border-radius:6px;overflow:hidden;font-size:12px;font-weight:600;color:#fff;margin-bottom:10px}.scale span{flex:1;padding:3px 8px}
.l0{background:var(--l0)}.l1{background:var(--l1)}.l2{background:var(--l2)}.l3{background:var(--l3)}.l4{background:var(--l4)}.chip.l0,.chip.l1,.chip.l2,.chip.l3,.chip.l4{color:#fff}
.score{display:grid;grid-template-columns:110px 1fr 64px 72px;gap:8px;align-items:center;padding:5px 0;border-bottom:1px solid var(--line);font-size:14px}.score:last-of-type{border-bottom:0}
.score .bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}.score .bar i{display:block;height:100%}.score .val{text-align:right;font-family:ui-monospace,Menlo,monospace}
footer{color:var(--muted);font-size:12px;text-align:center;margin:18px 0 8px}footer a{color:inherit}
@media (max-width:520px){.score{grid-template-columns:88px 1fr 52px 64px}.kv th{width:64px}}`;

  const title = R.landing ? `IP 检测报告：${showIP(R.landing.ip)}` : 'IP 检测报告';
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>IP 检测报告</title><style>${style}</style></head><body><div class="wrap">
<header><h1>${esc(title)}</h1><p>${esc(dateTime(R.ts))} · 用时 ${esc(secs(R.ms))} · ${esc(titleText(R))}</p>
<div class="actions"><a href="${REPORT_URL}">刷新</a><a href="${REPORT_URL}?nocache=1">重新查询质量</a><a href="${REPORT_URL}?mask=${OPT.mask ? 0 : 1}">${OPT.mask ? '显示完整 IP' : '隐藏 IP'}</a></div></header>
${body}
<footer>surge-ipcheck v${VERSION} · <a href="${REPO}">${REPO.replace('https://', '')}</a><br>各库结论来自其公开数据，可能互相矛盾；仅供参考。</footer>
</div></body></html>`;
}

/* ───────────────────────── 入口 ───────────────────────── */

function notify(R) {
  const L = lines(R);
  const landing = L.find(l => l.startsWith('落地：')) || '';
  $notification.post(titleText(R), landing.replace(/^落地：/, '落地 '), L.filter(l => l !== landing).join('\n'), { url: REPORT_URL });
}

async function handlePanel() {
  const isPanel = typeof $input !== 'undefined' && $input && $input.purpose === 'panel';
  try {
    const R = await detect({});
    const content = lines(R).concat(footText(R)).join('\n');
    if (!isPanel) {
      console.log('\n' + titleText(R) + '\n' + content);
      notify(R);
    }
    $done({ title: titleText(R), content, icon: 'network.badge.shield.half.filled', 'icon-color': riskColor(R.quality ? R.quality.risk.level : -1) });
  } catch (e) {
    console.log('IP 检测出错：' + (e && e.stack || e));
    $done({ title: 'IP 检测出错', content: String(e && e.message || e), icon: 'exclamationmark.triangle.fill', 'icon-color': '#FF453A' });
  }
}

async function handleReport() {
  const url = String($request.url || '');
  const m = url.match(/^https?:\/\/[^/]+(\/[^?#]*)?(\?[^#]*)?/);
  const path = (m && m[1]) || '/';
  const query = {};
  ((m && m[2]) || '').slice(1).split('&').forEach(kv => { const i = kv.indexOf('='); if (i > 0) query[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1)); });
  if (path !== '/' && path !== '/index.html' && path !== '/json') {
    $done({ response: { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: 'Not Found' } });
    return;
  }
  if (query.mask === '1') OPT.mask = true;
  if (query.mask === '0') OPT.mask = false;
  try {
    const R = await detect({ noCache: query.nocache === '1' });
    if (path === '/json') {
      let json = JSON.stringify(R, null, 2);
      if (OPT.mask) json = json.replace(/\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/g, '$1.*.*').replace(/\b([0-9a-f]{1,4}:[0-9a-f]{1,4}):[0-9a-f:]{2,}\b/gi, '$1:*');
      $done({ response: { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, body: json } });
    } else {
      $done({ response: { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, body: renderHTML(R) } });
    }
  } catch (e) {
    $done({ response: { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: 'IP 检测出错：' + (e && e.stack || e) } });
  }
}

async function handleEvent() {
  if (!OPT.notify) return $done();
  try {
    await sleep(3000); // 等网络稳定
    const n = netInfo();
    if (!n.lan && !n.lan6) return $done();
    const R = await detect({});
    const sig = [R.local && R.local.ip, R.entries.map(e => e.ip).join('+'), R.landing && R.landing.ip].join('|');
    const last = readStore(NOTIFY_KEY);
    if (last.sig !== sig || Date.now() - (last.ts || 0) > 6 * 3600 * 1000) {
      notify(R);
      writeStore(NOTIFY_KEY, { sig, ts: Date.now() });
    }
  } catch (e) {
    console.log('IP 检测出错：' + (e && e.stack || e));
  }
  $done();
}

if (typeof module !== 'undefined' && module.exports && typeof $done === 'undefined') {
  // 供 test/ 下的离线测试使用
  module.exports = { parseArgs, usageCode, riskScore, summarize, normalizeRec, mergeGeo, placeShort, placeFull, maskIP, isPrivate, lines, renderHTML, titleText, OPT, SOURCES, PROBES };
} else {
  const type = typeof $script !== 'undefined' && $script.type;
  if (typeof $request !== 'undefined' && type !== 'generic') handleReport();
  else if (type === 'event' || (typeof $event !== 'undefined' && type !== 'generic')) handleEvent();
  else handlePanel();
}
