// 离线测试：解析、判定与渲染逻辑。运行：node --test test/
// 所有响应都是按各接口真实格式构造的样例，IP 用文档保留段 203.0.113.0/24。
const test = require('node:test');
const assert = require('node:assert');

const FIXTURES = {};
global.$httpClient = {
  get(o, cb) {
    const body = FIXTURES[o.url];
    if (body === undefined) cb('no fixture for ' + o.url);
    else cb(null, { status: 200, headers: {} }, body);
  },
};

const S = require('../ipcheck.js');
const IP = '203.0.113.10';
const source = id => S.SOURCES.find(s => s.id === id);

async function run(id) {
  const r = await source(id).run(IP);
  return S.normalizeRec(Object.assign({ id, name: source(id).name, ok: true }, r));
}

test('参数解析：未替换的占位与空值当作未填写', () => {
  const a = S.parseArgs('policy=%F0%9F%87%BA%F0%9F%87%B8 US&timeout={{{TIMEOUT}}}&ipqs_key=&mask=1&cache=none');
  assert.strictEqual(a.policy, '🇺🇸 US');
  assert.strictEqual(a.timeout, '');
  assert.strictEqual(a.ipqs_key, '');
  assert.strictEqual(a.mask, '1');
  assert.strictEqual(a.cache, '');
});

test('使用类型归一', () => {
  const cases = {
    isp: 'isp', 'Fixed Line ISP': 'isp', Residential: 'isp', 'Mobile ISP': 'mobile', Wireless: 'mobile', 'ISP/MOB': 'mobile',
    hosting: 'hosting', 'Data Center/Web Hosting/Transit': 'hosting', 'Data Center': 'hosting', DCH: 'hosting',
    Business: 'business', Corporate: 'business', Commercial: 'business', 'Content Delivery Network': 'cdn',
    'University/College/School': 'education', education: 'education', government: 'government',
  };
  Object.keys(cases).forEach(k => assert.strictEqual(S.usageCode(k), cases[k], k));
  assert.strictEqual(S.usageCode(''), null);
  assert.strictEqual(S.usageCode(null), null);
});

test('风险分级', () => {
  assert.deepStrictEqual([S.riskScore('ipapiis', '0.0003 (Very Low)').display, S.riskScore('ipapiis', '0.0003 (Very Low)').level], ['0.03%', 0]);
  assert.strictEqual(S.riskScore('ipapiis', '0.0812 (Elevated)').level, 2);
  assert.strictEqual(S.riskScore('proxycheck', 0).level, 1);
  assert.strictEqual(S.riskScore('proxycheck', 50).level, 3);
  assert.strictEqual(S.riskScore('proxycheck', 80).level, 4);
  assert.strictEqual(S.riskScore('ipqs', 74).level, 1);
  assert.strictEqual(S.riskScore('ipqs', 88).level, 3);
  assert.strictEqual(S.riskScore('scamalytics', '3', 'low').level, 1);
  assert.strictEqual(S.riskScore('scamalytics', '61', 'high').level, 3);
  assert.strictEqual(S.riskScore('ipdata', 95).level, 1);
  assert.strictEqual(S.riskScore('generic', 30).level, 2);
  assert.strictEqual(S.riskScore('generic', undefined), null);
});

test('地址与 IP 显示', () => {
  assert.strictEqual(S.placePanel({ cc: 'CN', country: '中国', region: '广东', city: '广州市' }), '广东 广州市');
  assert.strictEqual(S.placePanel({ cc: 'CN', country: '中国', region: '北京市', city: '北京' }), '北京市');
  assert.strictEqual(S.placePanel({ cc: 'HK', country: '香港', region: '香港', city: '香港' }), '香港');
  assert.strictEqual(S.placePanel({ cc: 'US', country: '美国', region: '得克萨斯州', city: 'Gardendale' }), '美国 得克萨斯州');
  assert.strictEqual(S.placePanel({ cc: 'JP' }), '日本');
  assert.strictEqual(S.placeFull({ cc: 'US', country: '美国', region: '内华达州', city: '拉斯维加斯' }), '🇺🇸 美国 内华达州 拉斯维加斯');
  assert.strictEqual(S.maskIP('203.0.113.10'), '203.0.*.*');
  assert.strictEqual(S.maskIP('2001:db8:1:2::1'), '2001:db8:*');
  assert.ok(S.isPrivate('192.168.1.1') && S.isPrivate('198.18.0.5') && S.isPrivate('fd00::1'));
  assert.ok(!S.isPrivate('203.0.113.10'));
});

test('运营商简称', () => {
  assert.strictEqual(S.ispShort({ isp: 'NetWest Online, Inc.' }), 'NetWest');
  assert.strictEqual(S.ispShort({ isp: 'Cox Communications Inc.' }), 'Cox');
  assert.strictEqual(S.ispShort({ isp: 'China Mobile communications corporation' }), 'China Mobile');
  assert.strictEqual(S.ispShort({ isp: 'Google LLC' }), 'Google');
  assert.strictEqual(S.ispShort({ isp: 'Example Cable' }), 'Example Cable');
  assert.strictEqual(S.ispShort({ asn: 'AS9808' }), '移动');
  assert.strictEqual(S.ispShort({ asn: 'AS4809' }), '电信 CN2');
  assert.strictEqual(S.ispShort({ asn: 'AS45090' }), '腾讯云');
  assert.strictEqual(S.ispShort({ ispCN: '联通' }), '联通');
});

test('数据源解析：IPinfo / IPLocate / proxycheck / IP2Location / ipquery', async () => {
  FIXTURES[`https://ipinfo.io/widget/demo/${IP}`] = JSON.stringify({
    input: IP,
    data: { ip: IP, city: 'Las Vegas', region: 'Nevada', country: 'US', org: 'AS64500 Example Cable', asn: { asn: 'AS64500', type: 'isp' }, company: { type: 'isp' }, privacy: { vpn: false, proxy: false, tor: false, relay: false, hosting: false }, is_mobile: false, is_hosting: false },
  });
  FIXTURES[`https://iplocate.io/api/lookup/${IP}`] = JSON.stringify({
    ip: IP, country_code: 'US', subdivision: 'Nevada', city: 'Las Vegas', asn: { asn: 'AS64500', name: 'Example Cable', type: 'isp', country_code: 'US' }, company: { type: 'isp' },
    privacy: { is_abuser: false, is_anonymous: false, is_hosting: false, is_icloud_relay: false, is_proxy: false, is_tor: false, is_vpn: true },
  });
  FIXTURES[`https://proxycheck.io/v3/${IP}`] = JSON.stringify({
    status: 'ok',
    [IP]: { network: { asn: 'AS64500', provider: 'Example Cable', type: 'Residential' }, location: { country_code: 'US', region_name: 'Nevada', city_name: 'Las Vegas' }, detections: { proxy: false, vpn: false, compromised: false, scraper: false, tor: false, hosting: false, risk: 12 } },
  });
  FIXTURES[`https://api.ip2location.io/?ip=${IP}`] = JSON.stringify({ ip: IP, country_code: 'US', region_name: 'Nevada', city_name: 'Las Vegas', asn: '64500', as: 'Example Cable', is_proxy: false });
  FIXTURES[`https://api.ipquery.io/${IP}`] = JSON.stringify({ ip: IP, isp: { asn: 'AS64500', org: 'Example Cable', isp: 'Example Cable' }, location: { country_code: 'US', state: 'Nevada', city: 'Las Vegas' }, risk: { is_mobile: false, is_vpn: false, is_tor: false, is_proxy: false, is_datacenter: false, risk_score: 0 } });

  const ipinfo = await run('ipinfo');
  assert.strictEqual(ipinfo.usage, 'isp');
  assert.strictEqual(ipinfo.company, 'isp');
  assert.strictEqual(ipinfo.f.server, false);

  const iplocate = await run('iplocate');
  assert.strictEqual(iplocate.reg, 'US');
  assert.strictEqual(iplocate.f.vpn, true);

  const pc = await run('proxycheck');
  assert.strictEqual(pc.usage, 'isp');
  assert.strictEqual(pc.score.display, '12');
  assert.strictEqual(pc.f.bot, false);

  const i2l = await run('ip2location');
  assert.strictEqual(i2l.f.proxy, false);
  assert.strictEqual(i2l.f.vpn, undefined);
  assert.strictEqual(i2l.score, null);

  const iq = await run('ipquery');
  assert.strictEqual(iq.usage, null);
  assert.strictEqual(iq.score.level, 1);
});

test('数据源解析：Scamalytics 页面', async () => {
  FIXTURES[`https://scamalytics.com/ip/${IP}`] = `<title>${IP} ( Example Cable ) Fraud Risk | Scamalytics</title>
<pre style="margin: 0">
"ip":"${IP}",
"score":"7",
"risk":"low",
"is_blacklisted_external": false,
</pre>
<tr>
<th>Anonymizing VPN</th>
<td><div class="risk no">No</div></td>
</tr>
<tr>
<th>Tor Exit Node</th>
<td><div class="risk no">No</div></td>
</tr>
<tr><th>Server</th><td><div class="risk yes">Yes</div></td></tr>
<tr><th>Public Proxy</th><td><div class="risk no">No</div></td></tr>
<tr><th>Web Proxy</th><td><div class="risk no">No</div></td></tr>
<tr><th>Search Engine Robot</th><td><div class="risk no">No</div></td></tr>
<tr><th>Residential Proxy</th><td><div class="risk no">No</div></td></tr>`;
  const r = await run('scamalytics');
  assert.strictEqual(r.org, 'Example Cable');
  assert.strictEqual(r.score.display, '7');
  assert.strictEqual(r.score.level, 1);
  assert.deepStrictEqual(r.f, { proxy: false, vpn: false, tor: false, server: true, abuse: false, bot: false });

  FIXTURES[`https://scamalytics.com/ip/${IP}`] = '<html><title>Just a moment...</title></html>';
  await assert.rejects(() => source('scamalytics').run(IP), /Cloudflare/);
});

test('汇总判定：原生 / 广播、家宽、风险等级与因子', () => {
  const recs = [
    { id: 'maxmind', name: 'Surge GeoIP', ok: true, cc: 'US' },
    { id: 'a', name: 'A', ok: true, cc: 'US', usage: 'isp', f: { proxy: false, server: false }, score: S.riskScore('generic', 5) },
    { id: 'b', name: 'B', ok: true, cc: 'US', usage: 'Residential', f: { proxy: false, vpn: true } },
    { id: 'c', name: 'C', ok: true, cc: 'CA', usage: 'hosting', f: { server: true }, score: S.riskScore('proxycheck', 50) },
    { id: 'd', name: 'D', ok: false, error: '超时' },
  ].map(r => (r.ok ? S.normalizeRec(r) : r));

  const q = S.summarize(IP, recs, { cc: 'US', src: 'RIPEstat' });
  assert.strictEqual(q.native, '原生IP');
  assert.strictEqual(q.use.cc, 'US');
  assert.strictEqual(q.usage.top, 'isp');
  assert.deepStrictEqual(q.usage.votes, { isp: 2, hosting: 1 });
  assert.strictEqual(q.risk.level, 3);
  assert.deepStrictEqual([q.factors.vpn.hit, q.factors.vpn.total], [1, 1]);
  assert.deepStrictEqual(q.factors.server.by, ['C']);

  assert.strictEqual(S.summarize(IP, recs, { cc: 'DE', src: 'RIPEstat' }).native, '广播IP');
  assert.strictEqual(S.summarize(IP, recs.filter(r => r.id !== 'maxmind'), null).native, '未知');
});

test('合并地理信息：国内用 B 站中文库，机房泛称不当运营商', () => {
  const a = { status: 'success', query: IP, countryCode: 'CN', country: '中国', regionName: '广东', city: '广州市', isp: 'Example Cloud', as: 'AS45090 Example' };
  const g = S.mergeGeo(IP, a, { country: '中国', province: '广东', city: '广州', isp: '电信/联通/移动' });
  assert.strictEqual(g.city, '广州');
  assert.strictEqual(g.ispCN, undefined);
  const h = S.mergeGeo(IP, null, { country: '中国', province: '广东', city: '茂名', isp: '移动' });
  assert.strictEqual(h.cc, 'CN');
  assert.strictEqual(h.ispCN, '移动');
});

test('面板文本与网页报告', () => {
  const geo = { ip: IP, cc: 'US', country: '美国', region: '内华达州', city: '拉斯维加斯', isp: 'Example Cable', asn: 'AS64500' };
  const recs = [{ id: 'maxmind', name: 'Surge GeoIP', ok: true, cc: 'US' }, { id: 'a', name: 'A', ok: true, cc: 'US', usage: 'isp', f: { proxy: false }, score: S.riskScore('scamalytics', 3, 'low') }].map(S.normalizeRec);
  const R = {
    ts: Date.now(), ms: 1234, env: { system: 'iOS', version: '5.23.0', build: '1', model: 'iPhone' },
    net: { type: '蜂窝', carrier: '中国移动', radio: '5G', lan: '10.0.0.2' }, policyArg: '', apiOK: true,
    local: { ip: '203.0.113.1', cc: 'CN', country: '中国', region: '广东', city: '茂名', asn: 'AS9808' },
    entries: [{ ip: '203.0.113.2', cc: 'CN', country: '中国', region: '广东', city: '广州', asn: 'AS45090', nodes: ['US-01'], count: 3 }, { ip: '198.51.100.3', cc: 'HK', country: '香港', asn: 'AS4760', nodes: ['US-02'], count: 1 }],
    candidates: [{ ip: '198.51.100.4', cc: 'HK', country: '香港' }],
    landing: geo, landingAlt: [], v6: null, probes: [{ id: 'ip-api', ip: IP, ms: 100 }],
    exec: { rule: 'FINAL', path: ['Proxy', 'US-01'], node: 'US-01', nodes: ['US-01', 'US-02'], direct: false },
    quality: S.summarize(IP, recs, { cc: 'US', src: 'RIPEstat' }),
  };
  const L = S.lines(R);
  const SP = '　';
  assert.deepStrictEqual(L.slice(0, 7), [
    `本地${SP}203.0.113.1${SP}广东 茂名 · 移动`,
    `入口${SP}203.0.113.2${SP}广东 广州 · 腾讯云`,
    `${SP}${SP}${SP}198.51.100.3${SP}香港 · 香港电讯 HKT`,
    `${SP}${SP}${SP}DNS 另有 1 个备选地址`,
    `落地${SP}203.0.113.10${SP}美国 内华达州 · Example Cable`,
    `策略${SP}Proxy ➜ US-01（共 2 个节点）`,
    `评分${SP}A 3`,
  ]);
  assert.ok(L[7].startsWith(`因子${SP}1 库均未命中 · `) && L[7].endsWith(' · 1.2s'), L[7]);
  assert.strictEqual(L.length, 8);
  assert.strictEqual(S.titleText(R), '🇺🇸 原生IP · 家宽 · 低风险');

  const html = S.renderHTML(R);
  assert.ok(html.includes('<title>IP 检测报告</title>'));
  assert.ok(html.includes('备选入口1'));
  assert.ok(!/undefined|NaN/.test(html), 'HTML 里不应出现 undefined/NaN');

  assert.ok(html.includes('FINAL ➜ Proxy ➜ US-01'), '报告里的执行路径带规则');

  S.OPT.mask = true;
  assert.ok(!S.renderHTML(R).includes(IP));
  S.OPT.mask = false;

  // 隐藏本地：面板和报告都不出现本地 IP 与位置
  const H = Object.assign({}, R, { local: { hidden: true }, net: { hidden: true } });
  assert.ok(!S.lines(H).some(l => l.startsWith('本地')));
  const hh = S.renderHTML(H);
  assert.ok(!hh.includes('203.0.113.1<') && !hh.includes('<th>本地</th>') && !hh.includes('<th>内网</th>'));
});
