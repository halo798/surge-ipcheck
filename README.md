# Surge IP 检测

适用于 Surge iOS 和 Surge Mac 的检测模块。检测一次，就能看到本地出口、代理入口、落地出口三段各自的 IP、位置和运营商，以及落地 IP 是否原生、是否家宽、风险高低。

## 功能

| 项目 | 内容 |
|---|---|
| 本地 | 直连出口 IP、所在省市、运营商；内网 IP 和网关；iOS 走蜂窝网络时显示 SIM 卡运营商和 4G/5G。可用 `LOCAL=0` 整个隐藏 |
| 入口 | 代理服务器的实际连接地址、位置、运营商。负载均衡或检测中途切换节点时，列出全部入口；节点域名解析出多个地址时，列出 DNS 缓存里的备选入口 |
| 落地 | 代理出口 IP、位置、运营商、Cloudflare 节点；多个探测点看到的出口不同时全部列出；可选检测 IPv6 |
| 执行 | 本次检测实际走的规则和策略路径，例如 `FINAL ➜ Proxy ➜ 🇺🇸 US-01`，以及 Surge 版本 |
| 原生 IP | 注册地（RIPEstat 的 RIR 分配记录）与使用地（Surge GeoIP，缺失时按多库多数）相同就是原生 IP，不同就是广播 IP |
| 使用类型 | 多个数据库投票：家宽、手机、机房、商业、教育等 |
| 风险评分 | Scamalytics、proxycheck、ipquery；填 Key 后再加 IPQS、AbuseIPDB、ipapi.is、ipdata。综合等级取各库中最高的一项 |
| 风险因子 | 代理、VPN、Tor、机房、滥用、机器人，逐库列出 |

面板示例（IP 已打码）：

```
🇯🇵 原生IP · 家宽 · 低风险
本地　112.96.*.*　广东 广州 · 联通
入口　119.28.*.*　香港 · 腾讯云
　　　DNS 另有 1 个备选地址
落地　126.36.*.*　日本 东京都 · 软银 SoftBank
策略　Proxy ➜ 🇯🇵 JP-01
评分　proxycheck 0 · ipquery 0 · Scamalytics 2
因子　7 库均未命中 · 21:30 · 2.4s
```

面板只放精简信息：每段一行，国内位置到省市，国外到国家和省/州，运营商用简称。完整的库名、规则、注册地和各库明细看网页报告。

## 安装

Surge iOS：首页 → 模块 → 安装新模块，填入：

```
https://raw.githubusercontent.com/halo798/surge-ipcheck/main/IPCheck-iOS.sgmodule
```

Surge Mac：模块 → 安装新模块，填入：

```
https://raw.githubusercontent.com/halo798/surge-ipcheck/main/IPCheck-Mac.sgmodule
```

两个模块调用同一个脚本，区别只在适用平台和面板刷新间隔。模块参数从 Surge Mac 5.5.0 起支持，建议用最新版；作者在 Surge Mac 6.11.0 上实测过。

## 使用

1. **面板**：iOS 在「策略」页顶部，Mac 在菜单栏 Surge 图标的「面板」子菜单里。点刷新按钮重新检测。
2. **完整报告**：在浏览器打开 `http://ipcheck.surge`，注意是 `http`。报告按数据库分列，内容和 IPQuality 体检报告类似。
   - `http://ipcheck.surge/?nocache=1`：忽略缓存，重新查询质量库
   - `http://ipcheck.surge/?mask=1`：隐藏 IP 后两段
   - `http://ipcheck.surge/?local=0`：隐藏本地 IP 和位置（报告页上也有「隐藏本地」按钮）
   - `http://ipcheck.surge/json`：输出原始 JSON
3. **通知**：模块参数 `NOTIFY` 设为 `1` 后，网络切换时自动检测并发通知；IP 没变就不重复通知。点通知会打开完整报告。在 Surge 的脚本列表里手动运行 `IPCheck`，也会发一条通知。

## 模块参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `POLICY` | `auto` | 落地检测走的策略或策略组名称。`auto` 表示按规则分流，和日常上网一致 |
| `TIMEOUT` | `6` | 单个请求的超时秒数 |
| `CACHE` | `1800` | 落地 IP 质量结果的缓存秒数；落地 IP 一变就重新查询。设为 `0` 不缓存 |
| `LOCAL` | `1` | 设为 `0` 时隐藏本地 IP 和位置：面板、通知、网页报告都不显示，也不再去查询，内网 IP、Wi-Fi 名称一并隐藏 |
| `MASK` | `0` | 设为 `1` 时隐藏 IP 后两段，方便截图 |
| `IPV6` | `0` | 设为 `1` 时同时检测 IPv6 落地 |
| `NOTIFY` | `0` | 设为 `1` 时网络切换后发通知 |
| `IPQS_KEY` | `none` | [IPQualityScore](https://www.ipqualityscore.com/) 的 Key |
| `ABUSEIPDB_KEY` | `none` | [AbuseIPDB](https://www.abuseipdb.com/) 的 Key |
| `IPAPI_KEY` | `none` | [ipapi.is](https://ipapi.is/) 的 Key（不带 Key 时它不返回检测项，所以没 Key 就不查） |
| `IPREGISTRY_KEY` | `none` | [ipregistry](https://ipregistry.co/) 的 Key |
| `IPDATA_KEY` | `none` | [ipdata](https://ipdata.co/) 的 Key |
| `IP2LOCATION_KEY` | `none` | [IP2Location.io](https://www.ip2location.io/) 的 Key，用于提高额度；付费套餐另有使用类型和欺诈分 |
| `PROXYCHECK_KEY` | `none` | [proxycheck.io](https://proxycheck.io/) 的 Key，用于提高额度 |

Key 参数保持 `none` 就是不填。各家都有免费套餐，注册后就能拿到 Key。Key 只保存在你本机的 Surge 配置里。

> Surge 不接受冒号后为空的参数默认值（会报「模块头部的参数声明格式错误」），所以这里用 `auto` 和 `none` 占位，脚本会把它们当作未填写。

## 数据来源

| 数据库 | 需要 Key | 提供的数据 | 说明 |
|---|---|---|---|
| ip-api | 否 | 位置、运营商，代理、机房、移动网络标记 | 免费版仅限非商业使用，每分钟 45 次 |
| IPinfo | 否 | 使用类型、公司类型，代理、VPN、Tor、机房标记 | 用的是官网演示接口；被限流时退回基础接口，只有位置 |
| IPLocate | 否 | 使用类型、公司类型，代理、VPN、Tor、机房、滥用标记 | 不带 Key 时额度较低 |
| proxycheck | 可选 | 类型（家宽、商业、机房、无线），风险分 0–100，各项标记 | |
| IP2Location | 可选 | 位置、代理标记 | 不带 Key 时每天 1000 次 |
| ipquery | 否 | 代理、VPN、Tor、机房标记，风险分 | |
| Scamalytics | 否 | 欺诈分、风险等级，VPN、Tor、服务器、代理、爬虫标记 | 解析公开网页，网页改版后会失效 |
| DB-IP | 否 | 位置 | 免费接口，机场共享出口可能被封 |
| RIPEstat | 否 | 注册地（RIR 分配的国家） | 用于判定原生 IP |
| Surge GeoIP | 本地 | 使用地、ASN | Surge 自带的离线库，不发请求 |
| bilibili | 否 | 本地与入口的中文位置、运营商 | 走直连 |
| IPQS | 是 | 欺诈分、连接类型，各项标记 | 按官方文档实现，未用真实 Key 实测 |
| AbuseIPDB | 是 | 滥用置信度、使用类型、举报次数 | 同上 |
| ipapi.is | 是 | 滥用分、使用类型、公司类型，各项标记 | 同上 |
| ipregistry | 是 | 连接类型、公司类型，各项安全标记 | 同上 |
| ipdata | 是 | 信任分、ASN 类型，各项威胁标记 | 同上 |

每次报告的「数据源状态」一栏会列出各库是否成功、用时多少、失败原因。

## 判定方法

- **入口**：脚本发出检测请求后，读取 Surge 的最近请求记录，带 `(Proxy)` 标记的远端地址就是代理服务器的连接地址。链式代理（`underlying-proxy`）只能看到第一跳。
- **执行**：优先取请求备注里的「Policy decision path」。Surge 缓存了某个域名的规则结果时，备注里没有这一项，就按匹配到的规则和各策略组的当前选择推算。
- **原生 IP**：注册地等于使用地就是原生，否则是广播。广播 IP 通常是把别国注册的地址段拿来在本地广播。
- **家宽**：取各库使用类型的多数票。注意这里的家宽对应数据库里的 ISP 类型，个别库会把运营商的商业专线也算作 ISP。
- **风险等级**：各库按自己的阈值分级，比如 proxycheck 34 分起算高风险，IPQS 75 分起算可疑。综合等级取最高的一项，宁可从严。

各库的结论来自它们自己的数据，经常互相矛盾，只能作参考。

## 隐私

- 本地检测、入口和备选入口的位置查询走直连（bilibili、ip-api），其余请求走代理，或者走 `POLICY` 指定的策略。
- 请求只发往上表列出的数据库，不经过任何第三方中转服务器。
- 不想显示本地 IP 和位置时把 `LOCAL` 设为 `0`，脚本就不再查询本地出口。
- 截图前可以把 `MASK` 设为 `1`，或者在报告页点「隐藏 IP」。

## 开发与测试

```bash
node --test test/test.js
```

用 Surge Mac 自带的离线语言服务器检查两个模块文件，包括头部的参数声明（不需要 Surge 在运行）：

```bash
node test/check-modules.js
```

在 Surge Mac 上直接运行脚本（需要 Surge 正在运行）：

```bash
/Applications/Surge.app/Contents/Applications/surge-cli script evaluate "$PWD/ipcheck.js" generic 60
```

## 许可

[MIT](LICENSE)
