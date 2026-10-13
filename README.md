# SSRF 30x Redirector v2.9 — DNSlog 带外信道 · 盲SSRF靶场 · DNS Rebinding · 30x 重定向跳板

**语言 / Languages:** **简体中文** | [English](README_EN.md) | [日本語](README_JA.md) | [한국어](README_KO.md) | [Русский](README_RU.md)

> **SSRF** · **盲 SSRF (Blind SSRF)** · **30x 重定向跳板 (Redirector)** · **DNS Rebinding** · **DNSlog / OOB 带外信道** · **云元数据 (AWS IMDS / GCP / Azure / 阿里云 / 腾讯云)** · **TOCTOU** · **内网探测**
>
> 单文件 Flask 自托管 SSRF 测试平台。开箱即用，无需数据库、无需编译、无需外部依赖服务。

---

## 核心能力

| 模块 | 路由 | 作用 |
| --- | --- | --- |
| **30x 重定向引擎** | `/r` | 单跳重定向跳板，自定义状态码与目标，用于 SSRF 协议与状态码绕过 |
| **无状态重定向链** | `/c` | 无状态多跳跳转，逐跳可控，适合构造长链路 |
| **有状态重定向链** | `/<path>` | catch-all 兜底，带队列与目标栈，可动态改写落点 |
| **盲 SSRF 靶场** | `/bb/*` | 内置 6 类云元数据端点 + 状态码矩阵 + 延时/超时端点，验证盲打是否命中 |
| **重定向回环实验台** | `/loop/*` | 回环链路实验，单次最高 40 跳，验证客户端重定向跟随上限 |
| **DNS Rebinding** | 控制台 | `1.2.3.4` → `127.0.0.1` 二次解析切换，命中 TOCTOU 时序窗口 |
| **DNSlog 带外信道** | UDP 53531 | 自建 DNS 服务器，记录所有查询，不依赖第三方平台 |

**支持的 HTTP 方法：** `GET` `POST` `PUT` `DELETE` `PATCH` `TRACE` `OPTIONS` `HEAD` `CONNECT`（9 种全谱系）

---

## 为什么选它

- **单文件交付** —— 413 KB 一个 `.py`，`python3` 直接跑，无 pip 依赖地狱
- **回落矩阵** —— `30x` / `refresh` / `meta` / `js` / `combo` 五种回落模式，绕过只认某种跳转的客户端
- **HEAD 绕过伪装** —— 可伪造 `200 OK`、`text/html`、假 `Content-Length: 8192`、`Server: nginx/1.18.0`、`X-Powered-By: PHP/7.4.3`
- **占位符动态注入** —— `{{TIME}}` `{{UUID}}` `{{IP}}` `{{UA}}` `{{METHOD}}` `{{PATH}}` `{{HOST}}` `{{SELF}}` `{{REQ_JSON}}` `{{PAD:n}}`
- **Payload 构造器** —— 十进制 IP、十六进制 IP、IPv6 环回 `[::1]`、`localtest.me`、URL userinfo 混淆
- **随机控制台路径** —— 每次启动生成 16 位 hex 前缀，根路径让渡给攻击链，避免控制台被抓

---

## 快速开始

```bash
# 1. 启动
python3 SSRF_30x_Redirector_v2.9_DNSlog.py

# 2. 查看控制台地址 (每次启动都会变化)
#    [*] Console: http://0.0.0.0:5000/a1b2c3d4e5f6a7b8

# 3. 打开控制台，进入 Dashboard
```

**默认配置：** 端口 `5000` · 监听 `0.0.0.0` · 日志上限 `1000` 条 · 默认状态码 `302` · 未启用 HTTPS

---

## 常用命令

**单跳重定向**

```bash
curl -i "http://<your-ip>:5000/r?url=http://127.0.0.1:8080/admin&code=302"
```

**无状态多跳链**

```bash
curl -i "http://<your-ip>:5000/c?url=http://127.0.0.1:8080/step1&limit=5&code=307"
```

**盲 SSRF 靶场**

```bash
curl -i "http://<your-ip>:5000/bb/aws/imds"                  # IMDSv1，直接返回凭证
curl -i "http://<your-ip>:5000/bb/aws/token"                 # IMDSv2，无 token 返回 401
curl -i "http://<your-ip>:5000/bb/gcp/meta"                  # 需 Metadata-Flavor: Google
curl -i "http://<your-ip>:5000/bb/azure/imds"                # 需 Metadata: true
curl -i "http://<your-ip>:5000/bb/aliyun"                    # 阿里云元数据
curl -i "http://<your-ip>:5000/bb/tencent"                   # 腾讯云元数据
curl -i "http://<your-ip>:5000/bb/403"                       # 状态码矩阵
curl -i "http://<your-ip>:5000/bb/delay3s"                   # 3 秒延迟
curl -i "http://<your-ip>:5000/bb/timeout"                   # 悬挂超时
```

**重定向回环实验台**

```bash
curl -i "http://<your-ip>:5000/loop/start?limit=12&mode=http&code=302"
curl -i "http://<your-ip>:5000/loop/ok"                      # 基线对照
# limit 上限 40 · mode 可选 http / meta / js
```

**DNSlog 带外信道**

```bash
# 控制台 → DNSlog 模块 → 新建 Token → 取得专属子域名
# 收到查询后即可在界面查看：Token / 子域名 / 查询名 / 客户端 IP / 端口 / 北京时间
nslookup <token>.your-domain.com <your-ip>
```

**DNS Rebinding**

```bash
# 控制台 → DNS Rebinding → 新建会话
# 首次解析返回 1.2.3.4，达到触发条件后切换为 127.0.0.1
# 触发方式：按查询次数 或 按时间窗口（TOCTOU）
```

---

## 适用场景

- **SSRF 漏洞验证** —— 用受控跳板确认目标是否存在外连能力
- **盲 SSRF 判定** —— 目标无回显时，靠 DNSlog 与延时差判定命中
- **云元数据获取** —— 演练 `169.254.169.254` 系列端点与 IMDSv2 令牌流程
- **黑名单绕过验证** —— 十进制/十六进制 IP、IPv6、userinfo 混淆逐个试探
- **DNS Rebinding 利用** —— 绕过基于"首次解析"的 IP 白名单
- **客户端重定向上限测试** —— 用 `/loop` 测出对方爬虫/代理最多跟随几跳
- **内网端口与协议探测** —— 借助 30x 跳板与延时观察内部服务存活

---

## 部署建议

```bash
# 生产/演练环境建议用反向代理 + HTTPS
# 或修改文件顶部 CONFIG 区
CONFIG = {
    'port': 5000,
    'host': '0.0.0.0',
    'max_logs': 1000,
    'default_status_code': 302,
    'use_https': False,
}
```

- DNSlog 依赖 `UDP 53531` 可被外部访问，请在安全组放行
- DNS Rebinding 需要自行把域名 NS 指向本机
- 公网暴露时务必设置访问控制，或仅在内网/VPN 中使用

---

## 安全与合规

> **本项目仅供授权安全测试使用。**
>
> - 仅可对你**拥有或已获得书面授权**的系统使用
> - 禁止用于未授权访问、数据窃取或任何违法用途
> - 使用者需自行承担全部法律责任，作者不承担任何连带责任
> - 使用前请确认符合当地法律法规与目标系统所在司法辖区要求

MIT License

---

## 关键词 / Keywords

SSRF, 盲SSRF, Blind SSRF, SSRF 绕过, SSRF Bypass, SSRF Payload, 重定向跳板, Redirector, HTTP 重定向, Open Redirect, 开放重定向, DNS Rebinding, DNS 重绑定, DNSlog, 带外信道, OOB, Out-of-Band, TOCTOU, 云元数据, Cloud Metadata, 元数据服务, Metadata Service, AWS IMDS, IMDSv2, GCP Metadata, Azure IMDS, 阿里云元数据, 腾讯云元数据, 内网探测, 内网渗透, 穿透测试, 渗透测试, Pentest, Penetration Testing, Red Team, 红队, 漏洞验证, 漏洞扫描, Web 安全, 安全工具, Flask, Python, 自托管, Self-hosted, 单文件
