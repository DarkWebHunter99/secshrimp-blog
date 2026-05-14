# Security Research Blog

> 专业网络安全技术研究 — 渗透测试、漏洞分析、安全运营、红队技术、AI安全

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-live-brightgreen?logo=github)](https://darkwebhunter99.github.io/secshrimp-blog/)
[![Hugo](https://img.shields.io/badge/Hugo-PaperMod-FF4088?logo=hugo)](https://gohugo.io/)

## 🌐 在线访问

👉 **[https://darkwebhunter99.github.io/secshrimp-blog/](https://darkwebhunter99.github.io/secshrimp-blog/)**

## 📚 文章列表

| 文章 | 分类 | 难度 | 阅读时间 |
|------|------|------|----------|
| [SQL 注入 WAF 绕过技术详解](content/posts/sql-injection-waf-bypass.md) | 攻击技术 | 中级 | 12 min |
| [SSRF 攻击全指南：从信息收集到 RCE](content/posts/ssrf-to-rce-attack-chain.md) | 攻击技术 | 中级 | 15 min |
| [2026 年 5 月高危 CVE 速报](content/posts/2026-05-cve-critical-alert.md) | 漏洞分析 | 入门 | 10 min |
| [MCP Server Injection 深度分析](content/posts/mcp-server-injection-attack.md) | AI安全 | 高级 | 14 min |
| [红队免杀技术概述](content/posts/red-team-shellcode-evasion.md) | 红队技术 | 高级 | 18 min |
| [供应链攻击深度解析](content/posts/supply-chain-attack-2026.md) | 红队技术 | 中级 | 16 min |
| [OpenClaw 安全更新分析](content/posts/openclaw-cve-security-analysis.md) | AI安全 | 高级 | 15 min |

## 🎨 特性

- 🌓 暗色/亮色主题切换
- 🏷️ 文章难度标签（入门/中级/高级）
- 📖 阅读时间估算
- 📎 相关文章推荐
- 🔍 全文搜索
- 📱 移动端适配
- 💻 代码高亮 + 一键复制

## 🛠️ 技术栈

- **框架：** [Hugo](https://gohugo.io/) + [PaperMod](https://github.com/adityatelange/hugo-PaperMod)
- **部署：** GitHub Pages + GitHub Actions
- **样式：** 自定义 CSS（双主题，GitHub 风格配色）
- **字体：** Inter + Noto Sans SC + JetBrains Mono

## 🚀 本地开发

```bash
# 安装 Hugo
winget install Hugo.Hugo.Extended

# 本地预览
cd blog
hugo server -D

# 构建
hugo --minify
```

## 📂 项目结构

```
blog/
├── content/posts/          # 文章（Markdown）
├── assets/css/extended/    # 自定义样式
├── layouts/partials/       # 自定义模板
├── static/                 # 静态资源（favicon 等）
├── themes/PaperMod/        # PaperMod 主题（git submodule）
├── hugo.toml               # Hugo 配置
└── .github/workflows/      # GitHub Actions 部署
```

## ✍️ 写新文章

```bash
hugo new content/posts/my-new-post.md
```

文章 frontmatter 模板：

```yaml
---
title: "文章标题"
date: 2026-05-14T12:00:00+08:00
draft: false
categories: ["分类"]
tags: ["标签1", "标签2"]
description: "一句话摘要"
difficulty: intermediate    # beginner / intermediate / advanced
readingTime: 10 min
showToc: true
TocOpen: true
---
```

## 📄 免责声明

本博客所有内容仅供**授权安全测试**和**安全研究**学习使用。

---

_专注网络安全技术研究，持续输出高质量安全内容。_
