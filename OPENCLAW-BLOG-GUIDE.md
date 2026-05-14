# SecShrimp Blog - OpenClaw 持续优化指南

本文件指导 openclaw agent 如何持续优化博客的内容、排版、布局和特效。

## 博客技术栈

- **框架:** Hugo + PaperMod 主题
- **部署:** GitHub Pages (darkwebhunter99.github.io/secshrimp-blog/)
- **配置:** `blog/hugo.toml`
- **自定义样式:** `blog/assets/css/extended/scifi.css`
- **自定义脚本:** `blog/layouts/partials/extend_footer.html`
- **自定义头部:** `blog/layouts/partials/extend_head.html`
- **文章目录:** `blog/content/posts/`

## 优化维度

### 1. 文字对比度和可读性

检查项：
- `--text-primary` 和 `--text-secondary` 在深色背景上的对比度是否足够（WCAG AA 标准: 4.5:1）
- 正文字号是否 >= 16px
- 行高是否 >= 1.7
- 段落间距是否舒适

改进方向：
- 使用在线工具验证对比度：https://webaim.org/resources/contrastchecker/
- 调整 CSS 变量值

### 2. 排版布局

检查项：
- 卡片间距是否一致（建议 20px）
- 内容区宽度是否合理（建议 max-width 720px-800px）
- 移动端响应式是否正常
- 标题层级是否清晰

改进方向：
- 调整 `scifi.css` 中的 padding、margin
- 添加断点响应式样式

### 3. 视觉特效

检查项：
- 粒子背景是否影响阅读（opacity 不超过 0.5）
- 动画是否流畅（避免卡顿）
- hover 效果是否自然

改进方向：
- 调整 `extend_footer.html` 中的粒子参数
- 添加/修改 CSS 动画

### 4. 内容优化

检查项：
- 文章结构是否清晰（标题、段落、代码块）
- 代码块样式是否美观
- 标签和分类是否合理

## 优化工作流

1. **分析阶段**
   - 读取当前 `scifi.css` 和 `extend_footer.html`
   - 检查博客文章目录结构
   - 识别需要改进的点

2. **实施阶段**
   - 修改 CSS 变量和样式
   - 更新 JS 特效参数
   - 确保不破坏现有功能

3. **验证阶段**
   - 本地运行 `hugo server` 测试
   - 检查不同设备的显示效果
   - 确认动画性能

## 注意事项

- 保持科幻风格一致性
- 不要移除粒子背景和扫描线动画（品牌特色）
- 优先保证可读性，其次才是视觉效果
- 每次改动记录到 `memory/YYYY-MM-DD.md`

## 本地预览

```bash
cd blog
hugo server -D
```

访问 http://localhost:1313/secshrimp-blog/ 预览。
