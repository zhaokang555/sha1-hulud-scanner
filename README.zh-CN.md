# SHA1-HULUD Scanner

一个全面的 bash 扫描工具，用于检测 SHA1-HULUD pt 2 供应链攻击中受感染的 npm 包。

**在 [原版](https://github.com/standujar/sha1-hulud-scanner) 的基础上，我添加了递归扫描功能（v2.2，https://github.com/zhaokang555/sha1-hulud-scanner ），使其能够一次性扫描整个目录树中的所有 Node.js 项目，极大地提升了扫描效率和覆盖范围。**

[English](README.md) | 简体中文

## 🚨 关于 SHA1-HULUD pt 2

SHA1-HULUD pt 2 是一次针对 288+ 个 npm 包的供应链攻击，包括：
- PostHog 包 (`@posthog/*`, `posthog-node` 等)
- Zapier 包 (`@zapier/*`)
- AsyncAPI 包 (`@asyncapi/*`)
- Postman 包 (`@postman/*`)
- ENS Domains 包 (`@ensdomains/*`, `ethereum-ens`)
- MCP 包 (`mcp-use`, `@mcp-use/*`)
- 以及更多...

**更多信息：** [HelixGuard 博客文章](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

## ✨ 功能特性

- ✅ 扫描 SHA1-HULUD pt 2 攻击中的 **288+ 个受感染包**
- ✅ **递归扫描** - 支持 monorepo 和多项目目录
- ✅ 多包管理器支持：**npm**、**yarn**、**bun**、**pnpm**
- ✅ 4 阶段扫描：
  - 直接依赖 (`package.json`)
  - 传递依赖 (`node_modules`)
  - 锁文件（所有包管理器）
  - SHA1 标记检测
- ✅ **误报过滤** - 自动识别合法包如 `@aws-crypto/sha1-browser`
- ✅ 检测到 SHA1 标记时显示 **具体包名**
- ✅ **容错设计** - 即使个别项目失败也会继续扫描
- ✅ **综合摘要** - 包含统计信息和失败项目跟踪
- ✅ 清晰的彩色编码输出，提供可操作的修复步骤

## 📦 安装

```bash
git clone https://github.com/standujar/sha1-hulud-scanner.git
cd sha1-hulud-scanner
chmod +x sha1-hulud-scanner.sh
```

## 🚀 使用方法

### 单项目模式

```bash
./sha1-hulud-scanner.sh <project_directory>
```

### 递归模式（多项目扫描）

```bash
./sha1-hulud-scanner.sh -r <parent_directory>
```

### 选项

- `-r, --recursive` - 启用递归扫描（扫描最多 3 层深度的所有 Node.js 项目）
- `-h, --help` - 显示帮助信息
- `-v, --version` - 显示版本信息

### 示例

```bash
# 扫描单个项目
./sha1-hulud-scanner.sh /path/to/your/project

# 递归扫描 monorepo
./sha1-hulud-scanner.sh -r /path/to/monorepo

# 扫描目录中的所有项目
./sha1-hulud-scanner.sh -r ~/Projects

# 扫描当前目录
./sha1-hulud-scanner.sh .

# 递归扫描当前目录
./sha1-hulud-scanner.sh -r .
```

## 📊 输出示例

### 单项目模式

```
🔍 SHA1-HULUD Scanner v2.2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Project: /path/to/project
📋 288 packages to scan
📋 5 known false positives to exclude

🔎 [1/4] Scanning direct dependencies (package.json)...
  ✓ No compromised packages in direct dependencies

🔎 [2/4] Scanning node_modules (transitive)...
  ✓ No compromised packages installed

🔎 [3/4] Scanning lockfiles...
  ✓ No compromised packages in lockfiles

🔎 [4/4] Scanning for SHA1-HULUD markers...
  📄 Checking packages with 'sha1' in name (bun.lock):
    ℹ️  @aws-crypto/sha1-browser (legitimate package - skipped)
  ✓ No suspicious SHA1 markers (1 legitimate packages excluded)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ NO COMPROMISE DETECTED

Your project is clean — no SHA1-HULUD packages found.

📊 Statistics:
   • 288 packages scanned
   • 0 compromised packages
```

### 递归模式

```
🔍 SHA1-HULUD Scanner v2.2 (Recursive Mode)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Target directory: /Users/username
📋 288 packages to scan
📋 5 known false positives to exclude

🔎 Finding Node.js projects...
✓ Found 3 project(s)

📋 Projects to scan:
  • /Users/username/project1
  • /Users/username/work/api-service
  • /Users/username/personal/my-app

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 Project 1/3: /Users/username/project1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔎 [1/4] Scanning direct dependencies (package.json)...
  ✓ No compromised packages in direct dependencies
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total projects scanned: 3
✅ Clean projects: 3
```

## 🛡️ 检查内容

### 阶段 1：直接依赖
扫描 `package.json` 中 `dependencies` 和 `devDependencies` 里的受感染包。

### 阶段 2：Node Modules
检查受感染的包是否实际安装在 `node_modules/` 中（包括传递依赖）。

### 阶段 3：锁文件
扫描所有包管理器的锁文件：
- `package-lock.json` (npm)
- `yarn.lock` (yarn)
- `bun.lock` (bun - 二进制格式)
- `pnpm-lock.yaml` (pnpm)

### 阶段 4：SHA1 标记
检测名称中包含 "sha1" 的包，这是攻击的特征。过滤掉已知的误报，如 AWS 加密包。

## ⚠️ 如果发现受感染的包

扫描器将显示详细的修复步骤：

1. 🛑 **立即停止** 所有构建/CI
2. 🔒 **隔离** CI runner（如果是自托管）
3. 🔑 **轮换所有** 敏感密钥：
   - GitHub tokens (PAT, fine-grained, App)
   - AWS 凭证（如果不是 OIDC）
   - NPM tokens
   - API keys (PostHog, Stripe 等)
4. 🗑 **删除** `node_modules` 和锁文件
5. 📝 **更新** 依赖到干净版本
6. 🔍 **审计** 过去 48 小时的 CI 日志

## 📋 要求

- Bash 4.0+
- `grep`、`strings`、`sed`（标准 Unix 工具）
- 项目中存在包管理器锁文件

## 🔧 已知误报

扫描器会自动排除这些合法包：
- `@aws-crypto/sha1-browser` - AWS SDK 用于 S3 校验和
- `@aws-crypto/sha256-browser` - AWS 加密工具
- `@aws-crypto/sha256-js` - AWS 加密工具
- `sha1` - 合法的加密库
- `sha.js` - 合法的加密库

## 📝 包列表

扫描器检查 `sha1-hulud-packages.txt` 中定义的 288 个受感染包。

更新列表：
```bash
# 编辑 sha1-hulud-packages.txt
# 每行一个包名，支持 # 注释
```

## 🤝 贡献

欢迎贡献！请：
1. Fork 此仓库
2. 创建功能分支
3. 提交 pull request

## 📜 许可证

MIT License - 欢迎使用此扫描器保护您的项目。

## 🔗 资源

- [HelixGuard SHA1-HULUD 分析](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)
- [npm Advisory Database](https://npmjs.com/advisories)

## ⚡ 快速开始

```bash
# 克隆并运行
git clone https://github.com/standujar/sha1-hulud-scanner.git
cd sha1-hulud-scanner
chmod +x sha1-hulud-scanner.sh
./sha1-hulud-scanner.sh /path/to/your/project
```

---

**保持安全！定期扫描您的项目。** 🛡️
