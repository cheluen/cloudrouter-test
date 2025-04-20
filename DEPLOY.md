# CloudRouter 部署指南

本文档提供了详细的CloudRouter部署步骤，帮助您快速将CloudRouter部署到Cloudflare Workers或Pages。

## 在Cloudflare Workers上部署

### 方法一：一键部署（最简单）

1. 点击下面的按钮开始部署
   
   [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cheluen/cloudrouter)

2. 登录您的Cloudflare账户

3. 配置部署参数：
   - **项目名称**：为您的Worker选择一个名称（例如`cloudrouter`）
   - **KV命名空间**：创建一个名为`ROUTER_KV`的KV命名空间
   - **环境变量**：无需额外设置环境变量。

4. 点击"部署"按钮

5. 部署完成后，访问您的Worker URL（例如`https://cloudrouter.your-username.workers.dev`）。首次访问时，系统会提示您设置管理员密码。

### 方法二：使用Wrangler CLI

1. 确保已安装[Node.js](https://nodejs.org/)（14或更高版本）

2. 安装Wrangler CLI
   ```bash
   npm install -g wrangler
   ```

3. 登录到您的Cloudflare账户
   ```bash
   wrangler login
   ```

4. 克隆CloudRouter仓库
   ```bash
   git clone https://github.com/cheluen/cloudrouter.git
   cd cloudrouter
   ```

5. 安装依赖
   ```bash
   npm install
   ```

6. 创建KV命名空间
   ```bash
   wrangler kv:namespace create "ROUTER_KV"
   ```

7. 编辑`wrangler.toml`文件，确保KV命名空间ID正确：
   ```toml
   [[kv_namespaces]]
   binding = "ROUTER_KV"
   id = "您的KV命名空间ID" # 替换为上一步创建的KV命名空间ID
   # [vars] 部分不再需要 AUTH_KEY
   ```

8. 部署到Cloudflare Workers
   ```bash
   npm run deploy
   ```

## 在Cloudflare Pages上部署 (不推荐)

虽然可以将此 Worker 部署为 Pages Function，但直接部署为 Worker 通常更简单直接。如果您仍希望部署到 Pages：

1. 创建一个新的Pages项目，连接到您的GitHub仓库。
2. **构建设置**:
   - 框架预设: None
   - 构建命令: (留空或 `echo "No build needed"`)
   - 构建输出目录: (留空或 `/`)
3. **环境变量**: 无需设置 `AUTH_KEY`。
4. **Functions**: 确保启用了 Pages Functions。将 `src/index.js` 作为 Function 文件。
5. **KV 绑定**: 创建 `ROUTER_KV` 命名空间并将其绑定到 Pages 项目，变量名为 `ROUTER_KV`。
6. 部署项目。首次访问需要设置管理员密码。

## 首次使用设置

1. 访问您部署的 Worker URL（例如 `https://cloudrouter.your-username.workers.dev`）。
2. **设置管理员密码**：首次访问时，系统会引导您设置一个安全的管理员密码。请务必记住此密码，它用于访问管理面板。
3. **登录管理面板**：使用您刚刚设置的密码登录。
4. **添加 OpenRouter API 密钥**：在管理面板中，添加一个或多个您的 OpenRouter API 密钥。提供一个名称和密钥值（通常以 `sk-or-` 开头）。系统会自动轮询使用这些密钥。
5. **配置 AI 客户端**：
   - 将您的 AI 客户端（如 NextChat, LobeChat 等）的 API Base URL 设置为您的 Worker URL，并在末尾加上 `/v1`，例如：`https://cloudrouter.your-username.workers.dev/v1`。
   - API Key 字段可以填写任何以 `sk-` 开头的字符串（例如 `sk-12345`），它仅用于基础验证，实际的 OpenRouter 密钥由后端管理。

## 故障排除

如果您在部署或使用CloudRouter时遇到问题，请尝试以下步骤：

1. 确保您已正确创建并绑定了 `ROUTER_KV` 命名空间。

2. 检查Cloudflare Workers/Pages的日志，了解可能的错误原因

3. 确认您的OpenRouter API密钥是有效的

4. 如果添加API密钥后无法使用，请尝试刷新页面并重新检查密钥状态

5. 如果问题仍然存在，请在GitHub仓库中创建一个Issue
