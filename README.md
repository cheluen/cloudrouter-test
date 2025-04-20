# CloudRouter

CloudRouter 是一个运行在 Cloudflare Workers 或 Pages 上的代理服务，用于管理多个 OpenRouter API 密钥并提供与 OpenAI API 兼容的接口。

## 特性

- 🔑 管理多个 OpenRouter API 密钥
- 🔄 自动轮询使用 API 密钥，如果一个密钥无响应，自动切换到下一个
- 🔌 接口完全兼容 OpenAI API
- 🌐 支持客户端设置的模型自动映射到 OpenRouter 模型
- 🔒 支持自定义 API 密钥访问控制
- 📊 提供简单的管理界面
- ☁️ 支持一键部署到 Cloudflare Workers

## 一键部署

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/yourusername/cloudrouter)

## 手动部署

### 前提条件

- [Node.js](https://nodejs.org/) 14 或更高版本
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/get-started/)
- Cloudflare 账户

### 部署步骤

1. 克隆仓库
```bash
git clone https://github.com/yourusername/cloudrouter.git
cd cloudrouter
```

2. 安装依赖
```bash
npm install
```

3. 配置 Cloudflare 账户
```bash
npx wrangler login
```

4. 在 Cloudflare 控制台创建 KV 命名空间
```bash
npx wrangler kv:namespace create "ROUTER_KV"
```
创建后，将输出的 ID 填入 `wrangler.toml` 文件中的 `id = "your-kv-id"` 部分。

5. 修改 `wrangler.toml` 中的 `AUTH_KEY` 为您自定义的管理密钥
```toml
[vars]
AUTH_KEY = "your-auth-key" # 将此替换为您的自定义管理密钥
```

6. 部署到 Cloudflare Workers
```bash
npm run deploy
```

## 使用指南

### 管理 API 密钥

1. 访问您部署的 Workers URL (例如 `https://your-worker-subdomain.workers.dev`)
2. 使用您设置的管理密钥登录管理面板
3. 在管理面板中添加 OpenRouter API 密钥

### 在客户端使用

CloudRouter 提供与 OpenAI API 兼容的接口，您只需要修改客户端的 API 基础 URL：

```
API Base URL: https://your-worker-subdomain.workers.dev
```

请求示例：

```js
const response = await fetch('https://your-worker-subdomain.workers.dev/v1/chat/completions', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-api-key'
  },
  body: JSON.stringify({
    model: 'deepseek-coder',
    messages: [
      { role: 'user', content: '你好，请介绍一下自己' }
    ]
  })
});

const data = await response.json();
console.log(data);
```

## 工作原理

1. CloudRouter 在 Cloudflare Workers 上运行，使用 KV 存储保存 API 密钥
2. 当收到请求时，CloudRouter 会选择一个健康的 API 密钥转发请求到 OpenRouter
3. 如果请求失败，CloudRouter 会自动切换到下一个可用的 API 密钥
4. CloudRouter 定期执行健康检查，确保 API 密钥可用性

## 许可证

MIT

## 贡献

欢迎提交 Issues 和 Pull Requests！ 