# ProofPlay Poker Client - 部署文档

## 项目概述

前端项目 `secret-poker-client` (v2.0.0)，基于 **React 18 + Vite 6 + TypeScript** 构建。

## 环境要求

- **Node.js** >= 18
- **pnpm** (包管理器)
- **Nginx** (生产环境部署)

## 环境变量配置

创建 `client/.env.local` 文件（**构建前**配置）：

```env
# Contentful CMS
VITE_CONTENTFUL_SPACE_ID=
VITE_CONTENTFUL_ACCESS_TOKEN=

# Google Analytics
VITE_GOOGLE_ANALYTICS_TRACKING_ID=

# 后端服务器 URI (生产环境)
VITE_SERVER_URI=http://localhost:9001
```

> `.env.local` 仅在构建时由 Vite 读取，变量会被内联打包到 JS 中。**不要**将 `.env.local` 放入 `dist/` 目录。

## 可用脚本

| 命令 | 说明 |
|------|------|
| `pnpm dev` | 启动开发服务器（HMR 热更新），API 代理到 `localhost:9001` |
| `pnpm build` | 生产构建：TypeScript 类型检查 (`tsc -b`) + Vite 打包 (`vite build`)，输出到 `dist/` |
| `pnpm preview` | 本地预览构建产物 |
| `pnpm typecheck` | 仅 TypeScript 类型检查 |

## 生产构建

```bash
cd client
pnpm install
pnpm build
```

构建产物输出到 `client/dist/` 目录。

## 部署到服务器

### 方式一：SCP 手动部署

```bash
# 1. 构建
cd client
pnpm build

# 2. 上传到服务器
scp -r -i ~/pathtoyourdeploy.pem ./dist ec2-user@your-server:/home/ec2-user/zgame/front/

# 3. 登录服务器，替换旧版本
ssh -i ~/pathtoyourdeploy.pem ec2-user@your-server
mv /home/ec2-user/zgame/front/dist /home/ec2-user/zgame/front/dist_old
mv ./dist /home/ec2-user/zgame/front/

# 4. 修复权限（如果遇到 403 Permission denied）
chmod o+x /home/ec2-user
chmod -R o+rX /home/ec2-user/zgame/front/dist
```

### 方式二：Railway / 云平台部署

`public/_redirects` 文件配置了 SPA 路由重写和 API 代理：

```
/api/* https://vintage-poker-production.up.railway.app/api/:splat 200
/*    /index.html   200
```

适用于支持 `_redirects` 的静态托管平台（如 Railway、Vercel、Netlify、Cloudflare Pages）。

## Nginx 配置

```nginx
server {
    server_name your-domain.com;

    root /home/ec2-user/zgame/front/dist;
    index index.html;

    # favicon 静默处理
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    # SPA 路由支持
    location / {
        try_files $uri $uri/ /index.html;
    }

    # 后端 API 代理
    location /api/ {
        proxy_pass http://127.0.0.1:9001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket 代理（游戏实时通信）
    location /socket.io/ {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 静态资源缓存（图片、字体等）
    location ~* \.(jpg|jpeg|png|gif|ico|svg|woff2?|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # JS/CSS 缓存（Vite 产物自带 hash）
    location ~* \.(js|css)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### Nginx 配置要点

| 配置项 | 说明 |
|--------|------|
| `root` | 指向构建产物 `client/dist` 的**绝对路径** |
| `try_files $uri $uri/ /index.html` | SPA 路由支持，所有非文件请求 fallback 到 `index.html` |
| `/api/` → `proxy_pass` | 后端 HTTP API 代理到 `localhost:9001` |
| `/socket.io/` → `proxy_pass` | WebSocket 升级代理，用于游戏实时通信 |

### 部署后验证

```bash
# 测试 Nginx 配置
sudo nginx -t

# 重新加载
sudo nginx -s reload

# 查看错误日志（排查问题）
sudo tail -50 /var/log/nginx/error.log
```

## 常见问题

### 1. 访问返回 403 Permission denied

**错误日志**: `stat() "/home/ec2-user/zgame/front/dist/index.html" failed (13: Permission denied)`

**原因**: Nginx 运行用户无法读取 dist 目录。

**解决**:
```bash
chmod o+x /home/ec2-user
chmod -R o+rX /home/ec2-user/zgame/front/dist
```

### 2. 访问返回 500 Internal Server Error

检查 Nginx 错误日志和后端服务是否在运行：
```bash
sudo tail -50 /var/log/nginx/error.log
curl -v http://127.0.0.1:9001/
```

### 3. 环境变量未生效

如果构建后 `VITE_*` 变量未打包到产物中：
- 确认 `client/.env.local` 文件存在且路径正确
- 删除 `dist/` 目录后重新执行 `pnpm build`
- 验证变量是否被内联：
  ```bash
  node -e "
  const fs = require('fs');
  const file = fs.readdirSync('dist/assets').find(f => f.startsWith('index-') && f.endsWith('.js'));
  const content = fs.readFileSync('dist/assets/' + file, 'utf-8');
  console.log(content.includes('YOUR_VALUE') ? 'FOUND' : 'NOT FOUND');
  "
  ```

## 项目结构

```
client/
├── public/              # 静态资源（不参与构建）
├── src/                 # 源代码
│   ├── api/             # API 客户端 (REST + WebSocket)
│   ├── components/      # UI 组件
│   ├── context/         # React Context 状态管理
│   ├── pages/           # 页面组件
│   ├── starknet/       # Starknet 钱包与链上交互
│   ├── clientConfig.ts  # 环境变量配置读取
│   └── main.tsx         # 入口文件
├── dist/                # 构建产物（部署目标，被 .gitignore 忽略）
├── deploy/              # 部署脚本
├── .env.local           # 本地环境变量（不提交到 Git）
├── vite.config.ts       # Vite 配置
└── package.json         # 依赖与脚本
```

## 环境区分

| 环境 | 构建命令 | 说明 |
|------|---------|------|
| 开发环境 | `pnpm dev` | 本地开发，HMR，代理到 `localhost:9001` |
| 生产环境 | `pnpm build` | TypeScript 类型检查 + Vite 打包，输出到 `dist/` |

## SSL 证书（Certbot）

生产环境 Nginx 配置中包含 Certbot 自动管理的 Let's Encrypt SSL 证书：

```nginx
listen 443 ssl;
ssl_certificate /etc/letsencrypt/live/secretpokers.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/secretpokers.com/privkey.pem;
```

证书自动续期：
```bash
sudo certbot renew
```