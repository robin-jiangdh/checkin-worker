# checkin-worker

[checkin-panel](https://github.com/BingLi37/checkin-panel) 的 **API-only** Cloudflare Workers 移植版：
给 New API 类中转站做每日签到的面板，只保留 HTTP 协议签到，不含浏览器兜底。

## 功能对照

| 原版 | Worker 版 | 说明 |
|---|---|---|
| `newapi.py` 协议签到 | ✅ 完整移植 `src/newapi.ts` | probe / 密码登录 / access_token / session / JWT refresh / endpoint & login_bonus 两种签到 / bootstrap 设密码 |
| 内置调度器 | ✅ Cron Triggers `src/scheduler.ts` | 每 15 分钟 sweep，按账号 `checkin_after` 窗口 + 当天是否已成功决定跑谁 |
| SQLite 账号库 | ✅ D1 `src/store.ts`（`migrations/0001_accounts.sql`） | 表结构同源，另加 `site_info` 表缓存站点探测（24h TTL）；`password`/`access_token`/`session` 三列 AES-GCM 加密落盘 |
| 站点探测缓存 | ✅ `site_info` 表 24h TTL | 每天 sweep 不用对每个账号重复 probe |
| 账号 CRUD / 手动签到 / 批量签到 / probe / bootstrap | ✅ `src/index.ts` Hono 路由 | 路由形状与原版 `/api/*` 一致；返回账号时凭据只给 `has_password` 这类存在标记，不再明文返回 |
| 浏览器登录 / IdP 会话注入 / profile 管理 | ❌ 砍掉 | Workers 上没有持久化浏览器；`login_method=linuxdo|github`、`mechanism=visit` 会 422 拒绝 |
| Turnstile 验证 | ❌ 砍掉 | token 必须在浏览器里现铸；这类站点签到会明确报错，请用原版面板 |
| 桌面版 / 推荐卡片 | ❌ 砌掉 | — |

## 部署

```bash
cd checkin-worker
npm install

# 1. 建 D1（已建好：checkin_db，id 见 wrangler.toml）
# 如需新建：npx wrangler d1 create checkin_db

# 2. 跑迁移
npm run db:migrate:local   # 本地验证
npm run db:migrate:remote  # 线上

# 3. 设 secret
openssl rand -base64 32 | npx wrangler secret put ENCRYPTION_KEY
openssl rand -hex 24 | npx wrangler secret put ADMIN_TOKEN

# 4. 发布（wrangler 一步到位：脚本 + D1 绑定 + cron）
npm run deploy
# 或纯 API 部署（见 deploy/cf_deploy_checkin.py，schedules 的 PUT body 是裸数组）：
# npx esbuild src/index.ts --bundle --format=esm --platform=browser --outfile=dist/worker.js
# ENCRYPTION_KEY=... ADMIN_TOKEN=... python3 deploy/cf_deploy_checkin.py \
#   --account <id> --script checkin-worker --worker dist/worker.js --d1-id <uuid>
```

`ENCRYPTION_KEY` 丢了 = 所有存量凭据解不开，只能删账号重建。请把它和数据库备份分开保管。

## 安全（和原版最大的不同）

原版的设计假设是「单用户、本机、绑 127.0.0.1、无登录」（ADR-0003），`/api/accounts`
直接返回整行账号（含明文密码）。搬到公网后这三条是强制项：

1. **鉴权**：`ADMIN_TOKEN` 置空时 `/api/*` 无鉴权（仅本地开发用）。生产务必设置，
   更推荐前面再套一层 Cloudflare Access。
2. **落盘加密**：凭据三列 AES-GCM 加密，key 只在 `ENCRYPTION_KEY` secret 里。
   `api_user` 不是凭据（站点上的用户 id），明文存。
3. **不回显凭据**：账号列表/详情接口不再返回密码和 session，只返回 `has_*` 标记。
   前端编辑页原来会把存量凭据回填进表单——对接时注意，留空 = 不改。

## Web UI

访问 `https://checkin-worker.me3442.workers.dev/` 即打开管理页面（单文件 `public/index.html`，
打包时嵌进 Worker，`GET /` 直接 served）：

- **登录页**：输入 `ADMIN_TOKEN` 即可（存在浏览器 localStorage，点「退出」清除）；
- **列表页**：账号卡片（名称、站点、登录方式、今日状态、余额、上次运行、报错），
  每行可手动「签到」/「删除」；顶部有「全部签到」「添加账号」；
- **添加账号**：带「🔍 检测站点」（调 `/api/probe` 显示签到机制与登录方式），
  支持 password / access_token / session 三种，session 粘贴各种形状都行。

## 定时签到

cron 每 15 分钟跑一次 `sweep()`：

- `checkin_after`（HH:MM，按 `CHECKIN_TZ`，默认 Asia/Shanghai）还没到 → 跳过；
- 当天已有成功记录 → 跳过；
- 其余 enabled 账号逐个 `checkIn()`，结果写回 `last_*`，轮转下来的新 session /
  access_token 自动持久化（JWT 站点 refresh cookie 每次都会转，丢了就等于登出）。

手动触发：`POST /api/accounts/:id/check-in`，批量：`POST /api/check-in {"account_ids":[...]}`。

## 已知限制

- Workers 出口是机房 IP，个别站点的 WAF 可能拦截——签到失败时先看 `last_error`，
  403/人机验证类错误基本是这一类。
- 单次签到 25s 超时（`AbortSignal.timeout`），站点太慢会记一次失败并按原逻辑
  `failures` 计数。
- 从原版迁移账号：把 `data/panel.db` 里 `accounts` 表的 `password`/`access_token`/
  `session` 明文通过 `POST /api/accounts` 重新录入一遍即可（会自动加密存储）。
  `login_method` 为 linuxdo/github、或 `mechanism=visit` 的账号 Worker 版跑不了，
  请留在原版面板。
