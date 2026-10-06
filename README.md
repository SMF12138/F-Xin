# 极简双人聊天

无需域名、无需备案、无需 HTTPS 的双人文字聊天工具。

- 服务端：Node.js + WebSocket
- 存储：本地 JSON 文件（`messages.json`）
- 访问：`http://<公网IP>:8080`

## 功能

- 实时收发文字
- 断线自动重连（2 秒）
- 离线消息补发（重连后拉取最近 200 条）
- 消息持久化
- 上下线提醒
- 手机浏览器自适应

## 部署

```bash
npm install
node server.js
```

开放端口：`8080/tcp`（在云服务商安全组放行）

访问：`http://<你的公网IP>:8080`

## 后台常驻

```bash
npm install -g pm2
pm2 start server.js --name chat
pm2 save
pm2 startup
```

## 备份

`messages.json` 就是全部聊天记录，建议每日备份：

```bash
echo "0 3 * * * cp /opt/chat/messages.json ~/backup-\$(date +\%F).json" | crontab -
```

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `8080` | 监听端口 |
| `TOKEN` | 空 | 访问密码；设置后网页和 WebSocket 连接都需要验证，不设则不验证 |

运行示例：

```bash
TOKEN=*** node server.js
# 或 pm2 start server.js --name chat --env TOKEN=***
```

## 注意

- 消息传输**不加密**，请勿用于传输敏感内容
- 登录凭名字 + TOKEN 密码；Token 只防君子（明文传输），挡不住抓包
- `messages.json` 已被 `.gitignore` 排除，不会进入仓库