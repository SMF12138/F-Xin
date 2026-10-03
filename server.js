// 极简双人聊天服务端
// 运行: node server.js
// 访问: http://<你的公网IP>:8080

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;

// ---------- 简易存储：JSON 文件 ----------
const DB_FILE = path.join(__dirname, 'messages.json');

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { messages: [] };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDB();

// ---------- HTTP 服务 ----------
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } else {
    res.writeHead(404);
    res.end('not found');
  }
});

// ---------- WebSocket ----------
const wss = new WebSocket.Server({ server });

let nextId = 0;

// 在线用户： name -> ws
const online = new Map();

wss.on('connection', (ws) => {
  const clientId = ++nextId;
  let myName = null;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }

    switch (msg.type) {

      // 登录：告知自己的名字
      case 'login': {
        myName = String(msg.name || '').slice(0, 20);
        online.set(myName, ws);
        ws.myName = myName;

        // 推送离线期间的历史消息
        ws.send(JSON.stringify({
          type: 'history',
          messages: db.messages.slice(-200)
        }));

        // 通知对方我上线了
        broadcast({ type: 'online', name: myName }, myName);
        break;
      }

      // 发送文字
      case 'msg': {
        const text = String(msg.text || '').slice(0, 2000);
        if (!text) return;

        const record = {
          id: crypto.randomUUID(),
          from: myName,
          text,
          time: Date.now()
        };

        db.messages.push(record);
        if (db.messages.length > 5000) db.messages = db.messages.slice(-5000);
        saveDB(db);

        // 广播给所有人（包括自己，方便多端同步）
        broadcast({ type: 'msg', ...record });
        break;
      }
    }
  });

  // 断线：删掉我
  ws.on('close', () => {
    if (myName && online.get(myName) === ws) {
      online.delete(myName);
      broadcast({ type: 'offline', name: myName }, myName);
    }
  });
});

function broadcast(payload, exclude) {
  const data = JSON.stringify(payload);
  for (const [name, ws] of online) {
    if (name === exclude) continue;
    if (ws.readyState === 1) ws.send(data);
  }
}

server.listen(PORT, () => {
  console.log(`聊天服务已启动`);
  console.log(`本机访问: http://localhost:${PORT}`);
  console.log(`公网访问: http://<你的公网IP>:${PORT}`);
  console.log(`在线人数: ${online.size}`);
});