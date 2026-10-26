// 极简双人聊天服务端
// 运行: node server.js
// 访问: http://<你的公网IP>:8080

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const TOKEN = process.env.TOKEN || '';

const SRP = require('./srp.js');
const { toBuf } = SRP;

// SRP 多账号模式：accounts.json 保存 10 座口令账本（只存验证子，不存口令）
const ACCOUNTS_FILE = path.join(__dirname, '..', 'accounts.json');
const NUM_SEATS = 10;
function loadAccounts() {
  try {
    const d = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
    return d.seats || [];
  } catch {
    return [];
  }
}
function ensureAccounts() {
  let seats = loadAccounts();
  if (seats.length === 0) {
    // 初始化 10 个空座
    seats = [];
    for (let i = 1; i <= NUM_SEATS; i++) seats.push({ seat: i, name: null, salt: null, v: null });
    saveAccounts(seats);
  }
  return seats;
}
function saveAccounts(seats) {
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify({ seats }, null, 2), { mode: 0o600 });
}
function findSeatByName(seats, name) { return seats.find(s => s.name === name) || null; }
function firstEmptySeat(seats) { return seats.find(s => s.name === null) || null; }

// ---------- 万能口令（任意名字可登录，退出解绑，不占座） ----------
const MASTER_SEATS_FILE = path.join(__dirname, '..', 'master_seat.json');
const MASTER_IDENTITY = 'master';
function loadPresetSeats() {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'preset_seats.json'), 'utf8')).seats || []; } catch { return []; }
}
function loadMasterSeat() {
  try { return JSON.parse(fs.readFileSync(MASTER_SEATS_FILE, 'utf8')); } catch { return null; }
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

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
function httpHandler(req, res) {
  if (req.url === '/' || req.url === '/index.html') {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } else if (req.url === '/favicon.svg' || req.url === '/favicon.ico') {
    const f = path.join(__dirname, 'public', 'favicon.svg');
    if (fs.existsSync(f)) {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
      res.end(fs.readFileSync(f));
    } else {
      res.writeHead(404); res.end('not found');
    }
  } else if (req.url === '/srp-params.json') {
    const j = fs.readFileSync(path.join(__dirname, '..', 'srp_params.json'));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(j);
  } else if (req.url === '/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else {
    res.writeHead(404);
    res.end('not found');
  }
}
const server = http.createServer(httpHandler);

// ---------- HTTPS（自签证书，存在则启用） ----------
const TLS_DIR = process.env.TLS_DIR || path.join(__dirname, '..', 'tls');
const TLS_KEY = path.join(TLS_DIR, 'privkey.pem');
const TLS_CERT = path.join(TLS_DIR, 'fullchain.pem');
let tlsServer = null;
if (fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
  tlsServer = https.createServer(
    { key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) },
    (req, res) => httpHandler(req, res)
  );
}

// ---------- WebSocket ----------
const wss = new WebSocket.Server({ noServer: true });

function attach(serverObj) {
  serverObj.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });
}

let nextId = 0;

// 在线用户： name -> ws
const online = new Map();

wss.on('connection', (ws, req) => {
  const clientId = ++nextId;
  let myName = null;       // 本次握手绑定的名字（握手成功后锁定）
  let authed = false;
  let sessionKey = null;   // SRP 会话密钥（Buffer）
  let srpCtx = null;       // 本连接的 SRP 握手上下文
  let handshakeName = null; // srp_hello 里声明的名字

  // SRP 多账号模式（accounts.json 存在即启用；旧 token 模式保留兼容）
  const srpMode = ensureAccounts().length > 0;

  // Token 验证（旧模式）：未通过认证前，除 auth 外不响应任何消息
  if (!srpMode && TOKEN) {
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch { url = null; }
    const given = url && url.searchParams.get('token');
    if (!given || !safeEqual(given, TOKEN)) {
      ws.send(JSON.stringify({ type: 'auth_error', message: 'token 无效' }));
      ws.close(4001, 'unauthorized');
      return;
    }
  }
  authed = true;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (msg.type === 'srp_hello') {
      if (!srpMode) { ws.send(JSON.stringify({ type: 'auth_result', ok: false })); return; }
      const reqName = String(msg.name || '').trim().slice(0, 20);
      const masterSeat = loadMasterSeat();
      const usingMaster = (String(msg.identity || '') === MASTER_IDENTITY) && masterSeat && masterSeat.salt && masterSeat.v;
      // 非万能口令（普通座）才强制要求名字；master 万能口令允许空名（不绑定名字）
      if (!usingMaster && !reqName) { ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'no_name' })); return; }
      handshakeName = reqName;
      try {
        const presetSeats = loadPresetSeats();
        const accounts = loadAccounts();
        srpCtx = new SRP.SRPServer();
        if (usingMaster) {
          // 万能口令：固定 master 验证子，不占座、不绑定名字
          srpCtx.loadFromStore(masterSeat.salt, masterSeat.v);
          srpCtx.isMaster = true;
        } else {
          // 普通口令：客户端声明尝试的座编号（1-10），必须使用该座预置验证子
          const seatNum = parseInt(msg.seat, 10);
          if (!(seatNum >= 1 && seatNum <= 10)) {
            ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'bad_seat' })); return;
          }
          const preset = presetSeats.find(p => p.seat === seatNum);
          if (!preset || !preset.salt || !preset.v) {
            ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'no_preset' })); return;
          }
          // 该座是否已被绑定名字？若已绑定，只有同名才能用（绑定名字必须匹配）
          const accSeat = accounts.find(a => a.seat === seatNum);
          if (accSeat && accSeat.name && accSeat.name !== reqName) {
            // 该座已被别人占走，此名字对不上 -> 拒绝
            ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'seat_taken' })); return;
          }
          srpCtx.loadFromStore(preset.salt, preset.v);
          srpCtx.seatNum = seatNum;
          srpCtx.isMaster = false;
        }
        const out = srpCtx.hello(String(msg.A || ''));
        ws.send(JSON.stringify({ type: 'srp_challenge', salt: out.salt, B: out.B }));
      } catch (e) {
        srpCtx = null;
        ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'handshake' }));
      }
      return;
    }

    if (msg.type === 'srp_verify') {
      if (!srpCtx) { ws.send(JSON.stringify({ type: 'auth_result', ok: false })); return; }
      try {
        const res = srpCtx.verify(String(msg.M1 || ''));
        ws.seatNum = srpCtx.isMaster ? null : (srpCtx.seatNum || null);
        // 握手通过：普通口令（非万能键）将名字绑定到该座
        if (!srpCtx.isMaster) {
          const accounts = loadAccounts();
          const presetSeats = loadPresetSeats();
          const seatNum = srpCtx.seatNum;
          const preset = presetSeats.find(p => p.seat === seatNum);
          // 该座绑定名字（若尚未绑定）；已绑定则必须同名（已在 srp_hello 校验过）
          const accSeat = accounts.find(a => a.seat === seatNum);
          if (!accSeat) {
            accounts.push({ seat: seatNum, name: handshakeName, salt: preset.salt, v: preset.v });
          } else if (!accSeat.name) {
            accSeat.name = handshakeName;
            accSeat.salt = preset.salt;
            accSeat.v = preset.v;
          }
          saveAccounts(accounts);
        }
        myName = handshakeName;
        sessionKey = Buffer.from(res.key, 'hex');
        authed = true;
        ws.send(JSON.stringify({ type: 'srp_ready', M2: res.M2 }));
      } catch (e) {
        srpCtx = null;
        ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'bad_password' }));
        ws.close(4001, 'unauthorized');
      }
      return;
    }

    if (msg.type === 'auth') {
      if (srpMode) { ws.send(JSON.stringify({ type: 'auth_result', ok: false, error: 'use_srp' })); return; }
      const ok = !TOKEN || safeEqual(String(msg.token || ''), TOKEN);
      ws.send(JSON.stringify({ type: 'auth_result', ok }));
      if (ok) authed = true;
      return;
    }

    if (!authed) return;

    switch (msg.type) {

      // 登录：告知自己的名字
      case 'login': {
        myName = String(msg.name || '').slice(0, 20);
        online.set(myName, ws);
        ws.myName = myName;

        // 阅后即焚（退出即清）：客户端可传 since（上次退出时间戳），
        // 只下发该时间戳之后的新消息；退出前的历史对本人不再可见。
        const since = Number(msg.since) || 0;
        let hist = db.messages.filter(r => r.time > since).slice(-200);

        // 推送 offline 期间的新消息（SRP 模式：只回密文，由客户端本地解密）
        if (srpMode) {
          const enc = hist.map((r) => ({
            id: r.id, from: r.from, time: r.time,
            etext: r.etext || r.text || ''
          }));
          ws.send(JSON.stringify({ type: 'history', encrypted: true, since, messages: enc }));
        } else {
          ws.send(JSON.stringify({
            type: 'history',
            since,
            messages: hist
          }));
        }

        // 座位状态：把当前在线的座（seat->name）同步给所有人（含自己）
        ws.send(JSON.stringify({ type: 'seats', seats: currentSeats() }));
        broadcast({ type: 'seat_update', seat: ws.seatNum || null, name: myName });

        // 通知对方我上线了
        broadcast({ type: 'online', name: myName }, myName);
        break;
      }

      // 发送文字（SRP 模式：text 字段是客户端密文 base64，服务器不解析）
      case 'msg': {
        const raw = String(msg.text || '');
        if (!raw) return;
        let text;
        if (srpMode) {
          // 密文上限放宽，格式校验：base64，长度合理
          if (raw.length > 12000 || !/^[A-Za-z0-9+/=]+$/.test(raw)) return;
          text = raw;
        } else {
          text = raw.slice(0, 2000);
        }

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
      broadcast({ type: 'seat_update', seat: ws.seatNum || null, name: null });
      broadcast({ type: 'offline', name: myName }, myName);
    }
  });
});

// 当前在线座：返回 { seatNum: name } 映射（只含普通座；万能口令不占座）
function currentSeats() {
  const out = {};
  for (const [name, ws] of online) {
    if (ws && ws.seatNum) out[ws.seatNum] = name;
  }
  return out;
}

function broadcast(payload, exclude) {
  const data = JSON.stringify(payload);
  for (const [name, ws] of online) {
    if (name === exclude) continue;
    if (ws.readyState === 1) ws.send(data);
  }
}

attach(server);
if (tlsServer) attach(tlsServer);

const TLS_PORT = process.env.TLS_PORT || 8443;
server.listen(PORT, () => {
  console.log(`聊天服务已启动 (HTTP:${PORT})`);
});
if (tlsServer) {
  tlsServer.listen(TLS_PORT, () => {
    console.log(`HTTPS 已启用 (HTTPS:${TLS_PORT})`);
  });
}