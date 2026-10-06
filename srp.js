// SRP-6a 服务端实现（RFC 5054 兼容，SHA-256，3072-bit 安全素数群）
// 纯 Node 内置 crypto，无第三方依赖。
// 用途：基于共享口令的认证密钥交换（PAKE）。
// 服务器只存 verifier，不存口令；口令从未上线传输。
// 握手成功后双方得到相同会话密钥 K，且服务器可证明"我也知道口令"（双向）。

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const params = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'srp_params.json'), 'utf8'));
const N = BigInt('0x' + params.N);
const g = BigInt('0x' + params.g);
const N_BYTES = 384; // 3072 bits

// ---------- 大数 <-> Buffer ----------
function toBuf(bn) {
  let hex = bn.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const buf = Buffer.from(hex, 'hex');
  if (buf.length > N_BYTES) throw new Error('mod N overflow');
  return Buffer.concat([Buffer.alloc(N_BYTES - buf.length), buf], N_BYTES);
}
function toBn(buf) { return BigInt('0x' + Buffer.from(buf).toString('hex')); }

function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n, b = base, e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function sha256(...parts) {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(Buffer.isBuffer(p) ? p : toBuf(p));
  return h.digest();
}

// 均匀采样 1 <= s < N-1（拒绝采样）
function randScalar() {
  let s = 0n;
  while (s <= 0n || s >= N - 1n) {
    const cand = toBn(crypto.randomBytes(N_BYTES));
    if (cand < N - 1n) s = cand;
  }
  return s;
}

// k = H(N | g) —— SRP-6a 安全乘数
const K_MULT = toBn(sha256(toBuf(N), toBuf(g)));

// u = H(A | B)，防流加密预测攻击；为 0 时重生成
function compute_u(A, B) {
  const u = toBn(sha256(toBuf(A), toBuf(B)));
  if (u === 0n) throw new Error('u=0');
  return u;
}

// x = H(salt | H(I ":" P))  I=用户身份(此处用固定串), P=口令UTF-8
function compute_x(saltBuf, identity, password) {
  const inner = sha256(Buffer.concat([
    Buffer.from(String(identity), 'utf8'),
    Buffer.from(':', 'utf8'),
    Buffer.from(String(password), 'utf8')
  ]));
  return toBn(sha256(saltBuf, inner));
}

function compute_verifier(saltBuf, identity, password) {
  const x = compute_x(saltBuf, identity, password);
  return modPow(g, x, N); // v = g^x mod N
}

// HKDF(SHA-256) 从 SRP 共享密钥 S 派生 256-bit 会话密钥
function hkdf(ikm, salt, info, len = 32) {
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  return crypto.createHmac('sha256', prk).update(Buffer.concat([Buffer.from(info, 'utf8'), Buffer.from([1])])).digest().subarray(0, len);
}

// ---------- 注册器 ----------
class SRPServer {
  constructor() {
    this.verifier = null; // BigInt v
    this.salt = null;     // Buffer
  }

  register(identity, password) {
    this.salt = crypto.randomBytes(32);
    this.verifier = compute_verifier(this.salt, identity, password);
    return { salt: this.salt.toString('hex'), v: toBuf(this.verifier).toString('hex') };
  }

  loadFromStore(saltHex, vHex) {
    this.salt = Buffer.from(saltHex, 'hex');
    this.verifier = toBn(Buffer.from(vHex, 'hex'));
    if (this.verifier % N === 0n) throw new Error('bad verifier');
  }

  // 第一步：收到客户端 A（可选：注册时带 salt/v）
  // 返回 { salt, B }
  getChallenge(A_hex, reg) {
    const A = toBn(Buffer.from(A_hex, 'hex'));
    if (A % N === 0n) throw new Error('invalid A');

    if (reg && reg.salt && reg.v) {
      // 首次注册：客户端提供 salt/v（由口令在客户端派生）
      this.salt = Buffer.from(reg.salt, 'hex');
      this.verifier = toBn(Buffer.from(reg.v, 'hex'));
      if (this.verifier % N === 0n) throw new Error('bad verifier');
    }
    if (!this.verifier) throw new Error('not registered');

    // b 随机（拒绝采样，避免模偏置）, B = k*v + g^b mod N
    this.b = randScalar();
    this.B = (K_MULT * this.verifier + modPow(g, this.b, N)) % N;
    if (this.B % N === 0n) throw new Error('degenerate B');
    return { salt: this.salt.toString('hex'), B: toBuf(this.B).toString('hex') };
  }

  // 第二步：收到 M1，校验并返回 M2 + 会话密钥
  // 客户端：S = (B - k*g^x)^(a + u*x)；此处 v 已知：S = (A * v^u)^b
  verify(M1_hex) {
    const A = this.A;
    const B = this.B;
    const u = compute_u(A, B);
    const S = modPow(A * modPow(this.verifier, u, N) % N, this.b, N);
    const K = hkdf(toBuf(S), Buffer.from('chat2-srp-salt'), Buffer.from('chat2-session-key-v1'));

    // M1 = H(A | B | S)
    const M1 = sha256(toBuf(A), toBuf(B), toBuf(S));
    const given = Buffer.from(M1_hex, 'hex');
    const ok = given.length === M1.length && crypto.timingSafeEqual(given, M1);
    if (!ok) throw new Error('auth failed');

    // M2 = H(A | M1 | S)
    const M2 = sha256(toBuf(A), M1, toBuf(S));
    return { M2: M2.toString('hex'), key: K.toString('hex') };
  }

  // 完整服务端流程（与 getChallenge + verify 等价，按消息顺序驱动）
  hello(A_hex, reg) {
    const out = this.getChallenge(A_hex, reg);
    this.A = toBn(Buffer.from(A_hex, 'hex'));
    return out;
  }
}

module.exports = { SRPServer, N, g, N_BYTES, toBuf, toBn, modPow, sha256, compute_x, compute_verifier, hkdf };