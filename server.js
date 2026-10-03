const express = require('express');
const path = require('path');
const { execFile } = require('child_process');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3005;
const AUTH_FILE = path.join(__dirname, '.portal_auth');
const DEFAULT_PASS = 'iskan2026';
const TELBOT_ENV = '/root/telbot-data/.env';
const TELBOT_DIR = '/root/telbot-data';

// ---- body + cookie parse ----
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));
function parseCookies(req) {
  const h = req.headers.cookie || '';
  const out = {};
  h.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0,i).trim()] = decodeURIComponent(p.slice(i+1).trim());
  });
  return out;
}

// ---- auth hash ----
function hashPassword(pwd) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pwd, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pwd, stored) {
  try {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return false;
    const derived = crypto.scryptSync(pwd, salt, 64).toString('hex');
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(derived, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a,b);
  } catch(e){ return false; }
}
function loadStoredHash() {
  try {
    if (fs.existsSync(AUTH_FILE)) return fs.readFileSync(AUTH_FILE,'utf8').trim();
  } catch(e){}
  // create default
  const h = hashPassword(DEFAULT_PASS);
  try { fs.writeFileSync(AUTH_FILE, h, { mode: 0o600 }); console.log('[portal-auth] created default password: ' + DEFAULT_PASS + ' (change via /api/auth/change-password)'); } catch(e){}
  return h;
}
let storedHash = loadStoredHash();

// in-memory sessions token -> {exp}
const sessions = new Map();
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const failedAttempts = new Map(); // ip -> {count, until}

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  // cleanup old occasionally
  if (sessions.size > 200) {
    const now = Date.now();
    for (const [k,exp] of sessions) if (exp < now) sessions.delete(k);
  }
  return token;
}
function isValidToken(tok) {
  if (!tok) return false;
  const exp = sessions.get(tok);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(tok); return false; }
  // sliding: extend on use
  sessions.set(tok, Date.now() + SESSION_TTL_MS);
  return true;
}
function getTokenFromReq(req) {
  const c = parseCookies(req);
  return c['portal_token'] || req.headers['x-portal-token'] || null;
}
function isAuthenticated(req) {
  return isValidToken(getTokenFromReq(req));
}
function isApi(req) { return req.path.startsWith('/api/'); }
function isPublicPath(p) {
  return p === '/login.html' || p === '/robots.txt' || p === '/favicon.svg' || p === '/manifest.json' || p === '/sw.js' || p === '/offline.html' || p === '/apple-touch-icon.png' || p.startsWith('/icons/') || p.startsWith('/api/auth/');
}

// rate limit for login
function checkRateLimit(ip) {
  const rec = failedAttempts.get(ip) || { count: 0, until: 0 };
  if (Date.now() < rec.until) return { blocked: true, retryAfter: Math.ceil((rec.until - Date.now())/1000) };
  return { blocked: false, rec };
}
function recordFail(ip) {
  const rec = failedAttempts.get(ip) || { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= 5) { rec.until = Date.now() + 60 * 1000; rec.count = 0; }
  failedAttempts.set(ip, rec);
}
function resetRate(ip) { failedAttempts.delete(ip); }

// ---- common headers ----
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
  next();
});
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send("User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nDisallow: /\n\nUser-agent: ChatGPT-User\nDisallow: /\n\nUser-agent: Anthropic-ai\nDisallow: /\n\nUser-agent: PerplexityBot\nDisallow: /\n\nUser-agent: CCBot\nDisallow: /");
});

// ---- auth routes (public) ----
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const rl = checkRateLimit(ip);
  if (rl.blocked) return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi ' + rl.retryAfter + 's' });
  const pwd = (req.body && req.body.password) || '';
  if (!pwd) return res.status(400).json({ error: 'Password wajib diisi' });
  // reload hash in case changed on disk
  try { if (fs.existsSync(AUTH_FILE)) storedHash = fs.readFileSync(AUTH_FILE,'utf8').trim(); } catch(e){}
  if (!verifyPassword(String(pwd), storedHash)) {
    recordFail(ip);
    return res.status(401).json({ error: 'Password salah' });
  }
  resetRate(ip);
  const token = createSession();
  res.cookie ? null : null;
  // set cookie manually (no cookie-parser needed)
  res.setHeader('Set-Cookie', `portal_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS/1000}`);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  const tok = getTokenFromReq(req);
  if (tok) sessions.delete(tok);
  res.setHeader('Set-Cookie', 'portal_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/auth/check', (req, res) => {
  res.json({ authenticated: isAuthenticated(req) });
});

app.post('/api/auth/change-password', (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Belum login' });
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'oldPassword & newPassword wajib' });
  if (String(newPassword).length < 6) return res.status(400).json({ error: 'Password baru minimal 6 karakter' });
  try { if (fs.existsSync(AUTH_FILE)) storedHash = fs.readFileSync(AUTH_FILE,'utf8').trim(); } catch(e){}
  if (!verifyPassword(String(oldPassword), storedHash)) return res.status(401).json({ error: 'Password lama salah' });
  const nh = hashPassword(String(newPassword));
  try { fs.writeFileSync(AUTH_FILE, nh, { mode: 0o600 }); storedHash = nh; } catch(e){ return res.status(500).json({ error: 'Gagal simpan password' }); }
  // invalidate all sessions except current? keep current valid but rotate
  // clear all and reissue for this request
  sessions.clear();
  const token = createSession();
  res.setHeader('Set-Cookie', `portal_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS/1000}`);
  res.json({ ok: true, message: 'Password berhasil diubah' });
});

// ---- auth gate for protected routes ----
app.use((req, res, next) => {
  if (isPublicPath(req.path)) return next();
  // protect /api/* and / , /index.html
  const needAuth = req.path === '/' || req.path === '/index.html' || req.path.startsWith('/api/');
  if (!needAuth) return next(); // allow other static like .js/.css if any (but we only have index/login)
  if (isAuthenticated(req)) return next();
  if (isApi(req)) return res.status(401).json({ error: 'Unauthorized · login dulu di /login.html' });
  return res.redirect('/login.html');
});

const SERVICES = [
  { unit: 'iskan-drama.service',       name: 'Iskan Drama',        kind: 'app',   port: 3003,  desc: 'Streaming SPA (Express, native http)', path: '/root/iskan-drama', tech: 'Node.js', externalUrl: 'https://drama.nendi.web.id', dashboardPath: '/' },
  { unit: 'iskan-portfolio.service',   name: 'Iskan Portfolio',    kind: 'app',   port: 3004,  desc: 'Spotlight portfolio · nendi.web.id (apex via tunnel)', path: '/root/iskan-portfolio', tech: 'React / Next.js', externalUrl: 'https://nendi.web.id', dashboardPath: '/' },
  { unit: 'autoclipper-webjs.service', name: 'Auto-Clipper WebJS', kind: 'app',   port: 3000,  desc: 'Auto-Clipper v2 web panel', path: '/root/auto-clipper-v2', tech: 'Node.js / Python', externalUrl: 'https://clipper.nendi.web.id', dashboardPath: '/' },
  { unit: 'iskan-portal.service',      name: 'Iskan Portal',       kind: 'app',   port: 3005,  desc: 'Portal status (halaman ini)', path: '/root/iskan-portal', tech: 'Node.js / Express', externalUrl: 'https://portal.nendi.web.id', dashboardPath: '/' },
  { unit: 'auto-clipper-v2-bot.service', name: 'Auto-Clipper Bot', kind: 'bot', port: null, desc: 'Telegram bot pipeline', tech: 'Python', externalUrl: null },
  { unit: 'hermes-gateway.service',      name: 'Hermes Gateway',   kind: 'bot', port: null, desc: 'Hermes Agent messaging gateway', user: true, tech: 'Node.js', externalUrl: null },
  { unit: '9router-mibp.service',            name: '9Router',         kind: 'infra', port: 20127, desc: 'AI router dashboard (Next.js 16) · /dashboard', path: '/root/9router-mibp-version', tech: 'Next.js 16 / React 19', externalUrl: 'https://9r.nendi.web.id', dashboardPath: '/' },
  { unit: 'omniroute.service',               name: 'OmniRoute',      kind: 'infra', port: 20128, desc: 'AI gateway proxy (~2900 models) · dashboard /dashboard', tech: 'Go (Golang)', externalUrl: 'https://omni.nendi.web.id', dashboardPath: '/dashboard' },
  { unit: 'docker.service',                  name: 'Docker',         kind: 'infra', port: null,  desc: 'Container runtime', tech: 'Docker', externalUrl: null },
  { unit: 'cf-manager',                          name: 'CF Manager',     kind: 'infra', port: 3010,  desc: 'Cloudflare multi-account manager', path: '/root/cf-manager', tech: 'Vue3 + Express / Docker', docker: true, externalUrl: 'https://cf.nendi.web.id', dashboardPath: '/' },
  { unit: 'owrt.nendi.web.id',                 name: 'OpenWrt - iskanWRT', kind: 'infra', port: null,  desc: 'Router LuCI via tunnel → 192.168.1.1:80', path: null, tech: 'OpenWrt / LuCI', externalUrl: 'https://owrt.nendi.web.id', dashboardPath: '/', target: 'http://192.168.1.1:80', noCheck: true },
  { unit: 'telbot.service',                     name: 'Telbot',           kind: 'bot',   port: null, desc: 'Telkomsel bot (0xtbug/telbot v1.1.3) · Telegram Bot/CLI/MCP', path: '/root/telbot-data', tech: 'Go 1.26 · gotgbot', externalUrl: null },
  { unit: 'ttyd.service',                       name: 'Web Terminal',     kind: 'infra', port: 7681, desc: 'Web terminal (ttyd 1.7.7) → https://ssh.nendi.web.id', path: null, tech: 'ttyd / login', externalUrl: 'https://ssh.nendi.web.id', dashboardPath: '/' },
  { unit: 'cloudflared.service',                 name: 'Cloudflared Tunnel', kind: 'infra', port: null, desc: 'Named tunnel 204640e4 → 9 hostnames (nendi.web.id + 9r/drama/portal/clipper/cf/omni/llm/owrt/ssh)', tech: 'Cloudflare Tunnel', externalUrl: null },
];

const USER_ENV = { ...process.env, XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR || '/run/user/0' };

function fmtBytes(n) {
  n = Number(n);
  if (!n || n < 0) return null;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + u[i];
}
function fmtBps(bps) {
  if (bps == null || isNaN(bps)) return '-';
  if (bps < 1024) return Math.round(bps) + ' B/s';
  if (bps < 1024*1024) return (bps/1024).toFixed(1) + ' KB/s';
  if (bps < 1024*1024*1024) return (bps/1024/1024).toFixed(2) + ' MB/s';
  return (bps/1024/1024/1024).toFixed(2) + ' GB/s';
}
function run(bin, args, timeout = 5000, env) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout, env: env || process.env }, (err, stdout) => resolve(err ? null : stdout));
  });
}
async function systemctlShow(unit, user) {
  const args = user ? ['--user', 'show', unit, '-p', 'Id,ActiveState,SubState,MainPID,MemoryCurrent', '--no-pager'] : ['show', unit, '-p', 'Id,ActiveState,SubState,MainPID,MemoryCurrent', '--no-pager'];
  const stdout = await run('systemctl', args, 5000, user ? USER_ENV : undefined);
  if (!stdout) return null;
  const out = {};
  stdout.split('\n').forEach((line) => { const i = line.indexOf('='); if (i > 0) out[line.slice(0, i)] = line.slice(i + 1); });
  return out;
}
async function systemctlSince(unit, user) {
  const args = user ? ['--user', 'show', unit, '-p', 'ActiveEnterTimestamp', '--no-pager'] : ['show', unit, '-p', 'ActiveEnterTimestamp', '--no-pager'];
  const stdout = await run('systemctl', args);
  if (!stdout) return null;
  const m = stdout.match(/ActiveEnterTimestamp=.*?(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})/);
  if (!m) return null;
  const ts = Date.parse(`${m[1]}T${m[2]}`);
  return isNaN(ts) ? null : ts;
}
async function dockerStatus(name) {
  const cmd = await run('docker', ['inspect', '--format', '{{.State.Status}} {{.State.Running}} {{.ID}}', name], 3000);
  if (!cmd) return null;
  const parts = cmd.trim().split(/\s+/);
  return { status: parts[0] || 'unknown', running: parts[1] === 'true' };
}
async function dockerSince(name) {
  const cmd = await run('docker', ['inspect', '--format', '{{.State.StartedAt}}', name], 3000);
  if (!cmd) return null;
  const m = cmd.trim().match(/(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
  if (!m) return null;
  const ts = Date.parse(m[1] + 'T' + m[2]);
  return isNaN(ts) ? null : ts;
}
async function systemctlIsEnabled(unit, user) {
  return new Promise((resolve) => {
    const args = user ? ['--user', 'is-enabled', unit] : ['is-enabled', unit];
    const { execFile } = require('child_process');
    execFile('systemctl', args, { timeout: 3000, env: user ? USER_ENV : process.env }, (err, stdout, stderr) => {
      const raw = (stdout || stderr || '').toString().trim().split(/\s+/)[0] || '';
      if (raw) return resolve(raw);
      if (err) {
        const c = err.code;
        if (c === 1) return resolve('disabled');
        return resolve(null);
      }
      resolve(raw || null);
    });
  });
}
async function dockerRestartPolicy(name) {
  const out = await run('docker', ['inspect', '--format', '{{.HostConfig.RestartPolicy.Name}}', name], 3000);
  if (!out) return null;
  return String(out).trim() || null;
}
async function getDiskUsage() {
  try {
    const stdout = await run('df', ['-B1', '/']);
    if (!stdout) return null;
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) return null;
    const parts = lines[1].trim().split(/\s+/);
    if (parts.length >= 5) return { total: fmtBytes(parts[1]), used: fmtBytes(parts[2]), percent: parts[4], totalRaw: Number(parts[1]), usedRaw: Number(parts[2]) };
  } catch (e) {}
  return null;
}

let prevCpu = null;
let prevNet = null;
let prevDiskIo = null;
let prevTs = null;
let primaryIface = null;

function readCpuSnapshot() {
  try {
    const txt = fs.readFileSync('/proc/stat','utf8');
    const lines = txt.split('\n');
    let total = null, idle = null;
    const perCore = [];
    for (const l of lines) {
      if (!l.startsWith('cpu')) continue;
      const p = l.trim().split(/\s+/);
      const name = p[0];
      const nums = p.slice(1).map(Number);
      if (nums.some(isNaN)) continue;
      const t = nums.reduce((a,b)=>a+b,0);
      const id = (nums[3]||0) + (nums[4]||0);
      if (name === 'cpu') { total = t; idle = id; }
      else if (/^cpu\d+$/.test(name)) perCore.push({ name, total: t, idle: id });
    }
    return { total, idle, perCore };
  } catch(e) { return null; }
}
function readNetSnapshot() {
  try {
    const txt = fs.readFileSync('/proc/net/dev','utf8');
    const lines = txt.split('\n');
    let best = null, bestScore = -1;
    for (const l of lines) {
      const m = l.match(/^\s*([^:]+):\s*(.+)/);
      if (!m) continue;
      const iface = m[1].trim();
      if (iface === 'lo') continue;
      const vals = m[2].trim().split(/\s+/).map(Number);
      const rx = vals[0], tx = vals[8];
      const score = rx + tx;
      if (score > bestScore) { bestScore = score; best = { iface, rx, tx }; }
    }
    if (best) primaryIface = best.iface;
    if (primaryIface) {
      for (const l of lines) {
        const m = l.match(/^\s*([^:]+):\s*(.+)/);
        if (!m) continue;
        if (m[1].trim() === primaryIface) {
          const vals = m[2].trim().split(/\s+/).map(Number);
          return { iface: primaryIface, rx: vals[0], tx: vals[8] };
        }
      }
    }
    return best;
  } catch(e) { return null; }
}
function readDiskIoSnapshot() {
  try {
    const txt = fs.readFileSync('/proc/diskstats','utf8');
    for (const l of txt.split('\n')) {
      const p = l.trim().split(/\s+/);
      if (p.length < 14) continue;
      const name = p[2];
      if (name === 'sda') {
        const sectorsRead = Number(p[5]);
        const sectorsWritten = Number(p[9]);
        return { readBytes: sectorsRead * 512, writeBytes: sectorsWritten * 512 };
      }
    }
    for (const l of txt.split('\n')) {
      const p = l.trim().split(/\s+/);
      if (p[2] === 'sda1') return { readBytes: Number(p[5])*512, writeBytes: Number(p[9])*512 };
    }
  } catch(e) {}
  return null;
}
let raplState = { pkgW: 0, coreW: 0, uncoreW: 0, pkgEnergy: null, coreEnergy: null, uncoreEnergy: null, lastTs: 0, tdpW: 77, maxRange: 65532610987 };
function readRaplFile(p) { try { return parseInt(require('fs').readFileSync(p,'utf8').trim(),10); } catch(e){ return null; } }
function startRaplSampler() {
  try { raplState.tdpW = readRaplFile('/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw')/1e6 || 77; } catch(e){}
  try { raplState.maxRange = readRaplFile('/sys/class/powercap/intel-rapl:0/max_energy_range_uj') || 65532610987; } catch(e){}
  function tick() {
    const now = Date.now();
    const pkg = readRaplFile('/sys/class/powercap/intel-rapl:0/energy_uj');
    const core = readRaplFile('/sys/class/powercap/intel-rapl:0:0/energy_uj');
    const uncore = readRaplFile('/sys/class/powercap/intel-rapl:0:1/energy_uj');
    if (pkg!=null && raplState.pkgEnergy!=null && raplState.lastTs) {
      const dt = (now - raplState.lastTs)/1000;
      const maxR = raplState.maxRange;
      const delta = (a,b)=> b>=a ? b-a : (maxR - a + b);
      if (dt > 0) {
        raplState.pkgW = Number((delta(raplState.pkgEnergy, pkg)/(1e6*dt)).toFixed(2));
        if (core!=null && raplState.coreEnergy!=null) raplState.coreW = Number((delta(raplState.coreEnergy, core)/(1e6*dt)).toFixed(2));
        else raplState.coreW = 0;
        if (uncore!=null && raplState.uncoreEnergy!=null) raplState.uncoreW = Number((delta(raplState.uncoreEnergy, uncore)/(1e6*dt)).toFixed(2));
        else raplState.uncoreW = 0;
      }
    }
    if (pkg!=null) raplState.pkgEnergy = pkg;
    if (core!=null) raplState.coreEnergy = core;
    if (uncore!=null) raplState.uncoreEnergy = uncore;
    raplState.lastTs = now;
  }
  tick();
  setInterval(tick, 1000);
}

startRaplSampler();

app.get('/api/sysinfo', async (req, res) => {
  const diskInfo = await getDiskUsage();
  res.json({
    server: {
      cpu: os.cpus()[0]?.model || 'Unknown CPU',
      cores: os.cpus().length,
      ramTotal: fmtBytes(os.totalmem()),
      ramUsed: fmtBytes(os.totalmem() - os.freemem()),
      ramTotalRaw: os.totalmem(),
      ramUsedRaw: os.totalmem() - os.freemem(),
      uptime: os.uptime(),
      load: os.loadavg(),
      disk: diskInfo || { percent: '0%', used: '-', total: '-' }
    }
  });
});

app.get('/api/metrics', async (req, res) => {
  const now = Date.now();
  const cpuSnap = readCpuSnapshot();
  const netSnap = readNetSnapshot();
  const diskIoSnap = readDiskIoSnapshot();
  const diskInfo = await getDiskUsage();
  const memTotal = os.totalmem();
  const memUsed = memTotal - os.freemem();
  const memPct = memTotal ? (memUsed / memTotal * 100) : 0;

  let cpuPercent = 0;
  let perCorePct = [];
  let intervalSec = 0;
  if (prevCpu && prevTs && cpuSnap) {
    intervalSec = (now - prevTs) / 1000;
    if (intervalSec > 0) {
      const totalDelta = cpuSnap.total - prevCpu.total;
      const idleDelta = cpuSnap.idle - prevCpu.idle;
      if (totalDelta > 0) cpuPercent = Math.max(0, Math.min(100, (1 - idleDelta/totalDelta)*100));
      perCorePct = cpuSnap.perCore.map((c,i)=>{
        const p = prevCpu.perCore[i];
        if (!p) return 0;
        const td = c.total - p.total;
        const id = c.idle - p.idle;
        return td>0 ? Math.max(0,Math.min(100,(1-id/td)*100)) : 0;
      });
    }
  } else if (cpuSnap) {
    perCorePct = cpuSnap.perCore.map(()=>0);
  }

  let rxBps = 0, txBps = 0;
  if (prevNet && netSnap && prevTs) {
    const dt = (now - prevTs)/1000;
    if (dt > 0) {
      rxBps = Math.max(0, (netSnap.rx - prevNet.rx)/dt);
      txBps = Math.max(0, (netSnap.tx - prevNet.tx)/dt);
    }
  }

  let readBps = 0, writeBps = 0;
  if (prevDiskIo && diskIoSnap && prevTs) {
    const dt = (now - prevTs)/1000;
    if (dt > 0) {
      readBps = Math.max(0, (diskIoSnap.readBytes - prevDiskIo.readBytes)/dt);
      writeBps = Math.max(0, (diskIoSnap.writeBytes - prevDiskIo.writeBytes)/dt);
    }
  }

  if (cpuSnap) prevCpu = cpuSnap;
  if (netSnap) prevNet = netSnap;
  if (diskIoSnap) prevDiskIo = diskIoSnap;
  prevTs = now;

  res.json({
    ts: now,
    intervalSec: intervalSec || 0,
    cpu: {
      model: os.cpus()[0]?.model || 'Unknown',
      cores: os.cpus().length,
      percent: Number(cpuPercent.toFixed(1)),
      perCore: perCorePct.map(v=>Number(v.toFixed(1))),
      load: os.loadavg().map(v=>Number(v.toFixed(2))),
    },
    ram: {
      total: memTotal, used: memUsed, free: memTotal - memUsed,
      percent: Number(memPct.toFixed(1)),
      totalFmt: fmtBytes(memTotal), usedFmt: fmtBytes(memUsed), freeFmt: fmtBytes(memTotal - memUsed),
    },
    disk: {
      total: diskInfo?.totalRaw || 0, used: diskInfo?.usedRaw || 0,
      percent: diskInfo ? parseFloat(diskInfo.percent) : 0,
      totalFmt: diskInfo?.total || '-', usedFmt: diskInfo?.used || '-', percentFmt: diskInfo?.percent || '0%',
      readBps, writeBps,
      readFmt: fmtBps(readBps), writeFmt: fmtBps(writeBps),
    },
    net: {
      iface: netSnap?.iface || primaryIface || 'enp2s0',
      rx: netSnap?.rx || 0, tx: netSnap?.tx || 0,
      rxBps, txBps,
      rxFmt: fmtBps(rxBps), txFmt: fmtBps(txBps),
    },
    power: {
      pkgW: raplState.pkgW,
      coreW: raplState.coreW,
      uncoreW: raplState.uncoreW,
      tdpW: raplState.tdpW,
      estTotalW: Number((raplState.pkgW + 8).toFixed(1)),
      kwhDay: Number(( (raplState.pkgW + 8) * 24 / 1000).toFixed(2)),
      costDay: Number((((raplState.pkgW + 8) * 24 / 1000) * 1444).toFixed(0)),
    },
    uptime: os.uptime(),
  });
});

app.get('/api/status', async (req, res) => {
  const [results, ssOut, diskInfo] = await Promise.all([
    Promise.all(
      SERVICES.map(async (svc) => {
        if (svc.noCheck) {
          // external/tunnel target (e.g. OpenWrt on 192.168.1.1) - health via quick curl to target
          let healthy = true;
          let state = 'external';
          let sub = 'tunnel';
          if (svc.target) {
            const code = await run('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', '--connect-timeout', '2', svc.target], 3000);
            if (code) {
              const n = parseInt(String(code).trim(), 10);
              // 200 OK or 403 login required both mean LuCI is alive
              healthy = Number.isFinite(n) && n >= 200 && n < 600;
              state = healthy ? 'reachable' : 'unreachable';
              sub = healthy ? 'reachable' : 'unreachable';
            }
          }
          const { noCheck, target, ...meta } = svc;
          return { ...meta, active: healthy ? 'active' : 'inactive', state, sub, subState: sub, pid: null, memory: null, since: null, uptimeSec: null, healthy, portOpen: null, noCheck: true, target, enabled: null, autoBoot: null };
        }
        if (svc.docker) {
          const [dc, restartPolicy] = await Promise.all([ dockerStatus(svc.unit), dockerRestartPolicy(svc.unit) ]);
          const since = dc ? await dockerSince(svc.unit) : null;
          const running = !!(dc && dc.running);
          const status = dc ? dc.status : 'not found';
          let mem = null;
          if (running) {
            const stats = await run('docker', ['stats', '--no-stream', '--format', '{{.MemUsage}}', svc.unit], 5000);
            if (stats) { const m = stats.trim().split(/\s*\/\s*/)[0]; mem = m || null; }
          }
          const enabled = restartPolicy;
          const autoBoot = restartPolicy === 'always' || restartPolicy === 'unless-stopped';
          return { ...svc, active: running ? 'active' : 'inactive', state: status, sub: running ? 'running' : status, subState: running ? 'running' : status, pid: running ? 1 : 0, memory: mem, since, uptimeSec: since ? Math.floor((Date.now() - since)/1000) : null, healthy: running, portOpen: null, docker: true, enabled, autoBoot };
        }
        const [info, sinceTs, enabledRaw] = await Promise.all([ systemctlShow(svc.unit, svc.user), systemctlSince(svc.unit, svc.user), systemctlIsEnabled(svc.unit, svc.user) ]);
        const active = info ? info.ActiveState : 'unknown';
        const { user, ...meta } = svc;
        const enabled = enabledRaw;
        const autoBoot = enabledRaw === 'enabled' || enabledRaw === 'enabled-runtime';
        return { ...meta, active, sub: info ? info.SubState : 'unknown', pid: info && info.MainPID && info.MainPID !== '0' ? Number(info.MainPID) : null, memory: info ? fmtBytes(info.MemoryCurrent) : null, since: sinceTs, uptimeSec: sinceTs ? Math.floor((Date.now() - sinceTs) / 1000) : null, healthy: active === 'active', enabled, autoBoot };
      })
    ),
    run('ss', ['-tulpn']),
    getDiskUsage(),
  ]);
  results.forEach((r) => { if (r.port) r.portOpen = ssOut ? new RegExp(':' + r.port + '\\b').test(ssOut) : null; });
  res.json({
    generatedAt: Date.now(),
    host: require('os').hostname() || process.env.HOSTNAME || 'iskan-server',
    node: process.version,
    gatewayRss: fmtBytes(process.memoryUsage().rss),
    server: { cpu: os.cpus()[0]?.model || 'Unknown CPU', ramTotal: fmtBytes(os.totalmem()), ramUsed: fmtBytes(os.totalmem() - os.freemem()), uptime: os.uptime(), load: os.loadavg().map(v => v.toFixed(2)), disk: diskInfo },
    services: results,
    summary: { total: results.length, up: results.filter((r) => r.healthy).length, down: results.filter((r) => !r.healthy).length, },
  });
});


// ---- telbot (0xtbug/telbot) control API ----
function parseTelbotEnv() {
  try {
    if (!fs.existsSync(TELBOT_ENV)) return {};
    const txt = fs.readFileSync(TELBOT_ENV, 'utf8');
    const out = {};
    txt.split('\n').forEach(line => {
      const t = line.trim();
      if (!t || t.startsWith('#')) return;
      const i = t.indexOf('=');
      if (i < 1) return;
      let k = t.slice(0,i).trim();
      let v = t.slice(i+1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1,-1);
      out[k] = v;
    });
    return out;
  } catch(e){ return {}; }
}
function maskToken(tok) {
  if (!tok || tok.length < 8) return tok ? '••••' : '';
  return tok.slice(0,4) + '••••' + tok.slice(-4);
}
app.get('/api/telbot/status', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const env = parseTelbotEnv();
    const hasToken = !!(env.TELKOMSEL_BOT_TOKEN && env.TELKOMSEL_BOT_TOKEN !== 'your_bot_token_here' && env.TELKOMSEL_BOT_TOKEN.length > 10);
    const hasAdmin = !!(env.TELEGRAM_ADMIN_ID && env.TELEGRAM_ADMIN_ID !== 'your_telegram_id' && /^\d+$/.test(String(env.TELEGRAM_ADMIN_ID).trim()));
    const configured = hasToken && hasAdmin;
    const [info, enabledRaw, logs] = await Promise.all([
      systemctlShow('telbot.service', false),
      systemctlIsEnabled('telbot.service', false),
      run('journalctl', ['-u', 'telbot.service', '-n', '60', '--no-pager'], 4000)
    ]);
    const active = info ? info.ActiveState : 'unknown';
    const sub = info ? info.SubState : 'unknown';
    const enabled = enabledRaw;
    const autoBoot = enabled === 'enabled' || enabled === 'enabled-runtime';
    // check binary exists
    let binaryOk = false;
    try { binaryOk = fs.existsSync('/usr/local/bin/telbot'); } catch(e){}
    // data dir
    let dataFiles = [];
    try { dataFiles = fs.readdirSync(TELBOT_DIR).filter(f => !f.startsWith('.')).slice(0,20); } catch(e){}
    res.json({
      ok: true,
      binaryOk,
      binaryVersion: 'v1.1.3',
      envExists: fs.existsSync(TELBOT_ENV),
      configured,
      hasToken,
      hasAdmin,
      tokenMasked: hasToken ? maskToken(env.TELKOMSEL_BOT_TOKEN) : '',
      adminId: env.TELEGRAM_ADMIN_ID || '',
      webhookPort: env.OTP_WEBHOOK_PORT || '',
      webhookSecret: env.OTP_WEBHOOK_SECRET ? '••••' + String(env.OTP_WEBHOOK_SECRET).slice(-4) : '',
      webhookSecretSet: !!env.OTP_WEBHOOK_SECRET,
      dataDir: TELBOT_DIR,
      dataFiles,
      service: { active, sub, enabled, autoBoot, pid: info && info.MainPID && info.MainPID !== '0' ? Number(info.MainPID) : null, memory: info ? fmtBytes(info.MemoryCurrent) : null },
      logs: logs ? String(logs).trim().split('\n').slice(-60).join('\n') : ''
    });
  } catch(e){
    res.status(500).json({ error: String(e.message || e) });
  }
});
app.post('/api/telbot/config', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { token, adminId, webhookPort, webhookSecret } = req.body || {};
    const cur = parseTelbotEnv();
    let newToken = (token || '').toString().trim();
    let newAdmin = (adminId || '').toString().trim();
    let newPort = (webhookPort || '').toString().trim();
    let newSecret = (webhookSecret || '').toString().trim();
    // keep existing if empty token/admin and already configured (allow partial update)
    if (!newToken && cur.TELKOMSEL_BOT_TOKEN && cur.TELKOMSEL_BOT_TOKEN !== 'your_bot_token_here') newToken = cur.TELKOMSEL_BOT_TOKEN;
    if (!newAdmin && cur.TELEGRAM_ADMIN_ID) newAdmin = String(cur.TELEGRAM_ADMIN_ID);
    if (!newToken) return res.status(400).json({ error: 'TELKOMSEL_BOT_TOKEN wajib diisi (dari @BotFather)' });
    if (!newAdmin) return res.status(400).json({ error: 'TELEGRAM_ADMIN_ID wajib diisi (angka, dari @userinfobot)' });
    if (!/^\d+$/.test(newAdmin)) return res.status(400).json({ error: 'TELEGRAM_ADMIN_ID harus angka (contoh 123456789)' });
    if (newPort && !/^\d+$/.test(newPort)) return res.status(400).json({ error: 'OTP_WEBHOOK_PORT harus angka port' });
    // ensure dir
    try { fs.mkdirSync(TELBOT_DIR, { recursive: true }); } catch(e){}
    const lines = [];
    lines.push('# Telbot env - managed via Iskan Portal Kuota tab');
    lines.push('# Generated ' + new Date().toISOString());
    lines.push('TELKOMSEL_BOT_TOKEN=' + newToken);
    lines.push('TELEGRAM_ADMIN_ID=' + newAdmin);
    if (newPort) lines.push('OTP_WEBHOOK_PORT=' + newPort);
    if (newSecret) lines.push('OTP_WEBHOOK_SECRET=' + newSecret);
    else if (cur.OTP_WEBHOOK_SECRET && !newSecret) {
      // keep existing secret if not provided and port kept? only keep if user didn't clear port
      if (newPort && cur.OTP_WEBHOOK_SECRET) lines.push('OTP_WEBHOOK_SECRET=' + cur.OTP_WEBHOOK_SECRET);
    }
    fs.writeFileSync(TELBOT_ENV, lines.join('\n') + '\n', { mode: 0o600 });
    try { fs.chmodSync(TELBOT_ENV, 0o600); } catch(e){}
    res.json({ ok: true, message: 'Config tersimpan ke ' + TELBOT_ENV, maskedToken: maskToken(newToken) });
  } catch(e){
    res.status(500).json({ error: String(e.message || e) });
  }
});
app.post('/api/telbot/action', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  const act = (req.body && req.body.action || '').toString().trim();
  if (!['start','stop','restart','enable','disable'].includes(act)) return res.status(400).json({ error: 'action harus start|stop|restart|enable|disable' });
  try {
    let cmd = act;
    // systemctl enable/disable vs start/stop/restart
    const out = await run('systemctl', [cmd, 'telbot.service'], 8000);
    // run returns null on err, but we want journal
    await new Promise(r => setTimeout(r, 800));
    const info = await systemctlShow('telbot.service', false);
    const logs = await run('journalctl', ['-u', 'telbot.service', '-n', '30', '--no-pager'], 4000);
    res.json({ ok: true, action: act, active: info ? info.ActiveState : 'unknown', sub: info ? info.SubState : 'unknown', logs: logs ? String(logs).trim().split('\n').slice(-30).join('\n') : '' });
  } catch(e){
    res.status(500).json({ error: String(e.message || e) });
  }
});
app.get('/api/telbot/logs', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  const n = Math.min(500, Math.max(10, parseInt(req.query.n || '120', 10) || 120));
  const logs = await run('journalctl', ['-u', 'telbot.service', '-n', String(n), '--no-pager'], 5000);
  res.json({ ok: true, logs: logs ? String(logs).trim() : '(no logs yet)' });
});

app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('/sw.js')) {
      res.setHeader('Service-Worker-Allowed', '/');
      res.setHeader('Cache-Control', 'no-cache');
    }
    if (filePath.endsWith('/manifest.json')) {
      res.setHeader('Content-Type', 'application/manifest+json');
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));
app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => { console.log(`Iskan private portal on http://0.0.0.0:${PORT}`); });
