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
  { unit: 'autoclipper-v3.service',      name: 'Auto-Clipper v3',       kind: 'app',   port: 3006,  desc: 'Auto-Clipper v3 5 tabs pipeline · AI opencos 20127 · webjs/server.v3.js', path: '/root/auto-clipper-v3', tech: 'Node.js / Python · AI', externalUrl: 'https://clip.nendi.web.id', dashboardPath: '/' },
  { unit: 'iskan-portal.service',      name: 'Iskan Portal',       kind: 'app',   port: 3005,  desc: 'Portal status (halaman ini)', path: '/root/iskan-portal', tech: 'Node.js / Express', externalUrl: 'https://portal.nendi.web.id', dashboardPath: '/' },
  { unit: 'auto-clipper-v2-bot.service', name: 'Auto-Clipper Bot', kind: 'bot', port: null, desc: 'Telegram bot pipeline', tech: 'Python', externalUrl: null },
  { unit: 'hermes-gateway.service',      name: 'Hermes Gateway',   kind: 'bot', port: null, desc: 'Hermes Agent messaging gateway', user: true, tech: 'Node.js', externalUrl: null },
  { unit: '9router-mibp.service',            name: '9Router',         kind: 'infra', port: 20127, desc: 'AI router dashboard (Next.js 16) · /dashboard', path: '/root/9router-mibp-version', tech: 'Next.js 16 / React 19', externalUrl: 'https://9r.nendi.web.id', dashboardPath: '/' },
  { unit: 'omniroute.service',               name: 'OmniRoute',      kind: 'infra', port: 20128, desc: 'AI gateway proxy (~2900 models) · dashboard /dashboard', tech: 'Go (Golang)', externalUrl: 'https://omni.nendi.web.id', dashboardPath: '/dashboard' },
  { unit: 'docker.service',                  name: 'Docker',         kind: 'infra', port: null,  desc: 'Container runtime', tech: 'Docker', externalUrl: null },
  { unit: 'cf-manager',                          name: 'CF Manager',     kind: 'infra', port: 3010,  desc: 'Cloudflare multi-account manager', path: '/root/cf-manager', tech: 'Vue3 + Express / Docker', docker: true, externalUrl: 'https://cf.nendi.web.id', dashboardPath: '/' },
  { unit: 'owrt.nendi.web.id',                 name: 'OpenWrt - iskanWRT', kind: 'infra', port: null,  desc: 'Router LuCI via tunnel → 192.168.1.1:80 (MetaCubeXD di metacubex.nendi.web.id)', path: null, tech: 'OpenWrt / LuCI', externalUrl: 'https://owrt.nendi.web.id', dashboardPath: '/', target: 'http://192.168.1.1:80', noCheck: true },
  { unit: 'metacubex.nendi.web.id',            name: 'MetaCubeXD',         kind: 'infra', port: 9090,  desc: 'MetaCubeXD via tunnel → 192.168.1.1:9090/ui/metacubexd', path: null, tech: 'MetaCubeXD / Mihomo', externalUrl: 'https://metacubex.nendi.web.id/ui/metacubexd/#/setup?hostname=metacubex.nendi.web.id&secret=rzx', dashboardPath: '/ui/metacubexd/#/setup?hostname=metacubex.nendi.web.id&secret=rzx', target: 'http://192.168.1.1:9090', noCheck: true },
  { unit: 'ttyd.service',                       name: 'Web Terminal',     kind: 'infra', port: 7681, desc: 'Web terminal (ttyd 1.7.7) → https://ssh.nendi.web.id', path: null, tech: 'ttyd / login', externalUrl: 'https://ssh.nendi.web.id', dashboardPath: '/' },
  { unit: 'cloudflared.service',                 name: 'Cloudflared Tunnel', kind: 'infra', port: null, desc: 'Named tunnel 204640e4 → 13 hostnames (nendi.web.id + 9r/drama/portal/clipper/clip/cf/omni/llm/owrt/ssh)', tech: 'Cloudflare Tunnel', externalUrl: null },
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
let overviewPrevNet = null;
let overviewPrevDisk = null;
let overviewPrevTs = null;

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
function readCpuTemps() {
  try {
    var temps = {};
    var pkg = null;
    var cores = [];
    var all = [];
    try {
      var base = '/sys/class/hwmon/hwmon1';
      if (fs.existsSync(base)) {
        for (var i = 1; i <= 10; i++) {
          var p = base + '/temp' + i + '_input';
          try {
            if (!fs.existsSync(p)) continue;
            var v = parseInt(fs.readFileSync(p, 'utf8').trim(), 10);
            if (isNaN(v)) continue;
            var label = '';
            try { label = fs.readFileSync(base + '/temp' + i + '_label', 'utf8').trim(); } catch(e) {}
            var c = Number((v / 1000).toFixed(1));
            if (label.indexOf('Package') !== -1 || i === 1) {
              if (pkg == null) pkg = c;
              else pkg = c;
            } else if (label.indexOf('Core') !== -1) {
              cores.push(c);
            }
            all.push({ label: label || ('temp' + i), temp: c });
          } catch(e) {}
        }
      }
    } catch(e) {}
    if (pkg == null) {
      try {
        var t = fs.readFileSync('/sys/class/thermal/thermal_zone2/temp', 'utf8');
        var n = parseInt(t.trim(), 10);
        if (!isNaN(n)) pkg = Number((n / 1000).toFixed(1));
      } catch(e) {}
    }
    if (pkg == null && all.length) pkg = all[0].temp;
    temps.pkg = pkg;
    temps.cores = cores;
    temps.all = all;
    var zones = [];
    try {
      var dirs = fs.readdirSync('/sys/class/thermal');
      dirs.forEach(function(d) {
        if (d.indexOf('thermal_zone') === 0) {
          try {
            var tt = fs.readFileSync('/sys/class/thermal/' + d + '/temp', 'utf8');
            var nn = parseInt(tt.trim(), 10);
            var tp = '';
            try { tp = fs.readFileSync('/sys/class/thermal/' + d + '/type', 'utf8').trim(); } catch(e) {}
            if (!isNaN(nn)) zones.push({ type: tp, temp: Number((nn / 1000).toFixed(1)) });
          } catch(e) {}
        }
      });
    } catch(e) {}
    temps.zones = zones;
    return temps;
  } catch(e) { return { pkg: null, cores: [], zones: [], all: [] }; }
}
function fmtUptimeOverview(sec) {
  if (sec == null || sec < 0) return '-';
  var d = Math.floor(sec / 86400);
  var h = Math.floor((sec % 86400) / 3600);
  var m = Math.floor((sec % 3600) / 60);
  var s = Math.floor(sec % 60);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm ' + s + 's';
  if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
  if (m > 0) return m + 'm ' + s + 's';
  return s + 's';
}
function readMeminfoDetailed(){
  try{
    const txt = fs.readFileSync('/proc/meminfo','utf8');
    const m = {};
    txt.split('\n').forEach(l=>{
      const a=l.split(':');
      if(a.length<2) return;
      const k=a[0].trim(), v=parseInt(a[1].trim().split(/\s+/)[0],10)*1024;
      if(!isNaN(v)) m[k]=v;
    });
    return {
      memTotal: m.MemTotal||os.totalmem(),
      memAvailable: m.MemAvailable||os.freemem(),
      memBuffers: m.Buffers||0,
      memCached: (m.Cached||0)+(m.SReclaimable||0),
      memFree: m.MemFree||os.freemem(),
    };
  }catch(e){ return null; }
}
function readThermal(){
  try{
    let cpuTemp=null, boardTemp=null, amlThermal=null;
    // hwmon coretemp
    try{
      const c1=parseInt(fs.readFileSync('/sys/class/hwmon/hwmon1/temp1_input','utf8').trim(),10);
      if(!isNaN(c1)) cpuTemp=Math.round(c1/1000);
    }catch(e){}
    // fallback thermal_zone x86_pkg_temp
    if(cpuTemp==null){
      try{
        for(let i=0;i<4;i++){
          const type=fs.readFileSync('/sys/class/thermal/thermal_zone'+i+'/type','utf8').trim();
          if(type==='x86_pkg_temp'){
            const t=parseInt(fs.readFileSync('/sys/class/thermal/thermal_zone'+i+'/temp','utf8').trim(),10);
            if(!isNaN(t)) cpuTemp=Math.round(t/1000);
            break;
          }
        }
      }catch(e){}
    }
    // board / acpitz
    try{
      const t2=parseInt(fs.readFileSync('/sys/class/thermal/thermal_zone0/temp','utf8').trim(),10);
      if(!isNaN(t2)) boardTemp=Math.round(t2/1000);
    }catch(e){}
    // aml_thermal on OpenWrt mapped to boardTemp; on VPS we alias cpuTemp
    amlThermal=boardTemp!=null?boardTemp:cpuTemp;
    // per-core temps
    let coreTemps=[];
    try{
      for(let k=2;k<=5;k++){
        try{ const v=parseInt(fs.readFileSync('/sys/class/hwmon/hwmon1/temp'+k+'_input','utf8').trim(),10); if(!isNaN(v)) coreTemps.push(Math.round(v/1000)); }catch(e){}
      }
    }catch(e){}
    // cpu-thermal alias for x86_pkg_temp zone2
    let cpuThermal=null;
    try{ cpuThermal=parseInt(fs.readFileSync('/sys/class/thermal/thermal_zone2/temp','utf8').trim(),10); if(!isNaN(cpuThermal)) cpuThermal=Math.round(cpuThermal/1000); else cpuThermal=cpuTemp; }catch(e){ cpuThermal=cpuTemp; }
    return { cpuTemp, boardTemp, amlThermal, cpuThermal, coreTemps };
  }catch(e){ return { cpuTemp:null, boardTemp:null, amlThermal:null, cpuThermal:null, coreTemps:[] }; }
}
function readDfDetailed(){
  try{
    const out = require('child_process').execFileSync('df', ['-B1','/','/tmp','/dev/shm'], {timeout:1500}).toString();
    const lines=out.trim().split('\n').slice(1);
    const map={};
    lines.forEach(l=>{
      const p=l.trim().split(/\s+/);
      if(p.length<6) return;
      const mp=p[5];
      map[mp]={ total: Number(p[1]), used: Number(p[2]), avail: Number(p[3]), percent: p[4] };
    });
    return map;
  }catch(e){ return {}; }
}
function readNetDetailed(){
  try{
    const txt=fs.readFileSync('/proc/net/dev','utf8');
    const out={};
    txt.split('\n').forEach(l=>{
      const m=l.match(/^\s*([^:]+):\s*(.+)/);
      if(!m) return;
      const iface=m[1].trim();
      const vals=m[2].trim().split(/\s+/).map(Number);
      out[iface]={ rx: vals[0], tx: vals[8] };
      // try operstate/speed
      try{ out[iface].speed=parseInt(fs.readFileSync('/sys/class/net/'+iface+'/speed','utf8').trim(),10); }catch(e){ out[iface].speed=null; }
      try{ out[iface].operstate=fs.readFileSync('/sys/class/net/'+iface+'/operstate','utf8').trim(); }catch(e){ out[iface].operstate='unknown'; }
      try{ out[iface].carrier=fs.readFileSync('/sys/class/net/'+iface+'/carrier','utf8').trim(); }catch(e){ out[iface].carrier=null; }
    });
    return out;
  }catch(e){ return {}; }
}
function readFirmware(){
  try{
    const txt=fs.readFileSync('/etc/os-release','utf8');
    const m=txt.match(/PRETTY_NAME="([^"]+)"/);
    if(m) return m[1];
    const m2=txt.match(/PRETTY_NAME=([^\n]+)/);
    if(m2) return m2[1].replace(/"/g,'').trim();
  }catch(e){}
  return 'Debian '+os.release();
}
function readPveKernel(){ try{ return fs.readFileSync('/proc/sys/kernel/osrelease','utf8').trim(); }catch(e){ return os.release(); } }

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

// docker mem cache  -  biar /api/status gak ke-block 2s oleh `docker stats`
const dockerMemCache = new Map();
// warm cache once at boot (background, non-blocking)
setTimeout(() => {
  for (const svc of SERVICES) if (svc.docker) {
    run('docker', ['stats', '--no-stream', '--format', '{{.MemUsage}}', svc.unit], 2500).then(out => {
      try { const m = out ? String(out).trim().split(/\s*\/\s*/)[0] : null; if(m) dockerMemCache.set(svc.unit, { mem:m, ts:Date.now() }); } catch(e){}
    });
  }
}, 1500);

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
  const memDet = readMeminfoDetailed();
  const thermal = readThermal();
  const dfMap = readDfDetailed();
  const netMap = readNetDetailed();
  const firmware = readFirmware();
  const kernel = readPveKernel();

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

  // gather ip/gateway/dns for overview
  let enpIp='192.168.1.111';
  try{
    const ifs=os.networkInterfaces();
    const enp=(ifs['enp2s0']||[]).find(a=>a.family==='IPv4');
    if(enp) enpIp=enp.address;
  }catch(e){}
  let gateway=null;
  try{
    const gwOut=require('child_process').execFileSync('ip',['-4','route','show','default'],{timeout:1200}).toString();
    const m=gwOut.match(/via\s+([\d.]+)/);
    if(m) gateway=m[1];
  }catch(e){}
  let dns=null;
  try{
    const r=fs.readFileSync('/etc/resolv.conf','utf8');
    const m=r.match(/nameserver\s+([^\s]+)/);
    if(m) dns=m[1];
  }catch(e){}

  res.json({
    ts: now,
    intervalSec: intervalSec || 0,
    hostname: os.hostname(),
    firmware,
    kernel,
    localTime: new Date().toISOString(),
    cpu: {
      model: os.cpus()[0]?.model || 'Intel i5-3470',
      cores: os.cpus().length,
      percent: Number(cpuPercent.toFixed(1)),
      perCore: perCorePct.map(v=>Number(v.toFixed(1))),
      load: os.loadavg().map(v=>Number(v.toFixed(2))),
    },
    ram: {
      total: memTotal, used: memUsed, free: memTotal - memUsed,
      percent: Number(memPct.toFixed(1)),
      totalFmt: fmtBytes(memTotal), usedFmt: fmtBytes(memUsed), freeFmt: fmtBytes(memTotal - memUsed),
      available: memDet?memDet.memAvailable:null,
      availableFmt: memDet?fmtBytes(memDet.memAvailable):'-',
      buffered: memDet?memDet.memBuffers:null,
      bufferedFmt: memDet?fmtBytes(memDet.memBuffers):'-',
      cached: memDet?memDet.memCached:null,
      cachedFmt: memDet?fmtBytes(memDet.memCached):'-',
    },
    disk: {
      total: diskInfo?.totalRaw || 0, used: diskInfo?.usedRaw || 0,
      percent: diskInfo ? parseFloat(diskInfo.percent) : 0,
      totalFmt: diskInfo?.total || '-', usedFmt: diskInfo?.used || '-', percentFmt: diskInfo?.percent || '0%',
      readBps, writeBps,
      readFmt: fmtBps(readBps), writeFmt: fmtBps(writeBps),
      dfMap,
    },
    net: {
      iface: netSnap?.iface || primaryIface || 'enp2s0',
      rx: netSnap?.rx || 0, tx: netSnap?.tx || 0,
      rxBps, txBps,
      rxFmt: fmtBps(rxBps), txFmt: fmtBps(txBps),
      enpIp,
      gateway,
      dns,
      detailed: netMap,
    },
    thermal,
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
            const cached = dockerMemCache.get(svc.unit);
            if (cached) mem = cached.mem;
            // background refresh if stale (not awaited - fire & forget, never blocks /api/status)
            const ts = cached ? cached.ts : 0;
            if (Date.now() - ts > 8000) {
              run('docker', ['stats', '--no-stream', '--format', '{{.MemUsage}}', svc.unit], 2500).then(out => {
                try {
                  const m = out ? String(out).trim().split(/\s*\/\s*/)[0] : null;
                  if (m) dockerMemCache.set(svc.unit, { mem: m, ts: Date.now() });
                } catch(e){}
              });
            }
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


// ---- sidompul proxy (XL/Axis cek kuota via apigw; key di server, hindari CORS + bocor key) ----
const SIDOMPUL_AUTH = 'Basic c2lkb21wdWxhcGk6YXBpZ3drbXNw';
const SIDOMPUL_KEY = '60ef29aa-a648-4668-90ae-20951ef90c55';
const SIDOMPUL_CACHE_DIR = path.join(__dirname, 'data', 'sidompul');
try { fs.mkdirSync(SIDOMPUL_CACHE_DIR, { recursive: true }); } catch(e) {}
function sidompulCachePath(msisdn) {
  const safe = String(msisdn || '').replace(/\D/g, '').slice(0, 16);
  return path.join(SIDOMPUL_CACHE_DIR, safe + '.json');
}
// Cache hasil GET terakhir: buka tab tampil ini, Refresh baru fetch upstream
app.get('/api/sidompul/cache', (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  let msisdn = String(req.query.msisdn || '').replace(/\D/g, '');
  if (msisdn.charAt(0) === '0') msisdn = '62' + msisdn.slice(1);
  if (!/^62\d{8,14}$/.test(msisdn)) return res.status(400).json({ ok: false, error: 'Nomor tidak valid (contoh 0878xxx)' });
  try {
    const fp = sidompulCachePath(msisdn);
    if (!fs.existsSync(fp)) return res.status(404).json({ ok: false, cached: false, error: 'Belum ada data tersimpan, klik Refresh' });
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return res.json({ ok: true, cached: true, msisdn, fetchedAt: raw.fetchedAt || null, data: raw.data || raw });
  } catch(e) {
    return res.status(500).json({ ok: false, error: 'Gagal baca cache: ' + String((e && e.message) || e) });
  }
});
app.get('/api/sidompul/cek', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  let msisdn = String(req.query.msisdn || '').replace(/\D/g, '');
  if (msisdn.charAt(0) === '0') msisdn = '62' + msisdn.slice(1);
  if (!/^62\d{8,14}$/.test(msisdn)) return res.status(400).json({ ok: false, error: 'Nomor tidak valid (contoh 0878xxx)' });
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => { try { ctrl.abort(); } catch(e){} }, 15000);
    const url = 'https://apigw.kmsp-store.com/sidompul/v4/cek_kuota?msisdn=' + encodeURIComponent(msisdn) + '&isJSON=true&_=' + Date.now();
    const r = await fetch(url, { method: 'GET', headers: { 'Accept': 'application/json', 'Authorization': SIDOMPUL_AUTH, 'x-api-key': SIDOMPUL_KEY, 'x-app-version': '4.0.0' }, signal: ctrl.signal });
    clearTimeout(t);
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch(e) { return res.status(502).json({ ok: false, error: 'Upstream bukan JSON', raw: String(text).slice(0, 300) }); }
    if (!r.ok) return res.status(r.status).json(json);
    try { fs.writeFileSync(sidompulCachePath(msisdn), JSON.stringify({ fetchedAt: new Date().toISOString(), msisdn, data: json })); } catch(e) {}
    return res.json(json);
  } catch(e) {
    const msg = (e && e.name === 'AbortError') ? 'Upstream timeout (15s)' : String((e && e.message) || e);
    return res.status(502).json({ ok: false, error: msg });
  }
});

// ---- telkomsel native (CIAM OTP + TDW api, pola sama kayak TRI, tanpa telbot binary) ----
const TSEL_DIR = path.join(__dirname, 'data', 'telkomsel');
try { fs.mkdirSync(TSEL_DIR, { recursive: true }); } catch(e) {}
const TSEL_AUTH_FILE = path.join(TSEL_DIR, 'auth.json');
const TSEL_CACHE_FILE = path.join(TSEL_DIR, 'cache.json');
const TSEL_SESSION_FILE = path.join(TSEL_DIR, 'session.json');
const TSEL_PENDING_FILE = path.join(TSEL_DIR, 'otp_pending.json');
const TSEL_CIAM = 'https://ciam.telkomsel.com';
const TSEL_REALM = 'tsel';
const TSEL_CLIENT_ID = 'e7126474617aa39eb9e484233c9b0649';
const TSEL_CLIENT_SECRET = 'P@ssw0rd';
const TSEL_REDIRECT_URI = 'https://my.telkomsel.com/web/callback';
const TSEL_LOGIN_ORIGIN = 'https://my.telkomsel.com';
const TSEL_AUTH_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36';
const TSEL_TDW = 'https://tdw.telkomsel.com';
const TSEL_WEBAPP_VER = '2.0.0';
const TSEL_ENC_PASS = 'production';
function tselAuth() { try { return JSON.parse(fs.readFileSync(TSEL_AUTH_FILE, 'utf8')); } catch(e) { return null; } }
function tselLoadSession(){ try{ return JSON.parse(fs.readFileSync(TSEL_SESSION_FILE,'utf8')); }catch(e){ return null; } }
function tselSaveSession(obj){ try{ fs.writeFileSync(TSEL_SESSION_FILE, JSON.stringify(obj,null,2), {mode:0o600}); try{fs.chmodSync(TSEL_SESSION_FILE,0o600);}catch(e){} }catch(e){} }
function tselLoadPending(){ try{ return JSON.parse(fs.readFileSync(TSEL_PENDING_FILE,'utf8')); }catch(e){ return null; } }
function tselSavePending(obj){ try{ fs.writeFileSync(TSEL_PENDING_FILE, JSON.stringify(obj,null,2), {mode:0o600}); try{fs.chmodSync(TSEL_PENDING_FILE,0o600);}catch(e){} }catch(e){} }
function tselClearPending(){ try{ fs.unlinkSync(TSEL_PENDING_FILE);}catch(e){} }
function tselNormalizePhone(input){
  let clean=String(input||'').replace(/[^0-9]/g,'');
  if(clean.startsWith('62')) clean=clean.substring(2);
  else if(clean.startsWith('0')) clean=clean.substring(1);
  const isValid = clean.startsWith('8') && clean.length>=9 && clean.length<=13;
  return { clean, national:'0'+clean, international:'62'+clean, isValid };
}
function tselRandomHex(n){ return crypto.randomBytes(n).toString('hex'); }
function tselXDevice(){ return tselRandomHex(4)+'-'+tselRandomHex(2)+'-'+tselRandomHex(2)+'-'+tselRandomHex(2)+'-'+tselRandomHex(6); }
function tselTxId(){ const d=new Date(); const p=(n,l)=>String(n).padStart(l||2,'0'); return 'A'+p(d.getFullYear()%100)+p(d.getMonth()+1)+p(d.getDate())+p(d.getHours())+p(d.getMinutes())+p(d.getSeconds())+'000000148700'; }
function tselEvp(password, keyLen, ivLen){
  const pass=Buffer.from(password); let hb=Buffer.alloc(0); let res=Buffer.alloc(0);
  while(res.length<keyLen+ivLen){ const m=crypto.createHash('md5').update(Buffer.concat([hb,pass])).digest(); hb=m; res=Buffer.concat([res,m]); }
  return { key:res.slice(0,keyLen), iv:res.slice(keyLen,keyLen+ivLen) };
}
function tselEnc(payload){
  const {key,iv}=tselEvp(TSEL_ENC_PASS,16,16);
  const c=crypto.createCipheriv('aes-128-ofb',key,iv);
  return Buffer.concat([c.update(payload,'utf8'),c.final()]).toString('base64');
}
function tselAuthHeaders(accessToken,idToken){
  const ts=new Date().toISOString().slice(0,19)+'Z';
  return {
    accessAuth:'Bearer '+tselEnc(JSON.stringify({accessToken,timestamp:ts})),
    authorization:'Bearer '+tselEnc(JSON.stringify({token:idToken,timestamp:ts}))
  };
}
function tselAuthUrl(){ return TSEL_CIAM+'/iam/v1/realms/'+TSEL_REALM+'/authenticate?authIndexType=service&authIndexValue=phoneLogin'; }
function tselGetSetCookies(headers){
  try{ if(headers && typeof headers.getSetCookie==='function') return headers.getSetCookie()||[]; }catch(e){}
  try{ const sc=headers.get('set-cookie'); return sc?[sc]:[]; }catch(e){ return []; }
}
function tselCookie(arr,name){
  for(const c of (arr||[])){ const main=String(c).split(';')[0].trim(); if(main.startsWith(name+'=')) return main; }
  return '';
}
async function tselCiam(url, method, headers, body, ms){
  const ctrl=new AbortController(); const t=setTimeout(()=>{try{ctrl.abort();}catch(e){}}, ms||20000);
  try{
    const r=await fetch(url,{method,headers,body:body===undefined?undefined:body,redirect:'manual',signal:ctrl.signal});
    const text=await r.text(); let j=null; try{ j=JSON.parse(text); }catch(e){}
    return { status:r.status, headers:r.headers, text, json:j };
  } finally { clearTimeout(t); }
}
function tselJwtExp(token){
  try{
    var part=String(token||'').split('.')[1];
    if(!part) return null;
    var b=part.replace(/-/g,'+').replace(/_/g,'/');
    while(b.length%4) b+='=';
    var js=Buffer.from(b,'base64').toString('utf8');
    var pl=JSON.parse(js);
    var exp=Number(pl.exp)||0; var iat=Number(pl.iat)||0;
    if(!exp) return null;
    var now=Math.floor(Date.now()/1000);
    var rem=Math.max(0, exp-now);
    var ttl=iat? (exp-iat):0;
    return {exp:exp, iat:iat||null, expIso:new Date(exp*1000).toISOString(), iatIso:iat?new Date(iat*1000).toISOString():null, ttlSec:ttl, remainingSec:rem};
  }catch(e){ return null; }
}
function tselTdwHeaders(sess){
  return {
    'accept':'application/json',
    'accept-language':'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    'accessauthorization':'Bearer '+sess.accessAuth,
    'authorization':'Bearer '+sess.authorization,
    'authserver':'2',
    'channelid':'WEB',
    'content-type':'application/json',
    'dnt':'1',
    'hash':sess.hash||tselRandomHex(28),
    'language':'id',
    'mytelkomsel-web-app-version':sess.webAppVersion||TSEL_WEBAPP_VER,
    'origin':'https://my.telkomsel.com',
    'priority':'u=1, i',
    'referer':'https://my.telkomsel.com/',
    'sec-ch-ua':'"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
    'sec-ch-ua-mobile':'?0',
    'sec-ch-ua-platform':'"Windows"',
    'sec-fetch-dest':'empty',
    'sec-fetch-mode':'cors',
    'sec-fetch-site':'same-site',
    'transactionid':tselTxId(),
    'user-agent':tselRandomHex(2) ? TSEL_AUTH_UA : TSEL_AUTH_UA,
    'web-msisdn':sess.fullPhone||sess.msisdn||'',
    'x-device':sess.xDevice||''
  };
}
async function tselTdw(sess, method, endpoint, body){
  const url=TSEL_TDW+endpoint;
  for(let attempt=0; attempt<3; attempt++){
    const H=tselTdwHeaders(sess);
    const ctrl=new AbortController(); const t=setTimeout(()=>{try{ctrl.abort();}catch(e){}},20000);
    try{
      const r=await fetch(url,{method,headers:H,body:body?JSON.stringify(body):undefined,signal:ctrl.signal});
      const txt=await r.text();
      if(r.status===401){ const e=new Error('unauthorized: token expired'); e.code=401; throw e; }
      if(r.status===429){
        if(attempt<2){ await new Promise(rs=>setTimeout(rs,5000*(attempt+1))); continue; }
        throw new Error('rate limited (429) on '+endpoint);
      }
      if(r.status!==200){
        if(attempt<2){ await new Promise(rs=>setTimeout(rs,3000*(attempt+1))); continue; }
        throw new Error('HTTP '+r.status+' from '+endpoint+': '+String(txt).slice(0,300));
      }
      let j=null; try{ j=JSON.parse(txt); }catch(e){
        if(attempt<2){ await new Promise(rs=>setTimeout(rs,3000)); continue; }
        throw new Error('invalid JSON from '+endpoint);
      }
      return j;
    } finally { clearTimeout(t); }
  }
  throw new Error('max retries exceeded for '+method+' '+endpoint);
}
function tselQuotaItems(groups){
  const items=[];
  (groups||[]).forEach(function(g){
    const cls=String(g.class||g.Class||'Kuota');
    const list=g.items||g.bonusList||g.BonusList||[];
    (list||[]).forEach(function(it){
      const nm=it.name||it.Name||it.bucketdescription||cls;
      items.push({name:cls+' - '+nm, type:'MAIN', category:'internet', remainingQuota:null, quota:null, remainingFormatted:String(it.remaining||it.Remaining||it.remainingquota||'-'), exhausted:false, validUntil:it.expiry||it.Expiry||it.expirydate||'-'});
    });
  });
  return items;
}
// Cache hasil GET terakhir: buka tab tampil ini, Refresh baru fetch upstream
app.get('/api/telkomsel/cache', (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  try {
    if (!fs.existsSync(TSEL_CACHE_FILE)) return res.status(404).json({ ok: false, cached: false, error: 'Belum ada data tersimpan, klik Refresh' });
    const raw = JSON.parse(fs.readFileSync(TSEL_CACHE_FILE, 'utf8'));
    return res.json({ ok: true, cached: true, fetchedAt: raw.fetchedAt || null, data: raw });
  } catch(e) {
    return res.status(500).json({ ok: false, error: 'Gagal baca cache: ' + String((e && e.message) || e) });
  }
});
app.get('/api/telkomsel/status', (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const sess=tselLoadSession();
  const hasCache=fs.existsSync(TSEL_CACHE_FILE);
  const pending=tselLoadPending();
  var expiry=null;
  try{ if(sess&&sess.accessToken) expiry=tselJwtExp(sess.accessToken); else if(sess&&sess.idToken) expiry=tselJwtExp(sess.idToken); }catch(e){}
  var sessOut=null;
  if(sess) sessOut={phone:sess.phone,msisdn:sess.msisdn,userType:sess.userType,updatedAt:sess.updatedAt,expiry:expiry,expiresAt:expiry?expiry.expIso:null,remainingSec:expiry?expiry.remainingSec:null,ttlDays:expiry&&expiry.ttlSec?Math.round(expiry.ttlSec/86400):null};
  return res.json({ok:true, session: sessOut, expiry:expiry, hasToken:!!(sess&&sess.accessAuth&&sess.authorization), hasCache, pending: pending?{msisdn:pending.msisdn,transId:pending.transId,createdAt:pending.createdAt}:null});
});
app.post('/api/telkomsel/login', async (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const phoneRaw=String((req.body&&req.body.phone)||'').trim();
  const norm=tselNormalizePhone(phoneRaw);
  if(!norm.isValid) return res.status(400).json({ok:false,error:'Nomor Telkomsel tidak valid (contoh 0812xxxxxxx)'});
  try{
    const headers={
      'User-Agent':TSEL_AUTH_UA,'Accept':'application/json','Dnt':'1','Sec-Ch-Ua-Mobile':'?0',
      'Origin':TSEL_LOGIN_ORIGIN,'Referer':TSEL_LOGIN_ORIGIN+'/','Sec-Fetch-Site':'same-site','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty',
      'Am-Phonenumber':'+'+norm.international,'Am-Clientid':TSEL_CLIENT_ID,'Am-Send':'otp','Content-Type':'application/json',
      'Sec-Ch-Ua':'"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"','Sec-Ch-Ua-Platform':'"Windows"',
      'Accept-Language':'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7','Priority':'u=1, i'
    };
    const r1=await tselCiam(tselAuthUrl(),'POST',headers,'',20000);
    if(r1.status!==200) return res.status(400).json({ok:false,error:'Request OTP status '+r1.status+': '+String(r1.text).slice(0,300)});
    const authId=(r1.json&&r1.json.authId)||'';
    if(!authId) return res.status(400).json({ok:false,error:'Gagal request OTP: authId kosong'});
    const amlb=tselCookie(tselGetSetCookies(r1.headers),'amlbcookie');
    tselSavePending({msisdn:norm.international,phone:norm.national,transId:authId,amlb,createdAt:new Date().toISOString()});
    const sess=tselLoadSession()||{};
    sess.phone=norm.national; sess.msisdn=norm.international; sess.fullPhone=norm.international;
    sess.userType='PENDING'; sess.updatedAt=new Date().toISOString();
    sess.pendingAuthId=authId; sess.pendingAmlb=amlb;
    if(!sess.xDevice) sess.xDevice=tselXDevice();
    if(!sess.hash) sess.hash=tselRandomHex(28);
    tselSaveSession(sess);
    return res.json({ok:true,message:'OTP terkirim ke '+norm.national+' via SMS',transId:authId,msisdn:norm.international});
  }catch(e){
    return res.status(502).json({ok:false,error:String((e&&e.message)||e)});
  }
});
app.post('/api/telkomsel/verify', async (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const otp=String((req.body&&req.body.otp)||'').trim();
  let transId=String((req.body&&req.body.transId)||'').trim();
  let phone=String((req.body&&req.body.phone)||'').trim();
  if(!/^[0-9]{4,8}$/.test(otp)) return res.status(400).json({ok:false,error:'OTP harus 4-8 digit angka'});
  const pending=tselLoadPending();
  if(!transId) transId=(pending&&pending.transId)||((tselLoadSession()||{}).pendingAuthId)||'';
  if(!phone) phone=(pending&&pending.phone)||(pending&&pending.msisdn)||'';
  let amlb=(pending&&pending.amlb)||((tselLoadSession()||{}).pendingAmlb)||'';
  if(!transId) return res.status(400).json({ok:false,error:'Session OTP tidak ditemukan, kirim OTP dulu'});
  try{
    const norm=tselNormalizePhone(phone);
    const body2={authId:transId,callbacks:[
      {type:'PasswordCallback',output:[{name:'prompt',value:'One Time Password'}],input:[{name:'IDToken1',value:otp}]},
      {type:'ConfirmationCallback',output:[{name:'prompt',value:''},{name:'messageType',value:0},{name:'options',value:['Submit OTP','Request OTP']},{name:'optionType',value:-1},{name:'defaultOption',value:0}],input:[{name:'IDToken2',value:0}]}
    ]};
    const h2={'User-Agent':TSEL_AUTH_UA,'Accept':'application/json','Dnt':'1','Sec-Ch-Ua-Mobile':'?0','Origin':TSEL_LOGIN_ORIGIN,'Referer':TSEL_LOGIN_ORIGIN+'/','Am-Clientid':TSEL_CLIENT_ID,'Content-Type':'application/json','Sec-Fetch-Site':'same-site','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty','Sec-Ch-Ua':'"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"','Sec-Ch-Ua-Platform':'"Windows"','Accept-Language':'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7','Priority':'u=1, i'};
    if(amlb) h2['Cookie']=amlb;
    const r2=await tselCiam(tselAuthUrl(),'POST',h2,JSON.stringify(body2),20000);
    if(r2.status!==200) return res.status(400).json({ok:false,error:'Submit OTP status '+r2.status+': '+String(r2.text).slice(0,300)});
    const tokenId=(r2.json&&r2.json.tokenId)||'';
    if(!tokenId) return res.status(400).json({ok:false,error:'OTP salah / kadaluarsa (tokenId kosong)',raw:r2.json});
    let iPlanet=tselCookie(tselGetSetCookies(r2.headers),'iPlanetDirectoryPro');
    if(!iPlanet) iPlanet='iPlanetDirectoryPro='+tokenId;
    const params=new URLSearchParams({client_id:TSEL_CLIENT_ID,nonce:'true',redirect_uri:TSEL_REDIRECT_URI,response_type:'code',scope:'profile openid phone identifier'});
    const authzUrl=TSEL_CIAM+'/iam/v1/oauth2/realms/'+TSEL_REALM+'/authorize?'+params.toString();
    const h3={'User-Agent':TSEL_AUTH_UA,'Accept':'application/json','Referer':TSEL_LOGIN_ORIGIN+'/','Dnt':'1','Sec-Ch-Ua-Mobile':'?0','Sec-Ch-Ua':'"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"','Sec-Ch-Ua-Platform':'"Windows"','Accept-Language':'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7','Priority':'u=1, i','Sec-Fetch-Site':'same-site','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty'};
    const ck3=[amlb,iPlanet].filter(Boolean).join('; ');
    if(ck3) h3['Cookie']=ck3;
    const r3=await tselCiam(authzUrl,'GET',h3,undefined,20000);
    const loc=(r3.headers.get('location')||'');
    let code='';
    if(loc){ try{ const u=new URL(loc); code=u.searchParams.get('code')||''; }catch(e){} }
    if(!code){ const m=String(r3.text||'').match(/[?&]code=([^&"'\s]+)/); if(m) code=decodeURIComponent(m[1]); }
    if(!code) return res.status(400).json({ok:false,error:'Gagal authorize (code kosong). Location: '+String(loc).slice(0,200)});
    const tp=new URLSearchParams({client_id:TSEL_CLIENT_ID,client_secret:TSEL_CLIENT_SECRET,code,grant_type:'authorization_code',redirect_uri:TSEL_REDIRECT_URI,response_type:'code'});
    const tokenUrl=TSEL_CIAM+'/iam/v1/oauth2/realms/'+TSEL_REALM+'/access_token?'+tp.toString();
    const h4={'User-Agent':TSEL_AUTH_UA,'Accept':'application/json','Origin':TSEL_LOGIN_ORIGIN,'Referer':TSEL_LOGIN_ORIGIN+'/','Content-Type':'application/x-www-form-urlencoded','Content-Length':'0','Dnt':'1','Sec-Ch-Ua-Mobile':'?0','Sec-Ch-Ua':'"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"','Sec-Ch-Ua-Platform':'"Windows"','Accept-Language':'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7','Priority':'u=1, i','Sec-Fetch-Site':'same-site','Sec-Fetch-Mode':'cors','Sec-Fetch-Dest':'empty'};
    const r4=await tselCiam(tokenUrl,'POST',h4,'',20000);
    if(r4.status!==200) return res.status(400).json({ok:false,error:'Access token status '+r4.status+': '+String(r4.text).slice(0,300)});
    const accessToken=(r4.json&&r4.json.access_token)||'';
    const idToken=(r4.json&&r4.json.id_token)||'';
    if(!accessToken) return res.status(400).json({ok:false,error:'Access token kosong'});
    const ah=tselAuthHeaders(accessToken,idToken);
    const prev=tselLoadSession()||{};
    const newSess={phone:norm.national||prev.phone||phone, msisdn:norm.international||prev.msisdn||phone, fullPhone:norm.international||prev.fullPhone||phone,
      provider:'TELKOMSEL', brand:'MyTelkomsel', userType:'SUBSCRIBER',
      accessAuth:ah.accessAuth.replace(/^Bearer /,''), authorization:ah.authorization.replace(/^Bearer /,''),
      accessToken, idToken, xDevice:prev.xDevice||tselXDevice(), hash:prev.hash||tselRandomHex(28), webAppVersion:TSEL_WEBAPP_VER,
      cookies:ck3, pendingAuthId:'', pendingAmlb:'', updatedAt:new Date().toISOString()};
    tselSaveSession(newSess);
    try{
      const a=tselAuth()||{};
      a.msisdn=newSess.msisdn; a.fullPhone=newSess.fullPhone; a.xDevice=newSess.xDevice; a.hash=newSess.hash;
      a.accessAuth=newSess.accessAuth; a.authorization=newSess.authorization; a.accessToken=accessToken; a.idToken=idToken;
      fs.writeFileSync(TSEL_AUTH_FILE, JSON.stringify(a,null,2)); try{fs.chmodSync(TSEL_AUTH_FILE,0o600);}catch(e){}
    }catch(e){}
    tselClearPending();
    // auto prime cache: profile + loyalty + balance + bonuses
    try{
      const s2=Object.assign({},newSess);
      const [pR,lR,bR,qR]=await Promise.all([
        tselTdw(s2,'GET','/api/attributes/getprofile').catch(e=>({__err:String((e&&e.message)||e)})),
        tselTdw(s2,'GET','/api/subscriber/loyalty-info').catch(e=>({__err:String((e&&e.message)||e)})),
        tselTdw(s2,'GET','/api/subscriber/profile-balance').catch(e=>({__err:String((e&&e.message)||e)})),
        tselTdw(s2,'POST','/api/subscriber/v5/bonuses',{isPrepaid:true,location:'',roaming:false}).catch(e=>({__err:String((e&&e.message)||e)}))
      ]);
      const groups=[]; try{
        const ub=(qR&&qR.data&&qR.data.userBonuses)||[];
        ub.forEach(function(b){ groups.push({class:b.class||'Kuota', total:b.totalText||'', items:(b.bonusList||[]).map(function(it){ return {name:it.name||it.bucketdescription||'', remaining:it.remainingquota||'', expiry:it.expirydate||'', orderId:it.order_id||''}; })}); });
      }catch(e){}
      const out={fetchedAt:new Date().toISOString(), phone:newSess.phone, msisdn:newSess.msisdn,
        profile:pR, loyalty:lR, balance:bR, quota:{groups}, items:tselQuotaItems(groups),
        totalRemainingFormatted:tselQuotaItems(groups).map(function(i){return i.name+': '+i.remainingFormatted;}).join(', ')||'Active Quota'};
      try{ fs.writeFileSync(TSEL_CACHE_FILE, JSON.stringify(out)); }catch(e){}
    }catch(e){}
    return res.json({ok:true,message:'Login Telkomsel berhasil ('+(norm.national||phone)+')',session:{phone:newSess.phone,msisdn:newSess.msisdn,userType:newSess.userType,updatedAt:newSess.updatedAt}});
  }catch(e){
    return res.status(502).json({ok:false,error:String((e&&e.message)||e)});
  }
});
app.post('/api/telkomsel/logout', (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  try{ tselClearPending(); }catch(e){}
  try{ if(fs.existsSync(TSEL_SESSION_FILE)) fs.unlinkSync(TSEL_SESSION_FILE); }catch(e){}
  return res.json({ok:true,message:'Session Telkomsel dihapus, silakan login lagi'});
});
function tselHeaders(auth) {
  return {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'ID',
    'device-id': auth.deviceId,
    'priority': 'u=1, i',
    'Referer': 'https://www.telkomsel.com/user/halo',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36',
    'Cookie': auth.cookie
  };
}
async function tselFetchJson(url, opts, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => { try { ctrl.abort(); } catch(e){} }, ms || 20000);
  try {
    const r = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch(e) { json = null; }
    return { ok: r.ok, status: r.status, json, raw: json ? null : String(text).slice(0, 300) };
  } finally { clearTimeout(t); }
}
app.get('/api/telkomsel/cek', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  const sess = tselLoadSession();
  const hasNative = sess && sess.accessAuth && sess.authorization;
  if (hasNative) {
    try {
      const s2=Object.assign({},sess);
      const [pR,lR,bR,qR]=await Promise.all([
        tselTdw(s2,'GET','/api/attributes/getprofile'),
        tselTdw(s2,'GET','/api/subscriber/loyalty-info').catch(e=>({__err:String((e&&e.message)||e)})),
        tselTdw(s2,'GET','/api/subscriber/profile-balance').catch(e=>({__err:String((e&&e.message)||e)})),
        tselTdw(s2,'POST','/api/subscriber/v5/bonuses',{isPrepaid:true,location:'',roaming:false})
      ]);
      if(pR&&pR.status&&pR.status!=='00000') return res.json({ok:false,provider:'TELKOMSEL',cached:false,fetchedAt:new Date().toISOString(),authFail:{code:pR.status,message:pR.message},raw:pR});
      if(qR&&qR.status&&qR.status!=='00000') return res.json({ok:false,provider:'TELKOMSEL',cached:false,fetchedAt:new Date().toISOString(),error:qR.message||('TDW status '+qR.status),raw:qR});
      const groups=[];
      try{
        const ub=(qR&&qR.data&&qR.data.userBonuses)||[];
        ub.forEach(function(b){ groups.push({class:b.class||'Kuota', total:b.totalText||'', items:(b.bonusList||[]).map(function(it){ return {name:it.name||it.bucketdescription||'', remaining:it.remainingquota||'', expiry:it.expirydate||'', orderId:it.order_id||''}; })}); });
      }catch(e){}
      const items=tselQuotaItems(groups);
      const out={fetchedAt:new Date().toISOString(), phone:sess.phone, msisdn:sess.msisdn||sess.fullPhone,
        profile:pR, loyalty:lR, balance:bR, quota:{groups}, items,
        totalRemainingFormatted:items.map(function(i){return i.name+': '+i.remainingFormatted;}).join(', ')||'Active Quota'};
      try { fs.writeFileSync(TSEL_CACHE_FILE, JSON.stringify(out)); } catch(e) {}
      return res.json({ ok:true, provider:'TELKOMSEL', phone:out.phone, totalRemainingFormatted:out.totalRemainingFormatted, items, cached:false, fetchedAt:out.fetchedAt, data:out });
    } catch(e) {
      const em=String((e&&e.message)||e);
      if(e&&e.code===401||/unauthorized|token expired/i.test(em)) return res.json({ok:false,provider:'TELKOMSEL',cached:false,fetchedAt:new Date().toISOString(),authFail:{code:'401',message:'Token Telkomsel kadaluarsa, login ulang via OTP'}});
      const msg=(e&&e.name==='AbortError')?'Upstream timeout (20s)':em;
      return res.status(502).json({ok:false,provider:'TELKOMSEL',error:msg});
    }
  }
  const auth = tselAuth();
  if (!auth || !auth.cookie || !auth.deviceId) return res.status(500).json({ ok: false, error: 'auth telkomsel belum ada — login dulu via OTP' });
  try {
    const H = tselHeaders(auth);
    const [prof, bon] = await Promise.all([
      tselFetchJson('https://www.telkomsel.com/api/customer/v1/profile', { method: 'GET', headers: H }, 20000),
      tselFetchJson('https://www.telkomsel.com/api/customer/v1/active-bonuses?serviceType=Halo', { method: 'GET', headers: H }, 20000)
    ]);
    const out = {
      fetchedAt: new Date().toISOString(),
      msisdn: (prof.json && prof.json.data && prof.json.data.identifier) || auth.msisdn || null,
      profile: prof.json, profileStatus: prof.status,
      bonuses: bon.json, bonusesStatus: bon.status,
    };
    try { fs.writeFileSync(TSEL_CACHE_FILE, JSON.stringify(out)); } catch(e) {}
    return res.json({ ok: true, cached: false, fetchedAt: out.fetchedAt, data: out });
  } catch(e) {
    const msg = (e && e.name === 'AbortError') ? 'Upstream timeout (20s)' : String((e && e.message) || e);
    return res.status(502).json({ ok: false, error: msg });
  }
});

// ---- tri bimatri proxy (bimaplus-api.ioh.co.id; header x-imi-* computed per-request, secret di server) ----
const TRI_DIR = path.join(__dirname, 'data', 'tri');
try { fs.mkdirSync(TRI_DIR, { recursive: true }); } catch(e) {}
const TRI_AUTH_FILE = path.join(TRI_DIR, 'auth.json');
const TRI_CACHE_FILE = path.join(TRI_DIR, 'cache.json');
const TRI_SESSION_FILE = path.join(TRI_DIR, 'session.json');
const TRI_PENDING_FILE = path.join(TRI_DIR, 'otp_pending.json');
function triAuth(){ try{ return JSON.parse(fs.readFileSync(TRI_AUTH_FILE,'utf8')); }catch(e){ return null; } }
function triLoadSession(){ try{ return JSON.parse(fs.readFileSync(TRI_SESSION_FILE,'utf8')); }catch(e){ return null; } }
function triSaveSession(obj){ try{ fs.writeFileSync(TRI_SESSION_FILE, JSON.stringify(obj,null,2), {mode:0o600}); try{fs.chmodSync(TRI_SESSION_FILE,0o600);}catch(e){} }catch(e){} }
function triLoadPending(){ try{ return JSON.parse(fs.readFileSync(TRI_PENDING_FILE,'utf8')); }catch(e){ return null; } }
function triSavePending(obj){ try{ fs.writeFileSync(TRI_PENDING_FILE, JSON.stringify(obj,null,2), {mode:0o600}); try{fs.chmodSync(TRI_PENDING_FILE,0o600);}catch(e){} }catch(e){} }
function triClearPending(){ try{ fs.unlinkSync(TRI_PENDING_FILE);}catch(e){} }
function triNormalizePhone(input){
  let clean=String(input||'').replace(/[^0-9]/g,'');
  if(clean.startsWith('62')) clean=clean.substring(2);
  else if(clean.startsWith('0')) clean=clean.substring(1);
  const isValid = clean.startsWith('8') && clean.length>=9 && clean.length<=13;
  return { clean, national:'0'+clean, international:'62'+clean, isValid };
}
function triOdd(s){ let o=''; for(let i=0;i<s.length;i+=2) o+=s[i]; return o; }
function triBuildHeaders(auth, bodyStr){
  const cryptoMod = require('crypto');
  auth = auth || {};
  const os = auth.imiAppOs || 'BROWSER';
  const appVersion = auth.imiAppVersion || auth.imiVersion || '5.2.0';
  const channel = auth.imiChannel || 'PORTAL';
  const language = auth.imiLanguage || 'ID';
  const authorization = auth.authorization || '642d1cc69d90666962726e';
  const deviceId = auth.deviceId || '56826f1045584651bc499d268febea91';
  const deviceName = auth.deviceName || 'EnQuota Terminal (Linux)';
  const serviceKey = auth.imiServiceKey || 'FPi7ZP3Jy8Uv3KBd4QeG';
  const cookies = auth.cookie || 'TS01503f77=01334ce802d3fdb350e5f70de0216dd87e89b5b0b42039fa21a80610a6e9f41e405fae3d8d67f4e517f73cf985e5160a259dbf777e; BUI=56826f10-4558-4651-bc49-9d268febea91';
  const token = auth.imiTokenId || auth.tokenId || auth.authToken || '';
  const uid = (function(){ const d=new Date(); const pad=(n,l)=>String(n).padStart(l,'0'); return ''+d.getFullYear()+pad(d.getMonth()+1,2)+pad(d.getDate(),2)+pad(d.getHours(),2)+pad(d.getMinutes(),2)+pad(d.getSeconds(),2)+pad(d.getMilliseconds(),3)+String(Math.floor(100+Math.random()*900)); })();
  const oddToken = triOdd(token);
  const oauth = cryptoMod.createHash('sha512').update('REQBODY='+bodyStr+'&SALT='+oddToken).digest('hex');
  const parent = (auth.parent && auth.parent !== '') ? auth.parent : 'parent';
  const hp = parent+'$'+os+'$'+appVersion+'$'+token;
  const oddUid = triOdd(uid);
  const hhash = cryptoMod.createHash('sha512').update(hp+'&SALT='+oddUid).digest('hex');
  const H = {
    'Host': 'bimaplus-api.ioh.co.id',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'id,en-US;q=0.9,en;q=0.8',
    'Content-Type': 'application/json',
    'Origin': 'https://bimatri.ioh.co.id',
    'Referer': auth.referer || 'https://bimatri.ioh.co.id/',
    'Authorization': authorization,
    'X-IMI-App-OS': os,
    'X-IMI-APPVERSION': appVersion,
    'X-IMI-CHANNEL': channel,
    'X-IMI-LANGUAGE': language,
    'x-imi-oauth': oauth,
    'X-IMI-HASH': hhash,
    'X-IMI-TOKENID': token,
    'X-IMI-VERSION': appVersion,
    'X-DEVICEID': deviceId,
    'X-DEVICENAME': deviceName,
    'X-IMI-SERVICEKEY': serviceKey,
    'X-IMI-UID': uid,
    'Cookie': cookies,
  };
  return H;
}
function triBuildHeadersWithToken(tokenId, bodyStr){
  const a = triAuth() || {};
  const sess = triLoadSession();
  const base = Object.assign({}, a);
  if(sess){
    if(sess.deviceId) base.deviceId = sess.deviceId;
    if(sess.cookies) base.cookie = sess.cookies;
    if(sess.faiId) base.faiId = sess.faiId;
  }
  base.imiTokenId = tokenId;
  return triBuildHeaders(base, bodyStr);
}
function triUpdateCookies(cur, arr){
  const m = {};
  String(cur||'').split(';').forEach(c=>{ const s=c.trim(); const i=s.indexOf('='); if(i>0) m[s.slice(0,i).trim()]=s.slice(i+1); });
  (arr||[]).forEach(ch=>{ const main=String(ch).split(';')[0].trim(); const i=main.indexOf('='); if(i>0) m[main.slice(0,i).trim()]=main.slice(i+1); });
  return Object.entries(m).map(([k,v])=>k+'='+v).join('; ');
}
async function triRequest(endpoint, bodyObj){
  const bodyStr = JSON.stringify(bodyObj||{});
  const sess = triLoadSession();
  const auth = triAuth();
  let tokenId = (sess && sess.authToken) || (auth && (auth.imiTokenId||auth.tokenId)) || (Date.now().toString()+'1');
  // for guest init we may not have token yet, use dummy
  const H = triBuildHeadersWithToken(tokenId, bodyStr);
  const ctrl = new AbortController(); const t=setTimeout(()=>{try{ctrl.abort();}catch(e){}},20000);
  try{
    const r = await fetch('https://bimaplus-api.ioh.co.id/api/v2'+endpoint, {method:'POST', headers:H, body:bodyStr, signal:ctrl.signal});
    const text = await r.text();
    let j=null; try{ j=JSON.parse(text);}catch(e){ j=null; }
    // capture set-cookie (Enquota updateCookies style: merge per-name, overwrite)
    try{
      let scArr = [];
      if(r.headers && typeof r.headers.getSetCookie==='function') scArr = r.headers.getSetCookie()||[];
      else { const sc = r.headers.get('set-cookie'); if(sc) scArr = [sc]; }
      if(scArr.length){
        const cur = (sess && sess.cookies) || (auth && auth.cookie) || '';
        const merged = triUpdateCookies(cur, scArr);
        if(merged && merged!==cur){
          if(sess) { sess.cookies = merged; triSaveSession(sess); }
          else if(auth){ auth.cookie = merged; try{fs.writeFileSync(TRI_AUTH_FILE, JSON.stringify(auth,null,2));}catch(e){} }
        }
      }
    }catch(e){}
    return { statusCode:r.status, headers:r.headers, body:j, raw:j?null:text };
  } finally { clearTimeout(t); }
}
async function triEnsureGuest(){
  let sess = triLoadSession();
  if(sess && sess.authToken) return sess.authToken;
  const auth = triAuth();
  if(auth && auth.imiTokenId) {
    // create session from existing auth if not exists
    const s = { phone:'', msisdn:'', provider:'TRI', brand:'bima+', authToken: auth.imiTokenId, userType:'SUBSCRIBER', deviceId: auth.deviceId||'56826f1045584651bc499d268febea91', cookies: auth.cookie||'', faiId: auth.faiId||'eiU4ebGnX1jcwEKM0OoDD-', updatedAt:new Date().toISOString() };
    triSaveSession(s);
    return s.authToken;
  }
  // init guest via token/guest with dummy token
  const res = await triRequest('/token/guest', {});
  if(res.body && res.body.status==='0' && res.body.data && (res.body.data.tokenid||res.body.data.token)){
    const token = res.body.data.tokenid||res.body.data.token;
    const s = { phone:'', msisdn:'', provider:'TRI', brand:'bima+', authToken: token, userType:'GUEST', deviceId: (triAuth()&&triAuth().deviceId)||'56826f1045584651bc499d268febea91', cookies: (triAuth()&&triAuth().cookie)||'TS01503f77=01334ce802d3fdb350e5f70de0216dd87e89b5b0b42039fa21a80610a6e9f41e405fae3d8d67f4e517f73cf985e5160a259dbf777e; BUI=56826f10-4558-4651-bc49-9d268febea91', faiId: (triAuth()&&triAuth().faiId)||'eiU4ebGnX1jcwEKM0OoDD-', updatedAt:new Date().toISOString() };
    triSaveSession(s);
    // also update auth.json cookie/token for compat
    try{
      const a = triAuth()||{};
      a.imiTokenId = token;
      a.deviceId = s.deviceId;
      a.cookie = s.cookies;
      a.faiId = s.faiId;
      a.imiVersion = a.imiVersion||'5.2.0';
      a.imiAppVersion = a.imiAppVersion||'5.2.0';
      a.authorization = a.authorization||'642d1cc69d90666962726e';
      fs.writeFileSync(TRI_AUTH_FILE, JSON.stringify(a,null,2)); try{fs.chmodSync(TRI_AUTH_FILE,0o600);}catch(e){}
    }catch(e){}
    return token;
  }
  throw new Error('Gagal init guest Tri: '+(JSON.stringify(res.body)||res.raw||'unknown'));
}

app.get('/api/tri/cache', (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  try{
    if(!fs.existsSync(TRI_CACHE_FILE)) return res.status(404).json({ok:false,cached:false,error:'Belum ada data Tri tersimpan, klik Refresh'});
    const raw=JSON.parse(fs.readFileSync(TRI_CACHE_FILE,'utf8'));
    // Normalisasi bentuk lama: file bisa berisi {fetchedAt, data} atau out lengkap {fetchedAt,httpStatus,data,raw}
    let out=raw;
    if(out && typeof out==='object' && !out.fetchedAt && !out.httpStatus && (out.status!==undefined || out.data!==undefined)){
      out={fetchedAt:null, httpStatus:200, data:out, raw:null};
    }
    // Derivasi Enquota-like fields: items + totalRemainingFormatted via triParse logic (sama dgn frontend)
    let items=[]; let totalRemainingMB=0;
    try{
      const maybeJ = out && out.data;
      const dash = (maybeJ && maybeJ.data) ? maybeJ.data : maybeJ;
      const pkgs = (dash && dash.packdata && Array.isArray(dash.packdata.packageslist)) ? dash.packdata.packageslist : [];
      pkgs.forEach(function(pkg){
        const qs=pkg.Quotas||[]; if(!Array.isArray(qs)) return;
        qs.forEach(function(q){
          const rem=q.remainingQuota!=null?Number(q.remainingQuota):Number(q.rawRemainingQuota||0);
          let tot=q.quota!=null?Number(String(q.quota).replace(/[^0-9.]/g,'')):rem; if(isNaN(tot)||tot<=0) tot=Number(q.initialQuota||q.rawInitialQuota||rem)||0;
          const unit=String(q.quotaUnit||'').toUpperCase(); const benefit=String(q.benefitType||'').toUpperCase();
          const name=((q.name||q.description||'')+' '+(pkg.PackageName||pkg.ServiceName||'')).toLowerCase();
          let cat='internet';
          if(unit==='SMS') cat='sms';
          else if(unit==='MIN' || benefit==='VOICE' || name.indexOf('menit')>=0 || name.indexOf('voice')>=0 || name.indexOf('telepon')>=0 || name.indexOf('telp')>=0) cat='telepon';
          else if(benefit==='DATA' || unit==='MB' || unit==='GB'){
            if(name.indexOf('youtube')>=0 || name.indexOf('tiktok')>=0 || name.indexOf('sosmed')>=0 || name.indexOf('aplikasi')>=0 || name.indexOf('apps')>=0 || name.indexOf('chat')>=0 || name.indexOf('unlimited app')>=0) cat='aplikasi';
            else cat='internet';
          }
          if(rem>0||tot>0){
            items.push({name:(pkg.PackageName||pkg.ServiceName||'Paket')+' ('+(q.name||q.description||'')+')', category:cat, remainingQuota:rem, quota:tot, quotaUnit:unit, benefitType:benefit, exhausted:!(rem>0), validUntil:pkg.EndDate||pkg.expMsg||'-'});
            if(cat==='internet'||cat==='aplikasi') totalRemainingMB+=rem;
          }
        });
      });
    }catch(e){}
    const totalRemainingFormatted=(function(mb){ const n=Number(mb)||0; if(n>=1024) return (n/1024).toFixed(2)+' GB'; return Math.round(n)+' MB'; })(totalRemainingMB);
    let authFail=null; try{ const j=out&&out.data; if(j && (j.code==='10001' || String(j.message||'').toLowerCase().indexOf('authentication failed')>=0)) authFail={code:j.code,message:j.message}; }catch(e){}
    return res.json({ok:true,cached:true,fetchedAt:out.fetchedAt||null,data:out,items,totalRemainingMB,totalRemainingFormatted,raw:out.raw||null,authFail});
  }catch(e){ return res.status(500).json({ok:false,error:'Gagal baca cache Tri: '+String((e&&e.message)||e)}); }
});
app.get('/api/tri/cek', async (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const auth=triAuth();
  const sess=triLoadSession();
  const hasToken = (sess && sess.authToken) || (auth && auth.imiTokenId);
  if(!hasToken) return res.status(500).json({ok:false,error:'auth Tri belum ada — login dulu via OTP'});
  try{
    const data = await triRequest('/dashboard/get/v4', {});
    const j = data.body;
    const fetchedAt = new Date().toISOString();
    const isAuthFail = j && (j.code==='10001' || String(j.message||'').toLowerCase().includes('authentication failed'));
    if(isAuthFail){
      return res.json({ok:false, provider:'TRI', cached:false, fetchedAt, authFail:{code:j.code,message:j.message}, raw:(j&&j.data)||null});
    }
    if(!j){
      const rawTxt = data.raw ? String(data.raw).slice(0,600) : '';
      return res.status(data.statusCode||502).json({ok:false, provider:'TRI', error:'Upstream bukan JSON', raw:rawTxt});
    }
    if(j.status!=='0'){
      return res.json({ok:false, provider:'TRI', cached:false, fetchedAt, error:j.message||('Tri status '+j.status), raw:j.data||null});
    }
    const out={fetchedAt, httpStatus:data.statusCode, data:j, raw:data.raw||null};
    try{ fs.writeFileSync(TRI_CACHE_FILE, JSON.stringify(out)); }catch(e){}
    const dash=(j.data)||{};
    const packages=(dash.packdata && Array.isArray(dash.packdata.packageslist)) ? dash.packdata.packageslist : [];
    const phone=(sess&&(sess.phone||sess.msisdn))||dash.msisdn||dash.identifier||dash.phone||'';
    const items=[]; let totalMB=0;
    packages.forEach(function(pkg){
      const qs=pkg.Quotas||[]; if(!Array.isArray(qs)) return;
      qs.forEach(function(q){
        const rem=(q.remainingQuota!=null&&q.remainingQuota!=='')?Number(q.remainingQuota):Number(q.rawRemainingQuota||0);
        let tot=q.quota!=null?Number(String(q.quota).replace(/[^0-9.]/g,'')):rem; if(isNaN(tot)||tot<=0) tot=Number(q.initialQuota||q.rawInitialQuota||rem)||0;
        if(!(rem>0||tot>0)) return;
        const unit=String(q.quotaUnit||'').toUpperCase();
        const benefit=String(q.benefitType||'').toUpperCase();
        let remStr;
        if(unit==='SMS'||benefit==='SMS') remStr=Math.round(rem)+' SMS';
        else if(unit==='MIN'||benefit==='VOICE') remStr=Math.round(rem)+' min';
        else if(rem>=1024) remStr=(rem/1024).toFixed(2)+' GB';
        else remStr=Math.round(rem)+' MB';
        const _nm=((q.name||q.description||'')+' '+(pkg.PackageName||pkg.ServiceName||'')).toLowerCase();
        let _cat='internet';
        if(unit==='SMS'||benefit==='SMS') _cat='sms';
        else if(unit==='MIN'||benefit==='VOICE'||_nm.indexOf('menit')>=0||_nm.indexOf('telepon')>=0||_nm.indexOf('telp')>=0||_nm.indexOf('voice')>=0) _cat='telepon';
        else if(benefit==='DATA'||unit==='MB'||unit==='GB'){ if(_nm.indexOf('youtube')>=0||_nm.indexOf('tiktok')>=0||_nm.indexOf('sosmed')>=0||_nm.indexOf('aplikasi')>=0||_nm.indexOf('apps')>=0||_nm.indexOf('chat')>=0) _cat='aplikasi'; }
        items.push({name:(pkg.PackageName||pkg.ServiceName||'Paket')+' ('+(q.name||q.description||'')+')', type:q.benefitType||'', category:_cat, remainingQuota:rem, quota:tot, quotaUnit:unit, benefitType:benefit, remainingFormatted:remStr+(rem<=0?' (habis)':''), exhausted:!(rem>0), validUntil:pkg.EndDate||pkg.expMsg||'-'});
        if(!(unit==='SMS'||benefit==='SMS')) totalMB+=rem;
      });
    });
    const totalRemainingFormatted=totalMB>=1024 ? (totalMB/1024).toFixed(2)+' GB' : Math.round(totalMB)+' MB';
    return res.json({ok:true, provider:'TRI', phone, totalRemainingFormatted, items, raw:dash});
  }catch(e){
    const msg=(e&&e.name==='AbortError')?'Upstream timeout (20s)':String((e&&e.message)||e);
    return res.status(502).json({ok:false, provider:'TRI', error:msg});
  }
});
app.get('/api/tri/status', (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const sess=triLoadSession();
  const auth=triAuth();
  const hasCache = fs.existsSync(TRI_CACHE_FILE);
  const pending=triLoadPending();
  var expiry=null;
  try{ var tok=(sess&&sess.authToken)||(auth&&auth.imiTokenId)||''; if(tok&&String(tok).split('.').length>=3) expiry=tselJwtExp(tok); }catch(e){}
  var sessOut=sess?{phone:sess.phone,msisdn:sess.msisdn,userType:sess.userType,updatedAt:sess.updatedAt,expiry:expiry,expiresAt:expiry?expiry.expIso:null,remainingSec:expiry?expiry.remainingSec:null,ttlDays:expiry&&expiry.ttlSec?Math.round(expiry.ttlSec/86400):null}:null;
  return res.json({ok:true, session: sessOut, expiry:expiry, hasToken: !!(sess?.authToken||auth?.imiTokenId), hasCache, pending: pending ? {msisdn:pending.msisdn, transId:pending.transId, createdAt:pending.createdAt} : null});
});
app.post('/api/tri/login', async (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const phoneRaw = String((req.body&&req.body.phone)||'').trim();
  const norm = triNormalizePhone(phoneRaw);
  if(!norm.isValid) return res.status(400).json({ok:false, error:'Nomor Tri tidak valid (contoh 0895xxxxxxx)'});
  try{
    await triEnsureGuest();
    const sendRes = await triRequest('/otp/send/v1', {msisdn: norm.international, action:'register'});
    if(!sendRes.body || sendRes.body.status!=='0'){
      const isInvalidNumber = String(sendRes.body?.code||'')==='10005' || String(sendRes.body?.status||'')==='10005' || /Mobile Number is not valid/i.test(String(sendRes.body?.message||''));
      if(isInvalidNumber){
        return res.status(400).json({ok:false, error:'Nomor Tri tidak valid (Mobile Number is not valid) — pastikan nomor Tri aktif dan format 08xxxxxxxxxx', raw: sendRes.body});
      }
      return res.status(400).json({ok:false, error: sendRes.body?.message || 'Gagal kirim OTP Tri ('+sendRes.statusCode+')', raw: sendRes.body});
    }
    const transId = sendRes.body.transid || sendRes.body.data?.transid || '';
    triSavePending({msisdn: norm.international, phone:norm.national, transId, createdAt:new Date().toISOString()});
    // update session phone for next verify
    const sess=triLoadSession(); if(sess){ sess.phone=norm.national; sess.msisdn=norm.international; sess.updatedAt=new Date().toISOString(); triSaveSession(sess); }
    return res.json({ok:true, message:'OTP terkirim ke '+norm.national+' via SMS', transId, msisdn: norm.international});
  }catch(e){
    return res.status(502).json({ok:false, error:String((e&&e.message)||e)});
  }
});
app.post('/api/tri/verify', async (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  const otp = String((req.body&&req.body.otp)||'').trim();
  let transId = String((req.body&&req.body.transId)||'').trim();
  let phone = String((req.body&&req.body.phone)||'').trim();
  if(!/^[0-9]{4,8}$/.test(otp)) return res.status(400).json({ok:false, error:'OTP harus 4-6 digit angka'});
  const pending=triLoadPending();
  if(!transId) transId = pending?.transId || '';
  if(!phone) phone = pending?.phone || pending?.msisdn || '';
  try{
    const valRes = await triRequest('/otp/validate/v1', {transid: transId, otp});
    if(valRes.body && valRes.body.status==='0' && valRes.body.data){
      const token = valRes.body.data.tokenid || valRes.body.data.token;
      const norm = triNormalizePhone(phone);
      const sess = triLoadSession() || {};
      const newSess = {
        phone: norm.national || sess.phone || phone,
        msisdn: norm.international || sess.msisdn || phone,
        provider:'TRI', brand:'bima+',
        authToken: token, userType:'SUBSCRIBER',
        deviceId: sess.deviceId || (triAuth()&&triAuth().deviceId) || '56826f1045584651bc499d268febea91',
        cookies: sess.cookies || (triAuth()&&triAuth().cookie) || '',
        faiId: sess.faiId || (triAuth()&&triAuth().faiId) || 'eiU4ebGnX1jcwEKM0OoDD-',
        updatedAt: new Date().toISOString()
      };
      triSaveSession(newSess);
      // sync to auth.json for compat with old cek
      try{
        const a = triAuth()||{};
        a.imiTokenId = token;
        a.deviceId = newSess.deviceId;
        a.cookie = newSess.cookies;
        a.faiId = newSess.faiId;
        a.imiVersion = a.imiVersion||'5.2.0';
        a.imiAppVersion = a.imiAppVersion||'5.2.0';
        a.authorization = a.authorization||'642d1cc69d90666962726e';
        fs.writeFileSync(TRI_AUTH_FILE, JSON.stringify(a,null,2)); try{fs.chmodSync(TRI_AUTH_FILE,0o600);}catch(e){}
      }catch(e){}
      triClearPending();
      // auto fetch dashboard to prime cache
      try{
        const bodyStr='{}';
        const H=triBuildHeaders({imiTokenId:token, deviceId:newSess.deviceId, cookie:newSess.cookies, faiId:newSess.faiId, imiAppOs:'BROWSER', imiVersion:'5.2.0', imiAppVersion:'5.2.0', authorization:'642d1cc69d90666962726e'}, bodyStr);
        const r=await fetch('https://bimaplus-api.ioh.co.id/api/v2/dashboard/get/v4', {method:'POST', headers:H, body:bodyStr});
        const t=await r.text(); let j=null; try{j=JSON.parse(t);}catch(e){} ;
        if(j && j.status==='0'){
          const out={fetchedAt:new Date().toISOString(), httpStatus:r.status, data:j, raw:null};
          try{ fs.writeFileSync(TRI_CACHE_FILE, JSON.stringify(out)); }catch(e){}
        }
      }catch(e){}
      return res.json({ok:true, message:'Login Tri berhasil ('+(norm.national||phone)+')', session:newSess, data: valRes.body.data});
    }
    return res.status(400).json({ok:false, error: valRes.body?.message || 'OTP salah / kadaluarsa', raw: valRes.body});
  }catch(e){
    return res.status(502).json({ok:false, error:String((e&&e.message)||e)});
  }
});
app.post('/api/tri/logout', (req,res)=>{
  if(!isAuthenticated(req)) return res.status(401).json({error:'Unauthorized'});
  try{ triClearPending(); }catch(e){}
  try{ if(fs.existsSync(TRI_SESSION_FILE)) fs.unlinkSync(TRI_SESSION_FILE); }catch(e){}
  return res.json({ok:true, message:'Session Tri dihapus, silakan login lagi'});
});


app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('/sw.js')) {
      res.setHeader('Service-Worker-Allowed', '/');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Content-Type', 'application/javascript');
    }
    if (filePath.endsWith('/manifest.json')) {
      res.setHeader('Content-Type', 'application/manifest+json');
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));
app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => { console.log(`Iskan private portal on http://0.0.0.0:${PORT}`); });
