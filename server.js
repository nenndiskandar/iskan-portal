const express = require('express');
const path = require('path');
const { execFile } = require('child_process');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3005;

// Middleware to block indexing entirely via HTTP Headers for all routes
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
  next();
});

// Explicit robots.txt to disable all cralwers & AI bots (GPTBot, Anthropic-ai, etc)
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send("User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nDisallow: /\n\nUser-agent: ChatGPT-User\nDisallow: /\n\nUser-agent: Anthropic-ai\nDisallow: /\n\nUser-agent: PerplexityBot\nDisallow: /\n\nUser-agent: CCBot\nDisallow: /");
});

// scope: app = user-facing project, bot = telegram bot, infra = supporting service
const SERVICES = [
  // --- Apps ---
  { unit: 'iskan-drama.service',       name: 'Iskan Drama',        kind: 'app',   port: 3003,  desc: 'Streaming SPA (Express, native http)', path: '/root/iskan-drama', tech: 'Node.js' },
  { unit: 'iskan-portfolio.service',   name: 'Iskan Portfolio',    kind: 'app',   port: 3004,  desc: 'Spotlight portfolio — nendi.web.id', path: '/root/iskan-portfolio', tech: 'React / Next.js' },
  { unit: 'autoclipper-webjs.service', name: 'Auto-Clipper WebJS', kind: 'app',   port: 3000,  desc: 'Auto-Clipper v2 web panel', path: '/root/auto-clipper-v2', tech: 'Node.js / Python' },
  { unit: 'iskan-portal.service',      name: 'Iskan Portal',       kind: 'app',   port: 3005,  desc: 'Portal status (halaman ini)', path: '/root/iskan-portal', tech: 'Node.js / Express' },

  // --- Bots ---
  { unit: 'auto-clipper-v2-bot.service', name: 'Auto-Clipper Bot', kind: 'bot', port: null, desc: 'Telegram bot pipeline', tech: 'Python' },
  { unit: 'hermes-gateway.service',      name: 'Hermes Gateway',   kind: 'bot', port: null, desc: 'Hermes Agent messaging gateway', user: true, tech: 'Node.js' },

  // --- Infra ---
  { unit: 'omniroute.service',               name: 'OmniRoute',      kind: 'infra', port: 20128, desc: 'AI gateway proxy (~2900 models)', tech: 'Go (Golang)' },
  { unit: 'docker.service',                  name: 'Docker',         kind: 'infra', port: null,  desc: 'Container runtime (docker-proxy :8081)', tech: 'Docker' },
];

const USER_ENV = { ...process.env, XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR || '/run/user/0' };

function run(bin, args, timeout = 5000, env) {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout, env: env || process.env }, (err, stdout) => resolve(err ? null : stdout));
  });
}

async function systemctlShow(unit, user) {
  const args = user
    ? ['--user', 'show', unit, '-p', 'Id,ActiveState,SubState,MainPID,MemoryCurrent', '--no-pager']
    : ['show', unit, '-p', 'Id,ActiveState,SubState,MainPID,MemoryCurrent', '--no-pager'];
  const stdout = await run('systemctl', args, 5000, user ? USER_ENV : undefined);
  if (!stdout) return null;
  const out = {};
  stdout.split('\n').forEach((line) => {
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
  });
  return out;
}

async function systemctlSince(unit, user) {
  const args = user
    ? ['--user', 'show', unit, '-p', 'ActiveEnterTimestamp', '--no-pager']
    : ['show', unit, '-p', 'ActiveEnterTimestamp', '--no-pager'];
  const stdout = await run('systemctl', args);
  if (!stdout) return null;
  const m = stdout.match(/ActiveEnterTimestamp=.*?(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})/);
  if (!m) return null;
  // Fallback to local time by slicing string, avoids WIB/CET/etc parsing issues
  const ts = Date.parse(`${m[1]}T${m[2]}`);
  return isNaN(ts) ? null : ts;
}

function fmtBytes(n) {
  n = Number(n);
  if (!n || n < 0) return null;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + u[i];
}

async function getDiskUsage() {
  try {
    const stdout = await run('df', ['-B1', '/']);
    if (!stdout) return null;
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) return null;
    const parts = lines[1].trim().split(/\s+/);
    if (parts.length >= 5) {
      return {
        total: fmtBytes(parts[1]),
        used: fmtBytes(parts[2]),
        percent: parts[4]
      };
    }
  } catch (e) {}
  return null;
}

app.get('/api/sysinfo', async (req, res) => {
  const diskInfo = await getDiskUsage();
  res.json({
    server: {
      cpu: os.cpus()[0]?.model || 'Unknown CPU',
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

app.get('/api/status', async (req, res) => {
  const [results, ssOut, diskInfo] = await Promise.all([
    Promise.all(
      SERVICES.map(async (svc) => {
        const [info, sinceTs] = await Promise.all([
          systemctlShow(svc.unit, svc.user),
          systemctlSince(svc.unit, svc.user),
        ]);
        const active = info ? info.ActiveState : 'unknown';
        const { user, ...meta } = svc;
        return {
          ...meta,
          active,
          sub: info ? info.SubState : 'unknown',
          pid: info && info.MainPID && info.MainPID !== '0' ? Number(info.MainPID) : null,
          memory: info ? fmtBytes(info.MemoryCurrent) : null,
          since: sinceTs,
          uptimeSec: sinceTs ? Math.floor((Date.now() - sinceTs) / 1000) : null,
          healthy: active === 'active',
        };
      })
    ),
    run('ss', ['-tulpn']),
    getDiskUsage(),
  ]);

  results.forEach((r) => {
    if (r.port) r.portOpen = ssOut ? new RegExp(':' + r.port + '\\b').test(ssOut) : null;
  });

  res.json({
    generatedAt: Date.now(),
    host: process.env.HOSTNAME || 'clipper',
    node: process.version,
    gatewayRss: fmtBytes(process.memoryUsage().rss),
    server: {
      cpu: os.cpus()[0]?.model || 'Unknown CPU',
      ramTotal: fmtBytes(os.totalmem()),
      ramUsed: fmtBytes(os.totalmem() - os.freemem()),
      uptime: os.uptime(),
      load: os.loadavg().map(v => v.toFixed(2)),
      disk: diskInfo
    },
    services: results,
    summary: {
      total: results.length,
      up: results.filter((r) => r.healthy).length,
      down: results.filter((r) => !r.healthy).length,
    },
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Iskan private portal on http://0.0.0.0:${PORT}`);
});
