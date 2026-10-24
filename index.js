require("dotenv").config();
const { execSync, execFileSync, execFile, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const zlib = require('zlib');

// ============================================================
// CONFIG
// ============================================================
const BASE_DIR = fs.existsSync('/home/container') ? '/home/container' : __dirname;
process.env.RIZZ_BASE_DIR = BASE_DIR;

const DB_PATH = path.join(BASE_DIR, 'database.json');
const SERVERS_DIR = path.join(BASE_DIR, 'servers_data');
const SESSIONS_DIR = path.join(BASE_DIR, 'sessions');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = process.env.PORT || 3000;
const ENABLE_TUNNEL = !process.argv.includes('--no-tunnel');

const NGROK_AUTHTOKEN = process.env.NGROK_AUTHTOKEN || '';
const NGROK_DOMAIN = process.env.NGROK_DOMAIN || '';
const DEFAULT_OWNER_PASSWORD = process.env.INITIAL_OWNER_PASSWORD || '';

if (!DEFAULT_OWNER_PASSWORD || DEFAULT_OWNER_PASSWORD.length < 12) {
    console.error('❌ FATAL: INITIAL_OWNER_PASSWORD env required (min 12 chars)');
    console.error('   Example: export INITIAL_OWNER_PASSWORD="SuperStrongPassw0rd!2026"');
    process.exit(1);
}

function loadOrCreateSessionSecret() {
    if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
    const f = path.join(BASE_DIR, '.session_secret');
    if (fs.existsSync(f)) return fs.readFileSync(f, 'utf-8').trim();
    const s = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(f, s, { mode: 0o600 });
    return s;
}
const SESSION_SECRET = loadOrCreateSessionSecret();
if (SESSION_SECRET.length < 32) { console.error('FATAL: SESSION_SECRET must be at least 32 characters'); process.exit(1); }
const EXPIRE_CHECK_INTERVAL = 60 * 1000;

console.log('========================================');
console.log('🐉 RIZZ PTERODACTYL v2.0');
console.log('========================================');
console.log('📁 Base dir :', BASE_DIR);
console.log('📁 Servers  :', SERVERS_DIR);
console.log('🌐 Tunnel   :', ENABLE_TUNNEL && NGROK_AUTHTOKEN ? 'NGROK' : 'OFF');
console.log('🔗 Domain   :', ENABLE_TUNNEL && NGROK_DOMAIN ? NGROK_DOMAIN : '(disabled)');
console.log('💻 Platform :', os.platform(), os.arch());
console.log('========================================\n');

if (!fs.existsSync(SERVERS_DIR)) fs.mkdirSync(SERVERS_DIR, { recursive: true, mode: 0o700 });
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true, mode: 0o700 });

// Dependencies must be installed from the reviewed package-lock / package.json during deployment.
const security = require('./security');
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const app = express();

// Only trust a reverse proxy when explicitly configured by the operator.
// TRUST_PROXY=1 (one proxy hop) or a small number for chained proxies (e.g. 2 = Cloudflare + tunnel).
app.set('trust proxy', /^[1-9]\d?$/.test(process.env.TRUST_PROXY || '') ? parseInt(process.env.TRUST_PROXY, 10) : false);
app.disable('x-powered-by');

// ============================================================
// ANTI-DDOS / ABUSE PROTECTION (application layer)
// Network-level floods must still be absorbed in front of the app (Cloudflare / firewall).
// ============================================================
function envInt(name, def, min, max) {
    const n = parseInt(process.env[name], 10);
    if (!Number.isFinite(n)) return def;
    return Math.min(max, Math.max(min, n));
}
const DDOS = {
    apiPerMin: envInt('RATE_LIMIT_API_PER_MIN', 600, 30, 1000000),
    pagePerMin: envInt('RATE_LIMIT_PAGE_PER_MIN', 120, 10, 1000000),
    heavyPerMin: envInt('RATE_LIMIT_HEAVY_PER_MIN', 20, 3, 100000),
    banThreshold: envInt('AUTOBAN_STRIKES', 5, 2, 1000),
    banMs: envInt('AUTOBAN_MINUTES', 15, 1, 10080) * 60 * 1000,
    maxConnections: envInt('MAX_CONNECTIONS', 3000, 50, 1000000),
    maxUploads: envInt('MAX_CONCURRENT_UPLOADS', 5, 1, 1000),
    maxNpmInstalls: envInt('MAX_CONCURRENT_NPM_INSTALLS', 2, 1, 100),
    maxLoginConcurrent: envInt('MAX_CONCURRENT_LOGINS', 4, 1, 1000),
    requestTimeoutMs: envInt('REQUEST_TIMEOUT_SECONDS', 300, 30, 3600) * 1000,
    strikeSpacingMs: 10 * 1000,          // one strike per 10s at most, so short bursts never cause a ban
    strikeWindowMs: 10 * 60 * 1000,
};
let loginInFlight = 0;
const RL_ALLOWLIST = new Set((process.env.RATE_LIMIT_ALLOWLIST || '').split(',').map(v => v.trim()).filter(Boolean));
const ipStrikes = new Map();
const ipBans = new Map();
function reqIp(req) { return String(req.ip || (req.socket && req.socket.remoteAddress) || 'unknown'); }
function isLoopbackIp(ip) { return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1'; }
function trimMap(m, max) {
    if (m.size <= max) return;
    let n = Math.ceil(max / 10);
    for (const k of m.keys()) { m.delete(k); if (--n <= 0) break; }
}
function strikeIp(ip) {
    // Never ban loopback: behind a misconfigured proxy every visitor looks like 127.0.0.1.
    if (isLoopbackIp(ip) || RL_ALLOWLIST.has(ip)) return;
    const now = Date.now();
    let s = ipStrikes.get(ip);
    if (!s || now - s.first > DDOS.strikeWindowMs) s = { count: 0, first: now, last: 0 };
    if (now - s.last < DDOS.strikeSpacingMs) { ipStrikes.set(ip, s); return; }
    s.count++; s.last = now;
    ipStrikes.set(ip, s);
    trimMap(ipStrikes, 50000);
    if (s.count >= DDOS.banThreshold) {
        ipBans.set(ip, now + DDOS.banMs);
        ipStrikes.delete(ip);
        trimMap(ipBans, 50000);
        try { security.auditLog('IP_AUTOBAN', null, `ip=${ip} minutes=${Math.round(DDOS.banMs / 60000)}`); } catch (_) {}
    }
}
setInterval(() => {
    const now = Date.now();
    for (const [ip, until] of ipBans) if (until <= now) ipBans.delete(ip);
    for (const [ip, s] of ipStrikes) if (now - s.first > DDOS.strikeWindowMs) ipStrikes.delete(ip);
}, 60 * 1000).unref();

// 1) Banned IPs are rejected first, before any expensive work (sessions, disk, JSON parsing).
app.use((req, res, next) => {
    const ip = reqIp(req);
    const until = ipBans.get(ip);
    if (until) {
        if (Date.now() < until) {
            res.setHeader('Retry-After', String(Math.ceil((until - Date.now()) / 1000)));
            return res.status(429).type('text/plain').send('Too many requests');
        }
        ipBans.delete(ip);
    }
    next();
});
// 2) Global per-IP limits (API and pages are counted separately).
function floodLimiter(max, message) {
    return rateLimit({
        windowMs: 60 * 1000, max,
        standardHeaders: true, legacyHeaders: false,
        skip: (req) => RL_ALLOWLIST.has(reqIp(req)),
        handler: (req, res) => { strikeIp(reqIp(req)); res.status(429).json({ success: false, error: message }); },
    });
}
const apiFloodLimiter = floodLimiter(DDOS.apiPerMin, 'Too many requests. Slow down.');
const pageFloodLimiter = floodLimiter(DDOS.pagePerMin, 'Too many requests. Slow down.');
app.use((req, res, next) => (req.path.startsWith('/api/') ? apiFloodLimiter : pageFloodLimiter)(req, res, next));

if (ENABLE_TUNNEL && NGROK_AUTHTOKEN && !/^[1-9]\d?$/.test(process.env.TRUST_PROXY || '')) {
    console.warn('⚠️  Tunnel/proxy in use but TRUST_PROXY is not set: all visitors look like one IP, so rate limits are shared. Set TRUST_PROXY=1 (or 2 behind Cloudflare + tunnel).');
}

// ============================================================
// SECURITY HEADERS
// ============================================================
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
}));
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
        "font-src 'self' https://cdnjs.cloudflare.com data:; " +
        "img-src 'self' data: https:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none';"
    );
    next();
});

// ============================================================
// DATABASE
// ============================================================
function hashPassword(pwd) { return bcrypt.hashSync(pwd, 12); }
function verifyPassword(stored, plain) {
    if (!stored) return false;
    if (stored.startsWith('$2')) return bcrypt.compareSync(plain, stored);
    const legacy = crypto.createHash('sha256').update(plain + 'rizz_salt_2026').digest('hex');
    return stored === legacy;
}
const DUMMY_BCRYPT_HASH = bcrypt.hashSync('rizz-dummy-password', 12);
async function verifyPasswordAsync(stored, plain) {
    if (!stored) { await bcrypt.compare(plain, DUMMY_BCRYPT_HASH); return false; }
    if (stored.startsWith('$2')) return bcrypt.compare(plain, stored);
    return verifyPassword(stored, plain);
}
function generateKey(prefix, length = 40) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let key = ''; const bytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) key += chars.charAt(bytes[i] % chars.length);
    return prefix + '_' + key;
}

function writeJsonAtomic(filePath, value) {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tempPath = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
    try {
        fs.writeFileSync(tempPath, JSON.stringify(value, null, 2), { mode: 0o600, flag: 'wx' });
        fs.renameSync(tempPath, filePath);
        try { fs.chmodSync(filePath, 0o600); } catch (_) {}
    } catch (err) {
        try { fs.rmSync(tempPath, { force: true }); } catch (_) {}
        throw err;
    }
}

function loadDB() {
    if (!fs.existsSync(DB_PATH)) {
        const db = {
            users: [{
                id: 'owner-001', username: 'owner', password: hashPassword(DEFAULT_OWNER_PASSWORD),
                role: 'owner', email: 'owner@rizz.local',
                ptla: generateKey('ptla', 40), ptlc: generateKey('ptlc', 40),
                createdAt: new Date().toISOString(), servers: []
            }],
            servers: []
        };
        writeJsonAtomic(DB_PATH, db);
        console.log('📝 Initial owner account created. Username: owner');
        return db;
    }
    const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    let changed = false;
    db.users.forEach(u => {
        if (!u.ptla) { u.ptla = generateKey('ptla', 40); changed = true; }
        if (!u.ptlc) { u.ptlc = generateKey('ptlc', 40); changed = true; }
    });
    if (changed) writeJsonAtomic(DB_PATH, db);
    return db;
}
function saveDB(db) { writeJsonAtomic(DB_PATH, db); }
function getRoleLevel(role) { return { owner: 3, admin: 2, user: 1 }[role] || 0; }

// ============================================================
// PROCESS MANAGER
// ============================================================
const PROCS = {};
const CPU_CACHE = {};

function getServerDir(id, options = {}) {
    if (typeof id !== 'string' || !/^srv-\d+(?:-\d+)?$/.test(id)) throw new Error('Invalid server id');
    const dir = path.join(SERVERS_DIR, id);
    if (!fs.existsSync(dir)) {
        if (options.create === false) return null;
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const realRoot = path.resolve(SERVERS_DIR);
    const realDir = path.resolve(dir);
    if (realDir !== realRoot && !realDir.startsWith(realRoot + path.sep)) throw new Error('Invalid server directory');
    const st = fs.lstatSync(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('Invalid server directory');
    return dir;
}

function nextServerId(db) {
    let id;
    do { id = `srv-${Date.now()}-${crypto.randomBytes(4).readUInt32BE(0)}`; }
    while (db.servers.some(server => server.id === id));
    return id;
}

function validateDays(value, defaultDays = 30) {
    if (value === undefined || value === null || value === '') return defaultDays;
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0 || n > 36500) return null;
    return n;
}

function pushLog(id, line, type = 'output') {
    if (!PROCS[id]) PROCS[id] = { proc: null, startTime: 0, logs: [], lastCpuCheck: 0, lastCpuTicks: 0 };
    PROCS[id].logs.push({ line: String(line), type, ts: Date.now() });
    if (PROCS[id].logs.length > 800) PROCS[id].logs.shift();
}
function daemonLog(id, msg, type = 'system') { pushLog(id, `[Daemon]: ${msg}`, type); }

function readProcStat(pid) {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const rp = stat.lastIndexOf(')');
    if (rp < 0) return null;
    const parts = stat.slice(rp + 2).split(' ');
    return { totalTicks: (parseInt(parts[11]) || 0) + (parseInt(parts[12]) || 0) };
}
function calculateCpuPercent(serverId, pid) {
    const now = Date.now();
    const cached = CPU_CACHE[serverId];
    if (cached && (now - cached.ts) < 2500) return cached.cpu;
    try {
        if (process.platform !== 'linux') return 0;
        const s = readProcStat(pid);
        if (!s) return 0;
        const prev = PROCS[serverId] || {};
        const prevTicks = prev.lastCpuTicks || 0;
        const prevTime = prev.lastCpuCheck || now;
        const elapsed = now - prevTime;
        if (prevTicks === 0 || elapsed <= 0) {
            if (!PROCS[serverId]) PROCS[serverId] = {};
            PROCS[serverId].lastCpuTicks = s.totalTicks;
            PROCS[serverId].lastCpuCheck = now;
            CPU_CACHE[serverId] = { cpu: 0, ts: now };
            return 0;
        }
        const cpuSec = (s.totalTicks - prevTicks) / 100;
        const wallSec = elapsed / 1000;
        let p = (cpuSec / wallSec) * 100;
        if (p < 0) p = 0; if (p > 999) p = 999;
        if (!PROCS[serverId]) PROCS[serverId] = {};
        PROCS[serverId].lastCpuTicks = s.totalTicks;
        PROCS[serverId].lastCpuCheck = now;
        CPU_CACHE[serverId] = { cpu: p, ts: now };
        return p;
    } catch (e) { return 0; }
}
function getProcessRamMB(pid) {
    try {
        if (process.platform !== 'linux') return 0;
        const status = fs.readFileSync(`/proc/${pid}/status`, 'utf-8');
        const m = status.match(/VmRSS:\s+(\d+)\s+kB/);
        return m ? Math.round(parseInt(m[1]) / 1024) : 0;
    } catch (e) { return 0; }
}
function getServerMetrics(serverId) {
    const p = PROCS[serverId];
    if (!p || !p.proc || !p.proc.pid) return { cpu: 0, ram: 0, uptime: 0, running: false };
    const cpu = calculateCpuPercent(serverId, p.proc.pid);
    const ram = getProcessRamMB(p.proc.pid);
    const uptime = Math.floor((Date.now() - p.startTime) / 1000);
    return { cpu: Math.round(cpu * 10) / 10, ram, uptime, running: true };
}

let npmInstallsRunning = 0;
const NPM_INSTALLING = new Set();
// Disk usage per server directory: measured in the background and cached, so polling never blocks the panel.
const DISK_CACHE = {};
let diskScansRunning = 0;
async function scanDirBytes(root) {
    let total = 0, seen = 0;
    const stack = [root];
    while (stack.length) {
        const dir = stack.pop();
        let items;
        try { items = await fs.promises.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
        for (const it of items) {
            if (++seen > 300000) return total;
            try {
                if (it.isSymbolicLink()) continue;
                const full = path.join(dir, it.name);
                if (it.isDirectory()) stack.push(full);
                else if (it.isFile()) total += (await fs.promises.lstat(full)).size;
            } catch (_) {}
        }
    }
    return total;
}
function getDiskUsageMB(serverId) {
    const c = DISK_CACHE[serverId] || (DISK_CACHE[serverId] = { mb: null, ts: 0, scanning: false });
    if (!c.scanning && Date.now() - c.ts > 15000 && diskScansRunning < 2) {
        c.scanning = true; diskScansRunning++;
        let dir = null;
        try { dir = getServerDir(serverId, { create: false }); } catch (_) {}
        (dir ? scanDirBytes(dir) : Promise.resolve(0))
            .then(b => { c.mb = Math.round(b / 1048576 * 10) / 10; })
            .catch(() => {})
            .finally(() => { c.ts = Date.now(); c.scanning = false; diskScansRunning--; });
    }
    return c.mb; // null until the first scan finishes
}

function runNpmInstall(serverId) {
    // Async so a long install never freezes the whole panel; capped so it cannot be used to exhaust the host.
    return new Promise((resolve) => {
        let dir;
        try { dir = getServerDir(serverId); } catch (e) { return resolve({ success: false, error: e.message }); }
        if (NPM_INSTALLING.has(serverId)) return resolve({ success: false, error: 'npm install is already running for this server' });
        if (npmInstallsRunning >= DDOS.maxNpmInstalls) return resolve({ success: false, error: 'Too many npm installs running. Try again in a moment.' });
        NPM_INSTALLING.add(serverId); npmInstallsRunning++;
        daemonLog(serverId, '---------- Running npm install ----------');
        execFile('npm', ['install', '--production', '--no-audit', '--no-fund', '--no-optional', '--ignore-scripts'], {
            cwd: dir, encoding: 'utf-8', timeout: 300000, maxBuffer: 10 * 1024 * 1024,
            shell: process.platform === 'win32',
            env: security.buildSafeEnv(0)
        }, (err, stdout, stderr) => {
            NPM_INSTALLING.delete(serverId); npmInstallsRunning--;
            if (err) {
                const msg = (stdout || '') + (stderr || '') + err.message;
                msg.split('\n').filter(Boolean).forEach(l => pushLog(serverId, l, 'error'));
                daemonLog(serverId, `npm install failed: ${err.message.split('\n')[0]}`, 'error');
                return resolve({ success: false, error: msg });
            }
            const out = stdout || '';
            out.split('\n').filter(Boolean).forEach(l => pushLog(serverId, l, 'output'));
            daemonLog(serverId, 'npm install completed successfully');
            resolve({ success: true, output: out });
        });
    });
}

// ============================================================
// START SERVER (hardened)
// ============================================================
function serverDirectoryHasFiles(dir, depth = 0) {
    // Treat missing/empty server data as a configuration error, never as a reason
    // to create a directory and launch a process in it. Ignore symlinks for safety.
    if (depth > 20) return false;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { return false; }
    for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const full = path.join(dir, entry.name);
        if (entry.isFile()) return true;
        if (entry.isDirectory() && serverDirectoryHasFiles(full, depth + 1)) return true;
    }
    return false;
}

function startServer(serverId, startupCmd) {
    if (PROCS[serverId] && PROCS[serverId].proc) return { success: false, error: 'Server already running' };
    if (PROCS[serverId] && PROCS[serverId].deleted) return { success: false, error: 'Server deleted' };
    let dir;
    try { dir = getServerDir(serverId, { create: false }); }
    catch (e) { return { success: false, error: 'Invalid server data directory' }; }
    if (!dir) {
        const message = 'Cannot start server: data directory is missing. Restore or initialize its files first.';
        daemonLog(serverId, `❌ ${message}`, 'error');
        return { success: false, error: message };
    }
    if (!serverDirectoryHasFiles(dir)) {
        const message = 'Cannot start server: server directory is empty. Upload or restore server files first.';
        daemonLog(serverId, `❌ ${message}`, 'error');
        security.auditLog('STARTUP_REJECTED_EMPTY_DIRECTORY', serverId, message);
        return { success: false, error: message };
    }
    const cmd = startupCmd || 'node index.js';

    const validation = security.validateStartupCommand(cmd);
    if (!validation.ok) {
        daemonLog(serverId, `❌ Invalid startup command: ${validation.error}`, 'error');
        security.auditLog('STARTUP_REJECTED', serverId, validation.error + ' | cmd=' + cmd);
        return { success: false, error: 'Invalid startup command: ' + validation.error };
    }
    const { bin, args } = validation.parsed;

    let cfg = { image: 'node:18', ram: 0, cpu: 0, disk: 0 };
    try {
        const db = loadDB();
        const s = db.servers.find(x => x.id === serverId);
        if (s) cfg = { image: `node:${s.nodeVersion || '18'}`, ram: s.ram || 0, cpu: s.cpu || 0, disk: s.disk || 0 };
    } catch (e) {}

    daemonLog(serverId, '---------- Preparing server environment ----------');
    daemonLog(serverId, `Container Image: ${cfg.image}`);
    daemonLog(serverId, `Memory Limit   : ${cfg.ram > 0 ? cfg.ram + ' MB' : 'Unlimited'}`);
    daemonLog(serverId, `CPU Limit      : ${cfg.cpu > 0 ? cfg.cpu + '%' : 'Unlimited'}`);
    daemonLog(serverId, `Disk Limit     : ${cfg.disk > 0 ? cfg.disk + ' MB' : 'Unlimited'}`);
    daemonLog(serverId, `Working Dir    : ${dir}`);
    daemonLog(serverId, `Startup Cmd    : ${cmd}`);
    daemonLog(serverId, '---------- Starting process ----------');
    pushLog(serverId, `:/home/container$ ${cmd}`, 'command');

    try {
        const serverPort = 3001 + Math.floor(Math.random() * 2000);
        const safeEnv = security.buildSafeEnv(serverPort);

        const dropUid = process.platform !== 'win32' && process.getuid && process.getuid() === 0;
        const proc = spawn(bin, args, {
            cwd: dir,
            shell: false,
            detached: process.platform !== 'win32',
            env: safeEnv,
            stdio: ['pipe', 'pipe', 'pipe'],
            windowsHide: true,
            uid: dropUid ? 1000 : undefined,
            gid: dropUid ? 1000 : undefined,
        });

        proc.stdout.on('data', d => {
            d.toString().split('\n').filter(Boolean).forEach(l => pushLog(serverId, l, 'output'));
        });
        proc.stderr.on('data', d => {
            d.toString().split('\n').filter(Boolean).forEach(l => pushLog(serverId, l, 'error'));
        });
        proc.on('error', err => {
            daemonLog(serverId, `Spawn failed: ${err.message}`, 'error');
            if (PROCS[serverId] && PROCS[serverId].proc === proc) PROCS[serverId].proc = null;
        });
        proc.on('close', (code, signal) => {
            const isCurrent = PROCS[serverId] && PROCS[serverId].proc === proc;
            const reason = signal ? `signal ${signal}` : `exit code ${code}`;
            const isError = code !== 0 && signal !== 'SIGTERM' && signal !== 'SIGKILL';
            daemonLog(serverId, `Process terminated (${reason})`, isError ? 'error' : 'system');
            if (isCurrent) {
                PROCS[serverId].proc = null;
                daemonLog(serverId, '---------- Server stopped ----------');
            }
        });

        if (!PROCS[serverId]) PROCS[serverId] = { proc: null, startTime: 0, logs: [] };
        PROCS[serverId].proc = proc;
        PROCS[serverId].startTime = Date.now();
        PROCS[serverId].lastCpuCheck = 0;
        PROCS[serverId].lastCpuTicks = 0;
        PROCS[serverId].restarting = false;
        PROCS[serverId].deleted = false;

        daemonLog(serverId, `Container started (PID: ${proc.pid})`);
        security.auditLog('SERVER_START', serverId, cmd);
        return { success: true };
    } catch (err) {
        daemonLog(serverId, `Failed to start: ${err.message}`, 'error');
        return { success: false, error: err.message };
    }
}

function stopServer(serverId) {
    if (PROCS[serverId] && PROCS[serverId].proc) {
        const oldProc = PROCS[serverId].proc;
        const pid = oldProc.pid;
        PROCS[serverId].proc = null;

        daemonLog(serverId, 'Received stop signal, initiating graceful shutdown...');
        daemonLog(serverId, 'Sending SIGTERM to process tree...');

        try {
            if (process.platform === 'win32') {
                execFileSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' });
            } else {
                process.kill(-pid, 'SIGTERM');
            }
        } catch (e) {}

        setTimeout(() => {
            try {
                if (process.platform === 'win32') {
                    execFileSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' });
                } else {
                    process.kill(-pid, 'SIGKILL');
                }
            } catch (e) {}
        }, 3000);

        delete CPU_CACHE[serverId];
        security.auditLog('SERVER_STOP', serverId, '');
        return { success: true };
    }
    return { success: false, error: 'Server not running' };
}

// ============================================================
// AUTO-EXPIRE
// ============================================================
function deleteServerCompletely(serverId, reason = 'manual') {
    if (PROCS[serverId] && PROCS[serverId].restarting) {
        console.log(`⏳ [DELETE] Skip "${serverId}" - restarting in progress`);
        return false;
    }
    const db = loadDB();
    const s = db.servers.find(x => x.id === serverId);
    if (!s) return false;
    console.log(`🗑️  [DELETE] "${s.name}" (${s.id}) — ${reason}`);
    security.auditLog('SERVER_DELETE', null, `id=${serverId} reason=${reason}`);
    if (PROCS[serverId]) PROCS[serverId].deleted = true;
    stopServer(s.id);
    db.servers = db.servers.filter(x => x.id !== s.id);
    const owner = db.users.find(u => u.id === s.ownerId);
    if (owner) owner.servers = owner.servers.filter(x => x !== s.id);
    saveDB(db);
    const dir = getServerDir(s.id);
    if (fs.existsSync(dir)) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {} }
    delete PROCS[s.id];
    delete CPU_CACHE[s.id];
    delete DISK_CACHE[s.id];
    return true;
}

function checkExpiredServers() {
    try {
        const db = loadDB();
        const now = Date.now();
        const expired = [];
        db.servers.forEach(s => {
            if (!s.createdAt) return;
            const days = parseInt(s.days) || 0;
            if (days <= 0) return;
            const created = new Date(s.createdAt).getTime();
            const expireAt = created + (days * 24 * 60 * 60 * 1000);
            if (now >= expireAt) expired.push({ id: s.id, name: s.name, days });
        });
        if (expired.length) {
            console.log(`\n⏰ [EXPIRE] ${expired.length} expired server(s):`);
            expired.forEach(e => {
                console.log(`   - "${e.name}" (${e.id}) — age: ${e.days} days`);
                deleteServerCompletely(e.id, `auto-expired (${e.days} days)`);
            });
        }
    } catch (e) { console.log('[EXPIRE] Error:', e.message); }
}

// ============================================================
// MIDDLEWARE
// ============================================================
// Same-origin by default. Cross-origin API access must be explicitly allowlisted.
// Capture the request so same-host requests are not rejected by CORS behind HTTPS proxies.
const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(v => v.trim()).filter(Boolean);
app.use((req, res, next) => {
    const requestHost = (req.get('host') || '').toLowerCase();
    const corsMiddleware = cors({
        origin(origin, callback) {
            if (!origin) return callback(null, true);
            let originHost = '';
            try { originHost = new URL(origin).host.toLowerCase(); } catch (_) {}
            // Same host is allowed; other origins require an exact allowlist entry.
            if ((requestHost && originHost === requestHost) || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error('Origin not allowed'));
        },
        credentials: false,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'X-API-Key']
    });
    corsMiddleware(req, res, next);
});
app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '1mb', parameterLimit: 100 }));
app.use(session({
    name: 'rizz.sid',
    store: new FileStore({ path: SESSIONS_DIR, retries: 0, ttl: 24 * 60 * 60 }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'false' ? 'auto' : true }
}));

function csrfProtection(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    // API-key auth is supported only through X-API-Key, never URL/query/body.
    if (req.path.startsWith('/api/bot/') && req.headers['x-api-key']) return next();
    if (!req.session || !req.session.user) return next();
    const expected = allowedOrigins.length ? allowedOrigins : [];
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    const requestOrigin = `${req.protocol}://${req.get('host')}`;
    const source = origin || (referer ? (() => { try { return new URL(referer).origin; } catch (_) { return ''; } })() : '');
    if (!source) return res.status(403).json({ success: false, error: 'CSRF: missing origin' });
    if (source !== requestOrigin && !expected.includes(source)) return res.status(403).json({ success: false, error: 'CSRF blocked' });
    next();
}
app.use(csrfProtection);
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

app.use('/api/auth/login', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyGenerator: (req) => {
        const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
        const user = (req.body && req.body.username) ? String(req.body.username).toLowerCase() : '';
        return `${ip}::${user}`;
    },
    message: { success: false, error: 'Too many login attempts. Try again in 15 minutes.' },
    standardHeaders: true, legacyHeaders: false,
}));
app.use('/api/auth/login', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    keyGenerator: (req) => req.ip || 'unknown',
    message: { success: false, error: 'Too many login attempts from this IP.' },
    standardHeaders: true, legacyHeaders: false,
}));
const heavyLimiter = rateLimit({
    windowMs: 60 * 1000, max: DDOS.heavyPerMin,
    keyGenerator: (req) => (req.session && req.session.user ? 'u:' + req.session.user.id : reqIp(req)),
    skip: (req) => RL_ALLOWLIST.has(reqIp(req)),
    message: { success: false, error: 'Too many heavy actions. Wait a minute and try again.' },
    standardHeaders: true, legacyHeaders: false,
});
app.use([
    /^\/api\/servers\/[^/]+\/(?:npm-install|start|restart|file\/(?:extract|compress|upload))$/,
    /^\/api\/bot\/my-servers\/[^/]+\/(?:start|restart)$/,
], heavyLimiter);
app.use('/api/bot', rateLimit({
    windowMs: 60 * 1000, max: 120,
    message: { success: false, error: 'Rate limit exceeded' },
    standardHeaders: true, legacyHeaders: false,
}));

function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ success: false, error: 'Unauthorized' });
    next();
}
function requireAdmin(req, res, next) {
    if (!req.session.user || getRoleLevel(req.session.user.role) < 2)
        return res.status(403).json({ success: false, error: 'Admin/Owner only' });
    next();
}
function requireOwner(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'owner')
        return res.status(403).json({ success: false, error: 'Owner only' });
    next();
}
function checkServer(req, res, next) {
    const db = loadDB();
    const server = db.servers.find(s => s.id === req.params.id);
    if (!server) return res.status(404).json({ success: false, error: 'Server not found' });
    const role = req.session.user.role;
    if (role !== 'owner' && server.ownerId !== req.session.user.id)
        return res.status(403).json({ success: false, error: 'Access denied' });
    req.server = server;
    req.db = db;
    next();
}

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password || username.length > 64 || password.length > 1024) return res.status(400).json({ success: false, error: 'Invalid username or password' });
    const db = loadDB();
    const u = db.users.find(x => x.username === username);
    if (loginInFlight >= DDOS.maxLoginConcurrent) return res.status(503).json({ success: false, error: 'Server busy. Try again shortly.' });
    let passOk = false;
    loginInFlight++;
    try { passOk = await verifyPasswordAsync(u ? u.password : null, password); }
    catch (_) { passOk = false; }
    finally { loginInFlight--; }
    if (!u || !passOk)
        return res.json({ success: false, error: 'Invalid credentials' });
    if (!u.password.startsWith('$2')) {
        u.password = hashPassword(password);
        saveDB(db);
    }
    req.session.regenerate(err => {
        if (err) return res.status(500).json({ success: false, error: 'Unable to establish session' });
        req.session.user = { id: u.id, username: u.username, role: u.role, email: u.email || '' };
        req.session.save(saveErr => {
            if (saveErr) return res.status(500).json({ success: false, error: 'Unable to establish session' });
            security.auditLog('LOGIN_SUCCESS', u.username, `ip=${req.ip}`);
            res.json({ success: true, user: req.session.user });
        });
    });
});
app.post('/api/auth/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('rizz.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'false' ? 'auto' : true }); res.json({ success: true }); }); });
app.get('/api/auth/me', (req, res) => {
    if (!req.session.user) return res.json({ success: false });
    res.json({ success: true, user: req.session.user, usingDefaultPassword: false });
});

// ============================================================
// API KEYS
// ============================================================
app.get('/api/user/api-keys', requireAuth, (req, res) => {
    const db = loadDB();
    const u = db.users.find(x => x.id === req.session.user.id);
    if (!u) return res.json({ success: false, error: 'User not found' });
    const result = { success: true, ptlc: u.ptlc, isAdmin: getRoleLevel(u.role) >= 2 };
    if (getRoleLevel(u.role) >= 2) result.ptla = u.ptla;
    res.json(result);
});
app.post('/api/user/api-keys/regenerate', requireAuth, (req, res) => {
    const { type } = req.body;
    const db = loadDB();
    const u = db.users.find(x => x.id === req.session.user.id);
    if (!u) return res.json({ success: false, error: 'User not found' });
    if (type === 'ptla') {
        if (getRoleLevel(u.role) < 2) return res.json({ success: false, error: 'PTLA requires admin/owner role' });
        u.ptla = generateKey('ptla', 40);
    } else if (type === 'ptlc') {
        u.ptlc = generateKey('ptlc', 40);
    } else if (type === 'both') {
        u.ptlc = generateKey('ptlc', 40);
        if (getRoleLevel(u.role) >= 2) u.ptla = generateKey('ptla', 40);
    }
    saveDB(db);
    security.auditLog('APIKEY_REGEN', u.username, `type=${type}`);
    const result = { success: true, ptlc: u.ptlc };
    if (getRoleLevel(u.role) >= 2) result.ptla = u.ptla;
    res.json(result);
});

// ============================================================
// USER PROFILE
// ============================================================
app.put('/api/user/profile', requireAuth, (req, res) => {
    const { username, email } = req.body;
    const db = loadDB();
    const u = db.users.find(x => x.id === req.session.user.id);
    if (!u) return res.json({ success: false, error: 'User not found' });
    if (username !== undefined && (typeof username !== 'string' || !/^[a-zA-Z0-9_.-]{3,32}$/.test(username))) return res.status(400).json({ success: false, error: 'Username must be 3-32 characters (letters, numbers, _, ., -)' });
    if (email !== undefined && (typeof email !== 'string' || email.length > 254 || (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))) return res.status(400).json({ success: false, error: 'Invalid email address' });
    if (username && username !== u.username) {
        if (db.users.find(x => x.username === username && x.id !== u.id))
            return res.json({ success: false, error: 'Username already taken' });
        u.username = username;
    }
    if (email !== undefined) u.email = email;
    db.servers.forEach(s => { if (s.ownerId === u.id) s.ownerName = u.username; });
    saveDB(db);
    req.session.user.username = u.username;
    req.session.user.email = u.email;
    res.json({ success: true, user: { username: u.username, email: u.email, role: u.role } });
});
app.put('/api/user/password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.json({ success: false, error: 'Current and new password required' });
    if (typeof newPassword !== 'string' || newPassword.length < 12 || newPassword.length > 1024) return res.status(400).json({ success: false, error: 'New password must be 12-1024 characters' });
    const db = loadDB();
    const u = db.users.find(x => x.id === req.session.user.id);
    if (!u) return res.json({ success: false, error: 'User not found' });
    if (!verifyPassword(u.password, currentPassword)) return res.json({ success: false, error: 'Current password is incorrect' });
    u.password = hashPassword(newPassword);
    saveDB(db);
    security.auditLog('PASSWORD_CHANGE', u.username, '');
    res.json({ success: true });
});

// ============================================================
// ADMIN USERS
// ============================================================
app.get('/api/admin/users', requireAdmin, (req, res) => {
    const db = loadDB();
    const me = req.session.user;
    res.json({
        success: true,
        users: db.users.map(u => ({
            id: u.id, username: u.username, role: u.role, email: u.email,
            serverCount: u.servers.length, createdAt: u.createdAt,
            canDelete: (me.role === 'owner' && u.role !== 'owner') ||
                       (me.role === 'admin' && u.role === 'user')
        }))
    });
});
app.post('/api/admin/users', requireAdmin, (req, res) => {
    const { username, password, email, role } = req.body;
    if (typeof username !== 'string' || !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{2,31}$/.test(username)) return res.status(400).json({ success: false, error: 'Username must be 3-32 safe characters' });
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) return res.status(400).json({ success: false, error: 'Password must be 12-1024 characters' });
    if (email !== undefined && email !== '' && (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ success: false, error: 'Invalid email address' });
    const me = req.session.user;
    const targetRole = role || 'user';
    if (!['user', 'admin'].includes(targetRole))
        return res.json({ success: false, error: 'Role must be user or admin' });
    if (me.role === 'admin' && targetRole !== 'user')
        return res.json({ success: false, error: 'Admins can only create users' });
    const db = loadDB();
    if (db.users.find(u => String(u.username).toLowerCase() === username.toLowerCase())) return res.status(409).json({ success: false, error: 'Username already taken' });
    const u = {
        id: 'user-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex'),
        username, password: hashPassword(password), role: targetRole, email: email || '',
        ptla: generateKey('ptla', 40), ptlc: generateKey('ptlc', 40),
        createdAt: new Date().toISOString(), servers: []
    };
    db.users.push(u);
    saveDB(db);
    security.auditLog('USER_CREATE', me.username, `new=${username} role=${targetRole}`);
    res.json({ success: true, user: { id: u.id, username, role: u.role } });
});
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    const db = loadDB();
    const me = req.session.user;
    const u = db.users.find(x => x.id === req.params.id);
    if (!u) return res.json({ success: false, error: 'User not found' });
    const canDelete = (me.role === 'owner' && u.role !== 'owner') ||
                      (me.role === 'admin' && u.role === 'user');
    if (!canDelete) return res.status(403).json({ success: false, error: 'Cannot delete this user' });
    u.servers.forEach(sid => deleteServerCompletely(sid, 'user-deleted'));
    db.users = db.users.filter(x => x.id !== req.params.id);
    db.servers = db.servers.filter(s => s.ownerId !== req.params.id);
    saveDB(db);
    security.auditLog('USER_DELETE', me.username, `target=${u.username}`);
    res.json({ success: true });
});

// ============================================================
// SERVERS CRUD
// ============================================================
app.get('/api/servers', requireAuth, (req, res) => {
    const db = loadDB();
    const me = req.session.user;
    let list = me.role === 'owner' ? db.servers : db.servers.filter(s => s.ownerId === me.id);
    list = list.map(s => {
        const metrics = getServerMetrics(s.id);
        const created = s.createdAt ? new Date(s.createdAt).getTime() : Date.now();
        const days = parseInt(s.days) || 0;
        const expireAt = days > 0 ? created + (days * 24 * 60 * 60 * 1000) : null;
        return {
            ...s, status: PROCS[s.id] && PROCS[s.id].proc ? 'running' : 'offline',
            uptime: metrics.uptime, cpuUsage: metrics.cpu, ramUsage: metrics.ram,
            diskUsage: getDiskUsageMB(s.id),
            expireAt, isUnlimited: days <= 0,
        };
    });
    res.json({ success: true, servers: list });
});
app.post('/api/servers', requireAdmin, (req, res) => {
    const { name, ownerId, nodeVersion, ram, cpu, disk, days, startupCommand } = req.body;
    if (typeof name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,49}$/.test(name.trim())) return res.status(400).json({ success: false, error: 'Server name must be 1-50 safe characters' });
    const me = req.session.user;
    const db = loadDB();
    let targetOwnerId = ownerId;
    if (me.role === 'admin') targetOwnerId = me.id;
    else if (me.role === 'owner' && !ownerId) targetOwnerId = me.id;
    const owner = db.users.find(u => u.id === targetOwnerId);
    if (!owner) return res.json({ success: false, error: 'Owner not found' });

    const sc = String(startupCommand || 'node index.js').trim();
    const sv = security.validateStartupCommand(sc);
    if (!sv.ok) {
        security.auditLog('STARTUP_CREATE_REJECTED', me.username, sv.error);
        return res.status(400).json({ success: false, error: 'Invalid startup command: ' + sv.error });
    }

    const d = validateDays(days, 30);
    if (d === null) return res.status(400).json({ success: false, error: 'days must be an integer from 0 to 36500' });
    const id = nextServerId(db);
    const server = {
        id, name, ownerId: owner.id, ownerName: owner.username,
        nodeVersion: nodeVersion || '18',
        ram: parseInt(ram) || 0, cpu: parseInt(cpu) || 0, disk: parseInt(disk) || 0,
        days: d, status: 'offline',
        startupCommand: sc,
        createdAt: new Date().toISOString()
    };
    db.servers.push(server);
    owner.servers.push(id);
    saveDB(db);
    const dir = getServerDir(id);
    fs.writeFileSync(path.join(dir, 'index.js'),
        `// ${name}\nconsole.log('🐉 ${name.replace(/'/g, "\\'")} is running!');\nsetInterval(() => console.log('[Heartbeat]', new Date().toLocaleTimeString()), 5000);\n`);
    fs.writeFileSync(path.join(dir, 'package.json'),
        JSON.stringify({
            name: name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '') || 'server',
            version: '1.0.0', main: 'index.js', scripts: { start: 'node index.js' }
        }, null, 2));
    PROCS[id] = {
        proc: null, startTime: 0, lastCpuCheck: 0, lastCpuTicks: 0,
        logs: [
            { line: `[Daemon]: ---------- Server created ----------`, type: 'system', ts: Date.now() },
            { line: `[Daemon]: Name    : ${name}`, type: 'system', ts: Date.now() },
            { line: `[Daemon]: Owner   : ${owner.username}`, type: 'system', ts: Date.now() },
            { line: `[Daemon]: Startup : ${server.startupCommand}`, type: 'system', ts: Date.now() },
            { line: `[Daemon]: ---------- Ready ----------`, type: 'system', ts: Date.now() },
        ]
    };
    security.auditLog('SERVER_CREATE', me.username, `id=${id} name=${name}`);
    res.json({ success: true, server });
});
app.delete('/api/servers/:id', requireAuth, checkServer, (req, res) => {
    const me = req.session.user;
    if (me.role !== 'owner' && req.server.ownerId !== me.id)
        return res.status(403).json({ success: false, error: 'Access denied' });
    deleteServerCompletely(req.server.id, `manual delete by ${me.username}`);
    res.json({ success: true });
});
app.put('/api/servers/:id', requireAuth, checkServer, (req, res) => {
    const { name, startupCommand, ram, cpu, disk, days, ownerId } = req.body;
    const db = req.db;
    const s = req.server;
    const me = req.session.user;
    const roleLevel = getRoleLevel(me.role);
    if (name !== undefined) {
        if (!String(name).trim()) return res.json({ success: false, error: 'Server name cannot be empty' });
        s.name = String(name).trim();
    }
    if (startupCommand !== undefined) {
        const sc = String(startupCommand).trim();
        if (!sc) return res.json({ success: false, error: 'Startup command cannot be empty' });
        const v = security.validateStartupCommand(sc);
        if (!v.ok) {
            security.auditLog('STARTUP_UPDATE_REJECTED', me.username, v.error + ' | cmd=' + sc);
            return res.status(400).json({ success: false, error: 'Invalid startup command: ' + v.error });
        }
        s.startupCommand = sc;
    }
    if (roleLevel >= 2) {
        if (ram !== undefined) s.ram = parseInt(ram) || 0;
        if (cpu !== undefined) s.cpu = parseInt(cpu) || 0;
        if (disk !== undefined) s.disk = parseInt(disk) || 0;
        if (days !== undefined) {
            const d = parseInt(days);
            if (isNaN(d) || d < 0) return res.json({ success: false, error: 'Days must be >= 0 (0 = unlimited)' });
            s.days = d;
        }
    } else if (ram !== undefined || cpu !== undefined || disk !== undefined || days !== undefined) {
        return res.status(403).json({ success: false, error: 'Only admin/owner can change RAM/CPU/Disk/Days' });
    }
    if (ownerId !== undefined) {
        if (me.role !== 'owner') return res.status(403).json({ success: false, error: 'Only owner can transfer server ownership' });
        const newOwner = db.users.find(u => u.id === ownerId);
        if (!newOwner) return res.json({ success: false, error: 'New owner not found' });
        const oldOwner = db.users.find(u => u.id === s.ownerId);
        if (oldOwner) oldOwner.servers = oldOwner.servers.filter(x => x !== s.id);
        if (!newOwner.servers.includes(s.id)) newOwner.servers.push(s.id);
        s.ownerId = newOwner.id;
        s.ownerName = newOwner.username;
    }
    saveDB(db);
    daemonLog(s.id, `Configuration updated by ${me.username}`);
    res.json({ success: true, server: s });
});
app.put('/api/servers/:id/startup', requireAuth, checkServer, (req, res) => {
    const { startupCommand } = req.body;
    if (!startupCommand) return res.json({ success: false, error: 'Startup command required' });
    const sc = String(startupCommand).trim();
    const v = security.validateStartupCommand(sc);
    if (!v.ok) {
        security.auditLog('STARTUP_UPDATE_REJECTED', req.session.user.username, v.error + ' | cmd=' + sc);
        return res.status(400).json({ success: false, error: 'Invalid startup command: ' + v.error });
    }
    const db = req.db;
    const s = req.server;
    s.startupCommand = sc;
    saveDB(db);
    daemonLog(s.id, `Startup command updated: ${sc}`);
    res.json({ success: true });
});

// ============================================================
// SERVER ACTIONS
// ============================================================
app.post('/api/servers/:id/start', requireAuth, checkServer, (req, res) => {
    daemonLog(req.server.id, `Start request received from ${req.session.user.username}`);
    const r = startServer(req.server.id, req.server.startupCommand);
    if (!r.success) return res.json(r);
    res.json({ success: true, status: 'running' });
});
app.post('/api/servers/:id/stop', requireAuth, checkServer, (req, res) => {
    daemonLog(req.server.id, `Stop request received from ${req.session.user.username}`);
    stopServer(req.server.id);
    res.json({ success: true, status: 'offline' });
});
app.post('/api/servers/:id/restart', requireAuth, checkServer, (req, res) => {
    const id = req.server.id;
    const cmd = req.server.startupCommand;
    daemonLog(id, `Restart request received from ${req.session.user.username}`);
    stopServer(id);
    if (!PROCS[id]) PROCS[id] = { proc: null, startTime: 0, logs: [] };
    PROCS[id].restarting = true;
    setTimeout(() => {
        if (!PROCS[id] || PROCS[id].deleted) return;
        PROCS[id].restarting = false;
        daemonLog(id, 'Restarting server...');
        startServer(id, cmd);
    }, 1800);
    res.json({ success: true, status: 'restarting' });
});
app.post('/api/servers/:id/npm-install', requireAuth, checkServer, async (req, res) => {
    const r = await runNpmInstall(req.server.id);
    res.json(r);
});
app.post('/api/servers/:id/command', requireAuth, checkServer, (req, res) => {
    const { cmd } = req.body;
    const id = req.server.id;
    if (typeof cmd !== 'string' || cmd.length > 2000) {
        return res.status(400).json({ success: false, error: 'Invalid command' });
    }
    pushLog(id, `> ${cmd}`, 'command');
    if (PROCS[id] && PROCS[id].proc && PROCS[id].proc.stdin) {
        try { PROCS[id].proc.stdin.write(cmd + '\n'); }
        catch (e) { pushLog(id, `[Daemon]: Failed to send command: ${e.message}`, 'error'); }
    }
    res.json({ success: true });
});
app.get('/api/servers/:id/logs', requireAuth, checkServer, (req, res) => {
    const id = req.server.id;
    const logs = (PROCS[id] && PROCS[id].logs.length > 0)
        ? PROCS[id].logs
        : [{ line: '[Daemon]: No logs available yet', type: 'system', ts: Date.now() }];
    const m = getServerMetrics(id);
    res.json({
        success: true, logs,
        status: m.running ? 'running' : 'offline',
        uptime: m.uptime, cpuUsage: m.cpu, ramUsage: m.ram,
        diskUsage: getDiskUsageMB(id)
    });
});
app.get('/api/servers/:id/metrics', requireAuth, checkServer, (req, res) => {
    res.json({ success: true, ...getServerMetrics(req.server.id) });
});

// ============================================================
// FILE MANAGER + ARCHIVE
// ============================================================
let AdmZip, tar;
try { AdmZip = require('adm-zip'); } catch (e) {}
try { tar = require('tar'); } catch (e) {}

function safePath(base, userPath) {
    if (typeof userPath !== 'string' || userPath.includes('\0')) throw new Error('Invalid path');
    const baseResolved = path.resolve(base);
    const resolved = path.resolve(baseResolved, userPath || '');
    const norm = (p) => process.platform === 'win32' ? p.toLowerCase() : p;
    const b = norm(baseResolved);
    const r = norm(resolved);
    if (r !== b && !r.startsWith(b + path.sep)) throw new Error('Invalid path (path traversal blocked)');
    // Resolve existing ancestors to block symlink-based escapes, including writes to not-yet-existing files.
    let ancestor = resolved;
    while (!fs.existsSync(ancestor)) {
        const parent = path.dirname(ancestor);
        if (parent === ancestor) throw new Error('Invalid path');
        ancestor = parent;
    }
    if (fs.existsSync(resolved) && fs.lstatSync(resolved).isSymbolicLink()) throw new Error('Invalid path (symbolic links are not allowed)');
    const realBase = norm(fs.realpathSync(baseResolved));
    const realAncestor = norm(fs.realpathSync(ancestor));
    if (realAncestor !== realBase && !realAncestor.startsWith(realBase + path.sep)) throw new Error('Invalid path (symlink traversal blocked)');
    return resolved;
}

function extractArchive(serverId, archivePath, targetDir) {
    const serverDir = getServerDir(serverId);
    const fullArchive = safePath(serverDir, archivePath);
    const fullTarget = safePath(serverDir, targetDir || '');
    if (!fs.existsSync(fullArchive)) throw new Error('Archive not found');
    if (!fs.existsSync(fullTarget)) fs.mkdirSync(fullTarget, { recursive: true });
    const lower = fullArchive.toLowerCase();
    try {
        if (lower.endsWith('.zip')) {
            if (!AdmZip) throw new Error('ZIP extraction library unavailable; install dependencies before starting');
            const zip = new AdmZip(fullArchive);
            const entries = zip.getEntries();
            if (entries.length > 10000) throw new Error('Archive contains too many entries');
            let expandedBytes = 0;
            for (const entry of entries) {
                expandedBytes += Number(entry.header && entry.header.size || 0);
                if (expandedBytes > 250 * 1024 * 1024) throw new Error('Archive expands beyond the 250 MB safety limit');
                if (!security.isSafeExtractPath(fullTarget, entry.entryName)) throw new Error('Unsafe archive entry blocked');
                // ZIP external attributes can encode Unix symlinks; do not extract them.
                const unixMode = (entry.header && entry.header.attr) ? ((entry.header.attr >>> 16) & 0xF000) : 0;
                if (unixMode === 0xA000) throw new Error('Symbolic links in archives are not allowed');
            }
            zip.extractAllTo(fullTarget, true);
            return { success: true, method: 'adm-zip' };
        }
        if (lower.endsWith('.tar') || lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
            if (!tar) throw new Error('TAR extraction library unavailable');
            tar.x({ file: fullArchive, cwd: fullTarget, sync: true, preservePaths: false,
                filter: (entryPath, entry) => {
                    if (!security.isSafeExtractPath(fullTarget, entryPath)) return false;
                    if (entry && (entry.type === 'SymbolicLink' || entry.type === 'Link')) return false;
                    return true;
                }
            });
            return { success: true, method: 'tar-node' };
        }
        if (lower.endsWith('.gz') && !lower.endsWith('.tar.gz')) {
            const outName = path.basename(fullArchive).slice(0, -3);
            fs.writeFileSync(path.join(fullTarget, outName), zlib.gunzipSync(fs.readFileSync(fullArchive), { maxOutputLength: 100 * 1024 * 1024 }));
            return { success: true, method: 'gunzip' };
        }
        if (lower.endsWith('.7z') || lower.endsWith('.rar') || lower.endsWith('.tar.bz2') || lower.endsWith('.tar.xz')) {
            throw new Error('This archive format is disabled until extraction can validate every entry safely');
        }
        throw new Error('Unsupported archive format');
    } catch (err) { throw new Error('Extract failed: ' + err.message); }
}

function createZipArchive(serverId, sourcePaths, outputPath) {
    const serverDir = getServerDir(serverId);
    const fullOutput = safePath(serverDir, outputPath);
    const sources = sourcePaths.map(p => safePath(serverDir, p));
    if (!AdmZip) {
        execFileSync('zip', ['-r', fullOutput, ...sources], { stdio: 'pipe', timeout: 120000 });
        return { success: true, method: 'zip-cli' };
    }
    const zip = new AdmZip();
    sourcePaths.forEach((p, idx) => {
        const full = sources[idx];
        if (fs.existsSync(full)) {
            if (fs.statSync(full).isDirectory()) zip.addLocalFolder(full, path.basename(p));
            else zip.addLocalFile(full);
        }
    });
    zip.writeZip(fullOutput);
    return { success: true, method: 'adm-zip' };
}

app.get('/api/servers/:id/files', requireAuth, checkServer, (req, res) => {
    const sub = typeof req.query.path === 'string' ? req.query.path : '';
    try {
        const dir = getServerDir(req.server.id, { create: false });
        if (!dir) return res.status(409).json({ success: false, error: 'Server data directory is missing; files were not changed. Restore or initialize this server directory first.' });
        const target = safePath(dir, sub);
        if (!fs.existsSync(target)) return res.status(404).json({ success: false, error: 'Directory not found' });
        const targetStat = fs.lstatSync(target);
        if (targetStat.isSymbolicLink() || !targetStat.isDirectory()) return res.status(400).json({ success: false, error: 'Path is not a safe directory' });
        const files = fs.readdirSync(target, { withFileTypes: true }).map(entry => {
            const fp = path.join(target, entry.name);
            const st = fs.lstatSync(fp);
            if (st.isSymbolicLink()) return null;
            return { name: entry.name, isDirectory: st.isDirectory(), size: st.isFile() ? st.size : 0, path: path.posix.join(sub.replace(/\\/g, '/'), entry.name) };
        }).filter(Boolean);
        res.json({ success: true, files, currentPath: sub });
    } catch (e) { res.status(400).json({ success: false, error: 'Unable to list files safely' }); }
});
app.get('/api/servers/:id/file/read', requireAuth, checkServer, (req, res) => {
    const dir = getServerDir(req.server.id);
    try {
        const t = safePath(dir, req.query.path);
        if (fs.statSync(t).size > 5 * 1024 * 1024) return res.json({ success: false, error: 'File too large (>5MB)' });
        res.json({ success: true, content: fs.readFileSync(t, 'utf-8') });
    } catch (e) { res.json({ success: false, error: e.message }); }
});
app.post('/api/servers/:id/file/write', requireAuth, checkServer, (req, res) => {
    const dir = getServerDir(req.server.id);
    try {
        const t = safePath(dir, req.body.path);
        fs.mkdirSync(path.dirname(t), { recursive: true });
        fs.writeFileSync(t, req.body.content, 'utf-8');
        res.json({ success: true });
    } catch (e) { res.json({ success: false, error: e.message }); }
});
app.post('/api/servers/:id/file/mkdir', requireAuth, checkServer, (req, res) => {
    const dir = getServerDir(req.server.id);
    try {
        fs.mkdirSync(safePath(dir, req.body.path), { recursive: true });
        res.json({ success: true });
    } catch (e) { res.json({ success: false, error: e.message }); }
});
app.post('/api/servers/:id/file/rename', requireAuth, checkServer, (req, res) => {
    const dir = getServerDir(req.server.id);
    try {
        const oldPath = safePath(dir, req.body.oldPath);
        const newPath = safePath(dir, req.body.newPath);
        fs.renameSync(oldPath, newPath);
        res.json({ success: true });
    } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/servers/:id/file/bulk-move', requireAuth, checkServer, (req, res) => {
    const { paths, target } = req.body;
    if (!paths || !paths.length) return res.json({ success: false, error: 'Paths required' });
    const dir = getServerDir(req.server.id);
    try {
        const fullTarget = safePath(dir, target || '');
        if (!fs.existsSync(fullTarget)) fs.mkdirSync(fullTarget, { recursive: true });
        const results = [];
        paths.forEach(p => {
            try {
                const oldPath = safePath(dir, p);
                const newPath = path.join(fullTarget, path.basename(p));
                fs.renameSync(oldPath, newPath);
                results.push({ path: p, success: true });
            } catch(e) { results.push({ path: p, success: false, error: e.message }); }
        });
        res.json({ success: true, results });
    } catch (e) { res.json({ success: false, error: e.message }); }
});
app.delete('/api/servers/:id/file/delete', requireAuth, checkServer, (req, res) => {
    const dir = getServerDir(req.server.id);
    try {
        const t = safePath(dir, req.query.path);
        if (fs.statSync(t).isDirectory()) fs.rmSync(t, { recursive: true, force: true });
        else fs.unlinkSync(t);
        res.json({ success: true });
    } catch (e) { res.json({ success: false, error: e.message }); }
});
app.post('/api/servers/:id/file/bulk-delete', requireAuth, checkServer, (req, res) => {
    const { paths } = req.body;
    if (!paths || !paths.length) return res.json({ success: false, error: 'Paths required' });
    const dir = getServerDir(req.server.id);
    const results = [];
    paths.forEach(p => {
        try {
            const t = safePath(dir, p);
            if (fs.statSync(t).isDirectory()) fs.rmSync(t, { recursive: true, force: true });
            else fs.unlinkSync(t);
            results.push({ path: p, success: true });
        } catch (e) { results.push({ path: p, success: false, error: e.message }); }
    });
    res.json({ success: true, results });
});
app.post('/api/servers/:id/file/extract', requireAuth, checkServer, (req, res) => {
    const { path: archivePath, target } = req.body;
    if (!archivePath) return res.json({ success: false, error: 'Archive path required' });
    try {
        daemonLog(req.server.id, `Extracting: ${archivePath} → ${target || '.'}`);
        const result = extractArchive(req.server.id, archivePath, target || path.dirname(archivePath));
        daemonLog(req.server.id, `Extraction complete (${result.method})`);
        res.json({ success: true, ...result });
    } catch (e) {
        daemonLog(req.server.id, `Extraction failed: ${e.message}`, 'error');
        res.json({ success: false, error: e.message });
    }
});
app.post('/api/servers/:id/file/compress', requireAuth, checkServer, (req, res) => {
    const { paths, output } = req.body;
    if (!paths || !paths.length) return res.json({ success: false, error: 'Paths required' });
    if (!output) return res.json({ success: false, error: 'Output path required' });
    try {
        daemonLog(req.server.id, `Compressing ${paths.length} item(s) → ${output}`);
        const result = createZipArchive(req.server.id, paths, output);
        daemonLog(req.server.id, `Compression complete (${result.method})`);
        res.json({ success: true, ...result });
    } catch (e) {
        daemonLog(req.server.id, `Compression failed: ${e.message}`, 'error');
        res.json({ success: false, error: e.message });
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        try {
            const dir = getServerDir(req.params.id);
            const t = safePath(dir, req.query.path || '');
            if (!fs.existsSync(t)) fs.mkdirSync(t, { recursive: true });
            cb(null, t);
        } catch (e) { cb(e); }
    },
    filename: (req, file, cb) => cb(null, path.basename(file.originalname).replace(/[/\\]/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024, files: 1 } });
let uploadsInFlight = 0;
function uploadGate(req, res, next) {
    if (uploadsInFlight >= DDOS.maxUploads) return res.status(429).json({ success: false, error: 'Too many uploads in progress. Try again shortly.' });
    uploadsInFlight++;
    let released = false;
    res.on('close', () => { if (!released) { released = true; uploadsInFlight--; } });
    next();
}

app.post('/api/servers/:id/file/upload', requireAuth, checkServer, uploadGate, upload.single('file'), (req, res) => {
    if (!req.file) return res.json({ success: false, error: 'No file uploaded' });
    res.json({ success: true, file: req.file.filename });
});

// ============================================================
// BOT API
// ============================================================
function apiKeyAuth(req, res, next) {
    const key = req.headers['x-api-key'];
    if (!key) return res.status(401).json({ success: false, error: 'API key required' });
    const db = loadDB();
    let user = null, type = null;
    if (key.startsWith('ptla_')) { user = db.users.find(u => u.ptla === key); type = 'application'; }
    else if (key.startsWith('ptlc_')) { user = db.users.find(u => u.ptlc === key); type = 'client'; }
    if (!user) return res.status(401).json({ success: false, error: 'Invalid API key' });
    req.apiAuth = { type, user };
    next();
}
function requireApplication(req, res, next) {
    if (!req.apiAuth || req.apiAuth.type !== 'application') return res.status(403).json({ success: false, error: 'PTLA required' });
    next();
}
function requireClient(req, res, next) {
    if (!req.apiAuth || req.apiAuth.type !== 'client') return res.status(403).json({ success: false, error: 'PTLC required' });
    next();
}

app.get('/api/bot/me', apiKeyAuth, (req, res) => {
    res.json({ success: true, type: req.apiAuth.type,
        user: { id: req.apiAuth.user.id, username: req.apiAuth.user.username, role: req.apiAuth.user.role, email: req.apiAuth.user.email } });
});
app.get('/api/bot/users', apiKeyAuth, requireApplication, (req, res) => {
    const db = loadDB();
    res.json({ success: true, users: db.users.map(u => ({
        id: u.id, username: u.username, role: u.role, email: u.email,
        serverCount: u.servers.length, createdAt: u.createdAt
    })) });
});
app.post('/api/bot/users', apiKeyAuth, requireApplication, (req, res) => {
    const { username, password, email, role } = req.body;
    if (typeof username !== 'string' || !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{2,31}$/.test(username)) return res.status(400).json({ success: false, error: 'Username must be 3-32 safe characters' });
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) return res.status(400).json({ success: false, error: 'Password must be 12-1024 characters' });
    if (email !== undefined && email !== '' && (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ success: false, error: 'Invalid email address' });
    const me = req.apiAuth.user;
    const targetRole = role || 'user';
    if (!['user', 'admin'].includes(targetRole)) return res.json({ success: false, error: 'Role must be user or admin' });
    if (me.role === 'admin' && targetRole !== 'user') return res.json({ success: false, error: 'Admins can only create users' });
    const db = loadDB();
    if (db.users.find(u => String(u.username).toLowerCase() === username.toLowerCase())) return res.status(409).json({ success: false, error: 'Username already taken' });
    const u = {
        id: 'user-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex'),
        username, password: hashPassword(password), role: targetRole, email: email || '',
        ptla: generateKey('ptla', 40), ptlc: generateKey('ptlc', 40),
        createdAt: new Date().toISOString(), servers: []
    };
    db.users.push(u);
    saveDB(db);
    security.auditLog('USER_CREATE', me.username, `bot new=${username} role=${targetRole}`);
    res.json({ success: true, user: { id: u.id, username: u.username, role: u.role, ptlc: u.ptlc } });
});
app.delete('/api/bot/users/:id', apiKeyAuth, requireApplication, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    const u = db.users.find(x => x.id === req.params.id);
    if (!u) return res.json({ success: false, error: 'User not found' });
    const canDelete = (me.role === 'owner' && u.role !== 'owner') ||
                      (me.role === 'admin' && u.role === 'user');
    if (!canDelete) return res.status(403).json({ success: false, error: 'Cannot delete this user' });
    u.servers.forEach(sid => deleteServerCompletely(sid, 'user-deleted'));
    db.users = db.users.filter(x => x.id !== req.params.id);
    db.servers = db.servers.filter(s => s.ownerId !== req.params.id);
    saveDB(db);
    security.auditLog('USER_DELETE', me.username, `bot target=${u.username}`);
    res.json({ success: true });
});
app.get('/api/bot/servers', apiKeyAuth, requireApplication, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    let list = me.role === 'owner' ? db.servers : db.servers.filter(s => s.ownerId === me.id);
    res.json({ success: true, servers: list.map(s => ({ id: s.id, name: s.name, ownerId: s.ownerId, ownerName: s.ownerName, nodeVersion: s.nodeVersion, ram: s.ram, cpu: s.cpu, disk: s.disk, days: s.days, startupCommand: s.startupCommand, createdAt: s.createdAt, status: PROCS[s.id] && PROCS[s.id].proc ? 'running' : 'offline' })) });
});
app.post('/api/bot/servers', apiKeyAuth, requireApplication, (req, res) => {
    const { name, ownerId, nodeVersion, ram, cpu, disk, days, startupCommand } = req.body;
    if (typeof name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,49}$/.test(name.trim())) return res.status(400).json({ success: false, error: 'Server name must be 1-50 safe characters' });
    const me = req.apiAuth.user;
    const db = loadDB();
    let targetOwnerId = ownerId;
    if (me.role === 'admin') targetOwnerId = me.id;
    else if (me.role === 'owner' && !ownerId) targetOwnerId = me.id;
    const owner = db.users.find(u => u.id === targetOwnerId);
    if (!owner) return res.json({ success: false, error: 'Owner not found' });

    const sc = String(startupCommand || 'node index.js').trim();
    const sv = security.validateStartupCommand(sc);
    if (!sv.ok) {
        security.auditLog('STARTUP_CREATE_REJECTED', me.username, sv.error);
        return res.status(400).json({ success: false, error: 'Invalid startup command: ' + sv.error });
    }

    const d = validateDays(days, 30);
    if (d === null) return res.status(400).json({ success: false, error: 'days must be an integer from 0 to 36500' });
    const id = nextServerId(db);
    const server = {
        id, name, ownerId: owner.id, ownerName: owner.username,
        nodeVersion: nodeVersion || '18',
        ram: parseInt(ram) || 0, cpu: parseInt(cpu) || 0, disk: parseInt(disk) || 0,
        days: d, status: 'offline',
        startupCommand: sc,
        createdAt: new Date().toISOString()
    };
    db.servers.push(server);
    owner.servers.push(id);
    saveDB(db);
    const dir = getServerDir(id);
    fs.writeFileSync(path.join(dir, 'index.js'), `// ${name}\nconsole.log('🐉 ${name.replace(/'/g, "\\'")} is running!');\n`);
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
        name: name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '') || 'server',
        version: '1.0.0', main: 'index.js'
    }, null, 2));
    PROCS[id] = { proc: null, startTime: 0, lastCpuCheck: 0, lastCpuTicks: 0,
        logs: [{ line: `[Daemon]: Server "${name}" created`, type: 'system', ts: Date.now() }] };
    security.auditLog('SERVER_CREATE', me.username, `bot id=${id} name=${name}`);
    res.json({ success: true, server });
});
app.delete('/api/bot/servers/:id', apiKeyAuth, requireApplication, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    const s = db.servers.find(x => x.id === req.params.id);
    if (!s) return res.json({ success: false, error: 'Server not found' });
    if (me.role !== 'owner' && s.ownerId !== me.id) return res.status(403).json({ success: false, error: 'Access denied' });
    deleteServerCompletely(s.id, 'bot-deleted');
    res.json({ success: true });
});
app.get('/api/bot/my-servers', apiKeyAuth, requireClient, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    let servers = db.servers.filter(s => s.ownerId === me.id);
    if (me.role === 'owner') servers = db.servers;
    res.json({ success: true, servers: servers.map(s => ({
        id: s.id, name: s.name,
        status: PROCS[s.id] && PROCS[s.id].proc ? 'running' : 'offline',
        ram: s.ram, cpu: s.cpu, disk: s.disk, startupCommand: s.startupCommand
    })) });
});
app.post('/api/bot/my-servers/:id/start', apiKeyAuth, requireClient, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    const s = db.servers.find(x => x.id === req.params.id && (x.ownerId === me.id || me.role === 'owner'));
    if (!s) return res.json({ success: false, error: 'Server not found' });
    res.json(startServer(s.id, s.startupCommand));
});
app.post('/api/bot/my-servers/:id/stop', apiKeyAuth, requireClient, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    const s = db.servers.find(x => x.id === req.params.id && (x.ownerId === me.id || me.role === 'owner'));
    if (!s) return res.json({ success: false, error: 'Server not found' });
    stopServer(s.id);
    res.json({ success: true });
});
app.post('/api/bot/my-servers/:id/restart', apiKeyAuth, requireClient, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    const s = db.servers.find(x => x.id === req.params.id && (x.ownerId === me.id || me.role === 'owner'));
    if (!s) return res.json({ success: false, error: 'Server not found' });
    stopServer(s.id);
    if (!PROCS[s.id]) PROCS[s.id] = { proc: null, startTime: 0, logs: [] };
    PROCS[s.id].restarting = true;
    setTimeout(() => {
        if (!PROCS[s.id] || PROCS[s.id].deleted) return;
        PROCS[s.id].restarting = false;
        startServer(s.id, s.startupCommand);
    }, 1800);
    res.json({ success: true });
});
app.delete('/api/bot/my-servers/:id', apiKeyAuth, requireClient, (req, res) => {
    const db = loadDB();
    const me = req.apiAuth.user;
    const s = db.servers.find(x => x.id === req.params.id && (x.ownerId === me.id || me.role === 'owner'));
    if (!s) return res.json({ success: false, error: 'Server not found' });
    deleteServerCompletely(s.id, 'bot-deleted');
    res.json({ success: true });
});

// ============================================================
// STATIC + PROTECTED MULTI-PAGE ROUTES
// ============================================================
// Only explicitly public assets are exposed. HTML pages must go through auth routes.
app.get('/common.css', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'common.css')));
app.get('/common.js', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'common.js')));

function pageRequireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.redirect('/login');
    }
    next();
}

// Redirect root ke dashboard (kalau login) atau login
app.get('/', (req, res) => {
    if (req.session && req.session.user) return res.redirect('/dashboard');
    res.redirect('/login');
});

// Public: login page (kalau sudah login, redirect ke dashboard)
app.get('/login', (req, res) => {
    if (req.session && req.session.user) return res.redirect('/dashboard');
    res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

// Protected pages
app.get('/dashboard', pageRequireAuth, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html'));
});
app.get('/user', pageRequireAuth, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'user.html'));
});
app.get('/settings', pageRequireAuth, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'settings.html'));
});

// Fallback
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ success: false, error: 'Not found' });
    }
    res.redirect('/login');
});

// Generic error handler: avoid leaking stack traces, filesystem paths, or parser internals.
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = err && (err.status === 413 || err.status === 400) ? err.status :
        (err && err.message === 'Origin not allowed' ? 403 : 500);
    if (status >= 500) console.error('[HTTP_ERROR]', req.method, req.path, err && err.message ? err.message : 'unknown');
    res.status(status).json({ success: false, error: status === 413 ? 'Request too large' : status === 400 ? 'Invalid request' : status === 403 ? 'Origin not allowed' : 'Internal server error' });
});

// ============================================================
// NGROK
// ============================================================
let tunnel = null;
function startNgrok() {
    if (!ENABLE_TUNNEL) { console.log('🌐 Tunnel OFF'); return; }
    if (!NGROK_AUTHTOKEN) {
        console.log('🌐 Tunnel disabled (no NGROK_AUTHTOKEN).');
        return;
    }
    console.log('🌐 Starting Ngrok Tunnel...');
    try {
        const npxCmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
        const ngrokArgs = ['-y', 'ngrok', 'http', String(PORT)];
        if (NGROK_DOMAIN) ngrokArgs.push(`--domain=${NGROK_DOMAIN}`);
        // Keep the auth token out of process arguments; child inherits environment.
        tunnel = spawn(npxCmd, ngrokArgs, { stdio: ['ignore', 'pipe', 'pipe'], shell: process.platform === 'win32', env: { ...process.env, NGROK_AUTHTOKEN } });
        tunnel.stdout.on('data', d => process.stdout.write(d.toString()));
        tunnel.stderr.on('data', d => process.stdout.write(d.toString()));
        tunnel.on('close', (code) => { console.log(`⚠️ Ngrok exited (${code}). Restarting in 5s...`); setTimeout(startNgrok, 5000); });
        tunnel.on('error', (e) => console.log('⚠️ Ngrok error:', e.message));
    } catch (e) { console.log('⚠️ Tunnel failed:', e.message); }
}

// ============================================================
// START
// ============================================================
const httpServer = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Local: http://localhost:${PORT}`);
    if (ENABLE_TUNNEL && NGROK_AUTHTOKEN) console.log(`🔗 Public: https://${NGROK_DOMAIN || 'ngrok-tunnel'}`);
    console.log('');
    startNgrok();
    setInterval(checkExpiredServers, EXPIRE_CHECK_INTERVAL);
    setTimeout(checkExpiredServers, 5000);
});
// Slowloris / connection-exhaustion protection
httpServer.headersTimeout = 15 * 1000;
httpServer.keepAliveTimeout = 5 * 1000;
httpServer.requestTimeout = DDOS.requestTimeoutMs;
httpServer.maxHeadersCount = 50;
httpServer.maxConnections = DDOS.maxConnections;

// ============================================================
// SHUTDOWN
// ============================================================
function shutdown() {
    console.log('\n🛑 Shutting down...');
    Object.values(PROCS).forEach(p => {
        if (p.proc && p.proc.pid) {
            try {
                if (process.platform === 'win32') {
                    execFileSync('taskkill', ['/pid', String(p.proc.pid), '/T', '/F'], { stdio: 'ignore' });
                } else {
                    process.kill(-p.proc.pid, 'SIGKILL');
                }
            } catch (e) {}
        }
    });
    if (tunnel) { try { tunnel.kill(); } catch (e) {} }
    process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

process.on('uncaughtException', e => {
    console.error('💥 uncaughtException:', e);
    try {
        fs.appendFileSync(path.join(BASE_DIR, 'crash.log'),
            `[${new Date().toISOString()}] ${e.stack || e.message}\n`, { mode: 0o600 });
    } catch (_) {}
    shutdown();
    setTimeout(() => process.exit(1), 1500);
});
process.on('unhandledRejection', e => {
    console.error('💥 unhandledRejection:', e);
    try {
        fs.appendFileSync(path.join(BASE_DIR, 'crash.log'),
            `[${new Date().toISOString()}] unhandledRejection: ${e && e.stack ? e.stack : e}\n`, { mode: 0o600 });
    } catch (_) {}
});