// ============================================================
// security.js — Protection layer for Rizz Pterodactyl
// ============================================================
const path = require('path');
const fs = require('fs');

// ─── Whitelist binary ────────────────────────────────────────
const ALLOWED_BINARIES = {
    npm:  { allowArgs: true, blockFlags: [] },
    npx:  { allowArgs: true, blockFlags: [] },
    node: { allowArgs: true, blockFlags: ['-e', '--eval', '-p', '--print', '-r', '--require', '--experimental-loader', '--loader', '-i', '--interactive'] },
};

// Subcommand npm yang diizinkan
const ALLOWED_NPM_SUBCOMMANDS = new Set([
    'install', 'i', 'ci',
    'start', 'stop', 'restart', 'test',
    'run', 'run-script',
    'update', 'up',
    'ls', 'list',
    'outdated',
    'init',
]);

// Shell metachar yang HARAM
const FORBIDDEN_PATTERN = /[;&|`$<>(){}\\\n\r"']/;

// Path/argumen sensitif yang diblokir
const FORBIDDEN_ARG_PATTERNS = [
    /database\.json/i,
    /\.session_secret/i,
    /\.\.\//,
    /\/etc\//,
    /\/root\//,
    /\/home\/container\/(database|sessions|audit|crash)/i,
    /^\/proc\//,
    /^\/sys\//,
];

// ─── GitHub install allowlist ────────────────────────────────
// Format yang diizinkan (WAJIB ada #ref agar reproducible):
//   github:user/repo#ref
//   git+https://github.com/user/repo.git#ref
//   https://github.com/user/repo/archive/refs/tags/<tag>.tar.gz
//   https://github.com/user/repo/archive/<sha>.tar.gz
//   https://github.com/user/repo/archive/refs/heads/<branch>.tar.gz  (branch diblokir, lihat di bawah)
// Ref harus SHA (7-40 hex) atau tag semver-ish (v1.2.3, 1.2.3, dll)
const REF_PATTERN = /^(?:[a-f0-9]{7,40}|v?\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.]+)?|[a-zA-Z0-9._-]+)$/i;
const SHA_PATTERN = /^[a-f0-9]{7,40}$/i;

function isAllowedGithubSource(spec) {
    if (typeof spec !== 'string') return false;

    // 1) github:user/repo#ref
    let m = spec.match(/^github:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:#([A-Za-z0-9._+-]+))?$/);
    if (m) {
        const [, user, repo, ref] = m;
        if (!user || !repo) return false;
        if (!ref) return false;                 // wajib #ref
        return REF_PATTERN.test(ref);
    }

    // 2) git+https://github.com/user/repo(.git)#ref
    m = spec.match(/^git\+https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?#([A-Za-z0-9._+-]+)$/);
    if (m) {
        const [, user, repo, ref] = m;
        if (!user || !repo || !ref) return false;
        return REF_PATTERN.test(ref);
    }

    // 3) https://github.com/user/repo/archive/refs/tags/<tag>.tar.gz
    m = spec.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/archive\/refs\/tags\/([A-Za-z0-9._+-]+)\.tar\.gz$/);
    if (m) {
        const [, , , tag] = m;
        return REF_PATTERN.test(tag);
    }

    // 4) https://github.com/user/repo/archive/<sha>.tar.gz
    m = spec.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/archive\/([a-f0-9]{7,40})\.tar\.gz$/i);
    if (m) return true;

    // Semua bentuk lain (refs/heads/master, gitlab, git+ssh, dll) ditolak
    return false;
}

// ─── Validasi npm install source ─────────────────────────────
function isAllowedNpmInstallArg(a) {
    if (typeof a !== 'string' || !a) return false;

    // Local registry package: "express", "@scope/pkg", "pkg@1.2.3", "pkg@latest"
    // Blokir yang diawali ., /, ~, atau mengandung :// atau file: atau git+ssh
    if (/^[a-zA-Z0-9@][a-zA-Z0-9@/_.-]*(@[a-zA-Z0-9._^~<>=*|-]+)?$/.test(a)) {
        // Pastikan bukan URL/git
        if (!/^(git\+|https?:\/\/|file:|\.\.\/|\/)/.test(a)) return true;
    }

    // GitHub forms
    if (isAllowedGithubSource(a)) return true;

    return false;
}

function validateStartupCommand(cmd) {
    if (typeof cmd !== 'string') return { ok: false, error: 'Command must be a string' };
    const trimmed = cmd.trim();
    if (!trimmed) return { ok: false, error: 'Command is empty' };
    if (trimmed.length > 800) return { ok: false, error: 'Command too long (max 800 chars)' };
    if (FORBIDDEN_PATTERN.test(trimmed)) {
        return { ok: false, error: 'Command contains forbidden characters (; & | ` $ < > ( ) { } \\ quotes)' };
    }

    const parts = trimmed.split(/\s+/).filter(Boolean);
    if (!parts.length) return { ok: false, error: 'Command is empty' };

    const bin = path.basename(parts[0]);
    const rule = ALLOWED_BINARIES[bin];
    if (!rule) {
        return {
            ok: false,
            error: `Binary "${bin}" not allowed. Allowed: ${Object.keys(ALLOWED_BINARIES).join(', ')}`,
        };
    }

    const args = parts.slice(1);

    // Cek forbidden flag & path
    for (const a of args) {
        const lower = a.toLowerCase();
        for (const bad of rule.blockFlags) {
            if (lower === bad.toLowerCase() || lower.startsWith(bad.toLowerCase() + '=')) {
                return { ok: false, error: `Flag "${bad}" not allowed for ${bin}` };
            }
        }
        for (const pat of FORBIDDEN_ARG_PATTERNS) {
            if (pat.test(a)) return { ok: false, error: `Argument "${a}" references a forbidden path` };
        }
    }

    // ─── Khusus node: HANYA `node <file>.js` ───
    if (bin === 'node') {
        if (!args.length) {
            return { ok: false, error: 'node requires a script file (e.g. node index.js)' };
        }
        for (const a of args) {
            if (a.startsWith('-')) {
                return { ok: false, error: 'node flags not allowed (use plain "node <file>.js")' };
            }
        }
        const script = args[0];
        if (!/^[a-zA-Z0-9._\-/]+\.(js|mjs|cjs)$/.test(script)) {
            return { ok: false, error: `node script must be a .js/.mjs/.cjs file, got "${script}"` };
        }
        if (script.startsWith('/') || script.includes('..')) {
            return { ok: false, error: 'node script path must be relative (no absolute, no ..)' };
        }
    }

    // ─── Khusus npm ───
    if (bin === 'npm') {
        if (!args.length) {
            return { ok: false, error: 'npm requires a subcommand (start, stop, restart, install ...)' };
        }
        const sub = args[0].toLowerCase();
        if (!ALLOWED_NPM_SUBCOMMANDS.has(sub)) {
            return {
                ok: false,
                error: `npm subcommand "${sub}" not allowed. Allowed: ${[...ALLOWED_NPM_SUBCOMMANDS].join(', ')}`,
            };
        }
        // npm run <script>
        if ((sub === 'run' || sub === 'run-script') && args[1]) {
            const scriptName = args[1];
            if (!/^[a-zA-Z0-9:_-]+$/.test(scriptName)) {
                return { ok: false, error: 'npm run script name must be alphanumeric (a-z, 0-9, :, _, -)' };
            }
        }
        // npm install <pkg> — hanya registry + GitHub (dengan #ref)
        if (sub === 'install' || sub === 'i' || sub === 'ci') {
            for (const a of args.slice(1)) {
                // Skip flags npm (--save, --production, --no-audit, dll)
                if (a.startsWith('--') || a.startsWith('-')) continue;
                if (!isAllowedNpmInstallArg(a)) {
                    return {
                        ok: false,
                        error: `npm install source "${a}" not allowed. Only registry packages and GitHub with pinned #ref (SHA or tag) are permitted.`,
                    };
                }
            }
        }
    }

    // ─── Khusus npx: registry package atau github:...#ref ───
    if (bin === 'npx') {
        for (const a of args) {
            if (a.startsWith('-')) continue; // flag npx
            if (/^[a-zA-Z0-9@][a-zA-Z0-9@/_.-]*(@[a-zA-Z0-9._^~<>=*|-]+)?$/.test(a)) continue; // registry
            if (isAllowedGithubSource(a)) continue; // github:..#ref
            return { ok: false, error: `npx source "${a}" not allowed` };
        }
    }

    return { ok: true, parsed: { bin, args } };
}

// ─── Env sanitizer ───────────────────────────────────────────
const SAFE_ENV_KEYS = [
    'PATH', 'HOME', 'LANG', 'LC_ALL', 'TERM', 'TZ', 'NODE_ENV',
    'PYTHONUNBUFFERED', 'PYTHONIOENCODING',
];

function buildSafeEnv(port, extra = {}) {
    const safe = {};
    for (const k of SAFE_ENV_KEYS) {
        if (process.env[k] !== undefined) safe[k] = process.env[k];
    }
    safe.HOME = process.env.HOME || '/tmp';
    safe.PORT = String(port);
    safe.NODE_ENV = 'production';
    // Matikan pre/post script npm — cegah supply-chain attack
    safe.npm_config_ignore_scripts = 'true';
    safe.npm_config_audit = 'false';
    safe.npm_config_fund = 'false';
    // Jangan bocorkan kredensial git
    delete safe.GIT_TOKEN;
    delete safe.GITHUB_TOKEN;
    return { ...safe, ...extra };
}

// ─── Zip-slip protection ─────────────────────────────────────
function isSafeExtractPath(baseDir, entryName) {
    const base = path.resolve(baseDir);
    const target = path.resolve(base, entryName);
    if (target === base) return true;
    return target.startsWith(base + path.sep);
}

// ─── Audit log ───────────────────────────────────────────────
const AUDIT_PATH = path.join(process.env.RIZZ_BASE_DIR || process.cwd(), 'audit.log');
function auditLog(action, user, detail) {
    const line = `[${new Date().toISOString()}] ${action} | user=${user || '-'} | ${detail || ''}\n`;
    try { fs.appendFileSync(AUDIT_PATH, line, { mode: 0o600 }); } catch (_) {}
}

module.exports = {
    validateStartupCommand,
    buildSafeEnv,
    isSafeExtractPath,
    auditLog,
    isAllowedGithubSource,
    isAllowedNpmInstallArg,
    ALLOWED_BINARIES,
    ALLOWED_NPM_SUBCOMMANDS,
    SAFE_ENV_KEYS,
};