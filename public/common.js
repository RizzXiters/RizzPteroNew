// ============================================================
// common.js — Shared helpers for Rizz Pterodactyl
// ============================================================

// Global state (diisi setelah requireLogin berhasil)
// CATATAN: JANGAN ubah manual dari console — hanya UI yang berubah,
//          API tetap pakai session cookie di server (httpOnly).
let currentUser = null;

// ─── Role helpers ───────────────────────────────────────────
function roleLevel(role) {
  return { owner: 3, admin: 2, user: 1 }[role] || 0;
}

// ─── API wrapper ────────────────────────────────────────────
// - Auto credentials (session cookie)
// - Auto redirect ke /login kalau 401 (kecuali endpoint /api/auth/me)
// - Selalu return object (tidak throw untuk error HTTP biasa)
async function api(url, opt = {}) {
  let res;
  try {
    res = await fetch(url, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      ...opt
    });
  } catch (e) {
    return { success: false, error: 'Network error: ' + e.message };
  }

  // Session expired / belum login → redirect (kecuali cek auth)
  if (res.status === 401) {
    const isAuthCheck = url === '/api/auth/me';
    if (!isAuthCheck) {
      window.location.href = '/login';
    }
    return { success: false, error: 'Unauthorized', _redirect: true };
  }

  // Parse JSON
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { success: false, error: 'Invalid response (HTTP ' + res.status + ')' };
  }
  return data;
}

// ─── Toast notification ─────────────────────────────────────
function toast(msg, type = 'success') {
  let el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.className = 'toast show ' + type;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3000);
}

// ─── HTML escape (anti-XSS) ─────────────────────────────────
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

// ─── Auth guard ─────────────────────────────────────────────
// Panggil di awal setiap halaman protected.
async function requireLogin() {
  const d = await api('/api/auth/me');
  if (!d.success) {
    window.location.href = '/login';
    return null;
  }
  currentUser = d.user;
  return d.user;
}

// ─── Role guard (client-side, untuk UX) ─────────────────────
// NOTE: Ini HANYA untuk UX (sembunyikan UI).
// Otorisasi asli tetap di backend (API akan 403 kalau role tidak tepat).
function requireRole(minLevel) {
  if (!currentUser) return false;
  if (roleLevel(currentUser.role) < minLevel) {
    toast('Access denied: admin/owner only', 'error');
    setTimeout(() => { window.location.href = '/dashboard'; }, 1200);
    return false;
  }
  return true;
}

// ─── Navbar rendering ───────────────────────────────────────
function renderNavbar() {
  const el = document.getElementById('navbarUser');
  if (!el) return;
  if (!currentUser) return;
  el.innerHTML = `
    <span>${esc(currentUser.username)}</span>
    <span class="role-badge ${esc(currentUser.role)}">${esc(currentUser.role.toUpperCase())}</span>
    <button onclick="doLogout()"><i class="fas fa-power-off"></i> Logout</button>
  `;
}

// ─── Logout ─────────────────────────────────────────────────
async function doLogout() {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } catch (e) { /* ignore */ }
  currentUser = null;
  window.location.href = '/login';
}

// ─── Modal helpers ──────────────────────────────────────────
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
}

// ─── Format helpers ─────────────────────────────────────────
function fmtSize(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(2) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function fmtUptime(sec) {
  if (!sec || sec < 0) return '0h 0m';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

// ─── Guard navigasi (client-side) ───────────────────────────
function guardPageRole(minLevel) {
  if (!currentUser) return;
  if (roleLevel(currentUser.role) < minLevel) {
    window.location.href = '/dashboard';
  }
}

// ─── Expose ke window (untuk inline onclick) ────────────────
window.api = api;
window.toast = toast;
window.esc = esc;
window.requireLogin = requireLogin;
window.requireRole = requireRole;
window.renderNavbar = renderNavbar;
window.doLogout = doLogout;
window.openModal = openModal;
window.closeModal = closeModal;
window.fmtSize = fmtSize;
window.fmtUptime = fmtUptime;
window.roleLevel = roleLevel;
window.guardPageRole = guardPageRole;
