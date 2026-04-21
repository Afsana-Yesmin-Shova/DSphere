/**
 * DSphere — admin.js
 * Shared JS for all admin pages.
 * Handles: stats, threat feed, blocked IPs, user management,
 *          block/unblock actions, threat history.
 */
'use strict';

const API_BASE = 'https://your-backend.onrender.com';

/* ── helpers ─────────────────────────────────────────────── */
function getToken() { return sessionStorage.getItem('dsphere_access') || ''; }
function getUser()  { try { return JSON.parse(sessionStorage.getItem('dsphere_user') || '{}'); } catch { return {}; } }
function logout()   { sessionStorage.clear(); window.location.href = '../index.html'; }

async function apiFetch(endpoint, opts = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...opts,
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${getToken()}`,
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) { window.location.href = '../index.html'; return null; }
  if (res.status === 403) { showToast('Admin access required.', 'error'); return null; }
  return res;
}

function showToast(msg, type = 'info') {
  const t = document.getElementById('a-toast');
  if (!t) return;
  const colors = { info:'var(--a-accent)', error:'var(--a-critical)', success:'var(--a-success)', warn:'var(--a-warn)' };
  t.style.borderLeft = `4px solid ${colors[type] || colors.info}`;
  t.textContent = msg;
  t.style.opacity = '1'; t.style.pointerEvents = 'auto';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; t.style.pointerEvents = 'none'; }, 4000);
}

function esc(s = '') {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtBytes(b = 0) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(typeof ts === 'number' ? ts * 1000 : ts);
  return d.toLocaleString('en-GB', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
}

function fmtCountdown(secs) {
  if (secs <= 0) return 'expired';
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function riskBadge(level) {
  return `<span class="risk-badge risk-${level}"><span class="risk-dot"></span>${level}</span>`;
}

/* ── clock ───────────────────────────────────────────────── */
function startClock() {
  const el = document.getElementById('system-clock');
  if (!el) return;
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
  };
  tick();
  setInterval(tick, 1000);
}

/* ── init ────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const user = getUser();
  if (!getToken() || user.role !== 'admin') {
    showToast('Admin access required.', 'error');
    setTimeout(() => { window.location.href = '../index.html'; }, 1500);
    return;
  }

  const name = user.name || user.email || 'Admin';
  ['admin-name-side'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = name;
  });
  ['admin-avatar-side'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = name.charAt(0).toUpperCase();
  });

  startClock();
  loadAll();

  // Auto-refresh every 30 s
  setInterval(loadAll, 30_000);
});

/* ── LOAD ALL DATA ───────────────────────────────────────── */
async function loadAll() {
  await Promise.all([loadStats(), loadThreats(), loadBlockedIps(), loadUsers(), loadThreatHistory()]);
}

/* ── STATS ───────────────────────────────────────────────── */
async function loadStats() {
  const res = await apiFetch('/admin/stats');
  if (!res || !res.ok) return;
  const { stats } = await res.json();

  const set = (id, val) => { const el=document.getElementById(id); if(el) el.textContent=val; };

  set('s-blocked', stats.security.blocked_ips);
  set('s-high',    stats.security.high_risk_ips);
  set('s-users',   stats.users.total);
  set('s-users-sub', `${stats.users.active} active`);
  set('s-files',   stats.storage.total_files);
  set('s-storage-sub', fmtBytes(stats.storage.total_bytes));

  // Nav badge
  const navBadge = document.getElementById('nav-threat-count');
  if (navBadge) {
    navBadge.textContent = stats.security.total_flagged;
    navBadge.style.display = stats.security.total_flagged > 0 ? '' : 'none';
  }

  // System status dot
  const dot  = document.getElementById('system-dot');
  const text = document.getElementById('system-status-text');
  const isCritical = stats.security.high_risk_ips > 0 || stats.security.blocked_ips > 0;
  if (dot)  { dot.classList.toggle('critical', isCritical); }
  if (text) { text.textContent = isCritical ? 'Threats detected' : 'System operational'; text.style.color = isCritical ? 'var(--a-critical)' : 'var(--a-success)'; }

  // Users page summary
  set('u-total',     stats.users.total);
  set('u-active',    stats.users.active);
  set('u-suspended', stats.users.suspended);
}

/* ── THREAT FEED (live in-memory risks) ──────────────────── */
async function loadThreats() {
  const res = await apiFetch('/admin/threats');
  if (!res || !res.ok) return;
  const data = await res.json();

  renderThreatFeed(data.threats || []);
  renderLiveRisks(data.threats || []);
}

function renderThreatFeed(threats) {
  const feed = document.getElementById('threat-feed');
  if (!feed) return;

  if (!threats.length) {
    feed.innerHTML = '<div class="a-empty"><div class="a-empty__icon">🛡️</div>No active threats detected.</div>';
    return;
  }

  feed.innerHTML = threats.map(t => `
    <div class="threat-item">
      <span class="threat-item__icon">${t.risk_level === 'HIGH' ? '🚨' : '⚠️'}</span>
      <div class="threat-item__body">
        <div class="threat-item__ip">${esc(t.ip)}</div>
        <div class="threat-item__reasons">${(t.reasons || []).map(r => esc(r)).join(' · ')}</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px">
        ${riskBadge(t.risk_level)}
        <div class="threat-item__actions">
          <button class="a-btn a-btn-danger a-btn-sm" onclick="confirmBlockIp('${esc(t.ip)}')">Block IP</button>
          <button class="a-btn a-btn-ghost a-btn-sm" onclick="resetRisk('${esc(t.ip)}')">Clear</button>
        </div>
      </div>
    </div>`).join('');
}

function renderLiveRisks(threats) {
  const tbody = document.getElementById('live-tbody');
  if (!tbody) return;
  const countEl = document.getElementById('live-count');
  if (countEl) countEl.textContent = `${threats.length} IP(s) flagged`;

  if (!threats.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="a-empty"><div class="a-empty__icon">🛡️</div>No flagged IPs.</div></td></tr>';
    return;
  }

  tbody.innerHTML = threats.map(t => `
    <tr>
      <td><span class="mono">${esc(t.ip)}</span></td>
      <td>${riskBadge(t.risk_level)}</td>
      <td style="color:var(--a-muted)">${t.downloads_in_window ?? '—'}</td>
      <td style="color:var(--a-muted)">${t.uploads_in_window ?? '—'}</td>
      <td style="font-size:0.75rem;color:var(--a-muted);max-width:220px">${(t.reasons||[]).map(r=>esc(r)).join('<br>')}</td>
      <td style="text-align:right">
        <div style="display:flex;gap:5px;justify-content:flex-end">
          <button class="a-btn a-btn-danger a-btn-sm" onclick="confirmBlockIp('${esc(t.ip)}')">Block</button>
          <button class="a-btn a-btn-ghost a-btn-sm" onclick="resetRisk('${esc(t.ip)}')">Clear</button>
        </div>
      </td>
    </tr>`).join('');
}

/* ── THREAT HISTORY ──────────────────────────────────────── */
async function loadThreatHistory() {
  const res = await apiFetch('/admin/threats/history?limit=50');
  if (!res || !res.ok) return;
  const data = await res.json();
  renderThreatHistory(data.events || []);
}

function renderThreatHistory(events) {
  // Dashboard mini-table
  const tbody = document.getElementById('event-tbody');
  if (tbody) {
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="4"><div class="a-empty" style="padding:20px"><div class="a-empty__icon">📋</div>No events logged.</div></td></tr>';
    } else {
      tbody.innerHTML = events.slice(0,8).map(e => `
        <tr>
          <td style="font-size:0.75rem;color:var(--a-muted);white-space:nowrap">${fmtTime(e.timestamp_iso || e.timestamp)}</td>
          <td><span class="mono">${esc(e.ip||'—')}</span></td>
          <td>${riskBadge(e.risk_level||'LOW')}</td>
          <td style="font-size:0.75rem;color:var(--a-muted)">${esc((e.reasons||[])[0] || '—')}</td>
        </tr>`).join('');
    }
  }

  // Full history table (threats page)
  const histTbody = document.getElementById('history-tbody');
  if (histTbody) {
    const hCount = document.getElementById('history-count');
    if (hCount) hCount.textContent = `${events.length} events`;

    if (!events.length) {
      histTbody.innerHTML = '<tr><td colspan="6"><div class="a-empty"><div class="a-empty__icon">📋</div>No events.</div></td></tr>';
      return;
    }
    histTbody.innerHTML = events.map(e => `
      <tr>
        <td style="white-space:nowrap;font-size:0.75rem;color:var(--a-muted)">${fmtTime(e.timestamp_iso || e.timestamp)}</td>
        <td><span class="mono">${esc(e.ip||'—')}</span></td>
        <td style="font-size:0.75rem;color:var(--a-muted)">${esc(e.uid||'anon')}</td>
        <td>${riskBadge(e.risk_level||'LOW')}</td>
        <td style="font-size:0.75rem;color:var(--a-muted)">${(e.reasons||[]).map(r=>esc(r)).join('<br>')}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--a-muted)">${esc(e.path||'')}</td>
      </tr>`).join('');
  }
}

/* ── BLOCKED IPs ─────────────────────────────────────────── */
async function loadBlockedIps() {
  const res = await apiFetch('/admin/blocked-ips');
  if (!res || !res.ok) return;
  const data = await res.json();
  renderBlocked(data.blocked_ips || []);
}

function renderBlocked(blocked) {
  // Dashboard mini-table
  const tbody = document.getElementById('blocked-tbody');
  if (tbody) {
    if (!blocked.length) {
      tbody.innerHTML = '<tr><td colspan="4"><div class="a-empty" style="padding:20px"><div class="a-empty__icon">✅</div>No IPs blocked.</div></td></tr>';
    } else {
      tbody.innerHTML = blocked.map(b => `
        <tr>
          <td><span class="mono">${esc(b.ip)}</span></td>
          <td style="color:var(--a-muted)">${b.attempts}</td>
          <td style="color:var(--a-warn);font-size:0.78rem">${fmtCountdown(b.seconds_remaining)}</td>
          <td style="text-align:right">
            <button class="a-btn a-btn-success a-btn-sm" onclick="confirmUnblock('${esc(b.ip)}')">Unblock</button>
          </td>
        </tr>`).join('');
    }
  }

  // Threats-page full table
  const fullTbody = document.getElementById('blocked-full-tbody');
  if (fullTbody) {
    if (!blocked.length) {
      fullTbody.innerHTML = '<tr><td colspan="4"><div class="a-empty"><div class="a-empty__icon">✅</div>No IPs blocked.</div></td></tr>';
    } else {
      fullTbody.innerHTML = blocked.map(b => `
        <tr>
          <td><span class="mono">${esc(b.ip)}</span></td>
          <td style="color:var(--a-muted)">${b.attempts}</td>
          <td style="color:var(--a-warn)">${fmtCountdown(b.seconds_remaining)}</td>
          <td style="text-align:right">
            <button class="a-btn a-btn-success a-btn-sm" onclick="confirmUnblock('${esc(b.ip)}')">Unblock</button>
          </td>
        </tr>`).join('');
    }
  }
}

/* ── USERS ───────────────────────────────────────────────── */
async function loadUsers() {
  const res = await apiFetch('/admin/users');
  if (!res || !res.ok) return;
  const data = await res.json();

  // expose globally for filter
  window.allUsersData = data.users || [];

  renderUserTable(data.users || []);

  const label = document.getElementById('user-count-label');
  if (label) label.textContent = `${data.count} users`;

  // Dashboard quick table
  const quickTbody = document.getElementById('user-quick-tbody');
  if (quickTbody) {
    const recent = (data.users || []).slice(0, 6);
    if (!recent.length) {
      quickTbody.innerHTML = '<tr><td colspan="4"><div class="a-empty" style="padding:20px"><div class="a-empty__icon">👥</div>No users yet.</div></td></tr>';
    } else {
      quickTbody.innerHTML = recent.map(u => `
        <tr>
          <td style="font-weight:500">${esc(u.name||'—')}</td>
          <td style="font-size:0.78rem;color:var(--a-muted)">${esc(u.email)}</td>
          <td>
            <span class="user-status-dot ${u.active===false?'suspended':u.verified?'active':'inactive'}"></span>
            <span style="font-size:0.75rem;color:var(--a-muted)">${u.active===false?'Suspended':u.verified?'Active':'Unverified'}</span>
          </td>
          <td style="text-align:right">
            ${u.active===false
              ? `<button class="a-btn a-btn-success a-btn-sm" onclick="restoreUser('${u.uid}')">Restore</button>`
              : `<button class="a-btn a-btn-danger a-btn-sm" onclick="suspendUser('${u.uid}','${esc(u.name||u.email)}')">Suspend</button>`}
          </td>
        </tr>`).join('');
    }
  }
}

function renderUserTable(users) {
  const tbody = document.getElementById('user-tbody');
  if (!tbody) return;

  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="a-empty"><div class="a-empty__icon">👥</div>No users found.</div></td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => {
    const statusClass = u.active === false ? 'suspended' : u.verified ? 'active' : 'inactive';
    const statusText  = u.active === false ? 'Suspended' : u.verified ? 'Active' : 'Unverified';
    const roleColor   = u.role === 'admin' ? 'var(--a-critical)' : 'var(--a-muted)';
    return `
      <tr>
        <td style="font-weight:500;color:var(--a-text)">${esc(u.name||'—')}</td>
        <td style="font-size:0.78rem;font-family:'JetBrains Mono',monospace;color:var(--a-accent)">${esc(u.email)}</td>
        <td>
          <span style="font-size:0.72rem;font-weight:600;color:${roleColor};text-transform:uppercase;letter-spacing:0.04em">${esc(u.role||'user')}</span>
        </td>
        <td>
          <span style="font-size:0.75rem;color:${u.verified?'var(--a-success)':'var(--a-warn)'}">${u.verified?'✓ Yes':'✗ No'}</span>
        </td>
        <td>
          <span class="user-status-dot ${statusClass}"></span>
          <span style="font-size:0.75rem;color:var(--a-muted)">${statusText}</span>
        </td>
        <td style="font-size:0.75rem;color:var(--a-muted)">${fmtBytes(u.storage_used_bytes||0)}</td>
        <td>
          <div style="display:flex;gap:5px;justify-content:flex-end;flex-wrap:wrap">
            <button class="a-btn a-btn-accent a-btn-sm" onclick="openRoleModal('${u.uid}','${esc(u.name||u.email)}','${u.role||'user'}')">Role</button>
            ${u.active === false
              ? `<button class="a-btn a-btn-success a-btn-sm" onclick="restoreUser('${u.uid}')">Restore</button>`
              : `<button class="a-btn a-btn-danger a-btn-sm" onclick="suspendUser('${u.uid}','${esc(u.name||u.email)}')">Suspend</button>`}
            <button class="a-btn a-btn-ghost a-btn-sm" onclick="confirmDeleteUser('${u.uid}','${esc(u.name||u.email)}')">Delete</button>
          </div>
        </td>
      </tr>`;
  }).join('');
}

/* ── USER ACTIONS ────────────────────────────────────────── */
async function suspendUser(uid, name) {
  showConfirm(`Suspend ${name}?`, `The user will lose access immediately. You can restore them later.`, async () => {
    const res = await apiFetch(`/admin/users/${uid}/suspend`, { method: 'PATCH' });
    if (res?.ok) { showToast(`${name} suspended.`, 'warn'); loadAll(); }
  });
}
async function restoreUser(uid) {
  const res = await apiFetch(`/admin/users/${uid}/restore`, { method: 'PATCH' });
  if (res?.ok) { showToast('User restored.', 'success'); loadAll(); }
}
async function confirmDeleteUser(uid, name) {
  showConfirm(`Permanently delete ${name}?`, 'This removes the account from Firestore. Files are not automatically deleted.', async () => {
    const res = await apiFetch(`/admin/users/${uid}`, { method: 'DELETE' });
    if (res?.ok) { showToast(`${name} deleted.`, 'info'); loadAll(); }
  });
}

/* ── ROLE MODAL ──────────────────────────────────────────── */
function openRoleModal(uid, name, currentRole) {
  const modal = document.getElementById('role-modal');
  if (!modal) return;
  document.getElementById('role-modal-msg').textContent = `Change role for ${name}`;
  document.getElementById('role-select').value = currentRole;
  document.getElementById('role-confirm-btn').onclick = async () => {
    const newRole = document.getElementById('role-select').value;
    const res = await apiFetch(`/admin/users/${uid}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role: newRole }),
    });
    if (res?.ok) {
      modal.style.display = 'none';
      showToast(`Role updated to ${newRole}.`, 'success');
      loadAll();
    }
  };
  modal.style.display = 'flex';
}

/* ── BLOCK / UNBLOCK IP ──────────────────────────────────── */
function openBlockModal() {
  const modal = document.getElementById('block-modal') || document.getElementById('confirm-modal');
  // handled inline via quick form; modal version on dashboard page
  const m = document.getElementById('block-modal');
  if (m) m.style.display = 'flex';
}
function closeBlockModal() {
  const m = document.getElementById('block-modal');
  if (m) m.style.display = 'none';
}

async function quickBlockIp() {
  const ip  = document.getElementById('block-ip-input')?.value.trim();
  const min = parseInt(document.getElementById('block-minutes')?.value || '30', 10);
  if (!ip) { showToast('Enter an IP address.', 'error'); return; }
  await doBlockIp(ip, min, 'Manual block by admin');
}

async function quickBlockIpFull() {
  const ip     = document.getElementById('t-block-ip')?.value.trim();
  const min    = parseInt(document.getElementById('t-block-min')?.value || '30', 10);
  const reason = document.getElementById('t-block-reason')?.value.trim() || 'Manual block by admin';
  if (!ip) { showToast('Enter an IP address.', 'error'); return; }
  await doBlockIp(ip, min, reason);
}

async function submitBlockIp() {
  const ip     = document.getElementById('modal-ip')?.value.trim();
  const min    = parseInt(document.getElementById('modal-minutes')?.value || '30', 10);
  const reason = document.getElementById('modal-reason')?.value.trim() || 'Manual block by admin';
  closeBlockModal();
  if (!ip) { showToast('Enter an IP address.', 'error'); return; }
  await doBlockIp(ip, min, reason);
}

async function doBlockIp(ip, minutes, reason) {
  const res = await apiFetch('/admin/threats/block-ip', {
    method: 'POST',
    body: JSON.stringify({ ip, minutes, reason }),
  });
  if (res?.ok) { showToast(`IP ${ip} blocked for ${minutes} min.`, 'warn'); loadAll(); }
  else showToast('Block failed.', 'error');
}

function confirmBlockIp(ip) {
  showConfirm(`Block ${ip}?`, `The IP will be blocked for 30 minutes. You can unblock it manually.`, () => doBlockIp(ip, 30, 'Flagged by threat detection'));
}

function confirmUnblock(ip) {
  showConfirm(`Unblock ${ip}?`, 'Access will be restored immediately for this IP.', async () => {
    const res = await apiFetch(`/admin/threats/unblock-ip/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    if (res?.ok) { showToast(`IP ${ip} unblocked.`, 'success'); loadAll(); }
    else showToast('Unblock failed.', 'error');
  }, 'success');
}

async function resetRisk(ip) {
  const res = await apiFetch(`/admin/threats/reset-risk/${encodeURIComponent(ip)}`, { method: 'PATCH' });
  if (res?.ok) { showToast(`Risk cleared for ${ip}.`, 'info'); loadAll(); }
}

/* ── CONFIRM MODAL ───────────────────────────────────────── */
function showConfirm(title, msg, onConfirm, type = 'danger') {
  const modal = document.getElementById('confirm-modal');
  if (!modal) { if (confirm(`${title}\n${msg}`)) onConfirm(); return; }
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-msg').textContent   = msg;
  const btn = document.getElementById('confirm-btn');
  btn.className = `a-btn a-btn-${type}`;
  btn.onclick = () => { modal.style.display = 'none'; onConfirm(); };
  modal.style.display = 'flex';
}
function closeConfirm() {
  const m = document.getElementById('confirm-modal');
  if (m) m.style.display = 'none';
}
function closeUnblockModal() {
  const m = document.getElementById('unblock-modal');
  if (m) m.style.display = 'none';
}