/**
 * DSphere — storage.js
 * Cloud Storage page: upload, list, download (signed URL), delete.
 */
'use strict';

const API_BASE   = 'https://dsphere.onrender.com';
const QUOTA_MAX  = 500 * 1024 * 1024; // 500 MB display cap
const ALLOWED_EXT = new Set(['.png','.jpg','.jpeg','.pdf','.docx','.ppt','.pptx','.xml']);

const FILE_ICONS = {
  '.pdf':'📄', '.png':'🖼️', '.jpg':'🖼️', '.jpeg':'🖼️',
  '.docx':'📝', '.doc':'📝', '.ppt':'📊', '.pptx':'📊', '.xml':'🗂️',
};

let allFiles   = [];
let pendingDeleteId = null;

/* ── auth helper ─────────────────────────────────────────── */
function getToken() { return sessionStorage.getItem('dsphere_access') || ''; }
function getUser()  { try { return JSON.parse(sessionStorage.getItem('dsphere_user') || '{}'); } catch { return {}; } }

async function apiFetch(endpoint, opts = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...opts,
    headers: { 'Authorization': `Bearer ${getToken()}`, ...(opts.headers || {}) },
  });
  if (res.status === 401) { window.location.href = 'index.html'; return null; }
  return res;
}

/* ── init ────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const user = getUser();
  if (!getToken()) { window.location.href = 'index.html'; return; }

  // populate sidebar user info
  const name = user.name || user.email || 'User';
  document.getElementById('user-name').textContent = name;
  document.getElementById('user-role').textContent = user.role || 'user';
  document.getElementById('user-avatar').textContent = name.charAt(0).toUpperCase();

  loadFiles();
});

/* ── FILE LISTING ────────────────────────────────────────── */
async function loadFiles() {
  const res = await apiFetch('/storage/files');
  if (!res) return;
  const data = await res.json();
  allFiles = data.files || [];
  renderFiles(allFiles);
  updateStats(allFiles);
}

function renderFiles(files) {
  const tbody     = document.getElementById('file-tbody');
  const table     = document.getElementById('file-table');
  const emptyState = document.getElementById('empty-state');

  if (!files.length) {
    table.style.display = 'none';
    emptyState.style.display = 'block';
    return;
  }
  table.style.display = 'table';
  emptyState.style.display = 'none';

  tbody.innerHTML = files.map(f => {
    const ext  = extOf(f.filename);
    const icon = FILE_ICONS[ext] || '📎';
    const size = fmtBytes(f.size_bytes || 0);
    const date = fmtDate(f.uploaded_at);
    return `
      <tr>
        <td><span class="file-icon">${icon}</span><span class="file-name">${esc(f.filename)}</span></td>
        <td><span class="file-size">${size}</span></td>
        <td><span class="file-date">${date}</span></td>
        <td style="text-align:right">
          <div style="display:flex;gap:6px;justify-content:flex-end">
            <button class="btn btn-ghost btn-sm" onclick="downloadFile('${f.id}','${esc(f.filename)}')">
              <svg viewBox="0 0 20 20" fill="none"><path d="M10 3v11M5 13l5 5 5-5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 18h14" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
              Download
            </button>
            <button class="btn btn-danger btn-sm" onclick="confirmDelete('${f.id}','${esc(f.filename)}')">
              <svg viewBox="0 0 20 20" fill="none"><path d="M5 7h10M8 7V5h4v2M6 7l1 9h6l1-9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
              Delete
            </button>
          </div>
        </td>
      </tr>`;
  }).join('');
}

function updateStats(files) {
  const totalBytes = files.reduce((s, f) => s + (f.size_bytes || 0), 0);
  const pct        = Math.min(100, (totalBytes / QUOTA_MAX) * 100);

  document.getElementById('stat-files').textContent = files.length;
  document.getElementById('stat-used').textContent  = fmtBytes(totalBytes);

  const fill = document.getElementById('quota-fill');
  fill.style.width = pct.toFixed(1) + '%';
  fill.classList.toggle('warn', pct > 70 && pct <= 90);
  fill.classList.toggle('over', pct > 90);
}

/* ── UPLOAD ──────────────────────────────────────────────── */
function handleFileSelect(fileList) {
  Array.from(fileList).forEach(uploadFile);
}

async function uploadFile(file) {
  const ext = extOf(file.name);
  if (!ALLOWED_EXT.has(ext)) {
    showQueueItem(file.name, file.size, 0, 'error', `Type ${ext} not allowed`);
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    showQueueItem(file.name, file.size, 0, 'error', 'Exceeds 50 MB limit');
    return;
  }

  const itemId = 'up-' + Date.now() + Math.random().toString(36).slice(2);
  showQueueItem(file.name, file.size, 0, 'loading', 'Uploading…', itemId);

  const form = new FormData();
  form.append('file', file);

  try {
    // Use XMLHttpRequest for upload progress
    const pct = await uploadWithProgress(form, itemId);
    updateQueueItem(itemId, 100, 'done', '✓ Uploaded');
    setTimeout(() => { document.getElementById(itemId)?.remove(); }, 3000);
    loadFiles();
  } catch (err) {
    updateQueueItem(itemId, 0, 'error', err.message || 'Upload failed');
  }
}

function uploadWithProgress(formData, itemId) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE}/storage/upload`);
    xhr.setRequestHeader('Authorization', `Bearer ${getToken()}`);

    xhr.upload.onprogress = e => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        updateQueueItem(itemId, pct, 'loading', `${pct}%`);
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(100);
      else {
        try { reject(new Error(JSON.parse(xhr.responseText).detail || 'Upload failed')); }
        catch { reject(new Error('Upload failed')); }
      }
    };
    xhr.onerror = () => reject(new Error('Network error'));
    xhr.send(formData);
  });
}

/* ── DOWNLOAD ────────────────────────────────────────────── */
async function downloadFile(fileId, filename) {
  const res = await apiFetch(`/storage/download/${fileId}`);
  if (!res) return;
  if (!res.ok) { alert('Download failed.'); return; }
  const data = await res.json();
  const a = document.createElement('a');
  a.href = data.download_url;
  a.download = filename;
  a.target = '_blank';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/* ── DELETE ──────────────────────────────────────────────── */
function confirmDelete(fileId, filename) {
  pendingDeleteId = fileId;
  document.getElementById('modal-filename').textContent = `Delete "${filename}"? This cannot be undone.`;
  document.getElementById('modal-confirm-btn').onclick = () => doDelete(fileId);
  document.getElementById('modal-overlay').style.display = 'flex';
}
function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  pendingDeleteId = null;
}
async function doDelete(fileId) {
  closeModal();
  const res = await apiFetch(`/storage/delete/${fileId}`, { method: 'DELETE' });
  if (res && res.ok) loadFiles();
  else alert('Delete failed.');
}

/* ── FILTER ──────────────────────────────────────────────── */
function filterFiles(query) {
  const q = query.toLowerCase();
  renderFiles(allFiles.filter(f => f.filename.toLowerCase().includes(q)));
}
function filterByType(ext) {
  if (!ext) { renderFiles(allFiles); return; }
  const exts = ext.split(',');
  renderFiles(allFiles.filter(f => exts.includes(extOf(f.filename))));
}

/* ── QUEUE UI ────────────────────────────────────────────── */
function showQueueItem(name, size, pct, status, statusText, id) {
  const ext  = extOf(name);
  const icon = FILE_ICONS[ext] || '📎';
  const el   = document.createElement('div');
  el.className = 'upload-item';
  if (id) el.id = id;
  el.innerHTML = `
    <span class="upload-item__icon">${icon}</span>
    <div class="upload-item__info">
      <div class="upload-item__name">${esc(name)}</div>
      <div class="upload-item__size">${fmtBytes(size)}</div>
      <div class="upload-item__bar"><div class="upload-item__fill" style="width:${pct}%"></div></div>
    </div>
    <span class="upload-item__status status-${status}">${statusText}</span>`;
  document.getElementById('upload-queue').prepend(el);
}
function updateQueueItem(id, pct, status, statusText) {
  const el = document.getElementById(id);
  if (!el) return;
  const fill = el.querySelector('.upload-item__fill');
  const stat = el.querySelector('.upload-item__status');
  if (fill) fill.style.width = pct + '%';
  if (stat) { stat.textContent = statusText; stat.className = `upload-item__status status-${status}`; }
}

/* ── HELPERS ─────────────────────────────────────────────── */
function extOf(name) { return (name.match(/\.[^.]+$/) || [''])[0].toLowerCase(); }
function esc(s) { return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024**2) return (b/1024).toFixed(1) + ' KB';
  if (b < 1024**3) return (b/1024**2).toFixed(1) + ' MB';
  return (b/1024**3).toFixed(2) + ' GB';
}
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
}
function logout() { sessionStorage.clear(); window.location.href = 'index.html'; }
