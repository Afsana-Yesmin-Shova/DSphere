/**
 * DSphere — network.js
 * Calls POST /network/suggest and renders subnet + topology results.
 */
'use strict';

const API_BASE = 'https://dsphere.onrender.com';

function getToken() { return sessionStorage.getItem('dsphere_access') || ''; }
function getUser()  { try { return JSON.parse(sessionStorage.getItem('dsphere_user')||'{}'); } catch { return {}; } }

document.addEventListener('DOMContentLoaded', () => {
  if (!getToken()) { window.location.href = 'index.html'; return; }
  const u = getUser();
  const n = u.name || u.email || 'User';
  document.getElementById('user-name').textContent  = n;
  document.getElementById('user-role').textContent  = u.role || 'user';
  document.getElementById('user-avatar').textContent = n.charAt(0).toUpperCase();
});

function setPurpose(text, btn) {
  document.getElementById('purpose').value = text;
  document.querySelectorAll('.purpose-chip').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

async function calculate() {
  const deviceStr = document.getElementById('device-count').value.trim();
  const purpose   = document.getElementById('purpose').value.trim();
  const baseIp    = document.getElementById('base-ip').value.trim() || '192.168.1.0';

  // clear errors
  document.getElementById('err-devices').textContent = '';
  document.getElementById('err-purpose').textContent = '';

  let hasErr = false;
  const devices = parseInt(deviceStr, 10);
  if (!deviceStr || isNaN(devices) || devices < 1) {
    document.getElementById('err-devices').textContent = 'Enter a valid device count (≥ 1).';
    hasErr = true;
  }
  if (!purpose) {
    document.getElementById('err-purpose').textContent = 'Describe the network purpose.';
    hasErr = true;
  }
  if (hasErr) return;

  const btn = document.getElementById('calc-btn');
  btn.disabled = true;
  btn.textContent = 'Calculating…';

  try {
    const res = await fetch(`${API_BASE}/network/suggest`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${getToken()}`,
      },
      body: JSON.stringify({ device_count: devices, purpose, base_network: baseIp }),
    });

    if (res.status === 401) { window.location.href = 'index.html'; return; }
    if (!res.ok) { const d = await res.json(); alert(d.detail || 'Calculation failed.'); return; }

    const data = await res.json();
    renderResults(data);
  } catch (err) {
    alert('Network error. Is the backend running?');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 20 20" fill="none" style="width:16px;height:16px"><path d="M10 2v16M2 10h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg> Calculate &amp; Suggest`;
  }
}

function renderResults(data) {
  const { subnet, topology, input } = data;
  const primary = topology.primary;
  const alt     = topology.alternate;

  // Hide empty state, show results
  document.getElementById('net-empty-state').style.display = 'none';
  document.getElementById('results-panel').style.display   = 'block';

  // Banner
  document.getElementById('topo-icon').textContent  = primary.icon || '🕸️';
  document.getElementById('topo-name').textContent  = primary.name;
  document.getElementById('topo-desc').textContent  = primary.description;
  document.getElementById('topo-badge').textContent = subnet.cidr_notation;

  // Subnet grid
  const gridItems = [
    { label: 'CIDR Notation',      value: subnet.cidr_notation,     mono: true },
    { label: 'Subnet Mask',        value: subnet.subnet_mask,        mono: true },
    { label: 'Network Address',    value: subnet.network_address,    mono: true },
    { label: 'Broadcast Address',  value: subnet.broadcast_address,  mono: true },
    { label: 'First Usable Host',  value: subnet.first_host,         mono: true },
    { label: 'Last Usable Host',   value: subnet.last_host,          mono: true },
    { label: 'Usable Hosts',       value: subnet.usable_hosts.toLocaleString() },
    { label: 'Total Addresses',    value: subnet.network_size.toLocaleString() },
    { label: 'Host Bits',          value: `/${subnet.host_bits}` },
    { label: 'Network Bits',       value: `/${subnet.network_bits}` },
  ];

  document.getElementById('subnet-grid').innerHTML = gridItems.map(i => `
    <div class="subnet-cell">
      <div class="subnet-cell__label">${i.label}</div>
      <div class="subnet-cell__value${i.mono?' mono':''}">${i.value}</div>
    </div>`).join('');

  // Alternate topology
  if (alt) {
    document.getElementById('alt-topo-card').style.display = '';
    document.getElementById('alt-icon').textContent = alt.icon || '🔗';
    document.getElementById('alt-name').textContent = alt.name;
    document.getElementById('alt-desc').textContent = alt.description;
  } else {
    document.getElementById('alt-topo-card').style.display = 'none';
  }

  // Use cases
  document.getElementById('use-cases').innerHTML = (primary.use_cases || [])
    .map(u => `<li>${u}</li>`).join('');

  // Scroll results into view
  document.getElementById('results-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function copyResults() {
  const cidr  = document.querySelector('.subnet-cell__value.mono')?.textContent || '';
  const cells = document.querySelectorAll('.subnet-cell');
  let text    = 'DSphere Network Suggestion\n' + '─'.repeat(40) + '\n';
  cells.forEach(c => {
    const lbl = c.querySelector('.subnet-cell__label')?.textContent || '';
    const val = c.querySelector('.subnet-cell__value')?.textContent || '';
    text += `${lbl.padEnd(22)}: ${val}\n`;
  });
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('[onclick="copyResults()"]');
    btn.textContent = '✓ Copied!';
    setTimeout(() => {
      btn.innerHTML = '<svg viewBox="0 0 20 20" fill="none" style="width:15px;height:15px"><rect x="7" y="7" width="10" height="10" rx="2" stroke="currentColor" stroke-width="1.4"/><path d="M3 13V5a2 2 0 012-2h8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg> Copy Results to Clipboard';
    }, 2000);
  });
}

function logout() { sessionStorage.clear(); window.location.href = 'index.html'; }
