/**
 * DSphere — messenger.js
 * Real-time messaging via Firestore.
 * Collections:
 *   conversations/{id}  — metadata (type, name, members[], lastMessage, lastAt)
 *   conversations/{id}/messages/{mid} — {uid, name, text, createdAt}
 */
'use strict';

import { db }       from './firebase-config.js';
import {
  collection, doc, addDoc, query, where, orderBy,
  onSnapshot, serverTimestamp, updateDoc, getDocs, setDoc
} from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';

/* ── state ───────────────────────────────────────────────── */
let currentChatId   = null;
let currentChatType = 'dm';   // 'dm' | 'group'
let unsubMessages   = null;
let unsubConvList   = null;
let allConvos       = [];

/* ── auth ────────────────────────────────────────────────── */
function getUser() {
  try { return JSON.parse(sessionStorage.getItem('dsphere_user') || '{}'); } catch { return {}; }
}
function getToken() { return sessionStorage.getItem('dsphere_access') || ''; }

/* ── init ────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  if (!getToken()) { window.location.href = 'index.html'; return; }
  const user = getUser();
  const name = user.name || user.email || 'User';
  document.getElementById('user-name').textContent  = name;
  document.getElementById('user-role').textContent  = user.role || 'user';
  document.getElementById('user-avatar').textContent = name.charAt(0).toUpperCase();
  subscribeToConversations(user.uid);
});

/* ── CONVERSATION LIST ───────────────────────────────────── */
function subscribeToConversations(uid) {
  if (unsubConvList) unsubConvList();
  const q = query(
    collection(db, 'conversations'),
    where('members', 'array-contains', uid),
    orderBy('lastAt', 'desc')
  );
  unsubConvList = onSnapshot(q, snap => {
    allConvos = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    renderConvoList(allConvos, currentChatType);
  });
}

function renderConvoList(convos, type) {
  const user = getUser();
  const filtered = convos.filter(c => c.type === type);
  const list  = document.getElementById('chat-list');
  const empty = document.getElementById('chat-list-empty');

  if (!filtered.length) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  list.innerHTML = filtered.map(c => {
    const isGroup = c.type === 'group';
    const label   = isGroup ? c.name : (c.memberNames?.find(n => n !== (user.name||user.email)) || 'Unknown');
    const initial = label.charAt(0).toUpperCase();
    const preview = esc(c.lastMessage || 'No messages yet');
    const time    = c.lastAt ? fmtTime(c.lastAt.toDate ? c.lastAt.toDate() : new Date(c.lastAt)) : '';
    const active  = c.id === currentChatId ? ' active' : '';
    return `
      <div class="chat-item${active}" onclick="openChat('${c.id}')">
        <div class="chat-item__avatar${isGroup?' group':''}">${initial}</div>
        <div class="chat-item__info">
          <div class="chat-item__name">${esc(label)}</div>
          <div class="chat-item__preview">${preview}</div>
        </div>
        <div class="chat-item__meta">
          <span class="chat-item__time">${time}</span>
        </div>
      </div>`;
  }).join('');
}

/* ── OPEN CHAT ───────────────────────────────────────────── */
function openChat(convId) {
  if (unsubMessages) { unsubMessages(); unsubMessages = null; }
  currentChatId = convId;
  const convo = allConvos.find(c => c.id === convId);
  if (!convo) return;

  const user    = getUser();
  const isGroup = convo.type === 'group';
  const label   = isGroup ? convo.name : (convo.memberNames?.find(n => n !== (user.name||user.email)) || 'Unknown');
  const initial = label.charAt(0).toUpperCase();

  document.getElementById('no-chat-selected').style.display = 'none';
  const activeChat = document.getElementById('active-chat');
  activeChat.style.display = 'flex';

  document.getElementById('chat-avatar').textContent = initial;
  document.getElementById('chat-name').textContent   = label;
  document.getElementById('chat-status').textContent = isGroup
    ? `${convo.members?.length || 0} members`
    : 'Direct message';

  document.getElementById('chat-messages').innerHTML = '';

  // Re-render list to update active highlight
  renderConvoList(allConvos, currentChatType);

  // Subscribe to messages
  const msgQ = query(
    collection(db, 'conversations', convId, 'messages'),
    orderBy('createdAt', 'asc')
  );
  unsubMessages = onSnapshot(msgQ, snap => {
    renderMessages(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  });
}

/* ── RENDER MESSAGES ─────────────────────────────────────── */
function renderMessages(msgs) {
  const user      = getUser();
  const container = document.getElementById('chat-messages');
  let   lastDate  = '';

  container.innerHTML = msgs.map(m => {
    const isOwn = m.uid === user.uid;
    const ts    = m.createdAt?.toDate ? m.createdAt.toDate() : new Date(m.createdAt || Date.now());
    const date  = ts.toLocaleDateString('en-GB', { weekday:'long', day:'numeric', month:'long' });
    const time  = ts.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit' });
    const initial = (m.name || 'U').charAt(0).toUpperCase();

    let divider = '';
    if (date !== lastDate) {
      lastDate = date;
      divider  = `<div class="date-divider" style="margin:8px 0">${date}</div>`;
    }

    return `${divider}
      <div class="msg-group ${isOwn ? 'own' : 'other'}">
        ${!isOwn ? `<div class="msg-avatar">${initial}</div>` : ''}
        <div>
          ${!isOwn ? `<div class="msg-sender">${esc(m.name || 'Unknown')}</div>` : ''}
          <div class="msg-bubble">${esc(m.text)}</div>
          <div class="msg-meta">${time}</div>
        </div>
        ${isOwn ? `<div class="msg-avatar" style="background:var(--up-accent);color:var(--up-primary)">${initial}</div>` : ''}
      </div>`;
  }).join('');

  // scroll to bottom
  container.scrollTop = container.scrollHeight;
}

/* ── SEND MESSAGE ────────────────────────────────────────── */
async function sendMessage() {
  if (!currentChatId) return;
  const input = document.getElementById('msg-input');
  const text  = input.value.trim();
  if (!text) return;
  input.value = '';
  input.style.height = '';

  const user = getUser();
  const now  = new Date();

  try {
    await addDoc(
      collection(db, 'conversations', currentChatId, 'messages'),
      { uid: user.uid, name: user.name || user.email, text, createdAt: serverTimestamp() }
    );
    // update conversation lastMessage
    await updateDoc(doc(db, 'conversations', currentChatId), {
      lastMessage: text.slice(0, 60),
      lastAt: serverTimestamp(),
    });
  } catch (err) {
    console.error('Send failed:', err);
  }
}

function handleMsgKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}
function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

/* ── NEW CHAT ────────────────────────────────────────────── */
function openNewChatModal()  { document.getElementById('new-chat-modal').style.display = 'flex'; }
function closeNewChatModal() { document.getElementById('new-chat-modal').style.display = 'none'; }
function toggleGroupName() {
  const type = document.getElementById('new-chat-type').value;
  document.getElementById('group-name-field').style.display = type === 'group' ? '' : 'none';
}

async function createNewChat() {
  const user      = getUser();
  const type      = document.getElementById('new-chat-type').value;
  const groupName = document.getElementById('new-group-name').value.trim();
  const rawEmails = document.getElementById('new-chat-recipients').value.trim();
  const emails    = rawEmails.split(',').map(e => e.trim()).filter(Boolean);

  if (!emails.length) { alert('Enter at least one recipient email.'); return; }

  // Resolve emails to UIDs via Firestore
  const members     = [user.uid];
  const memberNames = [user.name || user.email];

  for (const email of emails) {
    const snap = await getDocs(
      query(collection(db, 'users'), where('email', '==', email.toLowerCase()))
    );
    if (snap.empty) { alert(`User not found: ${email}`); return; }
    const u = snap.docs[0];
    members.push(u.id);
    memberNames.push(u.data().name || email);
  }

  const convData = {
    type,
    name: type === 'group' ? (groupName || 'Unnamed Group') : '',
    members,
    memberNames,
    lastMessage: '',
    lastAt: serverTimestamp(),
    createdAt: serverTimestamp(),
  };

  const ref = await addDoc(collection(db, 'conversations'), convData);
  closeNewChatModal();
  switchChatTab(type);
  openChat(ref.id);
}

/* ── TABS ────────────────────────────────────────────────── */
function switchChatTab(type) {
  currentChatType = type;
  document.getElementById('tab-dm').classList.toggle('active',    type === 'dm');
  document.getElementById('tab-group').classList.toggle('active', type === 'group');
  renderConvoList(allConvos, type);
}

/* ── SEARCH ──────────────────────────────────────────────── */
function filterChats(q) {
  const filtered = allConvos.filter(c =>
    (c.name || c.memberNames?.join(' ') || '').toLowerCase().includes(q.toLowerCase())
  );
  renderConvoList(filtered, currentChatType);
}

/* ── CALL PLACEHOLDER ────────────────────────────────────── */
function callPlaceholder(type) {
  const toast = document.getElementById('call-toast');
  toast.textContent = `${type === 'audio' ? '📞' : '📹'} ${type === 'audio' ? 'Audio' : 'Video'} calls will be available in a future update (WebRTC / Agora.io integration).`;
  toast.style.display = 'block';
  setTimeout(() => { toast.style.display = 'none'; }, 4000);
}

/* ── HELPERS ─────────────────────────────────────────────── */
function esc(s = '') {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtTime(d) {
  const now   = new Date();
  const diff  = (now - d) / 1000;
  if (diff < 60)     return 'just now';
  if (diff < 3600)   return Math.floor(diff/60) + 'm';
  if (diff < 86400)  return d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
  return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'});
}
function logout() { sessionStorage.clear(); window.location.href = 'index.html'; }