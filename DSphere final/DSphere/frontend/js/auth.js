/**
 * DSphere — auth.js  (Phase 2 — wired to real FastAPI backend)
 */
'use strict';

const ALLOWED_DOMAINS = ['@uttarauniversity.edu.bd', '@uttarauniversity.ac.bd'];
const API_BASE = 'https://dsphere.onrender.com';
let   OTP_TIMER_ID   = null;
let   currentEmail   = '';
let   currentFlow    = 'register';

function switchTab(tab) {
  ['login','register','otp','forgot'].forEach(p => {
    const el = document.getElementById(`form-${p}`);
    if (el) el.hidden = (p !== tab);
  });
  const tabBar = document.querySelector('.auth-tabs');
  if (tabBar) tabBar.style.visibility = (tab==='otp'||tab==='forgot') ? 'hidden' : 'visible';
  const indicator = document.getElementById('tab-indicator');
  ['login','register'].forEach(t => {
    const btn = document.getElementById(`tab-${t}`);
    if (!btn) return;
    const active = t === tab;
    btn.classList.toggle('auth-tabs__btn--active', active);
    btn.setAttribute('aria-selected', active);
  });
  if (indicator) indicator.dataset.tab = tab === 'register' ? 'register' : 'login';
  clearAllErrors();
}

function validateUniversityEmail(e) { const email = e.trim().toLowerCase(); return ALLOWED_DOMAINS.some(domain => email.endsWith(domain)); }
function showError(id, msg) { const el=document.getElementById(id); if(el) el.textContent=msg; }
function clearError(id)     { const el=document.getElementById(id); if(el) el.textContent=''; }
function clearAllErrors()   {
  document.querySelectorAll('.field-error').forEach(el=>el.textContent='');
  document.querySelectorAll('.field-input').forEach(el=>el.classList.remove('is-valid','is-invalid'));
}
function setInputState(id, state) {
  const el=document.getElementById(id); if(!el) return;
  el.classList.remove('is-valid','is-invalid');
  if(state) el.classList.add(`is-${state}`);
}
function setLoading(btnId, state) {
  const btn=document.getElementById(btnId); if(!btn) return;
  btn.disabled=state; btn.classList.toggle('is-loading', state);
}
function showToast(msg, type='success') {
  const t=document.getElementById('toast'); if(!t) return;
  t.textContent=msg; t.className=`toast toast--${type} toast--show`;
  clearTimeout(t._timer);
  t._timer=setTimeout(()=>{ t.className='toast'; }, 3500);
}
function togglePw(inputId, btn) {
  const input=document.getElementById(inputId);
  const si=btn.querySelector('.eye-icon--show'), hi=btn.querySelector('.eye-icon--hide');
  if(!input) return;
  const isPass=input.type==='password';
  input.type=isPass?'text':'password';
  if(si) si.style.display=isPass?'none':'block';
  if(hi) hi.style.display=isPass?'block':'none';
}

const PW_RULES = {
  'rule-len':     pw=>pw.length>=8,
  'rule-upper':   pw=>/[A-Z]/.test(pw),
  'rule-num':     pw=>/[0-9]/.test(pw),
  'rule-special': pw=>/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw),
};
const STR_LABELS=['','Weak','Fair','Good','Strong'];
function updateStrength(pw) {
  let score=0;
  Object.entries(PW_RULES).forEach(([id,test])=>{
    const ok=test(pw); if(ok) score++;
    const el=document.getElementById(id); if(el) el.dataset.ok=String(ok);
  });
  const meter=document.getElementById('pw-strength');
  const label=document.getElementById('pw-strength-label');
  if(meter) meter.dataset.level=pw.length===0?'':String(score);
  if(label) label.textContent=pw.length===0?'Enter a password':(STR_LABELS[score]||'Weak');
}
function updateEmailBadge(email) {
  const b=document.getElementById('reg-email-badge'); if(!b) return;
  if(email.includes('@')){ const ok=validateUniversityEmail(email); b.textContent=ok?'✓':'✗'; b.style.color=ok?'var(--up-success)':'var(--up-error)'; }
  else b.textContent='';
}

function saveSession(data) {
  sessionStorage.setItem('dsphere_access',  data.access_token  ||'');
  sessionStorage.setItem('dsphere_refresh', data.refresh_token ||'');
  sessionStorage.setItem('dsphere_user',    JSON.stringify(data.user||{}));
}

async function apiFetch(endpoint, options={}) {
  const url=`${API_BASE}${endpoint}`;
  const headers={'Content-Type':'application/json'};
  const token=sessionStorage.getItem('dsphere_access');
  if(token) headers['Authorization']=`Bearer ${token}`;
  const res=await fetch(url,{...options, headers:{...headers,...(options.headers||{})}});
  const data=await res.json();
  if(!res.ok) throw {status:res.status, detail:data.detail||'Request failed.'};
  return data;
}

function startOtpTimer(seconds=120) {
  const cdEl=document.getElementById('otp-countdown');
  const rBtn=document.getElementById('otp-resend-btn');
  const tTxt=document.getElementById('otp-timer-text');
  if(rBtn) rBtn.disabled=true;
  if(tTxt) tTxt.style.display='inline';
  clearInterval(OTP_TIMER_ID);
  let rem=seconds;
  function tick(){
    const m=String(Math.floor(rem/60)).padStart(2,'0');
    const s=String(rem%60).padStart(2,'0');
    if(cdEl) cdEl.textContent=`${m}:${s}`;
    if(rem<=0){ clearInterval(OTP_TIMER_ID); if(rBtn) rBtn.disabled=false; if(tTxt) tTxt.style.display='none'; }
    rem--;
  }
  tick(); OTP_TIMER_ID=setInterval(tick,1000);
}
async function resendOtp() {
  if(!currentEmail) return;
  try {
    await apiFetch('/auth/resend-otp',{method:'POST',body:JSON.stringify({email:currentEmail,flow:currentFlow})});
    showToast('New OTP sent!'); startOtpTimer();
  } catch(e){ showToast(e.detail||'Failed to resend OTP.','error'); }
}

function initOtpInputs() {
  const digits=document.querySelectorAll('.otp-digit');
  digits.forEach((input,idx)=>{
    input.addEventListener('input',e=>{
      const val=e.target.value.replace(/\D/g,'').slice(-1);
      e.target.value=val; input.classList.toggle('filled',val!=='');
      if(val&&idx<digits.length-1) digits[idx+1].focus();
    });
    input.addEventListener('keydown',e=>{
      if(e.key==='Backspace'&&!input.value&&idx>0){
        digits[idx-1].focus(); digits[idx-1].value=''; digits[idx-1].classList.remove('filled');
      }
    });
    input.addEventListener('paste',e=>{
      e.preventDefault();
      const pasted=(e.clipboardData||window.clipboardData).getData('text').replace(/\D/g,'').slice(0,6);
      pasted.split('').forEach((ch,i)=>{ if(digits[i]){digits[i].value=ch;digits[i].classList.add('filled');} });
      const next=digits[Math.min(pasted.length,digits.length-1)]; if(next) next.focus();
    });
  });
}
function getOtpValue(){ return Array.from(document.querySelectorAll('.otp-digit')).map(d=>d.value).join(''); }

document.getElementById('login-form')?.addEventListener('submit', async e=>{
  e.preventDefault(); clearAllErrors();
  const email=document.getElementById('login-email')?.value.trim()||'';
  const password=document.getElementById('login-password')?.value||'';
  let err=false;
  if(!validateUniversityEmail(email)){ showError('login-email-err',`Email must end in ${ALLOWED_DOMAINS.join(' or ')}`); setInputState('login-email','invalid'); err=true; } else setInputState('login-email','valid');
  if(!password){ showError('login-pw-err','Password is required.'); setInputState('login-password','invalid'); err=true; }
  if(err) return;
  setLoading('login-submit',true);
  try {
    const data=await apiFetch('/auth/login',{method:'POST',body:JSON.stringify({email,password})});
    saveSession(data); showToast('Login successful! Redirecting…');
    setTimeout(()=>{ window.location.href='dashboard.html'; },1200);
  } catch(e){ showError('login-pw-err',e.detail||'Login failed.'); setInputState('login-password','invalid'); }
  finally { setLoading('login-submit',false); }
});

document.getElementById('register-form')?.addEventListener('submit', async e=>{
  e.preventDefault(); clearAllErrors();
  const name=document.getElementById('reg-name')?.value.trim()||'';
  const email=document.getElementById('reg-email')?.value.trim()||'';
  const password=document.getElementById('reg-password')?.value||'';
  const confirm=document.getElementById('reg-confirm-password')?.value||'';
  let err=false;
  if(name.length<2){ showError('reg-name-err','Full name required.'); setInputState('reg-name','invalid'); err=true; } else setInputState('reg-name','valid');
  if(!validateUniversityEmail(email)){ showError('reg-email-err',`Only ${ALLOWED_DOMAINS.join(' or ')} allowed.`); setInputState('reg-email','invalid'); err=true; } else setInputState('reg-email','valid');
  if(Object.values(PW_RULES).some(t=>!t(password))){ showError('reg-pw-err','Password does not meet all requirements.'); setInputState('reg-password','invalid'); err=true; } else setInputState('reg-password','valid');
  if(password!==confirm){ showError('reg-cpw-err','Passwords do not match.'); setInputState('reg-confirm-password','invalid'); err=true; } else if(confirm) setInputState('reg-confirm-password','valid');
  if(err) return;
  setLoading('register-submit',true);
  try {
    await apiFetch('/auth/register',{method:'POST',body:JSON.stringify({name,email,password})});
    currentEmail=email; currentFlow='register';
    document.getElementById('otp-email-display').textContent=email;
    switchTab('otp'); startOtpTimer(); showToast('Account created! Check your email for the OTP.');
  } catch(e){ showError('reg-email-err',e.detail||'Registration failed.'); }
  finally { setLoading('register-submit',false); }
});

document.getElementById('otp-form')?.addEventListener('submit', async e=>{
  e.preventDefault(); clearError('otp-err');
  const otp=getOtpValue();
  if(otp.length<6){ showError('otp-err','Please enter all 6 digits.'); return; }
  setLoading('otp-submit',true);
  try {
    const data=await apiFetch('/auth/verify-otp',{method:'POST',body:JSON.stringify({email:currentEmail,otp,flow:currentFlow})});
    clearInterval(OTP_TIMER_ID);
    if(currentFlow==='register'){
      if(data.access_token) saveSession(data);
      showToast('Email verified! Welcome to DSphere.');
      setTimeout(()=>{ window.location.href='dashboard.html'; },1400);
    } else {
      showToast('Verified! Redirecting to password reset…');
      sessionStorage.setItem('dsphere_reset_email',currentEmail);
      setTimeout(()=>{ window.location.href='reset-password.html'; },1400);
    }
  } catch(e){ showError('otp-err',e.detail||'Invalid or expired OTP.'); }
  finally { setLoading('otp-submit',false); }
});

document.getElementById('forgot-form')?.addEventListener('submit', async e=>{
  e.preventDefault(); clearError('forgot-email-err');
  const email=document.getElementById('forgot-email')?.value.trim()||'';
  if(!validateUniversityEmail(email)){ showError('forgot-email-err',`Only ${ALLOWED_DOMAINS.join(' or ')} allowed.`); setInputState('forgot-email','invalid'); return; }
  setInputState('forgot-email','valid');
  setLoading('forgot-submit',true);
  try {
    await apiFetch('/auth/forgot-password',{method:'POST',body:JSON.stringify({email})});
    currentEmail=email; currentFlow='forgot';
    document.getElementById('otp-email-display').textContent=email;
    switchTab('otp'); startOtpTimer(); showToast('Reset OTP sent if the email is registered.');
  } catch(e){ showError('forgot-email-err',e.detail||'Request failed.'); }
  finally { setLoading('forgot-submit',false); }
});

document.getElementById('reg-password')?.addEventListener('input',e=>{ updateStrength(e.target.value); });
document.getElementById('reg-email')?.addEventListener('input',e=>{ updateEmailBadge(e.target.value); clearError('reg-email-err'); });
document.getElementById('reg-confirm-password')?.addEventListener('input',e=>{
  const pw=document.getElementById('reg-password')?.value||'';
  if(e.target.value&&e.target.value!==pw){ showError('reg-cpw-err','Passwords do not match.'); setInputState('reg-confirm-password','invalid'); }
  else if(e.target.value===pw&&pw){ clearError('reg-cpw-err'); setInputState('reg-confirm-password','valid'); }
});
document.querySelectorAll('.field-input').forEach(input=>{
  input.addEventListener('focus',()=>input.classList.remove('is-invalid','is-valid'));
});

document.addEventListener('DOMContentLoaded',()=>{
  initOtpInputs();
  if(sessionStorage.getItem('dsphere_access')) window.location.href='dashboard.html';
  else switchTab('login');
});
