const $ = (id) => document.getElementById(id);

// ---------- storage (may be unavailable) ----------
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};

const state = {
  token: store.get('wl_token'),
  projects: [],
  current: null,
  keys: [],
  filter: 'all',
  search: '',
};

// ---------- icons ----------
const ICON = {
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a1 1 0 0 1 1-1h10"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5L20 7"/></svg>',
  reset: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>',
  ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>',
};

// ---------- API ----------
async function api(path, { method = 'GET', body } = {}) {
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    toast('Network error — is the server running?', 'error');
    throw new Error('network');
  }
  const data = res.headers.get('content-type')?.includes('json') ? await res.json() : null;
  if (res.status === 401 && path !== '/admin/login') {
    logout();
    toast('Session expired. Please sign in again.', 'error');
    throw new Error('unauthorized');
  }
  if (!res.ok) throw new Error(data?.error || `http_${res.status}`);
  return data;
}

// Wrap an async action so failures surface as toasts.
function guard(fn) {
  return async (...args) => {
    try { await fn(...args); }
    catch (e) {
      if (!['unauthorized', 'network'].includes(e.message)) toast(humanError(e.message), 'error');
    }
  };
}

function humanError(code) {
  return ({
    rate_limited: 'Too many attempts. Wait a bit and try again.',
    name_required: 'Enter a project name.',
    not_found: 'That item no longer exists.',
    invalid_project: 'That project no longer exists.',
  })[code] || `Something went wrong (${code}).`;
}

// ---------- toasts ----------
function toast(message, type = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${type === 'error' ? 'error' : ''}`;
  el.innerHTML = '<span class="dot"></span>';
  el.append(document.createTextNode(message));
  $('toasts').append(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 220); }, 3200);
}

async function copyText(text, msg = 'Copied to clipboard') {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
    return true;
  } catch {
    toast('Copy failed — select and copy manually.', 'error');
    return false;
  }
}

// ---------- modals ----------
let activeModal = null;
function openModal(id) {
  document.querySelectorAll('[data-modal]').forEach((m) => m.classList.add('hidden'));
  $('modalRoot').classList.remove('hidden');
  activeModal = $(id);
  activeModal.classList.remove('hidden');
  const focusable = activeModal.querySelector('input:not([type=hidden]), textarea, select, button[type=submit]');
  setTimeout(() => focusable?.focus(), 30);
}
function closeModal() {
  $('modalRoot').classList.add('hidden');
  activeModal?.classList.add('hidden');
  activeModal = null;
}
$('modalRoot').addEventListener('click', (e) => { if (e.target.closest('[data-close]')) closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && activeModal) closeModal(); });

let confirmAction = null;
function confirmDialog({ title, text, ok = 'Delete', danger = true, onConfirm }) {
  $('confirmTitle').textContent = title;
  $('confirmText').textContent = text;
  $('confirmOk').textContent = ok;
  $('confirmOk').className = `btn ${danger ? 'btn-danger' : ''}`;
  confirmAction = onConfirm;
  openModal('confirmModal');
}
$('confirmOk').addEventListener('click', guard(async () => {
  const fn = confirmAction;
  closeModal();
  if (fn) await fn();
}));

// ---------- auth ----------
$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.submitter || $('loginForm').querySelector('button[type=submit]');
  btn.disabled = true;
  $('loginError').textContent = '';
  try {
    const { token } = await api('/admin/login', { method: 'POST', body: { password: $('password').value } });
    state.token = token;
    store.set('wl_token', token);
    $('password').value = '';
    showApp();
  } catch (err) {
    $('loginError').textContent = err.message === 'rate_limited'
      ? 'Too many attempts. Try again in a few minutes.'
      : err.message === 'network' ? '' : 'Incorrect password.';
  } finally {
    btn.disabled = false;
  }
});

$('logoutBtn').addEventListener('click', logout);
function logout() {
  state.token = null;
  state.current = null;
  store.del('wl_token');
  closeModal();
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
  setTimeout(() => $('password').focus(), 30);
}

function showApp() {
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  loadProjects(Number(store.get('wl_project')) || null);
}

// ---------- mobile nav ----------
$('menuBtn').addEventListener('click', () => $('app').classList.add('nav-open'));
$('scrim').addEventListener('click', () => $('app').classList.remove('nav-open'));

// ---------- projects ----------
const loadProjects = guard(async (selectId) => {
  state.projects = await api('/admin/projects');
  const want = selectId ?? state.current?.id;
  const found = state.projects.find((p) => p.id === want) || state.projects[0] || null;
  renderProjects();
  if (found) selectProject(found);
  else showEmpty();
});

function avatarColor(name) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `hsl(${h} 55% 48%)`;
}

function renderProjects() {
  const list = $('projectList');
  list.innerHTML = '';
  if (!state.projects.length) {
    list.innerHTML = '<li class="p-empty">No projects yet</li>';
    return;
  }
  for (const p of state.projects) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    if (state.current?.id === p.id) b.className = 'active';
    const av = document.createElement('span');
    av.className = 'p-avatar';
    av.style.background = avatarColor(p.name);
    av.textContent = p.name.trim().charAt(0).toUpperCase() || '?';
    const nm = document.createElement('span');
    nm.className = 'p-name';
    nm.textContent = p.name;
    const ct = document.createElement('span');
    ct.className = 'p-count';
    ct.textContent = p.key_count;
    b.append(av, nm, ct);
    b.addEventListener('click', () => { selectProject(p); $('app').classList.remove('nav-open'); });
    li.append(b);
    list.append(li);
  }
}

function showEmpty() {
  state.current = null;
  $('projectView').classList.add('hidden');
  $('projActions').classList.add('hidden');
  $('projSlug').classList.add('hidden');
  $('projTitle').textContent = 'Dashboard';
  $('emptyState').classList.remove('hidden');
}

function selectProject(p) {
  state.current = p;
  store.set('wl_project', String(p.id));
  $('emptyState').classList.add('hidden');
  $('projectView').classList.remove('hidden');
  $('projActions').classList.remove('hidden');
  $('projSlug').classList.remove('hidden');
  $('projTitle').textContent = p.name;
  $('projSlug').textContent = p.slug;
  $('loaderSnippet').textContent = loaderSnippet(p);
  renderProjects();
  loadKeys();
}

function loaderSnippet(p) {
  return `_G.Key = "YOUR-KEY-HERE"\nloadstring(game:HttpGet("${location.origin}/loader/${p.slug}"))()`;
}

$('copyLoaderBtn').addEventListener('click', () => copyText(loaderSnippet(state.current), 'Loader copied'));

// create / rename
let nameMode = 'create';
function openNameModal(mode) {
  nameMode = mode;
  const renaming = mode === 'rename';
  $('nameModalTitle').textContent = renaming ? 'Rename project' : 'New project';
  $('nameModalSubmit').textContent = renaming ? 'Save' : 'Create project';
  $('nameModalHint').textContent = renaming
    ? `The loader URL keeps its slug (${state.current.slug}), so existing users aren't affected.`
    : "Its URL slug is set from the name and can't be changed later.";
  $('nameInput').value = renaming ? state.current.name : '';
  openModal('nameModal');
}
$('newProjectBtn').addEventListener('click', () => { $('app').classList.remove('nav-open'); openNameModal('create'); });
$('emptyNewBtn').addEventListener('click', () => openNameModal('create'));
$('renameBtn').addEventListener('click', () => openNameModal('rename'));

$('nameModal').addEventListener('submit', guard(async (e) => {
  e.preventDefault();
  const name = $('nameInput').value.trim();
  if (!name) return;
  if (nameMode === 'rename') {
    await api(`/admin/projects/${state.current.id}`, { method: 'PUT', body: { name } });
    closeModal();
    toast('Project renamed');
    await loadProjects(state.current.id);
  } else {
    const p = await api('/admin/projects', { method: 'POST', body: { name } });
    closeModal();
    toast(`Created “${p.name}”`);
    await loadProjects(p.id);
  }
}));

$('deleteProjectBtn').addEventListener('click', () => {
  const p = state.current;
  confirmDialog({
    title: `Delete “${p.name}”?`,
    text: `This permanently deletes the project, its script, and all ${p.key_count} key(s). Users with this loader will stop working.`,
    ok: 'Delete project',
    onConfirm: async () => {
      await api(`/admin/projects/${p.id}`, { method: 'DELETE' });
      toast('Project deleted');
      state.current = null;
      store.del('wl_project');
      await loadProjects(null);
    },
  });
});

// script editor
function updateScriptStats() {
  const v = $('scriptText').value;
  const lines = v ? v.split('\n').length : 0;
  const kb = new Blob([v]).size / 1024;
  $('scriptStats').textContent = `${lines} line${lines === 1 ? '' : 's'} · ${kb < 10 ? kb.toFixed(1) : Math.round(kb)} KB`;
}
$('editScriptBtn').addEventListener('click', () => {
  $('scriptText').value = state.current.script_source || '';
  updateScriptStats();
  openModal('scriptModal');
});
$('scriptText').addEventListener('input', updateScriptStats);
$('scriptText').addEventListener('keydown', (e) => {
  if (e.key === 'Tab' && !e.shiftKey) {
    e.preventDefault();
    const t = e.target;
    const { selectionStart: s, selectionEnd: end } = t;
    t.setRangeText('\t', s, end, 'end');
    updateScriptStats();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 's') {
    e.preventDefault();
    $('scriptModal').requestSubmit();
  }
});
$('scriptModal').addEventListener('submit', guard(async (e) => {
  e.preventDefault();
  const updated = await api(`/admin/projects/${state.current.id}`, {
    method: 'PUT',
    body: { script_source: $('scriptText').value },
  });
  state.current.script_source = updated.script_source;
  const inList = state.projects.find((p) => p.id === updated.id);
  if (inList) inList.script_source = updated.script_source;
  closeModal();
  toast('Script saved');
}));

// ---------- keys ----------
function keyStatus(k) {
  if (k.banned) return 'banned';
  if (k.expires_at && k.expires_at < Date.now()) return 'expired';
  if (!k.hwid) return 'unused';
  return 'active';
}
const STATUS_BADGE = {
  active: ['badge-ok', 'Active'],
  unused: ['badge-warn', 'Unused'],
  banned: ['badge-danger', 'Banned'],
  expired: ['badge-muted', 'Expired'],
};

const loadKeys = guard(async () => {
  const project = state.current;
  $('keysBody').innerHTML = '';
  $('keysEmpty').textContent = 'Loading keys…';
  $('keysEmpty').classList.remove('hidden');
  const keys = await api(`/admin/keys?project_id=${project.id}`);
  if (state.current?.id !== project.id) return; // switched away meanwhile
  state.keys = keys;
  // keep sidebar count in sync
  const inList = state.projects.find((p) => p.id === project.id);
  if (inList && inList.key_count !== keys.length) { inList.key_count = keys.length; renderProjects(); }
  renderStats();
  renderKeys();
});

function renderStats() {
  const ks = state.keys;
  const by = { active: 0, unused: 0, banned: 0, expired: 0 };
  let auths = 0, resets = 0, lastUsed = 0;
  for (const k of ks) {
    by[keyStatus(k)]++;
    auths += k.auth_count;
    resets += k.reset_count;
    if (k.last_used > lastUsed) lastUsed = k.last_used;
  }
  const bound = ks.filter((k) => k.hwid).length;
  $('statTotal').textContent = fmtNum(ks.length);
  $('statActive').textContent = fmtNum(by.active);
  $('statActiveSub').textContent = `${by.unused} unused · ${by.banned} banned`;
  $('statBound').textContent = fmtNum(bound);
  $('statBoundSub').textContent = `${resets} HWID reset${resets === 1 ? '' : 's'}`;
  $('statAuths').textContent = fmtNum(auths);
  $('statAuthsSub').textContent = lastUsed ? `Last ${timeAgo(lastUsed)}` : 'No auths yet';
  $('keysSummary').textContent = ks.length
    ? `${ks.length} key${ks.length === 1 ? '' : 's'} in this project`
    : 'No keys yet';

  // filter tab counts
  const counts = { all: ks.length, ...by };
  document.querySelectorAll('#filterTabs button').forEach((b) => {
    const f = b.dataset.filter;
    const label = b.dataset.label || (b.dataset.label = b.textContent);
    b.innerHTML = '';
    b.append(document.createTextNode(label));
    const c = document.createElement('span');
    c.className = 'count';
    c.textContent = counts[f];
    b.append(c);
  });
}

function visibleKeys() {
  const q = state.search.toLowerCase();
  return state.keys.filter((k) => {
    if (state.filter !== 'all' && keyStatus(k) !== state.filter) return false;
    if (!q) return true;
    return (
      k.key_value.toLowerCase().includes(q) ||
      (k.note || '').toLowerCase().includes(q) ||
      (k.hwid || '').toLowerCase().includes(q)
    );
  });
}

function renderKeys() {
  const body = $('keysBody');
  body.innerHTML = '';
  const rows = visibleKeys();
  const empty = $('keysEmpty');
  if (!state.keys.length) {
    empty.textContent = 'No keys yet. Click “Generate keys” to create some.';
    empty.classList.remove('hidden');
    return;
  }
  if (!rows.length) {
    empty.textContent = 'No keys match this filter.';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  const frag = document.createDocumentFragment();
  for (const k of rows) frag.append(keyRow(k));
  body.append(frag);
}

function td(content, cls) {
  const c = document.createElement('td');
  if (cls) c.className = cls;
  if (content instanceof Node) c.append(content);
  else if (content != null) c.textContent = content;
  return c;
}

function iconBtn(icon, title, onClick, extra = '') {
  const b = document.createElement('button');
  b.className = `btn-icon ${extra}`.trim();
  b.title = title;
  b.setAttribute('aria-label', title);
  b.innerHTML = ICON[icon];
  b.addEventListener('click', onClick);
  return b;
}

function keyRow(k) {
  const tr = document.createElement('tr');
  const status = keyStatus(k);

  // key + copy
  const kc = document.createElement('span');
  kc.className = 'key-cell';
  const code = document.createElement('code');
  code.textContent = k.key_value;
  const cp = iconBtn('copy', 'Copy key', async () => {
    if (await copyText(k.key_value, 'Key copied')) {
      cp.innerHTML = ICON.check;
      setTimeout(() => (cp.innerHTML = ICON.copy), 1200);
    }
  });
  kc.append(code, cp);

  // status
  const [cls, label] = STATUS_BADGE[status];
  const badge = document.createElement('span');
  badge.className = `badge ${cls}`;
  badge.textContent = label;

  // device
  let dev;
  if (k.hwid) {
    dev = document.createElement('span');
    dev.className = 'hwid';
    dev.title = k.hwid;
    dev.textContent = k.hwid.length > 14 ? `${k.hwid.slice(0, 8)}…${k.hwid.slice(-4)}` : k.hwid;
  } else {
    dev = document.createElement('span');
    dev.className = 'unbound';
    dev.textContent = 'Not bound';
  }

  // expiry
  let exp = 'Lifetime';
  let expTitle = '';
  if (k.expires_at) {
    const d = new Date(k.expires_at);
    expTitle = d.toLocaleString();
    exp = k.expires_at < Date.now() ? `${timeAgo(k.expires_at)}` : `in ${timeUntil(k.expires_at)}`;
  }
  const expCell = td(exp, 'muted');
  if (expTitle) expCell.title = expTitle;

  // last used
  const lu = td(k.last_used ? timeAgo(k.last_used) : '—', 'muted');
  if (k.last_used) lu.title = new Date(k.last_used).toLocaleString();

  // note
  const noteCell = td(k.note || '—', 'note');
  if (k.note) noteCell.title = k.note;

  // actions
  const acts = document.createElement('div');
  acts.className = 'row-actions';
  const resetB = iconBtn('reset', k.hwid ? 'Reset HWID' : 'No HWID to reset', guard(async () => {
    await api(`/admin/keys/${k.id}/reset-hwid`, { method: 'POST' });
    toast('HWID reset — the key will bind to the next device that uses it');
    loadKeys();
  }));
  resetB.disabled = !k.hwid;
  if (!k.hwid) resetB.style.opacity = '.35';
  const banB = iconBtn('ban', k.banned ? 'Unban key' : 'Ban key', guard(async () => {
    await api(`/admin/keys/${k.id}/ban`, { method: 'POST', body: { banned: !k.banned } });
    toast(k.banned ? 'Key unbanned' : 'Key banned');
    loadKeys();
  }), k.banned ? 'on' : '');
  const delB = iconBtn('trash', 'Delete key', () => confirmDialog({
    title: 'Delete this key?',
    text: `${k.key_value} will stop working immediately. This can't be undone.`,
    ok: 'Delete key',
    onConfirm: async () => {
      await api(`/admin/keys/${k.id}`, { method: 'DELETE' });
      toast('Key deleted');
      loadKeys();
    },
  }), 'danger');
  acts.append(resetB, banB, delB);

  tr.append(
    td(kc),
    td(badge),
    td(dev),
    expCell,
    td(fmtNum(k.auth_count), 'num'),
    lu,
    noteCell,
    td(acts),
  );
  return tr;
}

// search + filter
let searchTimer;
$('searchInput').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.search = e.target.value.trim(); renderKeys(); }, 120);
});
$('filterTabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-filter]');
  if (!b) return;
  state.filter = b.dataset.filter;
  document.querySelectorAll('#filterTabs button').forEach((x) => x.classList.toggle('active', x === b));
  renderKeys();
});

// generate
$('genOpenBtn').addEventListener('click', () => {
  $('genCount').value = 1;
  $('genNote').value = '';
  openModal('genModal');
});
$('genDuration').addEventListener('change', (e) => {
  $('genCustomWrap').classList.toggle('hidden', e.target.value !== 'custom');
});
$('genModal').addEventListener('submit', guard(async (e) => {
  e.preventDefault();
  const count = Math.min(Math.max(parseInt($('genCount').value, 10) || 1, 1), 500);
  const dur = $('genDuration').value;
  const days = dur === 'custom' ? Math.max(parseInt($('genDays').value, 10) || 1, 1) : Number(dur);
  const created = await api('/admin/keys', {
    method: 'POST',
    body: { project_id: state.current.id, count, days, note: $('genNote').value.trim() },
  });
  const text = created.map((k) => k.key_value).join('\n');
  $('resultTitle').textContent = `${created.length} key${created.length === 1 ? '' : 's'} generated`;
  $('resultKeys').value = text;
  openModal('resultModal');
  navigator.clipboard?.writeText(text).catch(() => {});
  loadKeys();
}));
$('copyKeysBtn').addEventListener('click', () => copyText($('resultKeys').value, 'Keys copied'));
$('downloadKeysBtn').addEventListener('click', () => {
  const blob = new Blob([$('resultKeys').value + '\n'], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${state.current.slug}-keys-${new Date().toISOString().slice(0, 10)}.txt`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

// ---------- formatting ----------
function fmtNum(n) { return Number(n).toLocaleString(); }

function span(ms) {
  const s = Math.abs(ms) / 1000;
  if (s < 60) return `${Math.max(1, Math.round(s))}s`;
  const m = s / 60; if (m < 60) return `${Math.round(m)}m`;
  const h = m / 60; if (h < 24) return `${Math.round(h)}h`;
  const d = h / 24; if (d < 60) return `${Math.round(d)}d`;
  const mo = d / 30; if (mo < 12) return `${Math.round(mo)}mo`;
  return `${Math.round(d / 365)}y`;
}
function timeAgo(ts) {
  const diff = Date.now() - ts;
  return diff < 10_000 ? 'just now' : `${span(diff)} ago`;
}
function timeUntil(ts) { return span(ts - Date.now()); }

// ---------- boot ----------
fetch('/api/site')
  .then((r) => r.json())
  .then(({ name }) => {
    if (!name) return;
    document.querySelectorAll('[data-site-name]').forEach((el) => (el.textContent = name));
    document.title = `Dashboard — ${name}`;
  })
  .catch(() => {});

if (state.token) showApp();
else {
  $('login').classList.remove('hidden');
}
