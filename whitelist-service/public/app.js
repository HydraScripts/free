const $ = (id) => document.getElementById(id);
let token = localStorage.getItem('wl_token') || null;
let projects = [];
let current = null; // selected project

// ---- API helper ----
async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { logout(); throw new Error('unauthorized'); }
  const data = res.headers.get('content-type')?.includes('json') ? await res.json() : null;
  if (!res.ok) throw new Error(data?.error || `http_${res.status}`);
  return data;
}

// ---- Auth ----
$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').textContent = '';
  try {
    const { token: t } = await api('/admin/login', { method: 'POST', body: { password: $('password').value } });
    token = t;
    localStorage.setItem('wl_token', t);
    showApp();
  } catch {
    $('loginError').textContent = 'Invalid password.';
  }
});

$('logout').addEventListener('click', logout);
function logout() {
  token = null;
  localStorage.removeItem('wl_token');
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
}

function showApp() {
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  loadProjects();
}

// ---- Projects ----
async function loadProjects() {
  projects = await api('/admin/projects');
  renderProjects();
  if (current) {
    const still = projects.find((p) => p.id === current.id);
    still ? selectProject(still) : clearSelection();
  }
}

function renderProjects() {
  const list = $('projectList');
  list.innerHTML = '';
  for (const p of projects) {
    const li = document.createElement('li');
    li.className = current && current.id === p.id ? 'active' : '';
    li.innerHTML = `<span>${escapeHtml(p.name)}</span><span class="count">${p.key_count}</span>`;
    li.addEventListener('click', () => selectProject(p));
    list.appendChild(li);
  }
}

$('newProject').addEventListener('click', async () => {
  const name = prompt('Project name:');
  if (!name) return;
  const p = await api('/admin/projects', { method: 'POST', body: { name } });
  await loadProjects();
  const created = projects.find((x) => x.id === p.id);
  if (created) selectProject(created);
});

$('deleteProject').addEventListener('click', async () => {
  if (!current || !confirm(`Delete project "${current.name}" and all its keys?`)) return;
  await api(`/admin/projects/${current.id}`, { method: 'DELETE' });
  clearSelection();
  loadProjects();
});

function clearSelection() {
  current = null;
  $('projectView').classList.add('hidden');
  $('empty').classList.remove('hidden');
  renderProjects();
}

async function selectProject(p) {
  current = p;
  $('empty').classList.add('hidden');
  $('projectView').classList.remove('hidden');
  $('projTitle').textContent = p.name;
  $('projSlug').textContent = p.slug;
  $('loaderSnippet').textContent =
    `_G.Key = "YOUR-KEY-HERE"\n` +
    `loadstring(game:HttpGet("${location.origin}/loader/${p.slug}"))()`;
  renderProjects();
  loadKeys();
}

// ---- Script editor ----
$('editScript').addEventListener('click', () => {
  $('scriptText').value = current.script_source || '';
  $('scriptModal').classList.remove('hidden');
});
$('scriptCancel').addEventListener('click', () => $('scriptModal').classList.add('hidden'));
$('scriptSave').addEventListener('click', async () => {
  const updated = await api(`/admin/projects/${current.id}`, {
    method: 'PUT',
    body: { script_source: $('scriptText').value },
  });
  current.script_source = updated.script_source;
  $('scriptModal').classList.add('hidden');
});

// ---- Keys ----
async function loadKeys() {
  const keys = await api(`/admin/keys?project_id=${current.id}`);
  const body = $('keysBody');
  body.innerHTML = '';
  if (!keys.length) {
    body.innerHTML = `<tr><td colspan="7" class="muted">No keys yet. Generate some above.</td></tr>`;
    return;
  }
  for (const k of keys) body.appendChild(keyRow(k));
}

function keyRow(k) {
  const tr = document.createElement('tr');
  const expired = k.expires_at && k.expires_at < Date.now();
  const status = k.banned
    ? '<span class="badge banned">banned</span>'
    : expired
    ? '<span class="badge expired">expired</span>'
    : '<span class="badge ok">active</span>';
  tr.innerHTML = `
    <td><code>${escapeHtml(k.key_value)}</code></td>
    <td class="muted">${k.hwid ? escapeHtml(k.hwid.slice(0, 16)) + '…' : '<em>unbound</em>'}</td>
    <td>${status}</td>
    <td class="muted">${k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'lifetime'}</td>
    <td>${k.auth_count}</td>
    <td class="muted">${escapeHtml(k.note || '')}</td>
    <td></td>`;
  const actions = tr.lastElementChild;

  const resetBtn = mkBtn('Reset HWID', 'ghost mini', async () => {
    await api(`/admin/keys/${k.id}/reset-hwid`, { method: 'POST' });
    loadKeys();
  });
  const banBtn = mkBtn(k.banned ? 'Unban' : 'Ban', 'ghost mini', async () => {
    await api(`/admin/keys/${k.id}/ban`, { method: 'POST', body: { banned: !k.banned } });
    loadKeys();
  });
  const delBtn = mkBtn('Delete', 'danger mini', async () => {
    if (!confirm('Delete this key?')) return;
    await api(`/admin/keys/${k.id}`, { method: 'DELETE' });
    loadKeys();
  });
  actions.append(resetBtn, banBtn, delBtn);
  return tr;
}

$('genKeys').addEventListener('click', async () => {
  const count = parseInt($('genCount').value, 10) || 1;
  const days = parseInt($('genDays').value, 10) || 0;
  const note = $('genNote').value;
  const created = await api('/admin/keys', {
    method: 'POST',
    body: { project_id: current.id, count, days, note },
  });
  $('genNote').value = '';
  if (created.length) {
    const list = created.map((k) => k.key_value).join('\n');
    navigator.clipboard?.writeText(list).catch(() => {});
    alert(`Generated ${created.length} key(s) (copied to clipboard):\n\n${list}`);
  }
  loadProjects();
  loadKeys();
});

// ---- helpers ----
function mkBtn(label, cls, onClick) {
  const b = document.createElement('button');
  b.textContent = label;
  b.className = cls;
  b.addEventListener('click', onClick);
  return b;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---- boot ----
if (token) showApp();
