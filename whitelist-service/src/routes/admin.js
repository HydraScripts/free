import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { db } from '../db.js';
import { requireAdmin } from '../middleware/adminAuth.js';
import { generateKey, slugify, signToken, safeEqual } from '../util.js';

const router = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited' },
});

// ---- Auth ----
router.post('/login', loginLimiter, (req, res) => {
  const password = String(req.body?.password || '');
  if (!process.env.ADMIN_PASSWORD || !safeEqual(password, process.env.ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'invalid_password' });
  }
  const token = signToken({ role: 'admin' }, process.env.SESSION_SECRET);
  res.json({ token });
});

// Everything below requires a valid admin token.
router.use(requireAdmin);

// ---- Projects ----
router.get('/projects', (_req, res) => {
  const rows = db
    .prepare(
      `SELECT p.*, (SELECT COUNT(*) FROM keys k WHERE k.project_id = p.id) AS key_count
       FROM projects p ORDER BY p.created_at DESC`
    )
    .all();
  res.json(rows);
});

router.post('/projects', (req, res) => {
  const name = String(req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name_required' });

  let slug = slugify(req.body?.slug || name);
  // Ensure slug uniqueness.
  const exists = db.prepare('SELECT 1 FROM projects WHERE slug = ?');
  let candidate = slug;
  let n = 1;
  while (exists.get(candidate)) candidate = `${slug}-${n++}`;
  slug = candidate;

  const info = db
    .prepare('INSERT INTO projects (name, slug, script_source, created_at) VALUES (?, ?, ?, ?)')
    .run(name, slug, String(req.body?.script_source || ''), Date.now());
  res.status(201).json(db.prepare('SELECT * FROM projects WHERE id = ?').get(info.lastInsertRowid));
});

router.put('/projects/:id', (req, res) => {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id);
  if (!project) return res.status(404).json({ error: 'not_found' });
  const name = req.body?.name != null ? String(req.body.name).trim() : project.name;
  const script = req.body?.script_source != null ? String(req.body.script_source) : project.script_source;
  db.prepare('UPDATE projects SET name = ?, script_source = ? WHERE id = ?').run(name, script, project.id);
  res.json(db.prepare('SELECT * FROM projects WHERE id = ?').get(project.id));
});

router.delete('/projects/:id', (req, res) => {
  const info = db.prepare('DELETE FROM projects WHERE id = ?').run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// ---- Keys ----
router.get('/keys', (req, res) => {
  const projectId = req.query.project_id;
  const rows = projectId
    ? db.prepare('SELECT * FROM keys WHERE project_id = ? ORDER BY created_at DESC').all(projectId)
    : db.prepare('SELECT * FROM keys ORDER BY created_at DESC').all();
  res.json(rows);
});

// Generate one or more keys for a project.
router.post('/keys', (req, res) => {
  const projectId = req.body?.project_id;
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId);
  if (!project) return res.status(400).json({ error: 'invalid_project' });

  const count = Math.min(Math.max(parseInt(req.body?.count ?? 1, 10) || 1, 1), 500);
  const note = String(req.body?.note || '');
  // days > 0 => expiring key; 0 or missing => lifetime
  const days = parseInt(req.body?.days ?? 0, 10) || 0;
  const expiresAt = days > 0 ? Date.now() + days * 24 * 60 * 60 * 1000 : null;

  const insert = db.prepare(
    'INSERT INTO keys (key_value, project_id, note, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
  );
  const created = [];
  const tx = db.transaction(() => {
    for (let i = 0; i < count; i++) {
      let value = generateKey();
      // Retry on the astronomically unlikely collision.
      while (db.prepare('SELECT 1 FROM keys WHERE key_value = ?').get(value)) value = generateKey();
      const info = insert.run(value, project.id, note, expiresAt, Date.now());
      created.push(db.prepare('SELECT * FROM keys WHERE id = ?').get(info.lastInsertRowid));
    }
  });
  tx();
  res.status(201).json(created);
});

router.post('/keys/:id/reset-hwid', (req, res) => {
  const info = db
    .prepare('UPDATE keys SET hwid = NULL, reset_count = reset_count + 1 WHERE id = ?')
    .run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'not_found' });
  res.json(db.prepare('SELECT * FROM keys WHERE id = ?').get(req.params.id));
});

router.post('/keys/:id/ban', (req, res) => {
  const banned = req.body?.banned ? 1 : 0;
  const info = db.prepare('UPDATE keys SET banned = ? WHERE id = ?').run(banned, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'not_found' });
  res.json(db.prepare('SELECT * FROM keys WHERE id = ?').get(req.params.id));
});

router.delete('/keys/:id', (req, res) => {
  const info = db.prepare('DELETE FROM keys WHERE id = ?').run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

export default router;
