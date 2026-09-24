import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { db } from '../db.js';

const router = Router();

// Protect the auth endpoint from brute-forcing keys.
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'rate_limited' },
});

/**
 * POST /api/v1/auth
 * body: { key, hwid, project }
 *
 * Validates a key against a project, binds the HWID on first use, and
 * returns the protected script source on success.
 */
router.post('/auth', authLimiter, (req, res) => {
  const key = String(req.body?.key || '').trim();
  const hwid = String(req.body?.hwid || '').trim();
  const slug = String(req.body?.project || '').trim();

  if (!key || !hwid || !slug) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  const project = db.prepare('SELECT * FROM projects WHERE slug = ?').get(slug);
  if (!project) {
    return res.status(404).json({ ok: false, error: 'project_not_found' });
  }

  const record = db
    .prepare('SELECT * FROM keys WHERE key_value = ? AND project_id = ?')
    .get(key, project.id);

  if (!record) {
    return res.status(403).json({ ok: false, error: 'invalid_key' });
  }
  if (record.banned) {
    return res.status(403).json({ ok: false, error: 'key_banned' });
  }
  if (record.expires_at && record.expires_at < Date.now()) {
    return res.status(403).json({ ok: false, error: 'key_expired' });
  }

  // HWID lock: bind on first use, enforce thereafter.
  if (!record.hwid) {
    db.prepare('UPDATE keys SET hwid = ? WHERE id = ?').run(hwid, record.id);
  } else if (record.hwid !== hwid) {
    return res.status(403).json({ ok: false, error: 'hwid_mismatch' });
  }

  db.prepare(
    'UPDATE keys SET last_used = ?, auth_count = auth_count + 1 WHERE id = ?'
  ).run(Date.now(), record.id);

  return res.json({
    ok: true,
    project: project.slug,
    expires_at: record.expires_at,
    script: project.script_source,
  });
});

export default router;
