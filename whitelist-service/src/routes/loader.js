import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { db } from '../db.js';

const router = Router();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const template = fs.readFileSync(
  path.join(__dirname, '..', '..', 'loader', 'loader.lua'),
  'utf8'
);

// Escape a value for safe inclusion inside a Lua double-quoted string.
function luaStr(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * GET /loader/:slug
 * Serves the loader with ENDPOINT and PROJECT pre-filled for this project,
 * so users only need to set _G.Key and loadstring(HttpGet(...))().
 */
router.get('/loader/:slug', (req, res) => {
  const project = db.prepare('SELECT slug FROM projects WHERE slug = ?').get(req.params.slug);
  if (!project) {
    return res.type('text/plain').status(404).send('-- project not found');
  }

  const base = (process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
  const filled = template
    .replace(/local ENDPOINT = ".*?"/, `local ENDPOINT = "${luaStr(base)}/api/v1/auth"`)
    .replace(/local PROJECT  = ".*?"/, `local PROJECT  = "${luaStr(project.slug)}"`);

  res.type('text/plain').send(filled);
});

export default router;
