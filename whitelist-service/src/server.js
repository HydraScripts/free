import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import authRouter from './routes/auth.js';
import adminRouter from './routes/admin.js';
import loaderRouter from './routes/loader.js';
import './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD) {
  console.error('FATAL: SESSION_SECRET and ADMIN_PASSWORD must be set (see .env.example).');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));

// The Lua loader calls /api/v1/auth from game clients, so allow cross-origin.
app.use('/api/v1', cors(), authRouter);

// Admin API is same-origin with the dashboard.
app.use('/api/admin', adminRouter);

// Per-project Lua loader (fetched by game clients via HttpGet).
app.use('/', cors(), loaderRouter);

app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Public site info used by the landing page and dashboard for branding.
app.get('/api/site', (_req, res) => {
  res.json({ name: process.env.SITE_NAME || 'Hydra Auth' });
});

// Landing page at /, admin dashboard at /dashboard.
app.use(express.static(path.join(__dirname, '..', 'public')));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`whitelist-service listening on http://localhost:${port}`);
});
