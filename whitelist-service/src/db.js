import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

const dbPath = process.env.DB_PATH || './data/whitelist.db';
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

export const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    slug          TEXT NOT NULL UNIQUE,
    script_source TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_value   TEXT NOT NULL UNIQUE,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hwid        TEXT,
    note        TEXT NOT NULL DEFAULT '',
    banned      INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER,               -- NULL = lifetime
    reset_count INTEGER NOT NULL DEFAULT 0,
    auth_count  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    last_used   INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_keys_project ON keys(project_id);
`);
