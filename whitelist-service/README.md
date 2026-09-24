# Whitelist Service

A self-hosted script whitelist / key-authentication service in the style of
[luarmor.net](https://luarmor.net). It issues license keys, locks each key to a
single hardware ID (HWID) on first use, and serves your protected Lua script
only to clients whose key + HWID pass authentication. Ships with a web admin
dashboard and a drop-in Lua loader.

## Features

- **HWID-locked keys** — each key binds to one machine on first auth; admins can
  reset the binding.
- **Multiple projects** — each project has its own slug, protected script, keys,
  and loader URL.
- **Key management** — bulk-generate keys, optional expiry (or lifetime), notes,
  ban/unban, delete, and per-key usage counts.
- **Public landing page** at `/`: hero, features, how it works, API docs, and a
  live status indicator.
- **Admin dashboard** at `/dashboard`: per-project stats, key search and status
  filters, copy buttons, bulk generation with .txt download, a script editor, and
  a mobile layout. No build step.
- **Lua loader** — a small snippet users run; it computes an HWID, authenticates,
  and executes the protected script returned by the server.
- **Rate limiting** on the auth and login endpoints.

## Quick start

**Windows:** double-click `start.bat`. **Mac/Linux:** run `./start.sh`.

The script checks for Node.js, installs dependencies, asks you to choose an
admin password on first run (it generates `SESSION_SECRET` for you), starts the
server, and opens the dashboard. Keep the window open while you test.

Or do it by hand:

```bash
cd whitelist-service
npm install
cp .env.example .env
# edit .env: set ADMIN_PASSWORD and a long random SESSION_SECRET
npm start
```

Open <http://localhost:3000> for the public site, or
<http://localhost:3000/dashboard> to log in with `ADMIN_PASSWORD`. Create a
project, paste your Lua in under **Script**, and generate keys.

To rebrand, set `SITE_NAME` in `.env`. The landing page and dashboard read it from
`/api/site`.

## How it fits together

```
User's executor              Your server                 Admin
--------------               -----------                 -----
_G.Key = "XXXX-..."   -->    GET  /loader/<slug>   <--   creates project + keys
loadstring(HttpGet)()        (loader with values         via the dashboard
   |                          pre-filled)
   v
POST /api/v1/auth      -->   validate key + project
{ key, hwid, project }       bind/enforce HWID
                             return protected script  -->  runs on success
```

## Distributing to users

Each project shows a loader snippet in the dashboard, e.g.:

```lua
_G.Key = "YOUR-KEY-HERE"
loadstring(game:HttpGet("https://your-domain.com/loader/myproject"))()
```

The server fills in the endpoint and project slug for that project, so users
only set their key.

## API

### Public (used by the loader)

`POST /api/v1/auth` — body `{ key, hwid, project }`
Returns `{ ok: true, script }` on success, or `{ ok: false, error }` with a
non-200 status. Errors: `missing_fields`, `project_not_found`, `invalid_key`,
`key_banned`, `key_expired`, `hwid_mismatch`, `rate_limited`.

`GET /loader/:slug` — returns the Lua loader with values pre-filled.

### Admin (require `Authorization: Bearer <token>` from `/api/admin/login`)

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST   | `/api/admin/login` | Exchange password for a session token |
| GET/POST/PUT/DELETE | `/api/admin/projects[/:id]` | Manage projects & script source |
| GET/POST/DELETE | `/api/admin/keys[/:id]` | List, generate (`{project_id,count,days,note}`), delete |
| POST   | `/api/admin/keys/:id/reset-hwid` | Unbind the HWID |
| POST   | `/api/admin/keys/:id/ban` | `{ banned: true|false }` |

## Configuration

See `.env.example`. `ADMIN_PASSWORD` and `SESSION_SECRET` are required — the
server refuses to start without them.

## Production notes

- Put this behind HTTPS (a reverse proxy such as Caddy or nginx). Keys and HWIDs
  should never travel over plain HTTP.
- The SQLite database lives at `DB_PATH` (default `./data/whitelist.db`); back it
  up. `data/` and `.env` are gitignored.
- HWID-based whitelisting deters casual key sharing; a determined user can still
  spoof an HWID or dump the returned script. Treat this as access control, not
  unbreakable DRM. Add server-side obfuscation of `script_source` if you need
  more.

## Security note

This is authentication/licensing software for scripts **you own or are
authorized to distribute**. Don't use it to gate content you don't have the
rights to.
