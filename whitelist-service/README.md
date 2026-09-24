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
- **Admin dashboard** — a single-page web UI (no build step).
- **Lua loader** — a small snippet users run; it computes an HWID, authenticates,
  and executes the protected script returned by the server.
- **Rate limiting** on the auth and login endpoints.

## Quick start

```bash
cd whitelist-service
npm install
cp .env.example .env
# edit .env: set ADMIN_PASSWORD and a long random SESSION_SECRET
npm start
```

Open <http://localhost:3000>, log in with `ADMIN_PASSWORD`, create a project,
paste your Lua into **Edit script**, and generate keys.

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
