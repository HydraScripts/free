# Operations

## Running with Docker

```sh
cp .env.example .env     # fill in LICENSE_HMAC_SECRET (>=32 chars) and ADMIN_KEY
docker compose up --build
```

The `mongo-init` service initiates the single-node replica set on first run (Prisma transactions
require a replica set). The app waits for MongoDB and Redis to be healthy. Data persists in the
`mongo-data` and `app-files` volumes.

Bootstrap the first admin once, then the endpoint disables itself:

```sh
curl -X POST localhost:8080/create_admin \
  -H 'content-type: application/json' \
  -d '{"username":"root","email":"you@example.com","password":"a-long-password","auth":"'"$ADMIN_KEY"'"}'
```

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | MongoDB connection string (replica set) |
| `LICENSE_HMAC_SECRET` | yes | HMAC key for license keys; >= 32 chars. Rotating it invalidates existing license keys |
| `ADMIN_KEY` | yes | Bootstraps the first admin; compared in constant time |
| `REDIS_URL` | no | Share sessions/limits across instances. Unset = in-memory, single instance |
| `LURAPH_KEY` | for publishing | Luraph API token |
| `LURAPH_NODE` | no | Luraph node id; unset uses the API's recommended node |
| `AUTH_BASE_URL` / `LOADER_BASE_URL` | yes in prod | Public URLs embedded in loaders; must be HTTPS |
| `CORS_ORIGINS` | prod | Comma-separated dashboard origins; unset leaves CORS open |
| `TRUSTED_PROXIES` | behind a proxy | IPs/CIDRs Fastify trusts for `X-Forwarded-For` |
| `WEBHOOK_MAX_ATTEMPTS` | no | Discord webhook delivery attempts (default 4) |

## Scaling to multiple instances

Set `REDIS_URL` on every instance so challenges, sessions, one-time payload claims, rate limits and
lockout counters are shared (see `server/modules/store.js`). Mount the same persistent volume for
`files/` on every instance (published scripts and audit logs live there), or put a shared filesystem
behind it. Without `REDIS_URL` you must run exactly one instance.

Readiness: point your load balancer at `GET /readyz` (checks MongoDB and the store) and your
orchestrator's liveness probe at `GET /healthz`.

## Backups

- **MongoDB** is the source of truth: `mongodump` on a schedule, test restores.
- **`files/`** holds obfuscated scripts and audit logs: back the volume up, or re-publish scripts
  from source after a restore.
- Prisma uses `db push` for MongoDB (no migration history). Back up before any schema change and
  apply with `npx prisma db push`.

## Known limitations

- Timestamps (`User.ExpireAt`, `Subscription.Expire/Reset`, `Buyer.RegisteredAt`) are stored as
  32-bit unix seconds and are capped at January 2038. Moving them to `DateTime` is a planned
  schema change that needs a data migration.
- Session state is in memory unless `REDIS_URL` is set; a restart logs players out.
