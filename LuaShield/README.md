# LuaShield | Potassium + Luraph v15

## Setup

Use Node.js 20.19+ with MongoDB **replica set** support (Prisma transactions require it). Built on Fastify 5 and Prisma 6.

```sh
npm install
npx prisma generate
node server/index.js
```

Copy `.env.example` to `.env` and fill it in. `LICENSE_HMAC_SECRET` is required (at least 32 characters) and the server refuses to start without it.

### Upgrading from the previous build

1. **Back up the database.**
2. **License/HMAC secret.** The old salt was committed to the repository, so treat it as public. To keep existing license keys and legacy passwords working during the move, set `LICENSE_HMAC_SECRET` to the old `salt` value from the previous build's `server/config.json`, then rotate: set a new secret and reset license keys (`POST /projects/:id/users/reset_key`). Passwords are already re-hashed with Argon2id on login and don't depend on the secret afterwards.
3. **API keys.** Run `npm run migrate:api-keys` (dry run) then `npm run migrate:api-keys -- --apply`. Customers keep their current key; only its SHA-256 digest is stored afterwards. Login and `/account` no longer return the key. Use `POST /regenerate_api_key` (username + password) to issue a new one.
4. **Timestamps are unix seconds** for `User.ExpireAt`, `Subscription.Expire/Reset` and `Buyer.RegisteredAt` (Prisma `Int` is 32-bit). Older millisecond values are still read correctly. API `expire` fields take seconds.
5. **Rebuild every script.** Publishing now produces a public loader plus a separate payload, and protected scripts receive LuaShield info as `...` (see below).
6. Run `npx prisma db push`.

Use **HTTPS** and configure proxy trust only for the addresses/CIDRs of your actual reverse proxies. `cf-connecting-ip` is never trusted directly. Configure public domains before creating any scripts because each obfuscated loader embeds the authentication URL. A reverse-proxy forwarding address must be trusted by Fastify's `TRUSTED_PROXIES` setting, not inferred from incoming headers.

Existing Project records must have `Potassium=true`. Previous Synapse/Script-Ware HWID bindings need to be reset and rebound to Potassium. Existing protected scripts need to be rebuilt, since legacy `/auth/version` and WebSocket authorization endpoints were replaced. Ensure schema indexes are applied to the database with `npx prisma db push` after backing up data. Duplicate project/username pairs must be resolved before adding the new unique index. Existing passwords stored as HMAC-SHA512 are migrated to Argon2id on successful login. Existing licenses with legacy millisecond expiry timestamps are interpreted correctly until rewritten in seconds, but values too large for Prisma `Int` may require manual data cleanup. Password hashes are never returned by login or account lookup.

## Authentication protocol

The client calls `POST /auth/challenge` with a project ID, script ID, `gethwid()` and Roblox UserId. It gets a 30-second, **single-use** random challenge. It then calls `POST /auth/authorize` with the challenge and license key **in the JSON request body**, over HTTPS. The server verifies project, script, license, expiration and execution limit, then issues a random bearer session token. The token rotates its deadline via `POST /auth/heartbeat` every 15 seconds; successful checks extend server session expiration to 45 seconds. After authorizing, the loader fetches the protected script once from `POST /auth/payload` with the bearer token and runs it. The script receives a table as `...`:

```lua
local Info = ...
print(Info.Username, Info.Executions, Info.ScriptName, Info.Version)
Info.SecureWebhook("https://your.luashield.host/webhooks/<token>", { content = "hello" })
```

Webhook submission uses the same session and verifies project ownership. Heartbeat, payload and webhook relays are rate-limited per session (not per IP), so many players behind one NAT don't share a bucket. Authorization counts only **failed** attempts toward the per-IP/project lockout (12 per minute). Failed attempts trigger the project's Unauthorized webhook; a key used from a different HWID increments `CrackAttempts` and triggers the Blacklist webhook (alerts are limited to one per type per project every 5 seconds).

The script distribution endpoint `GET /s/:project/:id` returns only the obfuscated **loader**, which does not contain the protected script. The script body (obfuscated separately) is only served to an authorized session, one time. Anyone with a valid license can still capture what their own client receives, and Roblox executor/client HWIDs and IDs are not cryptographic attestations. Strong authorization must occur on the server for genuinely sensitive functions.

## Running several instances

Challenges, sessions, one-time payload claims, failed-attempt counters, alert throttles, stats and HTTP rate limits live in a store. Without `REDIS_URL` it is in process memory: a single instance works, and a restart logs every player out. With `REDIS_URL` (Redis 6.2+, which provides `GETDEL`) all of it is shared:

- a challenge can be consumed exactly once across all instances (atomic `GETDEL`), even under concurrent use
- sessions survive an instance restart and work on any instance behind the load balancer
- the payload is released once per session across all instances (`SET NX`)
- failure lockouts and rate limits are counted globally
- only SHA-256 digests of challenges and session tokens are used as keys

If Redis is unreachable, requests fail with HTTP 500 within about a second. Nothing is granted.

Protected scripts and audit logs are files under `files/`, so every instance must mount the same persistent volume. Script versions are write-once (temp file + hard link), and the audit log is append-only JSON lines, so concurrent writers don't lose data.

## Luraph integration

Older `LS_OPCODESPAM` and the legacy Lua 5.1 source-rewriting stage have been removed. The client uses v15 `LPH_ATTRIBUTES`, `VM(ONYX)`, `PRESET(SECURE)`, `PRESET(FAST)` and `LPH_PRECHECK`. The precheck is an upvalue-free anonymous function with a fixed integer key, consistent with Luraph v15. Each publish runs two Luraph jobs, one for the loader and one for the payload, and counts as two obfuscations against the subscription. Script building submits the Luau source directly to Luraph v15 (without the former 5.1 AST source rewriting). The official SDK dependency is `luraph@^2.0.9`; real obfuscation requires a paid account with API access. `USE_DEBUG_LIBRARY` and other v14-era options were removed from the submission. Webhooks are sent directly to Discord. Only `discord.com`/`discordapp.com` webhook URLs are accepted, mentions are disabled, and the old third-party relay is no longer used.

## Tests

Run `npm test` (in-memory store), and `npm run test:redis` with a Redis server running (defaults to `redis://127.0.0.1:6379/15`, which is **flushed**). The Redis run adds multi-instance tests: two app instances with separate memory and Redis connections sharing one Redis, covering cross-instance challenge use, concurrent double-spend, session survival across a restart, one-time payload delivery and shared lockouts. A boot test builds the full app (every route and schema) without a database. The tests run the auth routes through Fastify (including rate limiting) against an in-memory database. They cover replayed challenges, shared-IP heartbeats, failure-only lockout, expiry in seconds and legacy milliseconds, quotas, HWID-mismatch alerts, one-time payload delivery, webhook URL validation and password migration. Browser/Roblox/Potassium runtime, MongoDB transactions, API obfuscation, and actual public HTTPS deployment require live end-to-end testing.

References: https://lura.ph/dashboard/documents/v15 | https://lura.ph/dashboard/documents/macros | https://docs.potassium.pro/api-reference/introduction

## Deployment

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for Docker Compose, environment variables, scaling across instances, health probes and backups.
