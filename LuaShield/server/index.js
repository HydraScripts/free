require("dotenv").config();
const { mkdirSync } = require("fs");
const path = require("path");
const cors = require("@fastify/cors");
const ratelimit = require("@fastify/rate-limit");
const Store = require("./modules/store");

for (const Folder of ["../files/projects", "../files/logs"]) {
    mkdirSync(path.join(__dirname, Folder), { recursive: true });
}

// Builds the full app without listening, so tests can boot every route.
async function build(Options = {}) {
    const fastify = require("fastify")({
        logger: {
            level: process.env.LOG_LEVEL || "info",
            redact: ["req.headers.authorization", "req.headers[\"luashield-api-key\"]", "req.headers.cookie"]
        },
        trustProxy: process.env.TRUSTED_PROXIES ? process.env.TRUSTED_PROXIES.split(",") : false,
        // Reject unknown body properties (Fastify strips them by default) so malformed or
        // tampered requests fail loudly instead of being silently accepted.
        ajv: { customOptions: { removeAdditional: false } },
        ...Options
    });

    fastify.addHook("onClose", () => Store.close());
    // Restrict the dashboard API to its own origins. CORS_ORIGINS is a comma-separated allowlist;
    // unset leaves CORS open (handy for local/dev), which should not be used in production.
    const Origins = (process.env.CORS_ORIGINS || "").split(",").map(O => O.trim()).filter(Boolean);
    await fastify.register(cors, Origins.length ? { origin: Origins, credentials: true } : {});
    // With REDIS_URL set, rate-limit counters are shared across instances too.
    await fastify.register(ratelimit, {
        max: 60,
        timeWindow: "1 minute",
        ...(Store.redis ? { redis: Store.redis, nameSpace: "ls:rl:" } : {})
    });

    fastify.register(require("./routes/health"));
    fastify.register(require("./routes/auth"), { prefix: "/auth" });
    fastify.register(require("./routes/verify"), { prefix: "/verify" });
    fastify.register(require("./routes/api"));
    fastify.register(require("./routes/script"), { prefix: "/s" });

    fastify.setErrorHandler((error, request, reply) => {
        if (error.statusCode && error.statusCode < 500) {
            return reply.code(error.statusCode).send({ error: error.message });
        }
        request.log.error(error);
        return reply.code(500).send({ error: "Internal server error" });
    });
    return fastify;
}

if (require.main === module) {
    (async () => {
        const fastify = await build();
        try {
            await fastify.listen({ port: Number(process.env.PORT) || 8080, host: "0.0.0.0" });
        } catch (er) {
            fastify.log.error(er);
            process.exit(1);
        }
        for (const Signal of ["SIGINT", "SIGTERM"]) {
            process.once(Signal, () => fastify.close().then(() => process.exit(0)));
        }
    })();
}

module.exports = { build };
