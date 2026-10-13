const { existsSync, mkdirSync } = require("fs");
const path = require("path");
const cors = require("@fastify/cors");
const ratelimit = require("@fastify/rate-limit");
require("dotenv").config()

let options = {
    logger: {
        level: process.env.LOG_LEVEL || "info",
        redact: ["req.headers.authorization", "req.headers[\"luashield-api-key\"]", "req.headers.cookie"]
    },
    trustProxy: process.env.TRUSTED_PROXIES ? process.env.TRUSTED_PROXIES.split(",") : false
}

const fastify = require("fastify")(options);

if (!existsSync(path.join(__dirname, "../files"))) {
    mkdirSync(path.join(__dirname, "../files"));
}


if (!existsSync(path.join(__dirname, "../files/projects"))) {
    mkdirSync(path.join(__dirname, "../files/projects"));
}

if (!existsSync(path.join(__dirname, "../files/logs"))) {
    mkdirSync(path.join(__dirname, "../files/logs"));
}

global.AuthenticationStats = {
    Potassium: {
        total: 0,
        times: 0
    },
    total: 0,
    times: 0
}

fastify.register(cors);
fastify.register(ratelimit, {
    max: 60,
    timeWindow: "1 minute"
});

fastify.register(require("./routes/auth"), { prefix: "/auth" });
fastify.register(require("./routes/verify"), { prefix: "/verify" });
fastify.register(require("./routes/api"));

fastify.register(require("./routes/script"), { prefix: "/s" });
fastify.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode < 500) {
        return reply.code(error.statusCode).send({ error: error.message });
    }
    return reply.code(500).send({ error: "Internal server error" });
});

(async () => {
    try {
        await fastify.listen({ port: Number(process.env.PORT) || 8080, host: "0.0.0.0" });
    } catch (er) {
        fastify.log.error(er);
        process.exit(1);
    }
})();