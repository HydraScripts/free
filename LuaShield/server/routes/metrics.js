const client = require("prom-client");
const Store = require("../modules/store");
const Sessions = require("../modules/sessions");
const { safeEqual } = require("../modules/crypto");

// Register default process metrics once per process (building multiple apps in tests must not
// double-register, which prom-client rejects).
if (!global.__luashieldMetricsInit) {
    global.__luashieldMetricsInit = true;
    client.collectDefaultMetrics({ prefix: "luashield_" });
}

const ActiveSessions = getOrCreate("gauge", {
    name: "luashield_active_sessions",
    help: "Currently active authenticated sessions"
});
const AuthTotal = getOrCreate("gauge", {
    name: "luashield_authentications_total",
    help: "Total successful authentications since the stats store was reset"
});

function getOrCreate(Type, Config) {
    return client.register.getSingleMetric(Config.name) || new client[Type === "gauge" ? "Gauge" : "Counter"](Config);
}

async function routes(fastify) {
    // Optional bearer-token guard so metrics aren't exposed publicly. Unset = open (dev).
    fastify.get("/metrics", { logLevel: "warn" }, async (request, reply) => {
        const Token = process.env.METRICS_TOKEN;
        if (Token) {
            const Header = request.headers.authorization || "";
            const Presented = Header.startsWith("Bearer ") ? Header.slice(7) : "";
            if (!safeEqual(Presented, Token)) return reply.code(401).send("Unauthorized");
        }
        try {
            const Stats = await Store.stats();
            AuthTotal.set(Stats.times || 0);
            ActiveSessions.set(await Sessions.sessionCount());
        } catch (er) {
            request.log.warn({ err: er }, "metrics: store read failed");
        }
        reply.header("Content-Type", client.register.contentType);
        return client.register.metrics();
    });
}

module.exports = routes;
