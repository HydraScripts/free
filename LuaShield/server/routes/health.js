const Database = new (require("../modules/database"))();
const Store = require("../modules/store");

// Liveness vs readiness:
//  - /healthz: the process is up and the event loop responds. Used by orchestrators to decide
//    whether to restart the container. It must not depend on external services.
//  - /readyz: the instance can actually serve traffic, i.e. MongoDB and the session store (Redis,
//    when configured) are reachable. Used by load balancers to decide whether to route to it.
async function routes(fastify) {
    fastify.get("/healthz", { logLevel: "warn" }, async () => ({ status: "ok" }));

    fastify.get("/readyz", { logLevel: "warn" }, async (request, reply) => {
        const Checks = { mongo: false, store: false };
        await Promise.all([
            Database.Ping().then(() => { Checks.mongo = true; })
                .catch(er => request.log.warn({ err: er }, "readiness: mongo unavailable")),
            Promise.resolve(Store.ping()).then(Ok => { Checks.store = Boolean(Ok); })
                .catch(er => request.log.warn({ err: er }, "readiness: store unavailable"))
        ]);
        const Ready = Checks.mongo && Checks.store;
        return reply.code(Ready ? 200 : 503).send({ status: Ready ? "ready" : "unavailable", checks: Checks });
    });
}

module.exports = routes;
