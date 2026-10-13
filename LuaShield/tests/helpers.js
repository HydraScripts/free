process.env.LICENSE_HMAC_SECRET = process.env.LICENSE_HMAC_SECRET || "test-secret-test-secret-test-secret-0123456789";

const Module = require("node:module");
const path = require("node:path");
const { mkdirSync, writeFileSync, rmSync } = require("node:fs");
const { evaluate } = require("../server/modules/license");

// In-memory stand-in for server/modules/database.js with the same compare-and-set semantics.
function makeDatabase() {
    const Users = new Map();
    const Calls = { cracks: 0 };
    const Database = {
        Users, Calls,
        GetProject: async ID => ID === "project1" ? {
            id: ID, Name: "Project", Online: true, Potassium: true,
            SuccessWebhook: "", BlacklistWebhook: "https://discord.com/api/webhooks/1/b",
            UnauthorizedWebhook: "https://discord.com/api/webhooks/1/u"
        } : null,
        GetScript: async (ProjectID, ScriptID) => ProjectID === "project1" && ScriptID === "script1"
            ? { id: "script1", Name: "Script", Version: "v1.0.0" } : null,
        GetWhitelist: async Hash => [...Users.values()].find(User => User.Key === Hash) || null,
        GetWhitelistByID: async ID => Users.get(ID) || null,
        AuthorizeExecution: async (ID, ProjectID, HWID) => {
            const User = Users.get(ID);
            const Reason = evaluate(User, { ProjectID, HWID, CheckQuota: true });
            if (Reason) return { ok: false, reason: Reason };
            User.Executions++;
            User.HWID = User.HWID || HWID;
            return { ok: true, user: { ...User } };
        },
        IncrementUserCracks: async () => { Calls.cracks++; }
    };
    return Database;
}

function loadAuthRoutes(Database, WebhookCalls) {
    const Load = Module._load;
    Module._load = function (Name, Parent) {
        if (Parent?.filename.endsWith(path.join("server", "routes", "auth.js"))) {
            if (Name === "../modules/database") return class { constructor() { return Database; } };
            if (Name === "../modules/webhooks") return new Proxy({}, {
                get: (_, Type) => async (Url, Data) => WebhookCalls.push({ Type, Url, Data })
            });
        }
        return Load.apply(this, arguments);
    };
    delete require.cache[require.resolve("../server/routes/auth")];
    try {
        return require("../server/routes/auth");
    } finally {
        Module._load = Load;
    }
}

async function buildApp() {
    const Database = makeDatabase();
    const WebhookCalls = [];
    const Routes = loadAuthRoutes(Database, WebhookCalls);
    global.AuthenticationStats = { Potassium: { times: 0, total: 0 }, times: 0, total: 0 };
    const App = require("fastify")();
    await App.register(require("@fastify/rate-limit"), { max: 60, timeWindow: "1 minute" });
    await App.register(Routes, { prefix: "/auth" });
    await App.ready();
    return { App, Database, WebhookCalls };
}

function writePayload(Source) {
    const Folder = path.join(__dirname, "../files/projects/project1/script1");
    mkdirSync(Folder, { recursive: true });
    writeFileSync(path.join(Folder, "v1.0.0.payload.lua"), Source);
    return () => rmSync(path.join(__dirname, "../files/projects/project1"), { recursive: true, force: true });
}

module.exports = { buildApp, writePayload };
