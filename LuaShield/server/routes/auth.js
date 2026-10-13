const { createHash } = require("node:crypto");
const { readFile } = require("node:fs/promises");
const path = require("node:path");
const Database = new (require("../modules/database"))();
const { sha512 } = require("../modules/crypto");
const Sessions = require("../modules/sessions");
const Webhooks = require("../modules/webhooks");
const { evaluate } = require("../modules/license");
const { failureLimiter, intervalGate } = require("../modules/throttle");

// Only failures count toward the limit, so a busy shared IP can still log in.
const Failures = failureLimiter({ Max: 12, WindowMs: 60_000 });
const AlertGate = intervalGate(5_000);

const VersionPattern = /^v\d+\.\d+\.\d+$/;

function BearerToken(request) {
    const Authorization = request.headers.authorization;
    return typeof Authorization === "string" && Authorization.startsWith("Bearer ") ? Authorization.slice(7) : "";
}

// Rate-limit by session when one is presented, so many clients behind one IP don't share a bucket.
function SessionKey(request) {
    const Token = BearerToken(request);
    return Token ? "s:" + createHash("sha256").update(Token).digest("hex") : "ip:" + request.ip;
}

function Alert(Project, Type, Data) {
    const Url = Project[`${Type}Webhook`];
    if (!Url || !AlertGate(`${Project.id}:${Type}`)) return;
    void Webhooks[Type](Url, Data);
}

async function routes(fastify) {
    const Identity = {
        type: "object",
        additionalProperties: false,
        required: ["project_id", "script_id", "hwid", "user_id"],
        properties: {
            project_id: { type: "string", minLength: 1, maxLength: 80 },
            script_id: { type: "string", minLength: 1, maxLength: 80 },
            hwid: { type: "string", minLength: 1, maxLength: 256 },
            user_id: { type: "string", pattern: "^[1-9][0-9]{0,19}$" }
        }
    };

    fastify.post("/challenge", { schema: { body: Identity }, config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
        if (request.headers["x-luashield-executor"] !== "potassium") {
            return reply.code(403).send({ error: "Unsupported client" });
        }
        const { project_id, script_id, hwid, user_id } = request.body;
        const Project = await Database.GetProject(project_id);
        if (!Project || !Project.Online || !Project.Potassium || !await Database.GetScript(project_id, script_id)) {
            return reply.code(403).send({ error: "Unavailable" });
        }
        const Challenge = Sessions.createChallenge({ ProjectID: project_id, ScriptID: script_id, HWID: hwid, UserID: user_id });
        if (!Challenge) return reply.code(429).send({ error: "Busy" });
        return { challenge: Challenge };
    });

    fastify.post("/authorize", {
        schema: {
            body: {
                type: "object", additionalProperties: false, required: ["challenge", "key"],
                properties: {
                    challenge: { type: "string", pattern: "^[a-f0-9]{64}$" },
                    key: { type: "string", minLength: 1, maxLength: 512 }
                }
            }
        },
        config: { rateLimit: { max: 60, timeWindow: "1 minute" } }
    }, async (request, reply) => {
        const Challenge = Sessions.consumeChallenge(request.body.challenge);
        if (!Challenge) return reply.code(403).send({ error: "Authentication failed" });

        const LimitKey = `${request.ip}:${Challenge.ProjectID}`;
        if (Failures.blocked(LimitKey)) return reply.code(429).send({ error: "Too many failed attempts" });
        const Fail = (Status, Message) => {
            Failures.record(LimitKey);
            return reply.code(Status).send({ error: Message });
        };

        const [Project, Script, Whitelist] = await Promise.all([
            Database.GetProject(Challenge.ProjectID),
            Database.GetScript(Challenge.ProjectID, Challenge.ScriptID),
            Database.GetWhitelist(sha512(request.body.key))
        ]);
        if (!Project || !Project.Online || !Project.Potassium || !Script) return Fail(403, "Authentication failed");

        if (!Whitelist || Whitelist.ProjectID !== Challenge.ProjectID) {
            Alert(Project, "Unauthorized", { IP: request.ip, Reason: "Unknown or wrong-project license key was used" });
            return Fail(403, "Authentication failed");
        }

        // One conditional write validates the license, counts the execution and binds the HWID.
        const Result = await Database.AuthorizeExecution(Whitelist.id, Challenge.ProjectID, Challenge.HWID);
        if (!Result.ok) {
            const Name = Whitelist.Username;
            switch (Result.reason) {
                case "hwid":
                    try { await Database.IncrementUserCracks(Whitelist, Challenge.ProjectID); } catch { /* counter only */ }
                    Alert(Project, "Blacklist", {
                        IP: request.ip, Reason: "License used from a different hardware ID",
                        Whitelist: { Username: Name, CrackAttempts: Whitelist.CrackAttempts + 1 }
                    });
                    return Fail(403, "Authentication failed");
                case "expired":
                case "quota":
                    Alert(Project, "Unauthorized", { IP: request.ip, Reason: `License ${Result.reason} for ${Name}` });
                    return Fail(403, "License expired or quota reached");
                case "busy":
                    return reply.code(503).send({ error: "Try again" });
                default:
                    Alert(Project, "Unauthorized", { IP: request.ip, Reason: `Disabled license used by ${Name}` });
                    return Fail(403, "Authentication failed");
            }
        }

        const User = Result.user;
        const Token = Sessions.createSession({
            UserID: Challenge.UserID, HWID: Challenge.HWID, WhitelistID: User.id,
            ProjectID: Challenge.ProjectID, ScriptID: Challenge.ScriptID, ScriptVersion: Script.Version
        });
        if (!Token) return reply.code(429).send({ error: "Busy" });

        const Duration = (Date.now() - Challenge.CreatedAt) / 1000;
        global.AuthenticationStats.Potassium.times++;
        global.AuthenticationStats.Potassium.total += Duration;
        global.AuthenticationStats.times++;
        global.AuthenticationStats.total += Duration;

        if (Project.SuccessWebhook) {
            Alert(Project, "Success", {
                IP: request.ip,
                UserAgent: request.headers["user-agent"] || "Unknown",
                Whitelist: { Username: User.Username, Executions: User.Executions },
                Duration,
                Project: Project.Name,
                Script: Script.Name
            });
        }
        return {
            token: Token, script: Script.Name, version: Script.Version, heartbeat: 15,
            username: User.Username, executions: User.Executions,
            crack_attempts: User.CrackAttempts, exploit: "Potassium"
        };
    });

    fastify.post("/heartbeat", { config: { rateLimit: { max: 15, timeWindow: "1 minute", keyGenerator: SessionKey } } }, async (request, reply) => {
        const Token = BearerToken(request);
        const Session = Sessions.getSession(Token);
        if (!Session) return reply.code(401).send({ error: "Session expired" });
        const [Whitelist, Project, Script] = await Promise.all([
            Database.GetWhitelistByID(Session.WhitelistID),
            Database.GetProject(Session.ProjectID),
            Database.GetScript(Session.ProjectID, Session.ScriptID)
        ]);
        if (evaluate(Whitelist, { ProjectID: Session.ProjectID, HWID: Session.HWID }) ||
            !Project || !Project.Online || !Project.Potassium || !Script) {
            Sessions.revokeSession(Token);
            return reply.code(403).send({ error: "License revoked" });
        }
        Sessions.renewSession(Token);
        return { valid: true };
    });

    // The protected script body is only released to an authorized session, once.
    fastify.post("/payload", { config: { rateLimit: { max: 15, timeWindow: "1 minute", keyGenerator: SessionKey } } }, async (request, reply) => {
        const Token = BearerToken(request);
        const Session = Sessions.getSession(Token);
        if (!Session) return reply.code(401).send({ error: "Session expired" });
        if (Session.PayloadServed) return reply.code(409).send({ error: "Payload already delivered" });
        if (!VersionPattern.test(Session.ScriptVersion)) return reply.code(404).send({ error: "Unavailable" });
        Session.PayloadServed = true;

        const File = path.join(__dirname, "../../files/projects", Session.ProjectID, Session.ScriptID, `${Session.ScriptVersion}.payload.lua`);
        try {
            const Source = await readFile(File, "utf8");
            return reply.header("Cache-Control", "no-store").type("text/plain; charset=utf-8").send(Source);
        } catch (Error) {
            Session.PayloadServed = false;
            if (Error.code === "ENOENT") return reply.code(404).send({ error: "Unavailable" });
            throw Error;
        }
    });
}

module.exports = routes;
