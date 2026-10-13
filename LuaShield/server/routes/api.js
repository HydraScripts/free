const database = require("../modules/database");
const webhooks = require("../modules/webhooks");
const crypto = require("../modules/crypto");
const path = require("path");
const validator = require("email-validator");
const { Luraph } = require("luraph");
const Passwords = require("../modules/password");
const Sessions = require("../modules/sessions");
const Store = require("../modules/store");
const AuditLog = require("../modules/auditlog");
const { randomUUID } = require("node:crypto");
const { linkSync, unlinkSync } = require("node:fs");
const { readFileSync, mkdirSync, writeFileSync, existsSync, rmSync } = require("fs");
const { subscription_data } = require("../config.json");
const { evaluate } = require("../modules/license");
const { nowSeconds, toSeconds, MaxInt32 } = require("../modules/time");
const { UserWebhook, CheckWebhook } = require("../modules/webhooks");

const Database = new database();
const luraph = new Luraph(process.env.LURAPH_KEY);
const AuthBaseURL = (process.env.AUTH_BASE_URL || "https://api.luashield.com").replace(/\/$/, "");
const LoaderBaseURL = (process.env.LOADER_BASE_URL || AuthBaseURL).replace(/\/$/, "");

// Function replacers are required: a string replacement would expand `$&`, `$'` etc. inside values.
function BuildLoader(ProjectID, ScriptID, Version) {
    if (!/^https:\/\//.test(AuthBaseURL) && !/^http:\/\/localhost(:\d+)?$/.test(AuthBaseURL)) {
        throw new Error("AUTH_BASE_URL must use HTTPS");
    }
    return readFileSync(path.join(__dirname, "../../client/client.lua"), "utf8")
        .replace("AUTH_BASE_URL", () => AuthBaseURL)
        .replace("PROJECT_ID", () => ProjectID)
        .replace("SCRIPT_ID", () => ScriptID)
        .replace("SCRIPT_VERSION", () => Version);
}

// `Kind` is "loader" (public, served from /s) or "payload" (released only to an authorized session).
function WriteProtectedScript(ProjectID, ScriptID, Version, Kind, Data) {
    const Folder = path.join(__dirname, "../../files/projects", ProjectID, ScriptID);
    mkdirSync(Folder, { recursive: true });
    const File = path.join(Folder, Kind === "payload" ? `${Version}.payload.lua` : `${Version}.lua`);
    const Temp = `${File}.${randomUUID()}.tmp`;
    writeFileSync(Temp, Data);
    try {
        linkSync(Temp, File);
    } finally {
        unlinkSync(Temp);
    }
    return File;
}

// Both Luraph jobs run before anything is written or counted.
async function ProtectScript(ProjectID, ScriptID, Version, RawScript) {
    const [Loader, Payload] = await Promise.all([
        ObfuscateWhitelist(BuildLoader(ProjectID, ScriptID, Version), `${ScriptID}.lua`),
        ObfuscateWhitelist(RawScript, `${ScriptID}.payload.lua`)
    ]);
    const Files = [];
    try {
        Files.push(WriteProtectedScript(ProjectID, ScriptID, Version, "loader", Loader));
        Files.push(WriteProtectedScript(ProjectID, ScriptID, Version, "payload", Payload));
    } catch (er) {
        for (const File of Files) if (existsSync(File)) rmSync(File);
        throw er;
    }
    return Files;
}

// Stored in a 32-bit Int, so clamp (the cap is January 2038).
function SecondsFrom(Date) {
    return Math.min(Math.floor(Date.getTime() / 1000), MaxInt32);
}

const ObfuscationsPerPublish = 2;

function HasObfuscationBudget(Subscription) {
    return (Subscription.Obfuscations || 0) + ObfuscationsPerPublish <= subscription_data.max_obfuscations;
}

// Webhook relays are limited per game session rather than per IP.
function SessionTokenKey(request) {
    const Token = request.headers["luashield-access-token"];
    return typeof Token === "string" && Token ? "s:" + crypto.sha256(Token) : "ip:" + request.ip;
}

// Never expose credentials or the stored key digest.
function PublicBuyer(Buyer) {
    if (!Buyer) return Buyer;
    const { Password, APIKey, ApiKeyHash, ...Rest } = Buyer;
    return Rest;
}

// Luraph's first job argument is a NODE id (from getNodes()), not the version string. Resolve it
// from LURAPH_NODE, else the API's recommended node, cached for the process.
let CachedNode = null;
async function ResolveLuraphNode() {
    if (process.env.LURAPH_NODE) return process.env.LURAPH_NODE;
    if (CachedNode) return CachedNode;
    const { recommendedId } = await luraph.getNodes();
    if (!recommendedId) throw new Error("Luraph returned no available node");
    CachedNode = recommendedId;
    return CachedNode;
}

async function ObfuscateWhitelist(Script, FileName) {
    const Node = await ResolveLuraphNode();
    const { jobId } = await luraph.createNewJob(Node, Script, FileName, {
        TARGET_VERSION: "Roblox",
        STATIC_ENVIRONMENT: false
    });

    const { success, error } = await luraph.getJobStatus(jobId);
    if (!success) {
        throw new Error(error || "Luraph obfuscation failed");
    }

    const { data } = await luraph.downloadResult(jobId);
    return data;
}

// Bump the patch component. No rollover: a 10th patch is v1.0.10, not v1.1.0.
function IncrementScriptVersion(version) {
    const [Major, Minor, Patch] = version.slice(1).split(".").map(Part => parseInt(Part, 10) || 0);
    return `v${Major}.${Minor}.${Patch + 1}`;
}

function AddToAuditLog(Username, IP, Log) {
    AuditLog.add(Username, IP, Log);
}

/**
 * @param {import("fastify").FastifyInstance} fastify  Encapsulated Fastify Instance
 * @param {Object} options plugin options, refer to https://www.fastify.io/docs/latest/Reference/Plugins/#plugin-options
*/
async function routes(fastify, options) {
    /**
     * @param {import("fastify").FastifyRequest} request
     * @param {import("fastify").FastifyReply} reply 
     */
    async function AuthenticationHandler(request, reply) {
        const Presented = request.headers["luashield-api-key"];
        const Buyer = typeof Presented === "string" && Presented
            ? await Database.GetBuyerFromAPIKeyHash(crypto.sha256(Presented)) : null;

        if (!Buyer) {
            return reply.status(401).send({ error: "Invalid API Key" });
        }

        const Subscription = await Database.GetSubscription(Buyer.SubscriptionID);
        if (!Subscription || nowSeconds() > toSeconds(Subscription.Expire)) {
            return reply.status(402).send({ error: "Your subscription has expired" });
        }

        // reset subscription obfuscations
        if (nowSeconds() > toSeconds(Subscription.Reset)) {
            request.Subscription = await Database.ResetSubscriptionObfuscations(Buyer.SubscriptionID);
        } else {
            request.Subscription = Subscription;
        }

        // The internal identifier (not the secret) is what ownership records reference.
        request.APIKey = Buyer.APIKey;
        request.Admin = Buyer.Admin;
        request.BuyerUsername = Buyer.Username;
    }

    const HeadersSchema = {
        type: "object",
        properties: {
            "luashield-api-key": { type: "string" }
        },
        required: ["luashield-api-key"]
    }

    const MakeProjectSchem = {
        type: "object",
        additionalProperties: false,
        properties: {
            name: { type: "string", maxLength: 30, minLength: 3 },
            success_webhook: { type: "string", maxLength: 150, minLength: 50 },
            blacklist_webhook: { type: "string", maxLength: 150, minLength: 50 },
            unauthorized_webhook: { type: "string", maxLength: 150, minLength: 50 },
            allowed_exploits: {
                type: "object",
                additionalProperties: false,
                properties: {
                    potassium: { type: "boolean" }
                },
                required: ["potassium"]
            }
        },
        required: ["name", "success_webhook", "blacklist_webhook", "unauthorized_webhook", "allowed_exploits"]
    }

    const UpdateProjectSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            name: { type: "string", maxLength: 30, minLength: 3 },
            success_webhook: { type: "string", maxLength: 150, minLength: 50 },
            blacklist_webhook: { type: "string", maxLength: 150, minLength: 50 },
            unauthorized_webhook: { type: "string", maxLength: 150, minLength: 50 },
            allowed_exploits: {
                type: "object",
                additionalProperties: false,
                properties: {
                    potassium: { type: "boolean" }
                },
                required: ["potassium"]
            },
            online: { type: "boolean" }
        }
    }

    const WhiteistUserSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            username: { type: "string", maxLength: 128, minLength: 3 },
            expire: { type: "integer", minimum: 0, maximum: 2147483647 },
            max_executions: { type: "integer", minimum: 0, maximum: 1000000 },
            whitelisted: { type: "boolean" },
            note: { type: "string", minLength: 3, maxLength: 128 },
            discord_id: { type: "string", minLength: 10, maxLength: 128 }
        },
        required: ["username", "whitelisted"]
    }

    const UpdateUserSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            username: { type: "string", maxLength: 128, minLength: 3 },
            whitelisted: { type: "boolean" },
            expire: { type: "integer", minimum: 0, maximum: 2147483647 },
            max_executions: { type: "integer", minimum: 0, maximum: 1000000 },
            note: { type: "string", minLength: 3, maxLength: 128 },
            discord_id: { type: "string", minLength: 10, maxLength: 128 }
        },
        required: ["whitelisted", "username"]
    }
    
    const SignupSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            email: { type: "string", maxLength: 254 },
            password: { type: "string", minLength: 12, maxLength: 128 },
            username: { type: "string", minLength: 3, maxLength: 15 },
            subscription_id: { type: "string" }
        },
        required: ["email", "password", "username", "subscription_id"]
    }

    const LoginSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            password: { type: "string", minLength: 6, maxLength: 128 },
            username: { type: "string", minLength: 3, maxLength: 15 }
        },
        required: ["password", "username"]
    }

    const UpdateScriptSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            script: { type: "string" }, // base 64 encoded,
            script_id: { type: "string" },
            name: { type: "string", maxLength: 30, minLength: 3 }
        },
        required: ["script", "script_id"]
    }

    const AddScriptSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            name: { type: "string", maxLength: 30, minLength: 3 },
            script: { type: "string" }, // base 64 encoded,
        },
        required: ["name", "script"]
    }

    const DeleteUserSchema = {
        type: "object",
        additionalProperties: false,
        properties: {
            username: { type: "string" },
        },
        required: ["username"]
    }

    const ResetKey = {
        type: "object",
        additionalProperties: false,
        properties: {
            username: { type: "string" }
        },
        required: ["username"]
    }

    const UpdateVersion = {
        type: "object",
        additionalProperties: false,
        properties: {
            script_id: { type: "string" },
            version: { type: "string" }
        },
        required: ["script_id", "version"]
    }

    const DeleteScript = {
        type: "object",
        additionalProperties: false,
        properties: {
            script_id: { type: "string" },
        },
        required: ["script_id"]
    }

    const DeleteAccount = {
        type: "object",
        additionalProperties: false,
        properties: {
            password: { type: "string", minLength: 6, maxLength: 128 },
            username: { type: "string", minLength: 3, maxLength: 15 }
        },
        required: ["password", "username"]
    }

    const ResetPassword = {
        type: "object",
        additionalProperties: false,
        properties: {
            password: { type: "string", minLength: 12, maxLength: 128 }
        },
        required: ["password"]
    }

    const MakeWebhook = {
        type: "object",
        additionalProperties: false,
        properties: {
            url: { type: "string", maxLength: 150, minLength: 50 },
            name: { type: "string", maxLength: 30, minLength: 3 }
        },
        required: ["url", "name"]
    }

    const ResponseScema = {
        400: {
            type: "object",
            properties: {
                error: { type: "string" }
            }
        },
        401: {
            type: "object",
            properties: {
                error: { type: "string" }
            }
        },
        500: {
            type: "object",
            properties: {
                error: { type: "string" }
            }
        }
    }

    const StatsResponse = {
        200: {
            type: "object",
            properties: {
                online: { type: "boolean" },
                clients: { type: "number" }, 
                authentication_speeds: {
                    type: "object",
                    properties: {
                        potassium: {
                            type: "object",
                            properties: {
                                average: { type: "number" }
                            }
                        }
                    }
                },
                average_authentication: { type: "number" }
            }
        }
    }

    fastify.get("/stats", { websocket: false, schema: { response: StatsResponse } }, async (request, reply) => {
        const Stats = await Store.stats();
        const Average = (Stats.total / Stats.times) || 0;
        return {
            online: true,
            clients: await Sessions.sessionCount(),
            authentication_speeds: { potassium: { average: Average } },
            average_authentication: Average
        };
    })

    // Verified against a throwaway hash when the user is unknown so timing doesn't reveal valid usernames.
    let DummyHash;
    async function AuthenticateBuyer(Username, Password) {
        const Buyer = await Database.GetBuyerFromUsername(Username);
        if (!Buyer) {
            DummyHash = DummyHash || await Passwords.hash(crypto.randomSecret());
            await Passwords.verify(DummyHash, Password);
            return null;
        }
        const Check = await Passwords.verify(Buyer.Password, Password);
        if (!Check.valid) return null;
        if (Check.legacy) {
            await Database.UpdatePasswordIfMatch(Buyer.APIKey, Buyer.Password, await Passwords.hash(Password));
        }
        return Buyer;
    }

    fastify.post("/signup", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } }, schema: { body: SignupSchema, response: ResponseScema }, websocket: false }, async (request, reply) => {
        const Email = request.body.email;
        const Password = request.body.password;
        const Username = request.body.username;
        const SubscriptionID = request.body.subscription_id;

        const Subscription = await Database.GetSubscription(SubscriptionID);
        if (!Subscription) {
            return reply.status(400).send({ error: "Invalid subscription id" });
        }

        if (Subscription.Email) {
            return reply.status(400).send({ error: "This subscription is already being used by another user" });
        }

        if (!validator.validate(Email)) {
            return reply.status(400).send({ error: "Email is invalid" });
        }

        if (Username.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "Your username cannot include special characters" });
        }

        if (!Password.match(/[A-Z]+/)) {
            return reply.status(400).send({ error: "Your password must include at least one uppercase letter" })
        }

        if (await Database.GetBuyerFromEmail(Email)) {
            return reply.status(400).send({ error: "This email is already registered to another user" });
        }

        if (await Database.GetBuyerFromUsername(Username)) {
            return reply.status(400).send({ error: "This username is already associated with another account" })
        }

        const APIKey = crypto.randomSecret();
        try {
            await Database.AddBuyer(Email, Username, await Passwords.hash(Password), crypto.randomUUID(), SubscriptionID, crypto.sha256(APIKey));

            return reply.send({ APIKey: APIKey });
        } catch (er) {
            return reply.status(500).send({ error: "There was an error with creating your account" });
        }
    });

    fastify.post("/login", { config: { rateLimit: { max: 8, timeWindow: "1 minute" } }, schema: { body: LoginSchema, response: ResponseScema }, websocket: false }, async (request, reply) => {
        const Password = request.body.password;
        const Username = request.body.username;
        const Buyer = await AuthenticateBuyer(Username, Password);

        if (!Buyer) {
            return reply.status(401).send({ error: "Incorrect username or password" });
        }

        AddToAuditLog(Username, request.ip, "Logged in");

        const Subscription = await Database.GetSubscription(Buyer.SubscriptionID);
        reply.send({ ...PublicBuyer(Buyer), Subscription });
    });

    // The API key is only stored as a digest, so a new one is issued on request. The old key stops working.
    fastify.post("/regenerate_api_key", { config: { rateLimit: { max: 3, timeWindow: "1 minute" } }, schema: { body: LoginSchema, response: ResponseScema }, websocket: false }, async (request, reply) => {
        const Buyer = await AuthenticateBuyer(request.body.username, request.body.password);
        if (!Buyer) {
            return reply.status(401).send({ error: "Incorrect username or password" });
        }

        const APIKey = crypto.randomSecret();
        try {
            await Database.SetAPIKeyHash(Buyer.id, crypto.sha256(APIKey));
            AddToAuditLog(Buyer.Username, request.ip, "Regenerated API key");
            reply.send({ APIKey });
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "There was an issue while regenerating your API key" });
        }
    });

    fastify.post("/delete_account", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } }, schema: { body: DeleteAccount, response: ResponseScema }, websocket: false }, async (request, reply) => {
        const Password = request.body.password;
        const Username = request.body.username;
        const Buyer = await AuthenticateBuyer(Username, Password);

        if (!Buyer) {
            return reply.status(401).send({ error: "Incorrect username or password" });
        }

        try {
            AuditLog.remove(Username);

            for (const project of Buyer.Projects) {
                if (existsSync(path.join(__dirname, `../../files/projects/${project}`))) {
                    rmSync(path.join(__dirname, `../../files/projects/${project}`), { force: true, recursive: true });
                }
                await Database.DeleteProject(project, Buyer.APIKey);
            }

            await Database.DeleteAccount(Buyer.Email);
            reply.send({ success: true })
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "There was an issue while trying to delete your account" });
        }
    });

    fastify.post("/change_password", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } }, schema: { headers: HeadersSchema, body: ResetPassword, response: ResponseScema }, websocket: false }, async (request, reply) => {
        const Presented = request.headers["luashield-api-key"];
        const Buyer = typeof Presented === "string" && Presented
            ? await Database.GetBuyerFromAPIKeyHash(crypto.sha256(Presented)) : null;
        const Password = request.body.password;
        
        if (!Buyer) {
            return reply.status(401).send({ error: "Unauthorized" });
        }

        if (!Password.match(/[A-Z]+/)) {
            return reply.status(400).send({ error: "Your password must include at least one uppercase letter" })
        }

        try {
            await Database.ResetPassword(Buyer.APIKey, await Passwords.hash(Password));
            reply.send({ success: true })
        } catch (er) {
            console.log(er);
            return reply.status(500).send({ error: "There was an issue while trying to reset your password" })
        }
    });

    fastify.get("/account", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        reply.send(PublicBuyer(await Database.GetBuyerFromAPIKey(request.APIKey)));
    });

    fastify.get("/audit_logs", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const Info = await Database.GetBuyerFromAPIKey(request.APIKey);
        reply.send(AuditLog.read(Info.Username));
    });

    // Make Project
    fastify.post("/projects", { schema: { headers: HeadersSchema, body: MakeProjectSchem, response: ResponseScema }, config: { rateLimit: { max: 5 } }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (request.Subscription.Projects >= subscription_data.max_projects) {
            return reply.status(403).send({ error: "You have reached your maximum amount of projects for your account" })
        }
        
        const Name = request.body.name;
        if (Name.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "Your project name cannot include special characters" });
        }

        const Exploits = request.body.allowed_exploits;

        let SuccessWebhook = request.body.success_webhook;
        let BlacklistWebhook = request.body.blacklist_webhook;
        let UnauthorizedWebhook = request.body.unauthorized_webhook;
        
        SuccessWebhook = SuccessWebhook.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);
        BlacklistWebhook = BlacklistWebhook.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);
        UnauthorizedWebhook = UnauthorizedWebhook.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);

        if (!SuccessWebhook) {
            return reply.status(400).send({ error: "success_webhook is not a valid webhook" });
        }

        if (!BlacklistWebhook) {
            return reply.status(400).send({ error: "blacklist_webhook is not a valid webhook" });
        }

        if (!UnauthorizedWebhook) {
            return reply.status(400).send({ error: "unauthorized_webhook is not a valid webhook" });
        }

        SuccessWebhook = "https://" + SuccessWebhook.shift();
        BlacklistWebhook = "https://" + BlacklistWebhook.shift();
        UnauthorizedWebhook = "https://" + UnauthorizedWebhook.shift();
        
        try {
            await webhooks.SetupWebhook(SuccessWebhook, Name, "success");
            await webhooks.SetupWebhook(BlacklistWebhook, Name, "blacklist");
            await webhooks.SetupWebhook(UnauthorizedWebhook, Name, "unauthorized");
        } catch (er) {
            return reply.status(500).send({ error: er.toString() });
        }

        let Information;
        try {
            await Database.SubscriptionIncrementProjectCount(request.Subscription.SubscriptionID, 1);
            Information = await Database.MakeProject(Name, SuccessWebhook, BlacklistWebhook, UnauthorizedWebhook, Exploits, request.APIKey);
            await Database.UpdateBuyerProjects(request.APIKey, Information.id);
            AddToAuditLog(request.BuyerUsername, request.ip, `Made a project called ${Name}`);
        } catch (er) {
            console.log(er);
            return reply.status(500).send({ error: "There was an issue while creating this project" });
        }
        
        mkdirSync(path.join(__dirname, `../../files/projects/${Information.id}`)); // make folder in projects for project
        reply.send(Information);
    });

    // Create Script
    fastify.post("/projects/:id/scripts", { schema: { headers: HeadersSchema, body: AddScriptSchema, response: ResponseScema }, config: { rateLimit: { max: 5 } }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (request.Subscription.Scripts >= subscription_data.max_scripts) {
            return reply.status(403).send({ error: "You have reached your maximum amount of scripts for your account" })
        }

        const ScriptName = request.body.name;
        const ProjectID = request.params.id;
        let Script = request.body.script;

        if (ScriptName.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "Your script name cannot include special characters" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "This project isn't owned by you" })
        }

        const Project = await Database.GetProject(ProjectID);
        if (!Project) {
            return reply.status(404).send({ error: "This project doesn't exist" });
        }

        if (!HasObfuscationBudget(request.Subscription)) {
            return reply.status(403).send({ error: "You have reached your obfuscation limit for this period" });
        }

        Script = Buffer.from(Script, "base64").toString();

        const GeneratedVersion = "v1.0.0";
        const ScriptID = randomUUID();
        let Files = [];
        try {
            Files = await ProtectScript(ProjectID, ScriptID, GeneratedVersion, Script);
            const Info = await Database.PublishNewScript(ProjectID, ScriptName, GeneratedVersion, ScriptID, request.Subscription.SubscriptionID, ObfuscationsPerPublish);
            Info.Loader = `${LoaderBaseURL}/s/${ProjectID}/${ScriptID}`;
            return reply.send(Info);
        } catch (Error) {
            for (const File of Files) if (existsSync(File)) rmSync(File);
            return reply.status(500).send({ error: "Unable to publish script: " + Error.message });
        }
    });

    // Update Existing User 
    fastify.patch("/projects/:id/users", { schema: { headers: HeadersSchema, body: UpdateUserSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;
        const Username = request.body.username;
        const Whitelisted = request.body.whitelisted;
        const Expiry = request.body.expire;
        const MaxExecutions = request.body.max_executions;
        const Note = request.body.note;
        const DiscordID = request.body.discord_id;

        if (Expiry && (!Number.isSafeInteger(Expiry) || Expiry <= nowSeconds() || Expiry > MaxInt32)) {
            return reply.status(400).send({ error: "Expire must be a valid unix epoch timestamp" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Existing = await Database.GetUser(Username, ProjectID);
        if (!Existing) {
            return reply.status(404).send({ error: "This user doesn't exist" });
        }

        // Distinguish "field omitted" from a real 0 (e.g. max_executions: 0 means unlimited).
        if (Expiry === undefined && MaxExecutions === undefined && Note === undefined &&
            DiscordID === undefined && Whitelisted === Existing.Whitelisted) {
            return reply.send(Existing);
        }

        try {
            const Info = await Database.UpdateUser(Existing.id, Expiry, MaxExecutions, Whitelisted, Note, DiscordID);
            return reply.send(Info);
        } catch (er) {
            return reply.status(500).send({ error: "There was an issue while updating this user" });
        }
    });

    fastify.post("/projects/:id/users/reset_key", { schema: { headers: HeadersSchema, body: ResetKey, response: ResponseScema }, websocket: false,  preHandler: AuthenticationHandler }, async (request, reply) => {
        const Username = request.body.username;
        const ProjectID = request.params.id;

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Existing = await Database.GetUser(Username, ProjectID);
        if (!Existing) {
            return reply.status(404).send({ error: "This user doesn't exist" });
        }

        const Key = crypto.randomUUID();
        try {
            await Database.UpdateKey(Existing.id, crypto.sha512(Key));
            reply.send({ Key: Key });
        } catch (er) {
            reply.status(500).send({ error: "There was an issue while resetting this users key" });
        }
    });

    fastify.post("/projects/:id/users/reset_hwid", { schema: { headers: HeadersSchema, body: ResetKey, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const Username = request.body.username;
        const ProjectID = request.params.id;

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Existing = await Database.GetUser(Username, ProjectID);
        if (!Existing) {
            return reply.status(404).send({ error: "This user doesn't exist" });
        }

        if (!Existing.HWID) {
            return reply.status(400).send({ error: "User doesn't have an HWID linked" });
        }

        try {
            const Info = await Database.ResetHWID(Existing.id);
            reply.send({ success: true });
        } catch (er) {
            reply.status(500).send({ error: "There was an issue while resetting this users HWID" });
        }
    });

    // Create User
    fastify.post("/projects/:id/users", { schema: { headers: HeadersSchema, body: WhiteistUserSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;
        const Username = request.body.username;
        const Expiry = request.body.expire;
        const MaxExecutions = request.body.max_executions || 0;
        const Whitelisted = request.body.whitelisted;
        const Note = request.body.note;
        const DiscordID = request.body.discord_id;

        if (Username.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "The username cannot contain special characters" });
        }

        if (Expiry && (!Number.isSafeInteger(Expiry) || Expiry <= nowSeconds() || Expiry > MaxInt32)) {
            return reply.status(400).send({ error: "Expire must be a valid unix epoch timestamp" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Existing = await Database.GetUser(Username, ProjectID);
        if (Existing) {
            return reply.status(400).send({ error: "A user with this username already exists" })
        }

        const Key = crypto.randomUUID();
        try {
            const Info = await Database.AddUser(Username, crypto.sha512(Key), ProjectID, Expiry || undefined, MaxExecutions, Whitelisted, Note, DiscordID);
            Info.Key = Key;
            AddToAuditLog(request.BuyerUsername, request.ip, `Created a user for project ${ProjectID} with username ${Username}`);
            reply.send(Info);
        } catch (er) {
            console.log(er);
            return reply.status(500).send({ error: "There was an issue creating this user" });
        }
    });

    // Delete User
    fastify.delete("/projects/:id/users", { schema: { headers: HeadersSchema, body: DeleteUserSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;
        const Username = request.body.username;

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const User = await Database.GetUser(Username, ProjectID);
        if (!User) {
            return reply.status(404).send({ error: "This user doesn't exist" });
        }

        try {
            await Database.DeleteUser(ProjectID, Username);
            AddToAuditLog(request.BuyerUsername, request.ip, `Deleted a user for project ${ProjectID} with username ${Username}`);
            reply.send({ success: true });
        } catch (er) {
            reply.status(500).send({ error: "Something went wrong trying to delete this user" });
        }
    });

    // Update Script
    fastify.patch("/projects/:id/scripts", { schema: { headers: HeadersSchema, body: UpdateScriptSchema, response: ResponseScema }, config: { rateLimit: { max: 5 } }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ScriptID = request.body.script_id;
        const ScriptName = request.body.name;
        const ProjectID = request.params.id;
        let RawScript = request.body.script;

        if (ScriptName && ScriptName.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "Your script name cannot include special characters" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Script = await Database.GetScript(ProjectID, ScriptID);
        if (!Script) {
            return reply.status(404).send({ error: "This script doesn't exist" });
        }

        if (!HasObfuscationBudget(request.Subscription)) {
            return reply.status(403).send({ error: "You have reached your obfuscation limit for this period" });
        }

        RawScript = Buffer.from(RawScript, "base64").toString();

        const GeneratedVersion = IncrementScriptVersion(Script.Version);
        let Files = [];
        try {
            Files = await ProtectScript(ProjectID, Script.id, GeneratedVersion, RawScript);
            const Info = await Database.PublishScriptVersion(
                ScriptID, Script.Version, GeneratedVersion, ScriptName || Script.Name,
                request.Subscription.SubscriptionID, ObfuscationsPerPublish
            );
            return reply.send(Info);
        } catch (Error) {
            for (const File of Files) if (existsSync(File)) rmSync(File);
            return reply.status(500).send({ error: "Unable to update script: " + Error.message });
        }
    });

    // Update Script Version
    fastify.patch("/projects/:id/scripts/version", { schema: { headers: HeadersSchema, body: UpdateVersion, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ScriptID = request.body.script_id;
        const ProjectID = request.params.id;
        const Version = request.body.version;

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Script = await Database.GetScript(ProjectID, ScriptID);
        if (!Script) {
            return reply.status(404).send({ error: "This script doesn't exist" });
        }

        if (!Script.Versions.find(x => x === Version)) {
            return reply.status(404).send({ error: "This version doesn't exist" });
        }

        try {
            const Info = await Database.UpdateScriptVersion(Script.id, Version);
            reply.send(Info);
        } catch (er) {
            reply.status(500).send({ error: "There was an issue while updating the script version" });
        }
    });

    // Delete Script Version
    fastify.delete("/projects/:id/scripts/version", { schema: { headers: HeadersSchema, body: UpdateVersion, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ScriptID = request.body.script_id;
        const ProjectID = request.params.id;
        const Version = request.body.version;

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Script = await Database.GetScript(ProjectID, ScriptID);
        if (!Script) {
            return reply.status(404).send({ error: "This script doesn't exist" });
        }

        if (!Script.Versions.find(x => x === Version)) {
            return reply.status(404).send({ error: "This version doesn't exist" });
        }
        
        if (Script.Version === Version) {
            return reply.status(400).send({ error: "You cannot delete the current version" });
        }

        try {
            const Info = await Database.DeleteScriptVersion(ScriptID, Version);
            for (const Name of [`${Version}.lua`, `${Version}.payload.lua`]) {
                const File = path.join(__dirname, `../../files/projects/${ProjectID}/${Script.id}/${Name}`);
                if (existsSync(File)) rmSync(File);
            }
            reply.send(Info);
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "There was an issue trying to delete the script version" });
        }
    });

    // Update Project
    fastify.patch("/projects/:id", { schema: { headers: HeadersSchema, body: UpdateProjectSchema, response: ResponseScema }, config: { rateLimit: { max: 5 } }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;
        const Name = request.body.name;
        let SuccessWebhook = request.body.success_webhook;
        let BlacklistWebhook = request.body.blacklist_webhook;
        let UnauthorizedWebhook = request.body.unauthorized_webhook;
        const Exploits = request.body.allowed_exploits;
        const Online = request.body.online;

        if (Name !== undefined && Name.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "Your project name cannot include special characters" });
        }

        const Project = await Database.GetProject(ProjectID);
        if (!Project) {
            return reply.status(404).send({ error: "This project doesn't exist" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "This project isn't owned by you" });
        }

        SuccessWebhook = SuccessWebhook || Project.SuccessWebhook;
        BlacklistWebhook = BlacklistWebhook || Project.BlacklistWebhook;
        UnauthorizedWebhook = UnauthorizedWebhook || Project.UnauthorizedWebhook;

        SuccessWebhook = SuccessWebhook.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);
        BlacklistWebhook = BlacklistWebhook.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);
        UnauthorizedWebhook = UnauthorizedWebhook.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);

        if (!SuccessWebhook) {
            return reply.status(400).send({ error: "success_webhook is not a valid webhook" });
        }

        if (!BlacklistWebhook) {
            return reply.status(400).send({ error: "blacklist_webhook is not a valid webhook" });
        }

        if (!UnauthorizedWebhook) {
            return reply.status(400).send({ error: "unauthorized_webhook is not a valid webhook" });
        }

        SuccessWebhook = "https://" + SuccessWebhook.shift();
        BlacklistWebhook = "https://" + BlacklistWebhook.shift();
        UnauthorizedWebhook = "https://" + UnauthorizedWebhook.shift();
        
        try {
            await webhooks.SetupWebhook(SuccessWebhook, Name || Project.Name, "success");
            await webhooks.SetupWebhook(BlacklistWebhook, Name || Project.Name, "blacklist");
            await webhooks.SetupWebhook(UnauthorizedWebhook, Name || Project.Name, "unauthorized");
        } catch (er) {
            return reply.status(500).send({ error: er.toString() });
        }

        try {
            const Info = await Database.UpdateProject(ProjectID, Name, SuccessWebhook, BlacklistWebhook, UnauthorizedWebhook, Exploits, Online);
            AddToAuditLog(request.BuyerUsername, request.ip, `Updated project ${Info.Name}`);
            reply.send(Info);
        } catch (er) {
            return reply.status(500).send({ error: "There was an issue while updating this project" });
        }
    });
    
    // Get Projects
    fastify.get("/projects", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const Projects = await Database.GetProjects(request.APIKey);

        for (const Project of Projects) {
            const Scripts = await Database.GetScripts(Project.id);
            Project.Scripts = Scripts;
        }

        reply.send(Projects);
    });

    // Get Project Users
    fastify.get("/projects/:id/users", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;
        const Project = await Database.GetProject(ProjectID);

        if (!Project) {
            return reply.status(404).send({ error: "This project doesn't exist" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Users = await Database.GetUsers(ProjectID);
        reply.send(Users);
    });

    // Get Project By Id
    fastify.get("/projects/:id", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;
        const Project = await Database.GetProject(ProjectID);

        if (!Project) {
            return reply.status(404).send({ error: "This project doesn't exist" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Scripts = await Database.GetScripts(Project.id);
        Project.Scripts = Scripts;
        reply.send(Project);
    });

    // Delete Project
    fastify.delete("/projects/:id", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ProjectID = request.params.id;

        const Project = await Database.GetProject(ProjectID);
        if (!Project) {
            return reply.status(404).send({ error: "This project doesn't exist" });
        }

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "This project isn't owned by you" });
        }

        try {
            if (existsSync(path.join(__dirname, `../../files/projects/${ProjectID}/`))) {
                rmSync(path.join(__dirname, `../../files/projects/${ProjectID}/`), { force: true, recursive: true });
            }

            await Database.SubscriptionIncrementProjectCount(request.Subscription.SubscriptionID, -1);
            await Database.DeleteProject(ProjectID, request.APIKey);
            AddToAuditLog(request.BuyerUsername, request.ip, `Deleted project ${Project.Name}`);
            reply.send({ success: true });
        } catch (er) {
            console.log(er);
            return reply.status(500).send({ error: "There was an issue while trying to delete this project" })
        }
    });

    // Delete Script
    fastify.delete("/projects/:id/scripts", { schema: { headers: HeadersSchema, body: DeleteScript, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const ScriptID = request.body.script_id;
        const ProjectID = request.params.id;

        if (!await Database.ProjectOwnedByBuyer(request.APIKey, ProjectID)) {
            return reply.status(403).send({ error: "You don't own this project" });
        }

        const Script = await Database.GetScript(ProjectID, ScriptID);
        if (!Script) {
            return reply.status(404).send({ error: "This script doesn't exist" });
        }

        try {

            await Database.DeleteScript(ScriptID, request.Subscription.SubscriptionID);

            if (existsSync(path.join(__dirname, `../../files/projects/${ProjectID}/${ScriptID}`))) {
                rmSync(path.join(__dirname, `../../files/projects/${ProjectID}/${ScriptID}`), { force: true, recursive: true });
            }
            
            AddToAuditLog(request.BuyerUsername, request.ip, `Deleted script ${Script.Name}`);
            reply.send({ success: true });
        } catch (er) {
            console.log(er);
            return reply.status(500).send({ error: "There was an issue trying to delete this script" });
        }
    });

    // Create Webhook
    fastify.post("/webhooks", { schema: { headers: HeadersSchema, body: MakeWebhook, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const WebhookName = request.body.name;
        let Url = request.body.url;

        if (WebhookName.match(/[^A-Za-z0-9 ]/)) {
            return reply.status(400).send({ error: "Your webhook name cannot include special characters" });
        }

        Url = Url.match(/discord\.com\/api\/webhooks\/\d+\/[\S]+$/);
        if (!Url) {
            return reply.status(400).send({ error: "url is not a valid webhook" });
        }

        Url = "https://" + Url.shift();
        
        try {
            await CheckWebhook(Url);
        } catch (er) {
            return reply.status(400).send({ error: er.toString() });
        }

        const Token = crypto.randomUUID();
        try {
            await Database.CreateWebhook(Url, Token, WebhookName, request.APIKey);
            await Database.UpdateBuyerWebhooks(Token, request.APIKey);

            reply.send({ url: `${LoaderBaseURL}/webhooks/${Token}`, token: Token });
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "Failed to create webhook" });
        }
    });

    fastify.delete("/webhooks/:id", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const Token = request.params.id;
        const Webhook = await Database.GetWebhook(Token);

        if (!Webhook) {
            return reply.status(400).send({ error: "This webhook doesn't exist" });
        }

        if (Webhook.Owner !== request.APIKey) {
            return reply.status(404).send({ error: "You don't own this webhook" });
        }

        try {
            await Database.DeleteWebhook(Token, request.APIKey);
            reply.send({ success: true });
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "Failed to delete webhook" })
        }
    });

    // Get Webhooks
    fastify.get("/webhooks", { schema: { headers: HeadersSchema, response: ResponseScema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        const Webhooks = await Database.GetWebhooks(request.APIKey);
        reply.send(Webhooks);
    });

    const WebhookSchema = {
        type: "object",
        properties: {
            ["LuaShield-Access-Token"]: { type: "string" }
        },
        required: ["LuaShield-Access-Token"]
    }

    // Webhook Request
    fastify.post("/webhooks/:token", { schema: { headers: WebhookSchema, response: ResponseScema }, config: { rateLimit: { max: 10, timeWindow: "1 minute", keyGenerator: SessionTokenKey } }, websocket: false }, async (request, reply) => {
        const Token = request.params.token;
        const AccessToken = request.headers["luashield-access-token"];

        const Webhook = await Database.GetWebhook(Token);
        if (!Webhook) {
            return reply.status(400).send({ error: "This webhook doesn't exist" });
        }

        const Session = await Sessions.getSession(AccessToken);
        const Project = Session && await Database.GetProject(Session.ProjectID);
        const Whitelist = Session && await Database.GetWhitelistByID(Session.WhitelistID);
        if (!Session || !Project || !Project.Online || !Project.Potassium || Webhook.Owner !== Project.Owner ||
            evaluate(Whitelist, { ProjectID: Session.ProjectID, HWID: Session.HWID })) {
            return reply.status(403).send({ error: "Invalid access token" });
        }

        if (!request.body) {
            return reply.status(400).send({ error: "Must have body" });
        }

        try {
            await UserWebhook(Webhook.Url, request.body);
        } catch (er) {
            console.log(er);
        }
        
        reply.send({ success: true });
    });


    // admin shit

    const CreateSubscription = {
        type: "object",
        additionalProperties: false,
        properties: {
            months: { type: "integer", minimum: 1, maximum: 1200 },
            auth: { type: "string" }
        },
        required: ["months"]
    }

    const SetAdmin = {
        type: "object",
        additionalProperties: false,
        properties: {
            username: { type: "string" },
            auth: { type: "string" },
            email: { type: "string" },
            password: { type: "string" }
        },
        required: ["username", "auth", "email", "password"]
    }

    const DeleteBuyer = {
        type: "object",
        additionalProperties: false,
        properties: {
            email: { type: "string" }
        },
        required: ["email"]
    }

    fastify.get("/admin/stats", { schema: { headers: HeadersSchema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (!request.Admin) {
            return reply.status(401).send({ error: "Your account needs admin privileges" });
        }

        const Info = await Database.GetAdminStats();
        reply.send(Info);
    })

    fastify.get("/admin/subscriptions", { schema: { headers: HeadersSchema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (!request.Admin) {
            return reply.status(401).send({ error: "Your account needs admin privileges" });
        }

        const Info = await Database.GetSubscriptions();
        reply.send(Info);
    });

    fastify.get("/admin/buyers", { schema: { headers: HeadersSchema }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (!request.Admin) {
            return reply.status(401).send({ error: "Your account needs admin privileges" });
        }

        const Buyers = await Database.GetBuyers();
        reply.send(Buyers.map(PublicBuyer));
    });

    fastify.delete("/admin/buyers", { schema: { headers: HeadersSchema, body: DeleteBuyer }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (!request.Admin) {
            return reply.status(401).send({ error: "Your account needs admin privileges" });
        }

        const Email = request.body.email;
        const Buyer = await Database.GetBuyerFromEmail(Email);

        if (!Buyer) {
            return reply.status(400).send({ error: "This buyer doesn't exist" });
        }

        /*
        if (Buyer.Admin) {
            return reply.status(400).send({ error: "You cannot delete an admin account" });
        }
        */

        try {
            AuditLog.remove(Buyer.Username);

            for (const project of Buyer.Projects) {
                if (existsSync(path.join(__dirname, `../../files/projects/${project}`))) {
                    rmSync(path.join(__dirname, `../../files/projects/${project}`), { force: true, recursive: true });
                }
                await Database.DeleteProject(project, Buyer.APIKey);
            }

            await Database.DeleteAccount(Email);
            reply.send({ success: true });
        } catch (er) {
            reply.status(500).send({ error: "There was an issue while trying to delete this buyer" });
        }
    });

    // Create Subscription
    fastify.post("/admin/subscriptions", { schema: { headers: HeadersSchema, body: CreateSubscription }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (!request.Admin) {
            return reply.status(401).send({ error: "Your account needs admin privileges" });
        }

        const Months = request.body.months;

        const Expire = new Date();
        Expire.setMonth(Expire.getMonth() + Months);

        const Reset = new Date();
        Reset.setMonth(Reset.getMonth() + 1);

        try {
            const Info = await Database.CreateSubscription(SecondsFrom(Expire), SecondsFrom(Reset));
            reply.send(Info);
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "There was an issue while creating this subscription" });
        }
    });

    // Update Subscriotion
    fastify.patch("/admin/subscriptions/:id", { schema: { headers: HeadersSchema, body: CreateSubscription }, websocket: false, preHandler: AuthenticationHandler }, async (request, reply) => {
        if (!request.Admin) {
            return reply.status(401).send({ error: "Your account needs admin privileges" });
        }

        const SubscriptionID = request.params.id;
        const Months = request.body.months;

        const Subscription = await Database.GetSubscription(SubscriptionID);
        if (!Subscription) {
            return reply.status(401).send({ error: "This subscription doesn't exist" })
        }

        const Expire = new Date();
        Expire.setMonth(Expire.getMonth() + Months);

        const Reset = new Date();
        Reset.setMonth(Reset.getMonth() + 1);

        try {
            const Info = await Database.UpdateSubscription(Subscription.SubscriptionID, SecondsFrom(Expire), SecondsFrom(Reset));
            reply.send(Info);
        } catch (er) {
            console.log(er);
            reply.status(500).send({ error: "There was an issue while updating this subscription" });
        }
    });

    // internal endpoint

    fastify.post("/create_admin", { schema: { body: SetAdmin }, websocket: false }, async (request, reply) => {
        const Username = request.body.username;
        const Email = request.body.email;
        const Password = request.body.password;
        const Auth = request.body.auth;

        if (Auth !== process.env.ADMIN_KEY) {
            return reply.status(401).send({ error: "Unauthorized" });
        }

        if (await Database.GetBuyerFromEmail(Email)) {
            return reply.status(400).send({ error: "This email is already registered to another user" });
        }

        if (await Database.GetBuyerFromUsername(Username)) {
            return reply.status(400).send({ error: "This username is already associated with another account" })
        }

        const Expire = new Date();
        Expire.setMonth(Expire.getMonth() + 200);

        const Reset = new Date();
        Reset.setMonth(Reset.getMonth() + 1);

        const APIKey = crypto.randomSecret();
        try {
            const Info = await Database.CreateSubscription(SecondsFrom(Expire), SecondsFrom(Reset));
            const Buyer = await Database.CreateAdminBuyer(Email, Username, await Passwords.hash(Password), crypto.randomUUID(), Info.SubscriptionID, crypto.sha256(APIKey));
            reply.send({ ...PublicBuyer(Buyer), APIKey });
        } catch (er) {
            console.log(er);
            return reply.status(500).send({ error: "There was a problem while updating this user" })
        }
    });
}

module.exports = routes;
module.exports.IncrementScriptVersion = IncrementScriptVersion;