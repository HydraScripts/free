const Avatar = "https://i.imgur.com/6xyJbAg.png";
const WebhookPattern = /^https:\/\/(?:(?:ptb|canary)\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d+\/[\w-]+$/;

function IsDiscordWebhook(Url) {
    return typeof Url === "string" && WebhookPattern.test(Url);
}

// Strips characters that would break out of the inline code blocks used in embeds.
function Clean(Value, Max = 200) {
    return String(Value ?? "").replace(/[`\u0000-\u001f]/g, "").slice(0, Max);
}

const MaxAttempts = Number(process.env.WEBHOOK_MAX_ATTEMPTS) || 4;
const sleep = Ms => new Promise(Resolve => setTimeout(Resolve, Ms));

// Discord rate-limits (429) and has transient 5xx. Retry those, honouring Retry-After,
// with exponential backoff; 4xx other than 429 is a permanent failure and is not retried.
async function Post(Url, Body) {
    if (!IsDiscordWebhook(Url)) throw new Error("Not a Discord webhook URL");
    const Payload = JSON.stringify({ ...Body, allowed_mentions: { parse: [] } });
    let LastStatus = 0;
    for (let Attempt = 1; Attempt <= MaxAttempts; Attempt++) {
        let Response;
        try {
            Response = await fetch(Url, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: Payload,
                redirect: "error",
                signal: AbortSignal.timeout(5000)
            });
        } catch (er) {
            // Network error / timeout: retry unless this was the last attempt.
            if (Attempt === MaxAttempts) throw er;
            await sleep(Math.min(250 * 2 ** (Attempt - 1), 4000));
            continue;
        }
        if (Response.ok || Response.status === 204) return;
        LastStatus = Response.status;
        const Retryable = Response.status === 429 || Response.status >= 500;
        if (!Retryable || Attempt === MaxAttempts) {
            throw new Error(`Webhook responded with ${Response.status}`);
        }
        const RetryAfter = Number(Response.headers.get("retry-after"));
        const Backoff = Number.isFinite(RetryAfter) && RetryAfter > 0
            ? Math.min(RetryAfter * 1000, 10000)
            : Math.min(250 * 2 ** (Attempt - 1), 4000);
        await sleep(Backoff);
    }
    throw new Error(`Webhook failed after ${MaxAttempts} attempts (last status ${LastStatus})`);
}

// Alerts must never break authentication, so failures are logged and swallowed.
async function Safe(Url, Body) {
    try {
        await Post(Url, Body);
    } catch (er) {
        console.error("Webhook delivery failed:", er.message);
    }
}

function Embed(Description, Fields, Footer) {
    return {
        username: "LuaShield",
        avatar_url: Avatar,
        content: null,
        embeds: [{
            description: Description,
            color: 3886815,
            fields: Fields,
            author: { name: "LuaShield" },
            thumbnail: { url: Avatar },
            ...(Footer ? { footer: { text: Footer } } : {})
        }]
    };
}

function Success(Url, Data) {
    return Safe(Url, Embed("User successfully authenticated", [
        { name: "User IP", value: `\`${Clean(Data.IP)}\``, inline: true },
        { name: "User-Agent", value: `\`${Clean(Data.UserAgent)}\``, inline: true },
        { name: "Authentication Speed", value: `\`${Clean(Data.Duration)}s\`` },
        { name: "Whitelist Data", value: `\`\`\`json\n${Clean(JSON.stringify(Data.Whitelist), 500)}\n\`\`\`` }
    ], `User was running -> ${Clean(Data.Project, 80)}/${Clean(Data.Script, 80)}`));
}

function Blacklist(Url, Data) {
    return Safe(Url, Embed("This user has been flagged for a possible blacklist", [
        { name: "User IP", value: `\`${Clean(Data.IP)}\`` },
        { name: "Reason", value: `\`${Clean(Data.Reason)}\`` },
        { name: "Whitelist Data", value: `\`\`\`json\n${Clean(JSON.stringify(Data.Whitelist), 500)}\n\`\`\`` }
    ], "This could be a mistake, such as a shared account. Use the information supplied to decide fairly."));
}

function Unauthorized(Url, Data) {
    return Safe(Url, Embed("This user has tried to run your script while unauthorized", [
        { name: "User IP", value: `\`${Clean(Data.IP)}\`` },
        { name: "Reason", value: `\`\`\`${Clean(Data.Reason)}\`\`\`` }
    ]));
}

async function SetupWebhook(Url, Name, Type) {
    await CheckWebhook(Url);
    await Post(Url, {
        username: "LuaShield",
        avatar_url: Avatar,
        content: `This channel is now being used for LuaShield **${Clean(Type, 20)}** alerts, project: \`${Clean(Name, 40)}\``
    });
}

async function CheckWebhook(Url) {
    if (!IsDiscordWebhook(Url)) throw new Error(`${Url} is not a Discord webhook`);
    const Response = await fetch(Url, { method: "GET", redirect: "error", signal: AbortSignal.timeout(5000) });
    if (Response.status !== 200) throw new Error(`${Url} doesn't exist`);
}

// Body comes from the script's end user: allow only a bounded, mention-free message.
async function UserWebhook(Url, Body) {
    if (!Body || typeof Body !== "object" || Array.isArray(Body)) throw new Error("Invalid webhook body");
    const Allowed = {};
    for (const Key of ["content", "username", "avatar_url", "embeds", "tts"]) {
        if (Body[Key] !== undefined) Allowed[Key] = Body[Key];
    }
    if (Array.isArray(Allowed.embeds)) Allowed.embeds = Allowed.embeds.slice(0, 10);
    await Post(Url, Allowed);
}

module.exports = { Success, Blacklist, Unauthorized, SetupWebhook, CheckWebhook, UserWebhook, IsDiscordWebhook };
