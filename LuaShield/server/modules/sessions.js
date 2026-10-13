const { createHash, randomBytes } = require("node:crypto");
const Store = require("./store");

const ChallengeTTL = 30_000;
const SessionTTL = 45_000;
const TokenPattern = /^[a-f0-9]{64}$/;

function token() {
    return randomBytes(32).toString("hex");
}

// Only digests are used as keys, so a store dump doesn't contain usable tokens.
function digest(Value) {
    return createHash("sha256").update(Value).digest("hex");
}

async function createChallenge(Data) {
    const Value = token();
    const Stored = await Store.put(`challenge:${digest(Value)}`, { ...Data, CreatedAt: Date.now() }, ChallengeTTL);
    return Stored ? Value : null;
}

// Atomic get-and-delete: of two concurrent uses (even on different instances) only one succeeds.
async function consumeChallenge(Value) {
    if (typeof Value !== "string" || !TokenPattern.test(Value)) return null;
    return Store.take(`challenge:${digest(Value)}`);
}

async function createSession(Data) {
    const Value = token();
    const Key = digest(Value);
    if (!await Store.put(`session:${Key}`, Data, SessionTTL)) return null;
    await Store.track("sessions", Key, SessionTTL);
    return Value;
}

async function getSession(Value) {
    if (typeof Value !== "string" || !TokenPattern.test(Value)) return null;
    return Store.get(`session:${digest(Value)}`);
}

async function renewSession(Value) {
    if (typeof Value !== "string" || !TokenPattern.test(Value)) return false;
    const Key = digest(Value);
    const Renewed = await Store.touch(`session:${Key}`, SessionTTL);
    if (Renewed) await Store.track("sessions", Key, SessionTTL);
    return Renewed;
}

async function revokeSession(Value) {
    if (typeof Value !== "string") return;
    const Key = digest(Value);
    await Store.del(`session:${Key}`);
    await Store.untrack("sessions", Key);
}

// One-time payload release per session. Returns a function that undoes the claim on failure.
async function claimPayload(Value) {
    const Key = `payload:${digest(Value)}`;
    if (!await Store.claim(Key, SessionTTL)) return null;
    return () => Store.del(Key);
}

module.exports = {
    createChallenge, consumeChallenge, createSession, getSession,
    renewSession, revokeSession, claimPayload,
    sessionCount: () => Store.active("sessions")
};
