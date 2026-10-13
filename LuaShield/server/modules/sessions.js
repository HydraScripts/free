const { createHash, randomBytes } = require("node:crypto");

const Challenges = new Map();
const Sessions = new Map();
const ChallengeTTL = 30_000;
const SessionTTL = 45_000;
const MaxChallenges = 5000;
const MaxSessions = 10000;

function token() {
    return randomBytes(32).toString("hex");
}

function digest(Value) {
    return createHash("sha256").update(Value).digest("hex");
}

function prune() {
    const Now = Date.now();
    for (const [Key, Data] of Challenges) {
        if (Data.Expires <= Now) Challenges.delete(Key);
    }
    for (const [Key, Data] of Sessions) {
        if (Data.Expires <= Now) Sessions.delete(Key);
    }
}

function createChallenge(Data) {
    prune();
    if (Challenges.size >= MaxChallenges) return null;
    const Value = token();
    Challenges.set(digest(Value), { ...Data, CreatedAt: Date.now(), Expires: Date.now() + ChallengeTTL });
    return Value;
}

function consumeChallenge(Value) {
    if (typeof Value !== "string" || !/^[a-f0-9]{64}$/.test(Value)) return null;
    const Key = digest(Value);
    const Data = Challenges.get(Key);
    Challenges.delete(Key);
    return Data && Data.Expires > Date.now() ? Data : null;
}

function createSession(Data) {
    prune();
    if (Sessions.size >= MaxSessions) return null;
    const Value = token();
    Sessions.set(digest(Value), { ...Data, Expires: Date.now() + SessionTTL });
    return Value;
}

function getSession(Value) {
    if (typeof Value !== "string" || !/^[a-f0-9]{64}$/.test(Value)) return null;
    const Key = digest(Value);
    const Data = Sessions.get(Key);
    if (!Data) return null;
    if (Data.Expires <= Date.now()) {
        Sessions.delete(Key);
        return null;
    }
    return Data;
}

function renewSession(Value) {
    const Data = getSession(Value);
    if (Data) Data.Expires = Date.now() + SessionTTL;
    return Boolean(Data);
}

function revokeSession(Value) {
    if (typeof Value === "string") Sessions.delete(digest(Value));
}

const Cleanup = setInterval(prune, 10_000);
Cleanup.unref();

module.exports = {
    createChallenge, consumeChallenge, createSession, getSession,
    renewSession, revokeSession, sessionCount: () => Sessions.size
};
