// Two server instances sharing Redis. Skipped unless REDIS_URL is set (npm run test:redis).
const { buildApp, makeDatabase, writePayload } = require("./helpers");
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const Crypto = require("../server/modules/crypto");

const Skip = !process.env.REDIS_URL && "set REDIS_URL to run multi-instance tests";
let A, B, Database;

before(async () => {
    if (Skip) return;
    Database = makeDatabase();
    A = await buildApp(Database);
    B = await buildApp(Database);
});
after(async () => {
    if (Skip) return;
    await A.App.close();
    await B.App.close();
});

let Counter = 0;
function addUser() {
    const Id = `multi${++Counter}`;
    Database.Users.set(Id, {
        id: Id, Key: Crypto.sha512(`key-${Id}`), Username: Id, ProjectID: "project1", Whitelisted: true,
        HWID: null, Executions: 0, MaxExecutions: 0, ExpireAt: null, CrackAttempts: 0
    });
    return { Key: `key-${Id}`, IP: `198.51.100.${Counter}` };
}

async function challenge(App, IP) {
    const Response = await App.inject({
        method: "POST", url: "/auth/challenge", remoteAddress: IP,
        headers: { "x-luashield-executor": "potassium" },
        payload: { project_id: "project1", script_id: "script1", hwid: "device1", user_id: "1" }
    });
    return Response.json().challenge;
}
const authorize = (App, IP, Challenge, Key) =>
    App.inject({ method: "POST", url: "/auth/authorize", remoteAddress: IP, payload: { challenge: Challenge, key: Key } });
const bearer = (App, Url, Token, IP) =>
    App.inject({ method: "POST", url: Url, remoteAddress: IP, payload: {}, headers: { authorization: `Bearer ${Token}` } });

test("the instances really are separate processes' worth of state", { skip: Skip }, () => {
    assert.notEqual(A.Store, B.Store);
    assert.notEqual(A.Store.redis, B.Store.redis);
});

test("a challenge issued by one instance is accepted by the other, once", { skip: Skip }, async () => {
    const User = addUser();
    const Challenge = await challenge(A.App, User.IP);
    assert.equal((await authorize(B.App, User.IP, Challenge, User.Key)).statusCode, 200);
    assert.equal((await authorize(A.App, User.IP, Challenge, User.Key)).statusCode, 403);
});

test("concurrent use of one challenge on two instances succeeds exactly once", { skip: Skip }, async () => {
    const User = addUser();
    const Challenge = await challenge(A.App, User.IP);
    const Results = await Promise.all([
        authorize(A.App, User.IP, Challenge, User.Key),
        authorize(B.App, User.IP, Challenge, User.Key)
    ]);
    assert.deepEqual(Results.map(R => R.statusCode).sort(), [200, 403]);
});

test("a session from one instance heartbeats on the other and survives its restart", { skip: Skip }, async () => {
    const User = addUser();
    const Token = (await authorize(A.App, User.IP, await challenge(A.App, User.IP), User.Key)).json().token;
    assert.equal((await bearer(B.App, "/auth/heartbeat", Token, User.IP)).statusCode, 200);
    const Restarted = await buildApp(Database);
    try {
        assert.equal((await bearer(Restarted.App, "/auth/heartbeat", Token, User.IP)).statusCode, 200);
    } finally {
        await Restarted.App.close();
    }
});

test("the payload is released once across all instances", { skip: Skip }, async () => {
    const Cleanup = writePayload("return 1");
    try {
        const User = addUser();
        const Token = (await authorize(A.App, User.IP, await challenge(A.App, User.IP), User.Key)).json().token;
        assert.equal((await bearer(A.App, "/auth/payload", Token, User.IP)).statusCode, 200);
        assert.equal((await bearer(B.App, "/auth/payload", Token, User.IP)).statusCode, 409);
    } finally {
        Cleanup();
    }
});

test("failed attempts are counted across instances", { skip: Skip }, async () => {
    const User = addUser();
    for (let i = 0; i < 12; i++) {
        const App = i % 2 ? A.App : B.App;
        assert.equal((await authorize(App, User.IP, await challenge(App, User.IP), "wrong")).statusCode, 403);
    }
    assert.equal((await authorize(A.App, User.IP, await challenge(A.App, User.IP), User.Key)).statusCode, 429);
});
