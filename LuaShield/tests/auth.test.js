const { buildApp, writePayload } = require("./helpers");
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const Crypto = require("../server/modules/crypto");

let App, Database, WebhookCalls, Sessions;
let Counter = 0;

before(async () => {
    ({ App, Database, WebhookCalls } = await buildApp());
    Sessions = require("../server/modules/sessions"); // the instance the app above loaded
});
after(() => App.close());

// Every test gets its own license and client IP so rate-limit buckets don't leak between tests.
function addUser(Overrides = {}) {
    const Id = `user${++Counter}`;
    const Key = `key-${Id}`;
    Database.Users.set(Id, {
        id: Id, Key: Crypto.sha512(Key), Username: Id, ProjectID: "project1", Whitelisted: true,
        HWID: null, Executions: 0, MaxExecutions: 0, ExpireAt: null, CrackAttempts: 0, ...Overrides
    });
    return { Id, Key, IP: `10.0.${Counter}.1` };
}

async function challenge(IP, HWID = "device1") {
    const Response = await App.inject({
        method: "POST", url: "/auth/challenge", remoteAddress: IP,
        headers: { "x-luashield-executor": "potassium" },
        payload: { project_id: "project1", script_id: "script1", hwid: HWID, user_id: "123" }
    });
    assert.equal(Response.statusCode, 200);
    return Response.json().challenge;
}

function authorize(IP, Challenge, Key) {
    return App.inject({ method: "POST", url: "/auth/authorize", remoteAddress: IP, payload: { challenge: Challenge, key: Key } });
}

async function login(User, HWID) {
    const Response = await authorize(User.IP, await challenge(User.IP, HWID), User.Key);
    return Response;
}

const bearer = (Url, Token, IP) => App.inject({
    method: "POST", url: Url, remoteAddress: IP, payload: {},
    headers: Token ? { authorization: `Bearer ${Token}` } : {}
});

test("a single-use challenge cannot be replayed", async () => {
    const User = addUser();
    const Challenge = await challenge(User.IP);
    assert.equal((await authorize(User.IP, Challenge, User.Key)).statusCode, 200);
    assert.equal((await authorize(User.IP, Challenge, User.Key)).statusCode, 403);
});

test("a bad key consumes its challenge", async () => {
    const User = addUser();
    const Challenge = await challenge(User.IP);
    assert.equal((await authorize(User.IP, Challenge, "wrong")).statusCode, 403);
    assert.equal((await authorize(User.IP, Challenge, User.Key)).statusCode, 403);
});

test("sessions are independent of a shared IP", async () => {
    const First = await Sessions.createSession({ ProjectID: "p1", HWID: "hw1" });
    const Second = await Sessions.createSession({ ProjectID: "p2", HWID: "hw2" });
    assert.notEqual(First, Second);
    await Sessions.revokeSession(First);
    assert.equal(await Sessions.getSession(First), null);
    assert.equal((await Sessions.getSession(Second)).HWID, "hw2");
});

test("many clients behind one IP can all keep heartbeating", async () => {
    const SharedIP = "203.0.113.7";
    const Tokens = [];
    for (let i = 0; i < 8; i++) {
        const User = addUser();
        User.IP = SharedIP;
        const Response = await login(User, `device-${i}`);
        assert.equal(Response.statusCode, 200);
        Tokens.push(Response.json().token);
    }
    // 8 clients x 4 heartbeats (one minute at the 15s interval) from a single IP.
    for (let Beat = 0; Beat < 4; Beat++) {
        for (const Token of Tokens) {
            assert.equal((await bearer("/auth/heartbeat", Token, SharedIP)).statusCode, 200);
        }
    }
});

test("successful logins do not count toward the failure limit", async () => {
    const User = addUser();
    for (let i = 0; i < 15; i++) {
        assert.equal((await login(User)).statusCode, 200);
    }
});

test("repeated failures from one IP are blocked", async () => {
    const User = addUser();
    for (let i = 0; i < 12; i++) {
        assert.equal((await authorize(User.IP, await challenge(User.IP), "wrong")).statusCode, 403);
    }
    assert.equal((await authorize(User.IP, await challenge(User.IP), User.Key)).statusCode, 429);
});

test("heartbeat rejects and revokes a disabled whitelist", async () => {
    const User = addUser();
    const Token = (await login(User)).json().token;
    assert.equal((await bearer("/auth/heartbeat", Token, User.IP)).statusCode, 200);
    Database.Users.get(User.Id).Whitelisted = false;
    assert.equal((await bearer("/auth/heartbeat", Token, User.IP)).statusCode, 403);
    assert.equal(await Sessions.getSession(Token), null);
});

test("expired licenses are rejected in seconds and legacy milliseconds", async () => {
    const Past = Math.floor(Date.now() / 1000) - 10;
    assert.equal((await login(addUser({ ExpireAt: Past }))).statusCode, 403);
    assert.equal((await login(addUser({ ExpireAt: Past * 1000 }))).statusCode, 403);
    assert.equal((await login(addUser({ ExpireAt: Past + 3600 }))).statusCode, 200);
});

test("execution quota rejects additional authentications", async () => {
    const User = addUser({ MaxExecutions: 2 });
    assert.equal((await login(User)).statusCode, 200);
    assert.equal((await login(User)).statusCode, 200);
    assert.equal((await login(User)).statusCode, 403);
});

test("a different HWID counts a crack attempt and alerts the blacklist webhook", async () => {
    const User = addUser({ HWID: "original-device" });
    const Before = Database.Calls.cracks;
    assert.equal((await login(User, "other-device")).statusCode, 403);
    assert.equal(Database.Calls.cracks, Before + 1);
    assert.ok(WebhookCalls.some(Call => Call.Type === "Blacklist"));
});

test("the payload is released once, only to an authorized session", async () => {
    const Cleanup = writePayload("return 'protected body with $& and $\\' intact'");
    try {
        const User = addUser();
        assert.equal((await bearer("/auth/payload", null, User.IP)).statusCode, 401);
        const Token = (await login(User)).json().token;
        const First = await bearer("/auth/payload", Token, User.IP);
        assert.equal(First.statusCode, 200);
        assert.equal(First.body, "return 'protected body with $& and $\\' intact'");
        assert.equal((await bearer("/auth/payload", Token, User.IP)).statusCode, 409);
    } finally {
        Cleanup();
    }
});
