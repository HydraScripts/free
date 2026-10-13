// Boots the real app (every route and schema) without a database connection.
require("./helpers");
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");

let App;
before(async () => {
    App = await require("../server/index").build({ logger: false });
    await App.ready();
});
after(() => App.close());

test("all routes compile and public endpoints answer", async () => {
    const Stats = await App.inject({ method: "GET", url: "/stats" });
    assert.equal(Stats.statusCode, 200);
    assert.equal(Stats.json().online, true);
    assert.equal((await App.inject({ method: "POST", url: "/auth/payload", payload: {} })).statusCode, 401);
    assert.equal((await App.inject({ method: "GET", url: "/s/bad..id/x" })).statusCode, 400);
});

test("API routes require the API key header", async () => {
    for (const [method, url] of [["GET", "/account"], ["POST", "/projects/x/users/reset_key"], ["POST", "/projects/x/users/reset_hwid"]]) {
        const Response = await App.inject({ method, url, payload: { username: "someone" } });
        assert.equal(Response.statusCode, 400, `${method} ${url}`);
        assert.match(Response.json().error, /luashield-api-key/);
    }
});

test("request bodies reject unknown properties", async () => {
    const Response = await App.inject({
        method: "POST", url: "/signup",
        payload: { email: "a@b.co", password: "LongEnoughPass1", username: "abcd", subscription_id: "x", evil: 1 }
    });
    assert.equal(Response.statusCode, 400);
});

test("the authorize body rejects unknown properties before touching state", async () => {
    const Response = await App.inject({
        method: "POST", url: "/auth/authorize",
        payload: { challenge: "a".repeat(64), key: "k", extra: true }
    });
    assert.equal(Response.statusCode, 400);
});

test("a password shorter than 12 characters is rejected at signup", async () => {
    const Response = await App.inject({
        method: "POST", url: "/signup",
        payload: { email: "a@b.co", password: "Short1", username: "abcd", subscription_id: "x" }
    });
    assert.equal(Response.statusCode, 400);
});
