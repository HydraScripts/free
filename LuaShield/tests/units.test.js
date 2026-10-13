require("./helpers");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { evaluate } = require("../server/modules/license");
const { toSeconds } = require("../server/modules/time");
const { IsDiscordWebhook, UserWebhook } = require("../server/modules/webhooks");
const { failureLimiter } = require("../server/modules/throttle");

test("timestamps normalise to seconds", () => {
    assert.equal(toSeconds(1_800_000_000), 1_800_000_000);
    assert.equal(toSeconds(1_800_000_000_123), 1_800_000_000);
    assert.equal(toSeconds(null), null);
    assert.equal(toSeconds(0), null);
});

test("license evaluation reports the failing rule", () => {
    const User = { Whitelisted: true, ProjectID: "p", HWID: "h", ExpireAt: null, MaxExecutions: 1, Executions: 1 };
    assert.equal(evaluate(User, { ProjectID: "p", HWID: "h" }), null);
    assert.equal(evaluate(User, { ProjectID: "p", HWID: "h", CheckQuota: true }), "quota");
    assert.equal(evaluate(User, { ProjectID: "x", HWID: "h" }), "project");
    assert.equal(evaluate(User, { ProjectID: "p", HWID: "other" }), "hwid");
    assert.equal(evaluate({ ...User, Whitelisted: false }, { ProjectID: "p", HWID: "h" }), "disabled");
    assert.equal(evaluate(null, { ProjectID: "p", HWID: "h" }), "disabled");
});

test("only Discord webhook URLs are accepted", async () => {
    assert.ok(IsDiscordWebhook("https://discord.com/api/webhooks/123/abc-DEF_1"));
    assert.ok(IsDiscordWebhook("https://canary.discord.com/api/webhooks/123/abc"));
    assert.ok(!IsDiscordWebhook("http://discord.com/api/webhooks/123/abc"));
    assert.ok(!IsDiscordWebhook("https://discord.com.evil.example/api/webhooks/123/abc"));
    assert.ok(!IsDiscordWebhook("https://169.254.169.254/api/webhooks/1/a"));
    await assert.rejects(UserWebhook("https://evil.example/x", { content: "hi" }));
});

test("failure limiter only blocks after the configured failures", async () => {
    const Limiter = failureLimiter({ Name: `unit-${Date.now()}`, Max: 2, WindowMs: 60_000 });
    assert.equal(await Limiter.blocked("k"), false);
    await Limiter.record("k");
    assert.equal(await Limiter.blocked("k"), false);
    await Limiter.record("k");
    assert.equal(await Limiter.blocked("k"), true);
    assert.equal(await Limiter.blocked("other"), false);
});

test.after(() => require("../server/modules/store").close());

test("audit log appends lines, merges the legacy JSON file and rejects unsafe names", () => {
    const AuditLog = require("../server/modules/auditlog");
    const { writeFileSync, mkdirSync } = require("node:fs");
    const path = require("node:path");
    const Name = `UnitTest${Date.now()}`;
    mkdirSync(path.join(__dirname, "../files/logs"), { recursive: true });
    writeFileSync(path.join(__dirname, `../files/logs/${Name}.json`), JSON.stringify([{ message: "legacy" }]));
    try {
        AuditLog.add(Name, "1.1.1.1", "first");
        AuditLog.add(Name, "1.1.1.1", "second");
        assert.deepEqual(AuditLog.read(Name).map(Entry => Entry.message), ["legacy", "first", "second"]);
        AuditLog.add("../../etc/x", "1.1.1.1", "nope");
        assert.deepEqual(AuditLog.read("../../etc/x"), []);
    } finally {
        AuditLog.remove(Name);
    }
    assert.deepEqual(AuditLog.read(Name), []);
});
