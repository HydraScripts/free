require("./helpers");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");
const Crypto = require("../server/modules/crypto");

const Original = Module._load;
Module._load = function (Name) {
    if (Name === "argon2") return {
        argon2id: 2,
        hash: async Value => `$argon2id$mock$${Value}`,
        verify: async (Hash, Value) => Hash === `$argon2id$mock$${Value}`
    };
    return Original.apply(this, arguments);
};
const Passwords = require("../server/modules/password");
Module._load = Original;

test("new password hash uses Argon2id verification", async () => {
    const Hash = await Passwords.hash("TestSecret123");
    assert.equal((await Passwords.verify(Hash, "TestSecret123")).valid, true);
    assert.equal((await Passwords.verify(Hash, "Wrong")).valid, false);
});

test("legacy HMAC passwords can migrate and wrong values are rejected", async () => {
    const Hash = Crypto.sha512("TestSecret123");
    assert.deepEqual(await Passwords.verify(Hash, "TestSecret123"), { valid: true, legacy: true });
    assert.equal((await Passwords.verify(Hash, "Wrong")).valid, false);
});
