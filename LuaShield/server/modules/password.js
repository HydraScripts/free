const argon2 = require("argon2");
const { timingSafeEqual } = require("node:crypto");
const { sha512 } = require("./crypto");

async function hash(Password) {
    return argon2.hash(Password, {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1
    });
}

async function verify(Stored, Password) {
    if (Stored.startsWith("$argon2id$")) {
        return { valid: await argon2.verify(Stored, Password), legacy: false };
    }
    const Expected = Buffer.from(sha512(Password), "utf8");
    const Actual = Buffer.from(Stored, "utf8");
    return {
        valid: Expected.length === Actual.length && timingSafeEqual(Expected, Actual),
        legacy: true
    };
}

module.exports = { hash, verify };
