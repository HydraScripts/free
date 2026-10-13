const { createHash, createHmac, randomBytes, randomUUID, randomInt } = require("node:crypto");

const Secret = process.env.LICENSE_HMAC_SECRET;
if (!Secret || Secret.length < 32) {
    throw new Error("LICENSE_HMAC_SECRET must be set to a random string of at least 32 characters");
}

function sha512(Value) {
    return createHmac("sha512", Secret).update(Value).digest("hex");
}

function sha256(Value) {
    return createHash("sha256").update(Value).digest("hex");
}

function randomstr(Length) {
    const Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let Value = "";
    for (let i = 0; i < Length; i++) {
        Value += Characters[randomInt(Characters.length)];
    }
    return Value;
}

// 256-bit secret for API keys. Only its sha256 digest is stored.
function randomSecret() {
    return randomBytes(32).toString("hex");
}

module.exports = { sha512, sha256, randomstr, randomSecret, randomUUID };
