const { createHash, createHmac, randomBytes, randomUUID, randomInt, timingSafeEqual } = require("node:crypto");

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

// Constant-time string comparison that doesn't leak length or content via timing.
// Compares sha256 digests so inputs of different lengths are still compared safely.
function safeEqual(A, B) {
    if (typeof A !== "string" || typeof B !== "string") return false;
    const DigestA = createHash("sha256").update(A).digest();
    const DigestB = createHash("sha256").update(B).digest();
    return timingSafeEqual(DigestA, DigestB);
}

// True only if the configured admin key is set and matches, in constant time.
function matchesAdminKey(Candidate) {
    const Expected = process.env.ADMIN_KEY;
    if (!Expected) return false;
    return safeEqual(String(Candidate ?? ""), Expected);
}

module.exports = { sha512, sha256, randomstr, randomSecret, randomUUID, safeEqual, matchesAdminKey };
