// Timestamps are stored as unix seconds so they fit Prisma's 32-bit Int.
// Older records may hold millisecond values; normalise them on read.
function toSeconds(Value) {
    if (typeof Value !== "number" || !Number.isFinite(Value) || Value <= 0) return null;
    return Value > 100_000_000_000 ? Math.floor(Value / 1000) : Value;
}

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

const MaxInt32 = 2147483647;

module.exports = { toSeconds, nowSeconds, MaxInt32 };
