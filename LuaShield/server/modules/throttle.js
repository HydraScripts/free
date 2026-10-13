// Limiters backed by the shared store, so limits hold across instances when REDIS_URL is set.
const Store = require("./store");

// Counts *failures* only: record() on a failed attempt, blocked() before doing work.
function failureLimiter({ Name, Max, WindowMs }) {
    return {
        async blocked(Key) {
            return await Store.count(`fail:${Name}:${Key}`) >= Max;
        },
        async record(Key) {
            await Store.incr(`fail:${Name}:${Key}`, WindowMs);
        }
    };
}

// Lets an event through at most once per interval per key (webhook spam control).
function intervalGate(Name, IntervalMs) {
    return Key => Store.claim(`gate:${Name}:${Key}`, IntervalMs);
}

module.exports = { failureLimiter, intervalGate };
