// Small in-memory limiters. Keys are never IP-only identities; callers choose them.

// Counts *failures* only: record() on a failed attempt, blocked() before working.
function failureLimiter({ Max, WindowMs, MaxKeys = 10000 }) {
    const Entries = new Map();
    function prune(Now) {
        for (const [Key, Value] of Entries) {
            if (Value.Expires <= Now) Entries.delete(Key);
        }
    }
    return {
        blocked(Key) {
            const Now = Date.now();
            const Entry = Entries.get(Key);
            return Boolean(Entry && Entry.Expires > Now && Entry.Count >= Max);
        },
        record(Key) {
            const Now = Date.now();
            prune(Now);
            const Entry = Entries.get(Key);
            if (Entry && Entry.Expires > Now) {
                Entry.Count++;
            } else if (Entries.size < MaxKeys) {
                Entries.set(Key, { Count: 1, Expires: Now + WindowMs });
            }
        },
        size: () => Entries.size
    };
}

// Lets an event through at most once per interval per key (webhook spam control).
function intervalGate(IntervalMs, MaxKeys = 10000) {
    const Last = new Map();
    return key => {
        const Now = Date.now();
        if (Last.size >= MaxKeys) {
            for (const [Key, Time] of Last) if (Now - Time >= IntervalMs) Last.delete(Key);
        }
        const Previous = Last.get(key);
        if (Previous && Now - Previous < IntervalMs) return false;
        if (Last.size < MaxKeys) Last.set(key, Now);
        return true;
    };
}

module.exports = { failureLimiter, intervalGate };
