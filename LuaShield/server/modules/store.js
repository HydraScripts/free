// Short-lived shared state (challenges, sessions, counters). In-memory by default; set REDIS_URL to
// share it between several server instances. Every operation is async so both backends are drop-in.

const Prefix = "ls:";

function memoryStore({ MaxKeys = 50000 } = {}) {
    const Entries = new Map();
    const Active = new Map(); // set name -> Map(member -> expires)
    const Stats = {};

    const live = (Key, Now = Date.now()) => {
        const Entry = Entries.get(Key);
        if (!Entry) return null;
        if (Entry.Expires <= Now) {
            Entries.delete(Key);
            return null;
        }
        return Entry;
    };
    const prune = () => {
        const Now = Date.now();
        for (const [Key, Entry] of Entries) if (Entry.Expires <= Now) Entries.delete(Key);
        for (const Members of Active.values()) {
            for (const [Member, Expires] of Members) if (Expires <= Now) Members.delete(Member);
        }
    };
    setInterval(prune, 10_000).unref();

    return {
        kind: "memory",
        redis: null,
        async put(Key, Value, TTL) {
            if (Entries.size >= MaxKeys) prune();
            if (Entries.size >= MaxKeys) return false;
            Entries.set(Key, { Value, Expires: Date.now() + TTL });
            return true;
        },
        async get(Key) {
            return live(Key)?.Value ?? null;
        },
        async take(Key) {
            const Entry = live(Key);
            Entries.delete(Key);
            return Entry ? Entry.Value : null;
        },
        async touch(Key, TTL) {
            const Entry = live(Key);
            if (!Entry) return false;
            Entry.Expires = Date.now() + TTL;
            return true;
        },
        async del(Key) {
            Entries.delete(Key);
        },
        async claim(Key, TTL) {
            if (live(Key)) return false;
            return this.put(Key, 1, TTL);
        },
        async incr(Key, TTL) {
            const Entry = live(Key);
            if (Entry) return ++Entry.Value;
            await this.put(Key, 1, TTL);
            return 1;
        },
        async count(Key) {
            return live(Key)?.Value ?? 0;
        },
        async track(Set, Member, TTL) {
            if (!Active.has(Set)) Active.set(Set, new Map());
            Active.get(Set).set(Member, Date.now() + TTL);
        },
        async untrack(Set, Member) {
            Active.get(Set)?.delete(Member);
        },
        async active(Set) {
            const Members = Active.get(Set);
            if (!Members) return 0;
            const Now = Date.now();
            for (const [Member, Expires] of Members) if (Expires <= Now) Members.delete(Member);
            return Members.size;
        },
        async addStat(Field, Amount) {
            Stats[Field] = (Stats[Field] || 0) + Amount;
        },
        async stats() {
            return { ...Stats };
        },
        async close() {}
    };
}

// INCR that starts the expiry window on the first hit only.
const IncrScript = `
local Count = redis.call("INCR", KEYS[1])
if Count == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[1]) end
return Count`;

function redisStore(Url) {
    const Redis = require("ioredis");
    // Fail fast: an unreachable store must reject auth, not hang requests.
    const Client = new Redis(Url, { maxRetriesPerRequest: 1, connectTimeout: 5000, enableOfflineQueue: true });
    Client.on("error", er => console.error("Redis error:", er.message));
    Client.defineCommand("lsIncr", { numberOfKeys: 1, lua: IncrScript });

    const K = Key => Prefix + Key;
    const parse = Raw => (Raw === null ? null : JSON.parse(Raw));

    return {
        kind: "redis",
        redis: Client,
        async put(Key, Value, TTL) {
            await Client.set(K(Key), JSON.stringify(Value), "PX", TTL);
            return true;
        },
        async get(Key) {
            return parse(await Client.get(K(Key)));
        },
        async take(Key) {
            return parse(await Client.getdel(K(Key))); // atomic: a challenge can be consumed once
        },
        async touch(Key, TTL) {
            return (await Client.pexpire(K(Key), TTL)) === 1;
        },
        async del(Key) {
            await Client.del(K(Key));
        },
        async claim(Key, TTL) {
            return (await Client.set(K(Key), "1", "PX", TTL, "NX")) === "OK";
        },
        async incr(Key, TTL) {
            return Number(await Client.lsIncr(K(Key), TTL));
        },
        async count(Key) {
            return Number(await Client.get(K(Key))) || 0;
        },
        async track(Set, Member, TTL) {
            await Client.zadd(K(Set), Date.now() + TTL, Member);
        },
        async untrack(Set, Member) {
            await Client.zrem(K(Set), Member);
        },
        async active(Set) {
            await Client.zremrangebyscore(K(Set), "-inf", Date.now());
            return Client.zcard(K(Set));
        },
        async addStat(Field, Amount) {
            await Client.hincrbyfloat(K("stats"), Field, Amount);
        },
        async stats() {
            const Raw = await Client.hgetall(K("stats"));
            return Object.fromEntries(Object.entries(Raw).map(([Field, Value]) => [Field, Number(Value)]));
        },
        async close() {
            await Client.quit();
        }
    };
}

module.exports = process.env.REDIS_URL ? redisStore(process.env.REDIS_URL) : memoryStore();
