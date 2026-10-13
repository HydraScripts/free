// Per-buyer audit log as append-only JSON lines. O_APPEND writes of a single line don't interleave,
// so several instances on a shared volume can log concurrently without losing entries
// (the previous read-modify-write of a JSON array could).
const { appendFileSync, existsSync, readFileSync, rmSync, mkdirSync } = require("node:fs");
const path = require("node:path");

const Folder = path.join(__dirname, "../../files/logs");

// Usernames are restricted to [A-Za-z0-9 ] at signup; reject anything else rather than build a path from it.
function files(Username) {
    if (typeof Username !== "string" || !/^[A-Za-z0-9 ]{1,32}$/.test(Username)) return null;
    return { Lines: path.join(Folder, `${Username}.jsonl`), Legacy: path.join(Folder, `${Username}.json`) };
}

function add(Username, IP, Message) {
    const Paths = files(Username);
    if (!Paths) return;
    mkdirSync(Folder, { recursive: true });
    appendFileSync(Paths.Lines, JSON.stringify({ timestamp: Date.now(), ip: IP, message: Message }) + "\n");
}

function read(Username) {
    const Paths = files(Username);
    if (!Paths) return [];
    const Entries = existsSync(Paths.Legacy) ? JSON.parse(readFileSync(Paths.Legacy, "utf8")) : [];
    if (existsSync(Paths.Lines)) {
        for (const Line of readFileSync(Paths.Lines, "utf8").split("\n")) {
            if (Line) Entries.push(JSON.parse(Line));
        }
    }
    return Entries;
}

function remove(Username) {
    const Paths = files(Username);
    if (!Paths) return;
    rmSync(Paths.Lines, { force: true });
    rmSync(Paths.Legacy, { force: true });
}

module.exports = { add, read, remove };
