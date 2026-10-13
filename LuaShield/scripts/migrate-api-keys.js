/**
 * One-off migration: stop storing API keys in plaintext.
 *
 * Before: Buyer.APIKey is both the credential the customer holds and the id other records reference.
 * After:  Buyer.ApiKeyHash = sha256(existing key), so customers keep using their current key, while
 *         Buyer.APIKey becomes a new random internal id that Project.Owner / Webhook.Owner point to.
 *
 * Back up the database first. Safe to re-run: buyers that already have ApiKeyHash are skipped.
 *   node scripts/migrate-api-keys.js          # dry run
 *   node scripts/migrate-api-keys.js --apply
 */
require("dotenv").config();
const { PrismaClient } = require("@prisma/client");
const { createHash, randomUUID } = require("node:crypto");

const prisma = new PrismaClient();
const Apply = process.argv.includes("--apply");

(async () => {
    const Buyers = await prisma.buyer.findMany({ where: { ApiKeyHash: null } });
    console.log(`${Buyers.length} buyer(s) still hold a plaintext API key`);
    for (const Buyer of Buyers) {
        const OldKey = Buyer.APIKey;
        const NewId = randomUUID();
        console.log(`${Apply ? "migrating" : "would migrate"} ${Buyer.Username}`);
        if (!Apply) continue;
        await prisma.$transaction([
            prisma.buyer.update({
                where: { id: Buyer.id },
                data: { APIKey: NewId, ApiKeyHash: createHash("sha256").update(OldKey).digest("hex") }
            }),
            prisma.project.updateMany({ where: { Owner: OldKey }, data: { Owner: NewId } }),
            prisma.webhook.updateMany({ where: { Owner: OldKey }, data: { Owner: NewId } })
        ]);
    }
    console.log(Apply ? "done" : "dry run only, re-run with --apply");
})().catch(er => { console.error(er); process.exit(1); }).finally(() => prisma.$disconnect());
