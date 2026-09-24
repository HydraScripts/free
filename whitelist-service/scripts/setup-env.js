// Creates .env from .env.example on first run: asks for an admin password
// and generates a random SESSION_SECRET. Does nothing if .env already exists.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');

if (fs.existsSync(envPath)) process.exit(0);

const prompt = 'Choose an admin password for the dashboard (6+ characters): ';
const rl = readline.createInterface({ input: process.stdin });
let password = '';
process.stdout.write(prompt);
for await (const line of rl) {
  password = line.trim();
  if (password.length >= 6) break;
  console.log('Too short, try again.');
  process.stdout.write(prompt);
}
rl.close();
if (password.length < 6) {
  console.error('\nNo password entered, setup cancelled.');
  process.exit(1);
}

const env = fs
  .readFileSync(path.join(root, '.env.example'), 'utf8')
  .replace(/^ADMIN_PASSWORD=.*$/m, `ADMIN_PASSWORD=${password}`)
  .replace(/^SESSION_SECRET=.*$/m, `SESSION_SECRET=${crypto.randomBytes(48).toString('hex')}`);

fs.writeFileSync(envPath, env);
console.log('Saved your settings to .env (edit it any time to change the password).\n');
