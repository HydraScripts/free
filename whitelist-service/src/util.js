import crypto from 'node:crypto';

// Generate a license key like: XXXX-XXXX-XXXX-XXXX (no ambiguous chars)
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export function generateKey(groups = 4, groupLen = 4) {
  const out = [];
  for (let g = 0; g < groups; g++) {
    let s = '';
    const bytes = crypto.randomBytes(groupLen);
    for (let i = 0; i < groupLen; i++) s += ALPHABET[bytes[i] % ALPHABET.length];
    out.push(s);
  }
  return out.join('-');
}

export function slugify(str) {
  return String(str)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'project';
}

// ---- Stateless signed session tokens (HMAC), no external deps ----
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function signToken(payload, secret, ttlSeconds = 60 * 60 * 12) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const data = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

export function verifyToken(token, secret) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const body = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (!body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
    return body;
  } catch {
    return null;
  }
}

// Constant-time string compare for passwords
export function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
