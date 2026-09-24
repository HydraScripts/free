import { verifyToken } from '../util.js';

export function requireAdmin(req, res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verifyToken(token, process.env.SESSION_SECRET);
  if (!payload || payload.role !== 'admin') {
    return res.status(401).json({ error: 'unauthorized' });
  }
  req.admin = payload;
  next();
}
