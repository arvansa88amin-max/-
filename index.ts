import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { db, migrate } from './lib/db.js';

const PORT = Number(process.env.PORT || 3001);
const MAX_MESSAGE_LENGTH = 700;
const SESSION_DAYS = 30;

migrate(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'open',
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    window_started INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, created_at, id);
`);

type User = { id: number; username: string; email: string; created_at: string };
type Message = { id: number; message: string; created_at: string; is_read: number };

function send(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(data));
}

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 20_000) throw new Error('body-too-large');
  }
  try { return raw ? JSON.parse(raw) as Record<string, unknown> : {}; }
  catch { throw new Error('invalid-json'); }
}

function cleanText(value: unknown): string { return typeof value === 'string' ? value.trim().normalize('NFC') : ''; }
function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const digest = scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + digest;
}
function checkPassword(password: string, encoded: string): boolean {
  const [salt, digest] = encoded.split(':');
  if (!salt || !digest) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  return timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(actual, 'hex'));
}
function tokenHash(token: string): string { return createHash('sha256').update(token).digest('hex'); }
function makeSession(userId: number): string {
  const token = randomBytes(32).toString('base64url');
  const expiry = new Date(Date.now() + SESSION_DAYS * 86_400_000).toISOString();
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(tokenHash(token), userId, expiry);
  return token;
}
function getUser(req: IncomingMessage): User | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  const row = db.prepare(`SELECT u.id, u.username, u.email, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP`).get(tokenHash(auth.slice(7))) as User | undefined;
  return row ?? null;
}
function rateLimited(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const found = db.prepare('SELECT count, window_started FROM rate_limits WHERE key = ?').get(key) as { count: number; window_started: number } | undefined;
  if (!found || now - found.window_started > windowMs) {
    db.prepare('INSERT OR REPLACE INTO rate_limits (key, count, window_started) VALUES (?, ?, ?)').run(key, 1, now);
    return false;
  }
  if (found.count >= limit) return true;
  db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').run(key);
  return false;
}
function publicUser(username: string): { username: string } | null {
  return (db.prepare('SELECT username FROM users WHERE username = ? COLLATE NOCASE').get(username) as { username: string } | undefined) ?? null;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  const path = url.pathname;
  if (!path.startsWith('/api/')) { send(res, 404, { error: 'not-found' }); return; }
  try {
    if (req.method === 'POST' && path === '/api/auth/register') {
      const data = await body(req);
      const username = cleanText(data.username);
      const email = cleanText(data.email).toLowerCase();
      const password = cleanText(data.password);
      if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) { send(res, 400, { error: 'نام کاربری باید ۳ تا ۲۴ حرف فارسی یا انگلیسی، عدد، _ یا - باشد.' }); return; }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { send(res, 400, { error: 'ایمیل واردشده معتبر نیست.' }); return; }
      if (password.length < 8) { send(res, 400, { error: 'رمز عبور باید حداقل ۸ کاراکتر باشد.' }); return; }
      if (db.prepare('SELECT 1 FROM users WHERE username = ? COLLATE NOCASE').get(username)) { send(res, 409, { error: 'این نام کاربری قبلاً استفاده شده است.' }); return; }
      if (db.prepare('SELECT 1 FROM users WHERE email = ? COLLATE NOCASE').get(email)) { send(res, 409, { error: 'این ایمیل قبلاً ثبت شده است.' }); return; }
      const result = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, hashPassword(password));
      const user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(result.lastInsertRowid) as User;
      send(res, 201, { token: makeSession(user.id), user }); return;
    }
    if (req.method === 'POST' && path === '/api/auth/login') {
      const data = await body(req);
      const identity = cleanText(data.identity);
      const password = cleanText(data.password);
      const row = db.prepare('SELECT id, username, email, password_hash, created_at FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE').get(identity.toLowerCase(), identity) as (User & { password_hash: string }) | undefined;
      if (!row || !checkPassword(password, row.password_hash)) { send(res, 401, { error: 'نام کاربری یا رمز عبور درست نیست.' }); return; }
      const user: User = { id: row.id, username: row.username, email: row.email, created_at: row.created_at };
      send(res, 200, { token: makeSession(user.id), user }); return;
    }
    if (req.method === 'POST' && path === '/api/auth/logout') {
      const auth = req.headers.authorization;
      if (auth?.startsWith('Bearer ')) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(auth.slice(7)));
      send(res, 200, { ok: true }); return;
    }
    if (req.method === 'GET' && path === '/api/auth/me') {
      const user = getUser(req); if (!user) { send(res, 401, { error: 'unauthorized' }); return; }
      send(res, 200, { user }); return;
    }
    const publicMatch = path.match(/^\/api\/public\/([^/]+)$/);
    if (req.method === 'GET' && publicMatch) {
      const user = publicUser(decodeURIComponent(publicMatch[1]));
      if (!user) { send(res, 404, { error: 'این لینک پیدا نشد.' }); return; }
      send(res, 200, { user }); return;
    }
    const messageMatch = path.match(/^\/api\/public\/([^/]+)\/messages$/);
    if (req.method === 'POST' && messageMatch) {
      const username = decodeURIComponent(messageMatch[1]);
      const user = publicUser(username);
      if (!user) { send(res, 404, { error: 'این لینک پیدا نشد.' }); return; }
      const ip = (req.headers['x-forwarded-for']?.toString().split(',')[0] || req.socket.remoteAddress || 'unknown').slice(0, 100);
      if (rateLimited('message:' + ip + ':' + user.username, 5, 60 * 60 * 1000)) { send(res, 429, { error: 'برای جلوگیری از پیام‌های ناخواسته، کمی بعد دوباره تلاش کن.' }); return; }
      const data = await body(req); const message = cleanText(data.message);
      if (!message) { send(res, 400, { error: 'پیام نمی‌تواند خالی باشد.' }); return; }
      if (message.length > MAX_MESSAGE_LENGTH) { send(res, 400, { error: 'پیام باید حداکثر ۷۰۰ کاراکتر باشد.' }); return; }
      const recipient = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(user.username) as { id: number };
      db.prepare('INSERT INTO messages (recipient_id, message) VALUES (?, ?)').run(recipient.id, message);
      send(res, 201, { ok: true }); return;
    }
    if (req.method === 'GET' && path === '/api/messages') {
      const user = getUser(req); if (!user) { send(res, 401, { error: 'unauthorized' }); return; }
      const messages = db.prepare('SELECT id, message, created_at, is_read FROM messages WHERE recipient_id = ? ORDER BY created_at ASC, id ASC').all(user.id) as Message[];
      db.prepare('UPDATE messages SET is_read = 1 WHERE recipient_id = ? AND is_read = 0').run(user.id);
      send(res, 200, { messages: messages.map((m) => ({ ...m, is_read: Boolean(m.is_read) })) }); return;
    }
    const deleteMatch = path.match(/^\/api\/messages\/(\d+)$/);
    if (req.method === 'DELETE' && deleteMatch) {
      const user = getUser(req); if (!user) { send(res, 401, { error: 'unauthorized' }); return; }
      const result = db.prepare('DELETE FROM messages WHERE id = ? AND recipient_id = ?').run(Number(deleteMatch[1]), user.id);
      if (!result.changes) { send(res, 404, { error: 'پیام پیدا نشد.' }); return; }
      send(res, 200, { ok: true }); return;
    }
    if (req.method === 'POST' && path === '/api/account/delete') {
      const user = getUser(req); if (!user) { send(res, 401, { error: 'unauthorized' }); return; }
      const data = await body(req);
      if (cleanText(data.confirmation) !== 'حذف') { send(res, 400, { error: 'برای حذف حساب، عبارت «حذف» را وارد کن.' }); return; }
      db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      send(res, 200, { ok: true }); return;
    }
    send(res, 404, { error: 'not-found' });
  } catch (error) {
    console.error('API error:', req.method, path, error);
    send(res, 500, { error: 'ارتباط با سرور برقرار نشد. دوباره تلاش کن.' });
  }
});

server.listen(PORT, () => console.log('AminMsg server listening on port', PORT));
