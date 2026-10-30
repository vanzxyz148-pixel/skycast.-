'use strict';
/**
 * SkyBot / SkyCast: server masukan pengguna + dashboard admin.
 * Tanpa dependensi npm. Butuh Node.js >= 22.5 (memakai node:sqlite bawaan).
 *
 * Environment variable:
 *   ADMIN_PASSWORD  (wajib, min. 8 karakter)  password dashboard admin
 *   PORT            (opsional, default 3000)
 *   DB_PATH         (opsional, default ./data/feedback.db)
 *   TRUST_PROXY     (opsional, "1" bila di belakang reverse proxy: IP dibaca dari X-Forwarded-For)
 *   COOKIE_SECURE   (opsional, "1" paksa cookie Secure; otomatis aktif bila akses lewat HTTPS)
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// ---------- Konfigurasi ----------
const loadEnvFile = () => { // baca .env sederhana bila ada (variabel yang sudah diset di sistem tidak ditimpa)
  try {
    for (const l of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
      const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  } catch {}
};
loadEnvFile();

const PORT = Number(process.env.PORT) || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data', 'feedback.db'));
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const SESSION_MS = 8 * 3600 * 1000;
const CATEGORIES = ['kritik', 'saran', 'bug', 'fitur', 'lainnya'];

if (ADMIN_PASSWORD.length < 8) {
  console.error('GAGAL: ADMIN_PASSWORD belum diisi atau kurang dari 8 karakter. Isi di file .env atau environment variable.');
  process.exit(1);
}

// ---------- Database ----------
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL CHECK (category IN ('kritik','saran','bug','fitur','lainnya')),
    message TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_feedback_cat ON feedback(category, created_at);
  CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
`);
const q = {
  insert: db.prepare('INSERT INTO feedback (name, category, message) VALUES (?, ?, ?)'),
  get: db.prepare('SELECT id FROM feedback WHERE id = ?'),
  setRead: db.prepare('UPDATE feedback SET is_read = ? WHERE id = ?'),
  del: db.prepare('DELETE FROM feedback WHERE id = ?'),
};
function listFeedback({ category, status, limit, offset }) {
  const w = [], a = [];
  if (category) { w.push('category = ?'); a.push(category); }
  if (status === 'unread') w.push('is_read = 0'); else if (status === 'read') w.push('is_read = 1');
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) AS n FROM feedback ${where}`).get(...a).n;
  const items = db.prepare(`SELECT id, name, category, message, is_read, created_at FROM feedback ${where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`).all(...a, limit, offset)
    .map((r) => ({ ...r, is_read: !!r.is_read }));
  const unread = db.prepare('SELECT COUNT(*) AS n FROM feedback WHERE is_read = 0').get().n;
  const all = db.prepare('SELECT COUNT(*) AS n FROM feedback').get().n;
  return { items, total, unread, all };
}

// ---------- Utilitas keamanan ----------
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const passwordOk = (p) => crypto.timingSafeEqual(sha(p), sha(ADMIN_PASSWORD));
const sessions = new Map(); // id sesi -> waktu kedaluwarsa (sesi hilang saat server restart)
const hits = new Map();     // pembatas laju sederhana: kunci -> [waktu, ...]
function limited(key, max, windowMs, record = true) {
  const now = Date.now(), arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  const blocked = arr.length >= max;
  if (record && !blocked) arr.push(now);
  hits.set(key, arr);
  return blocked;
}
setInterval(() => { // bersihkan memori
  const now = Date.now();
  for (const [k, v] of sessions) if (v < now) sessions.delete(k);
  for (const [k, v] of hits) if (!v.some((t) => now - t < 3600e3)) hits.delete(k);
}, 600e3).unref();

const clientIp = (req) => {
  if (TRUST_PROXY) { const x = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean); if (x.length) return x[x.length - 1]; }
  return req.socket.remoteAddress || 'unknown';
};
const isHttps = (req) => process.env.COOKIE_SECURE === '1' || req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
const parseCookies = (req) => Object.fromEntries(String(req.headers.cookie || '').split(';').map((c) => c.trim().split(/=(.*)/s).slice(0, 2)).filter((p) => p[0]));
const isAdmin = (req) => { const id = parseCookies(req).sb_admin; const exp = id && sessions.get(id); return !!exp && exp > Date.now(); };
function sameOrigin(req) { // tolak permintaan lintas situs untuk aksi yang mengubah data
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch { return false; }
}

// ---------- Respons ----------
const baseHeaders = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' };
function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...baseHeaders, ...headers });
  res.end(body);
}
const json = (res, status, obj, headers = {}) => send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
function readJson(req, max = 12 * 1024) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return reject(Object.assign(new Error('Content-Type harus application/json.'), { status: 415 }));
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > max) { reject(Object.assign(new Error('Data terlalu besar.'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {}); } catch { reject(Object.assign(new Error('JSON tidak valid.'), { status: 400 })); } });
    req.on('error', reject);
  });
}
const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);

// ---------- Berkas statis (hanya daftar putih; server.js, .env, dan database tidak pernah disajikan) ----------
const PAGES = { '/': 'SkyCast-mobile.html', '/SkyCast-mobile.html': 'SkyCast-mobile.html' };
const read = (f) => fs.readFileSync(path.join(__dirname, f), 'utf8');

// ---------- Router ----------
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'), p = url.pathname, m = req.method;

  if (m === 'GET' && PAGES[p]) {
    return send(res, 200, read(PAGES[p]), { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
  }
  if (m === 'GET' && (p === '/admin' || p === '/admin/')) { // halaman hanya berisi form login + UI; semua data dijaga endpoint backend
    const nonce = crypto.randomBytes(16).toString('base64');
    return send(res, 200, read('admin.html').replaceAll('{{NONCE}}', nonce), {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow',
      'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    });
  }
  if (m === 'GET' && p === '/robots.txt') return send(res, 200, 'User-agent: *\nDisallow: /admin\n', { 'Content-Type': 'text/plain; charset=utf-8' });
  if (m === 'GET' && p === '/api/health') return json(res, 200, { ok: true });

  // --- Publik: kirim masukan ---
  if (m === 'POST' && p === '/api/feedback') {
    if (!sameOrigin(req)) return json(res, 403, { ok: false, error: 'Permintaan ditolak.' });
    if (limited('fb:' + clientIp(req), 5, 10 * 60e3)) return json(res, 429, { ok: false, error: 'Terlalu banyak pengiriman. Coba lagi beberapa menit lagi.' });
    const b = await readJson(req);
    if (clean(b.website, 100)) return json(res, 200, { ok: true }); // honeypot: bot dianggap sukses tanpa disimpan
    const name = clean(b.name, 60), category = clean(b.category, 20), message = clean(b.message, 2000);
    if (!message) return json(res, 400, { ok: false, error: 'Pesan tidak boleh kosong.' });
    if (!CATEGORIES.includes(category)) return json(res, 400, { ok: false, error: 'Kategori tidak valid.' });
    q.insert.run(name, category, message);
    return json(res, 201, { ok: true });
  }

  // --- Admin ---
  if (m === 'POST' && p === '/api/admin/login') {
    if (!sameOrigin(req)) return json(res, 403, { ok: false, error: 'Permintaan ditolak.' });
    const ip = clientIp(req), key = 'login:' + ip;
    if (limited(key, 5, 15 * 60e3, false)) return json(res, 429, { ok: false, error: 'Terlalu banyak percobaan gagal. Coba lagi dalam 15 menit.' });
    const b = await readJson(req, 2048);
    if (typeof b.password !== 'string' || !passwordOk(b.password)) {
      limited(key, 5, 15 * 60e3); // hanya percobaan gagal yang dihitung
      await new Promise((r) => setTimeout(r, 400));
      return json(res, 401, { ok: false, error: 'Password salah.' });
    }
    hits.delete(key);
    const id = crypto.randomBytes(32).toString('hex');
    sessions.set(id, Date.now() + SESSION_MS);
    return json(res, 200, { ok: true }, { 'Set-Cookie': `sb_admin=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}${isHttps(req) ? '; Secure' : ''}` });
  }
  if (p.startsWith('/api/admin/')) {
    if (m === 'POST' && p === '/api/admin/logout') {
      if (!sameOrigin(req)) return json(res, 403, { ok: false, error: 'Permintaan ditolak.' });
      sessions.delete(parseCookies(req).sb_admin);
      return json(res, 200, { ok: true }, { 'Set-Cookie': `sb_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${isHttps(req) ? '; Secure' : ''}` });
    }
    if (!isAdmin(req)) return json(res, 401, { ok: false, error: 'Tidak diizinkan. Silakan login.' });
    if (m === 'GET' && p === '/api/admin/session') return json(res, 200, { ok: true });
    if (m === 'GET' && p === '/api/admin/feedback') {
      const category = CATEGORIES.includes(url.searchParams.get('category')) ? url.searchParams.get('category') : '';
      const status = ['read', 'unread'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : '';
      const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit'), 10) || 50, 1), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset'), 10) || 0, 0);
      return json(res, 200, { ok: true, ...listFeedback({ category, status, limit, offset }) });
    }
    const mm = p.match(/^\/api\/admin\/feedback\/(\d{1,12})$/);
    if (mm && (m === 'PATCH' || m === 'DELETE')) {
      if (!sameOrigin(req)) return json(res, 403, { ok: false, error: 'Permintaan ditolak.' });
      const id = Number(mm[1]);
      if (!q.get.get(id)) return json(res, 404, { ok: false, error: 'Masukan tidak ditemukan.' });
      if (m === 'DELETE') { q.del.run(id); return json(res, 200, { ok: true }); }
      const b = await readJson(req, 1024);
      if (typeof b.read !== 'boolean') return json(res, 400, { ok: false, error: 'Nilai "read" harus true atau false.' });
      q.setRead.run(b.read ? 1 : 0, id);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { ok: false, error: 'Endpoint tidak ditemukan.' });
  }
  return json(res, 404, { ok: false, error: 'Tidak ditemukan.' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    if (res.headersSent) return res.end();
    if (e.status) return json(res, e.status, { ok: false, error: e.message });
    console.error(e);
    json(res, 500, { ok: false, error: 'Terjadi kesalahan pada server.' });
  });
});
server.listen(PORT, () => console.log(`SkyCast berjalan di http://localhost:${PORT}  |  admin: http://localhost:${PORT}/admin  |  database: ${DB_PATH}`));
