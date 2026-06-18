'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

const PORT       = process.env.PORT       || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'GANTI_INI_DENGAN_STRING_ACAK_PANJANG';
const DB_PATH    = process.env.DB_PATH    || '/var/lib/ruangprint/ruangprint.db';
const ADMIN_EMAIL = (process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@ruangprint.co.id').toLowerCase();
// Tidak ada default password di source: kalau env kosong, pakai acak (aman, recover via setup-user.js)
const ADMIN_PWD   =  process.env.BOOTSTRAP_ADMIN_PASSWORD || require('crypto').randomBytes(9).toString('hex');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE,
    username      TEXT    UNIQUE,
    password_hash TEXT    NOT NULL,
    name          TEXT    DEFAULT '',
    cabang        TEXT    DEFAULT 'HO',
    role          TEXT    DEFAULT 'cabang',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS quotations (
    id            INTEGER PRIMARY KEY,
    no_quotation  TEXT,
    tipe          TEXT    DEFAULT 'P',
    cabang        TEXT    DEFAULT '-',
    cs_name       TEXT    DEFAULT '-',
    customer      TEXT,
    tanggal       TEXT,
    grand_total   REAL    DEFAULT 0,
    data_json     TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Migrasi kolom untuk DB lama
function ensureColumn(col, ddl) {
  try { db.prepare(`SELECT ${col} FROM users LIMIT 1`).get(); }
  catch { db.exec(`ALTER TABLE users ADD COLUMN ${ddl}`); }
}
ensureColumn('role',     "role TEXT DEFAULT 'cabang'");
ensureColumn('username', "username TEXT");

// Migrasi: DB lama punya kolom email NOT NULL, sehingga akun cabang tanpa email
// gagal dibuat ("NOT NULL constraint failed: users.email"). Bangun ulang tabel
// agar email opsional (nullable) dan username unik, tanpa kehilangan data.
try {
  const emailCol = db.prepare('PRAGMA table_info(users)').all().find(c => c.name === 'email');
  if (emailCol && emailCol.notnull === 1) {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE users_new (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          email         TEXT    UNIQUE,
          username      TEXT    UNIQUE,
          password_hash TEXT    NOT NULL,
          name          TEXT    DEFAULT '',
          cabang        TEXT    DEFAULT 'HO',
          role          TEXT    DEFAULT 'cabang',
          created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO users_new (id,email,username,password_hash,name,cabang,role,created_at)
          SELECT id,email,username,password_hash,name,cabang,role,created_at FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
      `);
    })();
    console.log('[Migrasi] Kolom email diubah menjadi opsional (nullable).');
  }
} catch (e) { console.error('[Migrasi email] gagal:', e.message); }

// Superadmin lama (sebelum ada kolom username) → set username 'admin'
try { db.prepare("UPDATE users SET username='admin' WHERE role='superadmin' AND (username IS NULL OR username='')").run(); }
catch (e) {}

// Bootstrap superadmin (username 'admin' + email), tanpa SSH
const adminExists = db.prepare("SELECT id FROM users WHERE role='superadmin' LIMIT 1").get();
if (!adminExists) {
  db.prepare(`
    INSERT INTO users (email, username, password_hash, name, cabang, role)
    VALUES (?, 'admin', ?, 'Super Admin', 'HO', 'superadmin')
    ON CONFLICT(email) DO UPDATE SET role='superadmin', username='admin'
  `).run(ADMIN_EMAIL, bcrypt.hashSync(ADMIN_PWD, 10));
  console.log(`[Bootstrap] Superadmin dibuat: ${ADMIN_EMAIL} (username: admin)`);
}

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '20mb' }));

// ── Middleware ───────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Sesi berakhir, silakan login ulang.' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Khusus superadmin.' });
  next();
}
const isAdmin = u => u.role === 'superadmin';

// Buat kode cabang dari teks (uppercase alnum, maks 10)
function makeCode(s) {
  return (s || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10) || ('C' + Date.now().toString().slice(-5));
}

// ── AUTH ─────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const id = (req.body.username || req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';
  if (!id || !password) return res.status(400).json({ error: 'Username dan password diperlukan.' });

  const user = db.prepare('SELECT * FROM users WHERE lower(username)=? OR lower(email)=?').get(id, id);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Username atau password salah.' });

  const payload = { id: user.id, username: user.username, email: user.email, name: user.name, cabang: user.cabang, role: user.role || 'cabang' };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: payload });
});

app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

app.post('/api/auth/change-password', auth, (req, res) => {
  const { old_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'Password baru minimal 6 karakter.' });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!u || !bcrypt.compareSync(old_password || '', u.password_hash)) return res.status(401).json({ error: 'Password lama salah.' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(new_password, 10), req.user.id);
  res.json({ ok: true });
});

// ── ADMIN: kelola cabang / user ──────────────────────────────
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  res.json(db.prepare('SELECT id,username,email,name,cabang,role,created_at FROM users ORDER BY role DESC, id').all());
});

app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  let { id, username, password, name, cabang, role } = req.body || {};
  username = (username || '').toLowerCase().trim();
  role = role || 'cabang';
  if (!username) return res.status(400).json({ error: 'Username wajib diisi.' });
  if (!name)     return res.status(400).json({ error: 'Nama cabang wajib diisi.' });
  // Kode cabang: pakai yg diberikan, atau buat dari nama
  const code = (cabang && cabang.trim()) ? makeCode(cabang) : makeCode(name);

  if (id) {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
    if (!u) return res.status(404).json({ error: 'Tidak ditemukan.' });
    const hash = password ? bcrypt.hashSync(password, 10) : u.password_hash;
    try {
      db.prepare('UPDATE users SET username=?, password_hash=?, name=?, cabang=?, role=? WHERE id=?')
        .run(username, hash, name, role === 'superadmin' ? (u.cabang || 'HO') : code, role, id);
    } catch (e) {
      if (/UNIQUE constraint/i.test(e.message)) return res.status(400).json({ error: 'Username sudah dipakai.' });
      console.error('Gagal update user:', e.message);
      return res.status(400).json({ error: 'Gagal menyimpan: ' + e.message });
    }
    return res.json({ ok: true });
  }

  if (!password) return res.status(400).json({ error: 'Password wajib untuk akun baru.' });
  try {
    db.prepare('INSERT INTO users (username,password_hash,name,cabang,role) VALUES (?,?,?,?,?)')
      .run(username, bcrypt.hashSync(password, 10), name, role === 'superadmin' ? 'HO' : code, role);
    res.json({ ok: true });
  } catch (e) {
    if (/UNIQUE constraint/i.test(e.message)) return res.status(400).json({ error: 'Username sudah terdaftar.' });
    console.error('Gagal membuat user:', e.message);
    res.status(400).json({ error: 'Gagal menyimpan: ' + e.message });
  }
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri.' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── ADMIN: statistik dashboard ───────────────────────────────
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  const totalBranches   = db.prepare("SELECT COUNT(*) n FROM users WHERE role!='superadmin'").get().n;
  const totalQuotations = db.prepare('SELECT COUNT(*) n FROM quotations').get().n;
  const totalValue      = db.prepare('SELECT COALESCE(SUM(grand_total),0) v FROM quotations').get().v;

  // Per cabang (gabung nama cabang dari users bila ada)
  const perBranch = db.prepare(`
    SELECT q.cabang AS code,
           COALESCE(MAX(u.name), q.cabang) AS name,
           COUNT(*) AS count,
           COALESCE(SUM(q.grand_total),0) AS value
    FROM quotations q
    LEFT JOIN users u ON u.cabang = q.cabang AND u.role!='superadmin'
    GROUP BY q.cabang ORDER BY value DESC
  `).all();

  const recent = db.prepare(`
    SELECT no_quotation, cabang, cs_name, customer, grand_total, created_at
    FROM quotations ORDER BY created_at DESC LIMIT 10
  `).all();

  const byMonth = db.prepare(`
    SELECT substr(created_at,1,7) AS ym, COUNT(*) AS count, COALESCE(SUM(grand_total),0) AS value
    FROM quotations GROUP BY ym ORDER BY ym DESC LIMIT 6
  `).all().reverse();

  res.json({ totalBranches, totalQuotations, totalValue, perBranch, recent, byMonth });
});

// ── ADMIN: settings ──────────────────────────────────────────
app.get('/api/admin/settings', auth, adminOnly, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const out = {}; rows.forEach(r => out[r.key] = r.value);
  res.json(out);
});
app.post('/api/admin/settings', auth, adminOnly, (req, res) => {
  const up = db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  const tx = db.transaction(obj => { for (const k in obj) up.run(k, String(obj[k])); });
  tx(req.body || {});
  res.json({ ok: true });
});
// Settings publik (dibaca tool tanpa harus superadmin) — mis. info perusahaan
app.get('/api/settings/public', auth, (req, res) => {
  const rows = db.prepare("SELECT key, value FROM settings WHERE key LIKE 'comp_%'").all();
  const out = {}; rows.forEach(r => out[r.key] = r.value);
  res.json(out);
});

// ── QUOTATIONS (CS/cabang hanya cabang sendiri) ──────────────
app.get('/api/quotations', auth, (req, res) => {
  let rows;
  if (isAdmin(req.user)) {
    const { cabang } = req.query;
    rows = (cabang && cabang !== 'semua')
      ? db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations WHERE cabang=? ORDER BY created_at DESC LIMIT 200').all(cabang)
      : db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations ORDER BY created_at DESC LIMIT 200').all();
  } else {
    rows = db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations WHERE cabang=? ORDER BY created_at DESC LIMIT 200').all(req.user.cabang);
  }
  res.json(rows);
});

app.post('/api/quotations', auth, (req, res) => {
  const e = req.body;
  const cabang  = isAdmin(req.user) ? (e.cabang || '-') : req.user.cabang;
  const cs_name = isAdmin(req.user) ? (e.cs_name || '-') : (e.cs_name || req.user.name || '-');
  db.prepare(`
    INSERT INTO quotations (id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,data_json,updated_at)
    VALUES (@id,@no_quotation,@tipe,@cabang,@cs_name,@customer,@tanggal,@grand_total,@data_json,CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      no_quotation=excluded.no_quotation, tipe=excluded.tipe, cabang=excluded.cabang,
      cs_name=excluded.cs_name, customer=excluded.customer, tanggal=excluded.tanggal,
      grand_total=excluded.grand_total, data_json=excluded.data_json, updated_at=CURRENT_TIMESTAMP
  `).run({
    id: e.id, no_quotation: e.no_quotation, tipe: e.tipe || 'P',
    cabang, cs_name, customer: e.customer, tanggal: e.tanggal,
    grand_total: e.grand_total || 0, data_json: e.data_json
  });
  res.json({ ok: true });
});

function canAccess(user, row) { return row && (isAdmin(user) || row.cabang === user.cabang); }

app.get('/api/quotations/:id/data', auth, (req, res) => {
  const row = db.prepare('SELECT cabang, data_json FROM quotations WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  res.json({ data_json: row.data_json });
});

app.delete('/api/quotations/:id', auth, (req, res) => {
  const row = db.prepare('SELECT cabang FROM quotations WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  db.prepare('DELETE FROM quotations WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/quotations', auth, (req, res) => {
  if (isAdmin(req.user)) {
    const { cabang } = req.query;
    if (cabang && cabang !== 'semua') db.prepare('DELETE FROM quotations WHERE cabang=?').run(cabang);
    else db.prepare('DELETE FROM quotations').run();
  } else {
    db.prepare('DELETE FROM quotations WHERE cabang=?').run(req.user.cabang);
  }
  res.json({ ok: true });
});

app.listen(PORT, '127.0.0.1', () =>
  console.log(`[RuangPrint API] Berjalan di port ${PORT} · DB: ${DB_PATH}`)
);
