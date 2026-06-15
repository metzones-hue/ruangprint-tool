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

// Pastikan direktori DB ada
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    name          TEXT    DEFAULT '',
    cabang        TEXT    DEFAULT 'HO',
    role          TEXT    DEFAULT 'cs',
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
`);

// Migrasi: tambah kolom role kalau DB lama belum punya
try { db.prepare('SELECT role FROM users LIMIT 1').get(); }
catch { db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'cs'"); }

// Bootstrap superadmin pertama (tanpa perlu SSH)
const adminExists = db.prepare("SELECT id FROM users WHERE role='superadmin' LIMIT 1").get();
if (!adminExists) {
  db.prepare(`
    INSERT INTO users (email, password_hash, name, cabang, role)
    VALUES (?, ?, 'Super Admin', 'HO', 'superadmin')
    ON CONFLICT(email) DO UPDATE SET role='superadmin'
  `).run(ADMIN_EMAIL, bcrypt.hashSync(ADMIN_PWD, 10));
  console.log(`[Bootstrap] Superadmin dibuat: ${ADMIN_EMAIL}`);
}

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '20mb' }));

// ── Auth middleware ──────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token tidak valid atau kadaluarsa, silakan login ulang.' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Khusus superadmin.' });
  next();
}

// ── POST /api/auth/login ─────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email dan password diperlukan.' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Email atau password salah.' });

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, cabang: user.cabang, role: user.role || 'cs' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, cabang: user.cabang, role: user.role || 'cs' } });
});

// ── GET /api/auth/me ─────────────────────────────────────────
app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// ── POST /api/auth/change-password (ganti password sendiri) ──
app.post('/api/auth/change-password', auth, (req, res) => {
  const { old_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ error: 'Password baru minimal 6 karakter.' });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!u || !bcrypt.compareSync(old_password || '', u.password_hash))
    return res.status(401).json({ error: 'Password lama salah.' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(new_password, 10), req.user.id);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════
//  ADMIN — kelola user (khusus superadmin)
// ════════════════════════════════════════════════════════════
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  res.json(db.prepare('SELECT id,email,name,cabang,role,created_at FROM users ORDER BY id').all());
});

app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  const { id, email, password, name, cabang, role } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email wajib diisi.' });

  if (id) {
    // Update user yg sudah ada
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
    if (!u) return res.status(404).json({ error: 'User tidak ditemukan.' });
    const hash = password ? bcrypt.hashSync(password, 10) : u.password_hash;
    db.prepare('UPDATE users SET email=?, password_hash=?, name=?, cabang=?, role=? WHERE id=?')
      .run(email.toLowerCase().trim(), hash, name || '', cabang || 'HO', role || 'cs', id);
    return res.json({ ok: true });
  }

  // User baru — password wajib
  if (!password) return res.status(400).json({ error: 'Password wajib untuk user baru.' });
  try {
    db.prepare('INSERT INTO users (email,password_hash,name,cabang,role) VALUES (?,?,?,?,?)')
      .run(email.toLowerCase().trim(), bcrypt.hashSync(password, 10), name || '', cabang || 'HO', role || 'cs');
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Email sudah terdaftar.' });
  }
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  if (Number(req.params.id) === req.user.id)
    return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri.' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════
//  QUOTATIONS — CS hanya cabang sendiri, superadmin semua
// ════════════════════════════════════════════════════════════
const isAdmin = u => u.role === 'superadmin';

app.get('/api/quotations', auth, (req, res) => {
  let rows;
  if (isAdmin(req.user)) {
    const { cabang } = req.query;
    rows = (cabang && cabang !== 'semua')
      ? db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations WHERE cabang=? ORDER BY created_at DESC LIMIT 200').all(cabang)
      : db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations ORDER BY created_at DESC LIMIT 200').all();
  } else {
    // CS: dipaksa hanya cabang miliknya
    rows = db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations WHERE cabang=? ORDER BY created_at DESC LIMIT 200').all(req.user.cabang);
  }
  res.json(rows);
});

app.post('/api/quotations', auth, (req, res) => {
  const e = req.body;
  // CS: cabang & cs_name dipaksa dari token (tidak percaya input klien)
  const cabang  = isAdmin(req.user) ? (e.cabang || '-') : req.user.cabang;
  const cs_name = isAdmin(req.user) ? (e.cs_name || '-') : (req.user.name || e.cs_name || '-');
  db.prepare(`
    INSERT INTO quotations (id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,data_json,updated_at)
    VALUES (@id,@no_quotation,@tipe,@cabang,@cs_name,@customer,@tanggal,@grand_total,@data_json,CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      no_quotation=excluded.no_quotation, tipe=excluded.tipe, cabang=excluded.cabang,
      cs_name=excluded.cs_name, customer=excluded.customer, tanggal=excluded.tanggal,
      grand_total=excluded.grand_total, data_json=excluded.data_json,
      updated_at=CURRENT_TIMESTAMP
  `).run({
    id: e.id, no_quotation: e.no_quotation, tipe: e.tipe || 'P',
    cabang, cs_name, customer: e.customer, tanggal: e.tanggal,
    grand_total: e.grand_total || 0, data_json: e.data_json
  });
  res.json({ ok: true });
});

// Helper: cek akses 1 quotation
function canAccess(user, row) {
  return row && (isAdmin(user) || row.cabang === user.cabang);
}

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
    // CS hanya boleh hapus cabang sendiri
    db.prepare('DELETE FROM quotations WHERE cabang=?').run(req.user.cabang);
  }
  res.json({ ok: true });
});

app.listen(PORT, '127.0.0.1', () =>
  console.log(`[RuangPrint API] Berjalan di port ${PORT} · DB: ${DB_PATH}`)
);
