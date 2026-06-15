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

// ── POST /api/auth/login ─────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email dan password diperlukan.' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Email atau password salah.' });

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, cabang: user.cabang },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, cabang: user.cabang } });
});

// ── GET /api/auth/me ─────────────────────────────────────────
app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// ── GET /api/quotations ──────────────────────────────────────
app.get('/api/quotations', auth, (req, res) => {
  const { cabang } = req.query;
  const rows = (cabang && cabang !== 'semua')
    ? db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations WHERE cabang=? ORDER BY created_at DESC LIMIT 200').all(cabang)
    : db.prepare('SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at FROM quotations ORDER BY created_at DESC LIMIT 200').all();
  res.json(rows);
});

// ── POST /api/quotations ─────────────────────────────────────
app.post('/api/quotations', auth, (req, res) => {
  const e = req.body;
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
    cabang: e.cabang || '-', cs_name: e.cs_name || '-',
    customer: e.customer, tanggal: e.tanggal,
    grand_total: e.grand_total || 0, data_json: e.data_json
  });
  res.json({ ok: true });
});

// ── GET /api/quotations/:id/data ─────────────────────────────
app.get('/api/quotations/:id/data', auth, (req, res) => {
  const row = db.prepare('SELECT data_json FROM quotations WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Tidak ditemukan.' });
  res.json({ data_json: row.data_json });
});

// ── DELETE /api/quotations/:id ───────────────────────────────
app.delete('/api/quotations/:id', auth, (req, res) => {
  db.prepare('DELETE FROM quotations WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── DELETE /api/quotations  (hapus semua / per cabang) ───────
app.delete('/api/quotations', auth, (req, res) => {
  const { cabang } = req.query;
  if (cabang && cabang !== 'semua')
    db.prepare('DELETE FROM quotations WHERE cabang=?').run(cabang);
  else
    db.prepare('DELETE FROM quotations').run();
  res.json({ ok: true });
});

app.listen(PORT, '127.0.0.1', () =>
  console.log(`[RuangPrint API] Berjalan di port ${PORT} · DB: ${DB_PATH}`)
);
