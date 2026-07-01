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
  CREATE TABLE IF NOT EXISTS calc_saves (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tool        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    cabang      TEXT    DEFAULT '-',
    cs_name     TEXT    DEFAULT '-',
    summary     TEXT    DEFAULT '',
    data_json   TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS delivery_notes (
    id            INTEGER PRIMARY KEY,
    no_sj         TEXT,
    cabang        TEXT    DEFAULT '-',
    cs_name       TEXT    DEFAULT '-',
    customer      TEXT,
    tanggal       TEXT,
    ref_quotation TEXT    DEFAULT '',
    data_json     TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS label_prints (
    id          TEXT PRIMARY KEY,
    cabang      TEXT    DEFAULT '-',
    cs_name     TEXT    DEFAULT '-',
    customer    TEXT    DEFAULT '',
    tanggal     TEXT,
    jml_label   INTEGER DEFAULT 0,
    kategori    TEXT    DEFAULT '',
    summary     TEXT    DEFAULT '',
    data_json   TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reklame_harga (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kategori  TEXT NOT NULL,
    kode      TEXT NOT NULL,
    label     TEXT NOT NULL,
    nilai     REAL NOT NULL DEFAULT 0,
    satuan    TEXT DEFAULT '',
    urutan    INTEGER DEFAULT 0,
    UNIQUE(kategori,kode)
  );
  CREATE TABLE IF NOT EXISTS reklame_toko (
    id       INTEGER PRIMARY KEY,
    nama     TEXT NOT NULL,
    alamat   TEXT DEFAULT '',
    telepon  TEXT DEFAULT ''
  );
`);

// Seed harga reklame (sekali, dari kalkulator lokal) bila kosong
const _seedReklame = [
  ['visual_m2','Acrylic','Acrylic',450000,'/m²',1],
  ['visual_m2','Flexy Backlite','Flexy Backlite',150000,'/m²',2],
  ['visual_m2','Stainless','Stainless',550000,'/m²',3],
  ['visual_m2','Galvanis','Galvanis',300000,'/m²',4],
  ['visual_m2','Flexy Frontlite','Flexy Frontlite',120000,'/m²',5],
  ['huruf_cm','Acrylic','Acrylic',12000,'/cm',1],
  ['huruf_cm','Stainless','Stainless',15000,'/cm',2],
  ['huruf_cm','Galvanis','Galvanis',14000,'/cm',3],
  ['komponen','rangkaPerM2','Rangka & Dudukan',250000,'/m²',1],
  ['komponen','elektrikalPerM2','Elektrikal / LED',200000,'/m²',2],
  ['komponen','tiangPerMeter','Tiang',600000,'/m',3],
  ['komponen','pasangDasar','Biaya Pasang Dasar',500000,'flat',4],
  ['pengali','Lantai 1','Lantai 1',1.0,'x',1],
  ['pengali','Lantai 2','Lantai 2',1.2,'x',2],
  ['pengali','Lantai 3+','Lantai 3+',1.4,'x',3],
];
if (db.prepare('SELECT COUNT(*) n FROM reklame_harga').get().n === 0) {
  const ins = db.prepare('INSERT INTO reklame_harga (kategori,kode,label,nilai,satuan,urutan) VALUES (?,?,?,?,?,?)');
  db.transaction(rows => rows.forEach(r => ins.run(...r)))(_seedReklame);
  console.log('[Bootstrap] Seed harga reklame ditambahkan.');
}
// Tambahan bahan (idempotent) untuk DB lama yang sudah berisi data
{
  const _ensureReklameRows = [
    ['huruf_cm','Galvanis','Galvanis',14000,'/cm',3],
  ];
  const insIgn = db.prepare('INSERT OR IGNORE INTO reklame_harga (kategori,kode,label,nilai,satuan,urutan) VALUES (?,?,?,?,?,?)');
  _ensureReklameRows.forEach(r => insIgn.run(...r));
}
if (db.prepare('SELECT COUNT(*) n FROM reklame_toko').get().n === 0) {
  db.prepare('INSERT INTO reklame_toko (id,nama,alamat,telepon) VALUES (1,?,?,?)')
    .run('RuangPrint', 'Jl. Gilimanuk No 60 Kalideres, Jakarta Barat', '0812 8816 1119');
}


// Migrasi kolom untuk DB lama
function ensureColumn(col, ddl) {
  try { db.prepare(`SELECT ${col} FROM users LIMIT 1`).get(); }
  catch { db.exec(`ALTER TABLE users ADD COLUMN ${ddl}`); }
}
ensureColumn('role',     "role TEXT DEFAULT 'cabang'");
ensureColumn('username', "username TEXT");
try { db.prepare('SELECT customer FROM label_prints LIMIT 1').get(); }
catch { db.exec("ALTER TABLE label_prints ADD COLUMN customer TEXT DEFAULT ''"); }

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
    } catch { return res.status(400).json({ error: 'Username sudah dipakai.' }); }
    return res.json({ ok: true });
  }

  if (!password) return res.status(400).json({ error: 'Password wajib untuk akun baru.' });
  try {
    db.prepare('INSERT INTO users (username,password_hash,name,cabang,role) VALUES (?,?,?,?,?)')
      .run(username, bcrypt.hashSync(password, 10), name, role === 'superadmin' ? 'HO' : code, role);
    res.json({ ok: true });
  } catch { res.status(400).json({ error: 'Username sudah terdaftar.' }); }
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

  const topCS = db.prepare(`
    SELECT cs_name, cabang, COUNT(*) AS count, COALESCE(SUM(grand_total),0) AS value
    FROM quotations WHERE cs_name IS NOT NULL AND cs_name != '-'
    GROUP BY cs_name, cabang ORDER BY value DESC LIMIT 5
  `).all();

  res.json({ totalBranches, totalQuotations, totalValue, perBranch, recent, byMonth, topCS });
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
  const { cabang, from, to } = req.query;
  const conds = [];
  const params = [];
  if (isAdmin(req.user)) {
    if (cabang && cabang !== 'semua') { conds.push('cabang=?'); params.push(cabang); }
  } else {
    conds.push('cabang=?'); params.push(req.user.cabang);
  }
  if (from) { conds.push('tanggal>=?'); params.push(from); }
  if (to)   { conds.push('tanggal<=?'); params.push(to); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const rows = db.prepare(`
    SELECT id,no_quotation,tipe,cabang,cs_name,customer,tanggal,grand_total,created_at
    FROM quotations ${where} ORDER BY created_at DESC LIMIT 1000
  `).all(...params);
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

// ── SURAT JALAN (delivery notes) — pola sama dgn quotations ───
app.get('/api/delivery-notes', auth, (req, res) => {
  const { cabang, from, to } = req.query;
  const conds = [];
  const params = [];
  if (isAdmin(req.user)) {
    if (cabang && cabang !== 'semua') { conds.push('cabang=?'); params.push(cabang); }
  } else {
    conds.push('cabang=?'); params.push(req.user.cabang);
  }
  if (from) { conds.push('tanggal>=?'); params.push(from); }
  if (to)   { conds.push('tanggal<=?'); params.push(to); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const rows = db.prepare(`
    SELECT id,no_sj,cabang,cs_name,customer,tanggal,ref_quotation,created_at
    FROM delivery_notes ${where} ORDER BY created_at DESC LIMIT 1000
  `).all(...params);
  res.json(rows);
});

app.post('/api/delivery-notes', auth, (req, res) => {
  const e = req.body;
  const cabang  = isAdmin(req.user) ? (e.cabang || '-') : req.user.cabang;
  const cs_name = isAdmin(req.user) ? (e.cs_name || '-') : (e.cs_name || req.user.name || '-');
  db.prepare(`
    INSERT INTO delivery_notes (id,no_sj,cabang,cs_name,customer,tanggal,ref_quotation,data_json,updated_at)
    VALUES (@id,@no_sj,@cabang,@cs_name,@customer,@tanggal,@ref_quotation,@data_json,CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      no_sj=excluded.no_sj, cabang=excluded.cabang, cs_name=excluded.cs_name,
      customer=excluded.customer, tanggal=excluded.tanggal, ref_quotation=excluded.ref_quotation,
      data_json=excluded.data_json, updated_at=CURRENT_TIMESTAMP
  `).run({
    id: e.id, no_sj: e.no_sj, cabang, cs_name,
    customer: e.customer, tanggal: e.tanggal,
    ref_quotation: e.ref_quotation || '', data_json: e.data_json
  });
  res.json({ ok: true });
});

app.get('/api/delivery-notes/:id/data', auth, (req, res) => {
  const row = db.prepare('SELECT cabang, data_json FROM delivery_notes WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  res.json({ data_json: row.data_json });
});

app.delete('/api/delivery-notes/:id', auth, (req, res) => {
  const row = db.prepare('SELECT cabang FROM delivery_notes WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  db.prepare('DELETE FROM delivery_notes WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/delivery-notes', auth, (req, res) => {
  if (isAdmin(req.user)) {
    const { cabang } = req.query;
    if (cabang && cabang !== 'semua') db.prepare('DELETE FROM delivery_notes WHERE cabang=?').run(cabang);
    else db.prepare('DELETE FROM delivery_notes').run();
  } else {
    db.prepare('DELETE FROM delivery_notes WHERE cabang=?').run(req.user.cabang);
  }
  res.json({ ok: true });
});

// ── CALC SAVES (hitungan kalkulator Offset/Booklet) ──────────
// Akses sama seperti quotations: cabang hanya melihat miliknya, superadmin semua.
const CALC_TOOLS = ['offset', 'booklet'];

app.get('/api/calc-saves', auth, (req, res) => {
  const { tool, cabang } = req.query;
  const conds = [];
  const params = [];
  if (tool) {
    if (!CALC_TOOLS.includes(tool)) return res.status(400).json({ error: 'Tool tidak dikenal.' });
    conds.push('tool=?'); params.push(tool);
  }
  if (isAdmin(req.user)) {
    if (cabang && cabang !== 'semua') { conds.push('cabang=?'); params.push(cabang); }
  } else {
    conds.push('cabang=?'); params.push(req.user.cabang);
  }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const rows = db.prepare(`
    SELECT id,tool,name,cabang,cs_name,summary,created_at,updated_at
    FROM calc_saves ${where} ORDER BY updated_at DESC LIMIT 1000
  `).all(...params);
  res.json(rows);
});

app.post('/api/calc-saves', auth, (req, res) => {
  const e = req.body || {};
  const tool = e.tool;
  if (!CALC_TOOLS.includes(tool)) return res.status(400).json({ error: 'Tool tidak dikenal.' });
  const name = (e.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Nama simpanan wajib diisi.' });
  const cabang  = isAdmin(req.user) ? (e.cabang || '-') : req.user.cabang;
  const cs_name = isAdmin(req.user) ? (e.cs_name || '-') : (req.user.name || '-');

  if (e.id) {
    const row = db.prepare('SELECT cabang FROM calc_saves WHERE id=?').get(e.id);
    if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
    db.prepare(`UPDATE calc_saves SET name=?, summary=?, data_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .run(name, e.summary || '', e.data_json, e.id);
    return res.json({ ok: true, id: e.id });
  }

  const info = db.prepare(`
    INSERT INTO calc_saves (tool,name,cabang,cs_name,summary,data_json)
    VALUES (?,?,?,?,?,?)
  `).run(tool, name, cabang, cs_name, e.summary || '', e.data_json);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/calc-saves/:id/data', auth, (req, res) => {
  const row = db.prepare('SELECT cabang, data_json FROM calc_saves WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  res.json({ data_json: row.data_json });
});

app.delete('/api/calc-saves/:id', auth, (req, res) => {
  const row = db.prepare('SELECT cabang FROM calc_saves WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  db.prepare('DELETE FROM calc_saves WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── KALKULATOR REKLAME: harga & info toko (master, global) ───
function bentukPriceDB(rows) {
  const out = {
    visualPerM2: {}, hurufTimbulPerCm: {},
    rangkaPerM2: 0, elektrikalPerM2: 0, tiangPerMeter: 0, pasangDasar: 0,
    pengaliKetinggian: {},
    _meta: { visual_m2: [], huruf_cm: [], komponen: [], pengali: [] },
  };
  for (const r of rows) {
    const nilai = Number(r.nilai);
    if (r.kategori === 'visual_m2')      out.visualPerM2[r.kode] = nilai;
    else if (r.kategori === 'huruf_cm')  out.hurufTimbulPerCm[r.kode] = nilai;
    else if (r.kategori === 'pengali')   out.pengaliKetinggian[r.kode] = nilai;
    else if (r.kategori === 'komponen')  out[r.kode] = nilai;
    if (out._meta[r.kategori]) out._meta[r.kategori].push(r);
  }
  return out;
}
const _selHarga = () => db.prepare('SELECT id,kategori,kode,label,nilai,satuan,urutan FROM reklame_harga ORDER BY kategori,urutan').all();

app.get('/api/reklame/harga', auth, (req, res) => res.json(bentukPriceDB(_selHarga())));

app.put('/api/reklame/harga', auth, adminOnly, (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  const upd = db.prepare('UPDATE reklame_harga SET nilai=?, label=COALESCE(?,label), satuan=COALESCE(?,satuan) WHERE id=?');
  const ins = db.prepare(`INSERT INTO reklame_harga (kategori,kode,label,nilai,satuan,urutan) VALUES (?,?,?,?,?,?)
    ON CONFLICT(kategori,kode) DO UPDATE SET nilai=excluded.nilai,label=excluded.label,satuan=excluded.satuan`);
  db.transaction(rows => {
    for (const it of rows) {
      if (it.id) upd.run(it.nilai, it.label ?? null, it.satuan ?? null, it.id);
      else if (it.kategori && it.kode) ins.run(it.kategori, it.kode, it.label || it.kode, it.nilai || 0, it.satuan || '', it.urutan || 99);
    }
  })(items);
  res.json(bentukPriceDB(_selHarga()));
});

app.get('/api/reklame/toko', auth, (req, res) => {
  const row = db.prepare('SELECT nama,alamat,telepon FROM reklame_toko WHERE id=1').get();
  res.json(row || { nama: 'RuangPrint', alamat: '', telepon: '' });
});

app.put('/api/reklame/toko', auth, adminOnly, (req, res) => {
  const { nama, alamat, telepon } = req.body || {};
  db.prepare(`INSERT INTO reklame_toko (id,nama,alamat,telepon) VALUES (1,?,?,?)
    ON CONFLICT(id) DO UPDATE SET nama=excluded.nama,alamat=excluded.alamat,telepon=excluded.telepon`)
    .run(nama || 'RuangPrint', alamat || '', telepon || '');
  res.json({ ok: true });
});

// ── PRINT LABEL (riwayat cetak label) ────────────────────────
// Akses sama seperti dokumen lain: cabang hanya melihat miliknya, superadmin semua.
app.get('/api/labels', auth, (req, res) => {
  const { cabang, from, to } = req.query;
  const conds = [];
  const params = [];
  if (isAdmin(req.user)) {
    if (cabang && cabang !== 'semua') { conds.push('cabang=?'); params.push(cabang); }
  } else {
    conds.push('cabang=?'); params.push(req.user.cabang);
  }
  if (from) { conds.push('tanggal>=?'); params.push(from); }
  if (to)   { conds.push('tanggal<=?'); params.push(to); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const rows = db.prepare(`
    SELECT id,cabang,cs_name,customer,tanggal,jml_label,kategori,summary,created_at
    FROM label_prints ${where} ORDER BY created_at DESC LIMIT 1000
  `).all(...params);
  res.json(rows);
});

app.post('/api/labels', auth, (req, res) => {
  const e = req.body || {};
  if (!e.id) return res.status(400).json({ error: 'id wajib.' });
  const cabang  = isAdmin(req.user) ? (e.cabang || '-') : req.user.cabang;
  const cs_name = isAdmin(req.user) ? (e.cs_name || '-') : (e.cs_name || req.user.name || '-');
  db.prepare(`
    INSERT INTO label_prints (id,cabang,cs_name,customer,tanggal,jml_label,kategori,summary,data_json,created_at)
    VALUES (@id,@cabang,@cs_name,@customer,@tanggal,@jml_label,@kategori,@summary,@data_json,CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      cabang=excluded.cabang, cs_name=excluded.cs_name, customer=excluded.customer, tanggal=excluded.tanggal,
      jml_label=excluded.jml_label, kategori=excluded.kategori, summary=excluded.summary,
      data_json=excluded.data_json
  `).run({
    id: String(e.id), cabang, cs_name, customer: e.customer || '',
    tanggal: e.tanggal || '', jml_label: parseInt(e.jml_label) || 0,
    kategori: e.kategori || '', summary: e.summary || '',
    data_json: e.data_json || '{}'
  });
  res.json({ ok: true, id: String(e.id) });
});

app.get('/api/labels/:id/data', auth, (req, res) => {
  const row = db.prepare('SELECT cabang, data_json FROM label_prints WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  res.json({ data_json: row.data_json });
});

app.delete('/api/labels/:id', auth, (req, res) => {
  const row = db.prepare('SELECT cabang FROM label_prints WHERE id=?').get(req.params.id);
  if (!canAccess(req.user, row)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  db.prepare('DELETE FROM label_prints WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/labels', auth, (req, res) => {
  if (isAdmin(req.user)) {
    const { cabang } = req.query;
    if (cabang && cabang !== 'semua') db.prepare('DELETE FROM label_prints WHERE cabang=?').run(cabang);
    else db.prepare('DELETE FROM label_prints').run();
  } else {
    db.prepare('DELETE FROM label_prints WHERE cabang=?').run(req.user.cabang);
  }
  res.json({ ok: true });
});

app.listen(PORT, '127.0.0.1', () =>
  console.log(`[RuangPrint API] Berjalan di port ${PORT} · DB: ${DB_PATH}`)
);
