#!/usr/bin/env node
/**
 * Kelola user RuangPrint (cadangan via SSH — normalnya pakai panel admin.html)
 *
 * Cara pakai (via SSH ke VPS):
 *   Tambah/update CS:
 *     node /opt/ruangprint-api/setup-user.js add ani@ruangprint.co.id Password123 "Ani Rahayu" DMB
 *
 *   Tambah/update superadmin (role di argumen ke-5):
 *     node /opt/ruangprint-api/setup-user.js add admin@ruangprint.co.id Pass123 "Admin" HO superadmin
 *
 *   Hapus user:
 *     node /opt/ruangprint-api/setup-user.js del ani@ruangprint.co.id
 *
 *   Lihat semua user:
 *     node /opt/ruangprint-api/setup-user.js list
 *
 * Kode cabang: HO | DMB | CTR | GDS | CGK | BKS
 * Role: cs (default) | superadmin
 */
'use strict';
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || '/var/lib/ruangprint/ruangprint.db';
const db = new Database(DB_PATH);

const [,, cmd, ...args] = process.argv;

if (cmd === 'add') {
  const [email, password, name, cabang, role] = args;
  if (!email || !password) {
    console.error('Penggunaan: node setup-user.js add <email> <password> "<nama>" <cabang> [role]');
    process.exit(1);
  }
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`
    INSERT INTO users (email, password_hash, name, cabang, role)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET
      password_hash=excluded.password_hash,
      name=excluded.name,
      cabang=excluded.cabang,
      role=excluded.role
  `).run(email.toLowerCase().trim(), hash, name || '', cabang || 'HO', role || 'cs');
  console.log(`✓ User "${email}" (${name || '-'} / ${cabang || 'HO'} / ${role || 'cs'}) berhasil ditambah/diupdate.`);

} else if (cmd === 'del') {
  const [email] = args;
  if (!email) { console.error('Penggunaan: node setup-user.js del <email>'); process.exit(1); }
  const result = db.prepare('DELETE FROM users WHERE email=?').run(email.toLowerCase().trim());
  console.log(result.changes ? `✓ User "${email}" dihapus.` : `⚠ User "${email}" tidak ditemukan.`);

} else if (cmd === 'list') {
  const users = db.prepare('SELECT id, email, name, cabang, role, created_at FROM users ORDER BY id').all();
  if (!users.length) { console.log('Belum ada user.'); }
  else {
    console.log(`\n${'ID'.padEnd(5)} ${'Email'.padEnd(30)} ${'Nama'.padEnd(18)} ${'Cabang'.padEnd(8)} Role`);
    console.log('─'.repeat(75));
    users.forEach(u => console.log(`${String(u.id).padEnd(5)} ${u.email.padEnd(30)} ${(u.name||'').padEnd(18)} ${(u.cabang||'').padEnd(8)} ${u.role||'cs'}`));
    console.log(`\nTotal: ${users.length} user`);
  }

} else {
  console.log(`
RuangPrint User Manager
  node setup-user.js add  <email> <password> "<nama>" <cabang>
  node setup-user.js del  <email>
  node setup-user.js list
`);
}
