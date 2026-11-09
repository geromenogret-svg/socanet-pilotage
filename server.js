'use strict';
// Socanet Services — planning & pointage — serveur (Node >= 22, sans dépendance)
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(DATA_DIR, 'backups');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SETUP_TOKEN = process.env.SETUP_TOKEN || '';
const COLLS = ['ivs', 'abs', 'types', 'contrats', 'chantiers', 'emps', 'contracts', 'params', 'log', 'weeks'];

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'socanet.db'));
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS docs(coll TEXT, id TEXT, json TEXT NOT NULL, ver INTEGER NOT NULL, PRIMARY KEY(coll,id));
CREATE INDEX IF NOT EXISTS docs_ver ON docs(ver);
CREATE TABLE IF NOT EXISTS tomb(coll TEXT, id TEXT, ver INTEGER NOT NULL, PRIMARY KEY(coll,id));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS users(login TEXT PRIMARY KEY, name TEXT, role TEXT NOT NULL, emp TEXT, hash TEXT, salt TEXT, active INTEGER DEFAULT 1, fails INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0, updated INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, login TEXT NOT NULL, expires INTEGER NOT NULL);
`);

/* ---------- utilitaires ---------- */
const now = () => Date.now();
const getMeta = k => { const r = db.prepare('SELECT v FROM meta WHERE k=?').get(k); return r ? r.v : null; };
const setMeta = (k, v) => db.prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v));
const getVersion = () => +(getMeta('version') || 0);
function hashSecret(secret, salt) { return crypto.scryptSync(String(secret), salt, 32).toString('hex'); }
function checkSecret(u, secret) { if (!u.hash) return false; const h = hashSecret(secret, u.salt); return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(u.hash, 'hex')); }
function setSecret(login, secret) { const salt = crypto.randomBytes(16).toString('hex'); db.prepare('UPDATE users SET hash=?, salt=?, fails=0, locked_until=0, updated=? WHERE login=?').run(hashSecret(secret, salt), salt, now(), login); }
const genCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
function todayMQ(offsetDays = 0) { const d = new Date(Date.now() + offsetDays * 864e5); return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Martinique', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d); }
const toMin = t => { const a = String(t).split(':').map(Number); return a[0] * 60 + a[1]; };
const isTime = t => typeof t === 'string' && /^\d{2}:\d{2}$/.test(t);
function getDoc(coll, id) { const r = db.prepare('SELECT json FROM docs WHERE coll=? AND id=?').get(coll, id); return r ? JSON.parse(r.json) : null; }
function allDocs(coll) { return db.prepare('SELECT json FROM docs WHERE coll=?').all(coll).map(r => JSON.parse(r.json)); }

/* ---------- données initiales ---------- */
if (getVersion() === 0 && !db.prepare('SELECT 1 FROM docs LIMIT 1').get()) {
  const seedFile = path.join(__dirname, 'seed.json');
  if (fs.existsSync(seedFile)) {
    const seed = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
    const ins = db.prepare('INSERT INTO docs(coll,id,json,ver) VALUES(?,?,?,1)');
    db.exec('BEGIN');
    for (const coll of Object.keys(seed)) for (const o of seed[coll]) ins.run(coll, String(o.id), JSON.stringify(o));
    db.exec('COMMIT');
    setMeta('version', 1);
    console.log('Données initiales chargées');
  }
}

/* ---------- sessions ---------- */
function parseCookies(req) { const out = {}; (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); }); return out; }
function currentUser(req) {
  const tok = parseCookies(req).sid; if (!tok) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(tok); if (!s || s.expires < now()) return null;
  const u = db.prepare('SELECT * FROM users WHERE login=? AND active=1').get(s.login); if (!u) return null;
  u.token = tok; return u;
}
function publicUser(u) { if (!u) return null; const e = u.emp ? getDoc('emps', u.emp) : null; return { login: u.login, name: u.name || (e ? e.prenom + ' ' + e.nom : u.login), role: u.role, emp: u.emp || null }; }
function teamOf(u) { const emps = allDocs('emps'); const set = new Set([u.emp]); if (u.role === 'chef') emps.filter(e => e.chef === u.emp).forEach(e => set.add(e.id)); return set; }

/* ---------- visibilité ---------- */
function visibleFilter(u) {
  if (u.role === 'admin' || u.role === 'gest') return () => true;
  const team = teamOf(u);
  return (coll, o) => {
    switch (coll) {
      case 'ivs': case 'abs': return team.has(o.emp);
      case 'emps': return team.has(o.id);
      case 'contracts': return o.id === u.emp;
      case 'types': return o.emp === u.emp;
      case 'params': case 'weeks': return true;
      case 'chantiers': return u.role === 'chef' && (o.slots || []).some(s => team.has(s.emp));
      default: return false;
    }
  };
}
function stateFor(u, since) {
  const vis = visibleFilter(u); const version = getVersion();
  const up = {}, del = {};
  const rows = since > 0 ? db.prepare('SELECT coll, json FROM docs WHERE ver>?').all(since) : db.prepare('SELECT coll, json FROM docs').all();
  for (const r of rows) { const o = JSON.parse(r.json); if (vis(r.coll, o)) (up[r.coll] = up[r.coll] || []).push(o); }
  if (since > 0) for (const t of db.prepare('SELECT coll, id FROM tomb WHERE ver>?').all(since)) (del[t.coll] = del[t.coll] || []).push(t.id);
  return { version, full: !(since > 0), up, del };
}

/* ---------- écriture ---------- */
class Refus extends Error { constructor(m) { super(m); this.status = 403; } }
function checkIvChange(u, oldIv, nv, params) {
  const team = teamOf(u);
  if (!oldIv) throw new Refus('Création d\'intervention réservée à la gestion');
  if (!team.has(oldIv.emp)) throw new Refus('Intervention hors de ton périmètre');
  const ref = { ...oldIv };
  if (oldIv.emp !== u.emp) { // chef qui valide un écart de son équipe
    if (u.role !== 'chef' || oldIv.status !== 'ecart' || nv.status !== 'validee_chef') throw new Refus('Action non autorisée');
    return { ...oldIv, status: 'validee_chef', chefBy: (getDoc('emps', u.emp) || {}).prenom || u.login };
  }
  // le salarié (ou le chef) pointe ses propres heures
  if (oldIv.date > todayMQ() || oldIv.date < todayMQ(-7)) throw new Refus('Pointage possible uniquement sur les 7 derniers jours');
  if (oldIv.decision || oldIv.validBy || ['validee_chef', 'refusee'].includes(oldIv.status)) throw new Refus('Journée déjà validée par la gestion');
  const allowed = ['rs', 're', 'status', 'motif'];
  for (const k of Object.keys({ ...ref, ...nv })) if (!allowed.includes(k) && JSON.stringify(ref[k]) !== JSON.stringify(nv[k])) throw new Refus('Champ non modifiable : ' + k);
  const out = { ...oldIv, rs: nv.rs ?? null, re: nv.re ?? null, motif: String(nv.motif || '').slice(0, 200) };
  if (out.rs && !isTime(out.rs) || out.re && !isTime(out.re)) throw new Refus('Heure invalide');
  if (out.rs && out.re) {
    if (toMin(out.re) <= toMin(out.rs)) throw new Refus('Départ avant l\'arrivée');
    const diff = (toMin(out.re) - toMin(out.rs)) - (toMin(out.pe) - toMin(out.ps));
    out.status = Math.abs(diff) > (+params.tol || 15) ? 'ecart' : 'validee'; out.decision = null;
  } else if (out.rs) out.status = 'en_cours'; else out.status = 'prevue';
  return out;
}
function applySync(u, changes) {
  const isMgr = u.role === 'admin' || u.role === 'gest';
  const params = getDoc('params', 'p') || { tol: 15 };
  const version = getVersion() + 1;
  const ups = db.prepare('INSERT INTO docs(coll,id,json,ver) VALUES(?,?,?,?) ON CONFLICT(coll,id) DO UPDATE SET json=excluded.json, ver=excluded.ver');
  const delDoc = db.prepare('DELETE FROM docs WHERE coll=? AND id=?');
  const tomb = db.prepare('INSERT INTO tomb(coll,id,ver) VALUES(?,?,?) ON CONFLICT(coll,id) DO UPDATE SET ver=excluded.ver');
  const untomb = db.prepare('DELETE FROM tomb WHERE coll=? AND id=?');
  const me = publicUser(u);
  let n = 0;
  db.exec('BEGIN');
  try {
    for (const coll of Object.keys(changes || {})) {
      if (!COLLS.includes(coll)) throw new Refus('Collection inconnue');
      const c = changes[coll] || {};
      if (!isMgr) {
        if (!['ivs', 'log'].includes(coll) || (c.del || []).length) throw new Refus('Modification réservée à la gestion');
      } else if (u.role === 'gest' && coll === 'params') throw new Refus('Paramètres réservés à l\'administrateur');
      for (let o of (c.up || [])) {
        if (!o || typeof o.id !== 'string' || o.id.length > 120) throw new Refus('Identifiant invalide');
        if (coll === 'log') o = { id: o.id, at: new Date().toLocaleString('fr-FR', { timeZone: 'America/Martinique' }), by: me.name, txt: String(o.txt || '').slice(0, 300) };
        else if (coll === 'ivs' && !isMgr) o = checkIvChange(u, getDoc('ivs', o.id), o, params);
        ups.run(coll, o.id, JSON.stringify(o), version); untomb.run(coll, o.id); n++;
      }
      for (const id of (c.del || [])) { delDoc.run(coll, String(id)); tomb.run(coll, String(id), version); n++; }
    }
    if (n) setMeta('version', version);
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  return n;
}

/* ---------- sauvegardes ---------- */
function backupNow(tag) {
  const file = path.join(BACKUP_DIR, 'socanet-' + (tag || todayMQ()) + '.db');
  try { fs.rmSync(file, { force: true }); db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`); } catch (e) { console.error('Sauvegarde échouée', e.message); return null; }
  const files = fs.readdirSync(BACKUP_DIR).filter(f => /^socanet-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
  while (files.length > 30) fs.rmSync(path.join(BACKUP_DIR, files.shift()), { force: true });
  return file;
}
setInterval(() => { const h = +new Intl.DateTimeFormat('en-US', { timeZone: 'America/Martinique', hour: 'numeric', hour12: false }).format(new Date()); if (h === 2 && getMeta('lastBackup') !== todayMQ()) { if (backupNow()) setMeta('lastBackup', todayMQ()); } }, 10 * 60 * 1000);
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(now()), 3600 * 1000);

/* ---------- HTTP ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.png': 'image/png', '.js': 'text/javascript', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml' };
function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, { 'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY', ...headers });
  res.end(isObj ? JSON.stringify(body) : body);
}
function readBody(req) { return new Promise((resolve, reject) => { let size = 0; const chunks = []; req.on('data', c => { size += c.length; if (size > 5e6) { reject(Object.assign(new Error('Requête trop grosse'), { status: 413 })); req.destroy(); } else chunks.push(c); }); req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(Object.assign(new Error('JSON invalide'), { status: 400 })); } }); req.on('error', reject); }); }
function setSession(res, login, role) {
  const token = crypto.randomBytes(32).toString('hex'); const days = (role === 'admin' || role === 'gest') ? 7 : 60;
  db.prepare('INSERT INTO sessions(token,login,expires) VALUES(?,?,?)').run(token, login, now() + days * 864e5);
  res.setHeader('Set-Cookie', `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${days * 86400}`);
}
const ipFails = new Map();
function serveStatic(req, res, p) {
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (file.startsWith(PUBLIC_DIR) && !fs.existsSync(file) && fs.existsSync(file + '.b64')) { const buf = Buffer.from(fs.readFileSync(file + '.b64', 'utf8').trim(), 'base64'); res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'public, max-age=86400' }); return res.end(buf); }
  if (file.startsWith(PUBLIC_DIR) && !fs.existsSync(file) && fs.existsSync(file + '.b64')) { const buf = Buffer.from(fs.readFileSync(file + '.b64', 'utf8').trim(), 'base64'); res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'public, max-age=86400' }); return res.end(buf); }
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Introuvable');
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': p === '/index.html' ? 'no-cache' : 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY' });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'); const p = url.pathname;
  try {
    if (!p.startsWith('/api/')) return serveStatic(req, res, p);
    if (req.method === 'GET' && p === '/api/health') return send(res, 200, { ok: true, version: getVersion() });
    const hasAdmin = !!db.prepare("SELECT 1 FROM users WHERE role='admin' AND hash IS NOT NULL").get();
    if (p === '/api/setup' && req.method === 'POST') {
      if (hasAdmin) return send(res, 409, { error: 'Déjà configuré' });
      const b = await readBody(req);
      if (!SETUP_TOKEN || b.token !== SETUP_TOKEN) return send(res, 403, { error: 'Code d\'installation incorrect' });
      if (!b.login || String(b.password || '').length < 10) return send(res, 400, { error: 'Mot de passe de 10 caractères minimum' });
      const login = String(b.login).trim().toLowerCase();
      db.prepare('INSERT INTO users(login,name,role,active,updated) VALUES(?,?,?,1,?) ON CONFLICT(login) DO UPDATE SET role=excluded.role').run(login, String(b.name || 'Administrateur'), 'admin', now());
      setSecret(login, b.password); setSession(res, login, 'admin');
      return send(res, 200, { user: publicUser(db.prepare('SELECT * FROM users WHERE login=?').get(login)) });
    }
    if (p === '/api/login' && req.method === 'POST') {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress; const f = ipFails.get(ip) || { n: 0, t: now() };
      if (f.n >= 30 && now() - f.t < 15 * 60e3) return send(res, 429, { error: 'Trop de tentatives, réessaie dans 15 minutes' });
      const b = await readBody(req); const login = String(b.login || '').trim().toLowerCase();
      const u = db.prepare('SELECT * FROM users WHERE login=? AND active=1').get(login);
      if (u && u.locked_until > now()) return send(res, 429, { error: 'Compte bloqué 15 minutes après 5 erreurs' });
      if (!u || !checkSecret(u, String(b.code || ''))) {
        ipFails.set(ip, { n: (now() - f.t > 15 * 60e3 ? 0 : f.n) + 1, t: now() - f.t > 15 * 60e3 ? now() : f.t });
        if (u) { const fails = u.fails + 1; db.prepare('UPDATE users SET fails=?, locked_until=? WHERE login=?').run(fails >= 5 ? 0 : fails, fails >= 5 ? now() + 15 * 60e3 : 0, login); }
        return send(res, 401, { error: 'Identifiant ou code incorrect' });
      }
      db.prepare('UPDATE users SET fails=0 WHERE login=?').run(login); setSession(res, login, u.role);
      return send(res, 200, { user: publicUser(u) });
    }
    const u = currentUser(req);
    if (p === '/api/me') return send(res, 200, { user: publicUser(u), setup: !hasAdmin });
    if (!u) return send(res, 401, { error: 'Non connecté' });
    if (p === '/api/logout' && req.method === 'POST') { db.prepare('DELETE FROM sessions WHERE token=?').run(u.token); return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax' }); }
    if (p === '/api/state' && req.method === 'GET') return send(res, 200, stateFor(u, +url.searchParams.get('since') || 0));
    if (p === '/api/sync' && req.method === 'POST') {
      const b = await readBody(req); const since = +b.since || 0;
      applySync(u, b.changes || {});
      return send(res, 200, stateFor(u, since));
    }
    if (p === '/api/password' && req.method === 'POST') {
      const b = await readBody(req); if (!checkSecret(u, String(b.old || ''))) return send(res, 403, { error: 'Mot de passe actuel incorrect' });
      if ((u.role === 'admin' || u.role === 'gest') && String(b.password || '').length < 10) return send(res, 400, { error: '10 caractères minimum' });
      setSecret(u.login, b.password); db.prepare('DELETE FROM sessions WHERE login=? AND token<>?').run(u.login, u.token); return send(res, 200, { ok: true });
    }
    // ---- administration des comptes (admin uniquement) ----
    if (p.startsWith('/api/users') || p === '/api/backup') { if (u.role !== 'admin') return send(res, 403, { error: 'Réservé à l\'administrateur' }); }
    if (p === '/api/users' && req.method === 'GET') return send(res, 200, db.prepare('SELECT login,name,role,emp,active,(hash IS NOT NULL) AS hasCode,locked_until,updated FROM users ORDER BY role, login').all());
    if (p === '/api/users' && req.method === 'POST') {
      const b = await readBody(req); const login = String(b.login || '').trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,40}$/.test(login)) return send(res, 400, { error: 'Identifiant : 3 à 40 lettres, chiffres, point ou tiret' });
      const role = ['gest', 'chef', 'sal'].includes(b.role) ? b.role : null; if (!role) return send(res, 400, { error: 'Rôle invalide' });
      const exists = db.prepare('SELECT * FROM users WHERE login=?').get(login);
      if (exists && exists.role === 'admin') return send(res, 400, { error: 'Compte administrateur non modifiable ici' });
      if (b.emp) { const other = db.prepare('SELECT login FROM users WHERE emp=? AND login<>?').get(b.emp, login); if (other) db.prepare('UPDATE users SET active=0 WHERE login=?').run(other.login); }
      db.prepare('INSERT INTO users(login,name,role,emp,active,updated) VALUES(?,?,?,?,?,?) ON CONFLICT(login) DO UPDATE SET name=excluded.name, role=excluded.role, emp=excluded.emp, active=excluded.active, updated=excluded.updated').run(login, String(b.name || ''), role, b.emp || null, b.active === false ? 0 : 1, now());
      let code = null;
      if (role === 'gest') { if (b.password) { if (String(b.password).length < 10) return send(res, 400, { error: '10 caractères minimum' }); setSecret(login, b.password); } }
      else if (b.newCode || !exists || !exists.hash) { code = genCode(); setSecret(login, code); db.prepare('DELETE FROM sessions WHERE login=?').run(login); }
      return send(res, 200, { ok: true, login, code });
    }
    if (p === '/api/backup' && req.method === 'GET') {
      const f = backupNow('manuel-' + todayMQ()); if (!f) return send(res, 500, { error: 'Sauvegarde impossible' });
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="socanet-${todayMQ()}.db"`, 'Cache-Control': 'no-store' });
      return fs.createReadStream(f).pipe(res);
    }
    return send(res, 404, { error: 'Introuvable' });
  } catch (e) {
    if (!e.status) console.error(e);
    return send(res, e.status || 500, { error: e.status ? e.message : 'Erreur serveur' });
  }
});
server.listen(PORT, () => console.log('Socanet pointage — port ' + PORT + ' — version des données ' + getVersion()));
