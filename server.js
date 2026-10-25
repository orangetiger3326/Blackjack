// Blackjack Accounts – Server ohne externe Pakete (nur Node.js >= 16)
// Start:  ADMIN_USER=meinname ADMIN_PASS=meinpasswort node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS;
if (!ADMIN_PASS) { console.error('Bitte ADMIN_PASS setzen, z. B.: ADMIN_PASS=geheim node server.js'); process.exit(1); }

const FILE = path.join(process.env.DATA_DIR || __dirname, 'data.json');
let DATA = { players: [] };
try { DATA = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const save = () => { fs.writeFileSync(FILE + '.tmp', JSON.stringify(DATA)); fs.renameSync(FILE + '.tmp', FILE); };

const sessions = new Map();   // sid -> Ablaufzeit
const fails = new Map();      // ip -> { n, until }
const SESSION_MS = 12 * 3600 * 1000;

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const ipOf = req => (process.env.TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '') || req.socket.remoteAddress;

function send(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((ok, no) => {
    let s = '';
    req.on('data', c => { s += c; if (s.length > 10000) { req.destroy(); no(new Error('Anfrage zu groß')); } });
    req.on('end', () => { try { ok(JSON.parse(s || '{}')); } catch (e) { no(new Error('Ungültige Anfrage')); } });
  });
}
function cookie(req, name) {
  const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : null;
}
function isAdmin(req) {
  const sid = cookie(req, 'sid');
  const exp = sid && sessions.get(sid);
  if (exp && exp > Date.now()) return true;
  if (sid) sessions.delete(sid);
  return false;
}

// Öffentliche Daten: Rangliste (nur Name + letzter Wert) und – nur mit gültigem Spieler-Token – der eigene Verlauf
function publicData(token) {
  const me = token ? DATA.players.find(p => p.token === token) : null;
  const rank = {};
  for (let a = 1; a <= 5; a++) {
    rank[a] = [];
    for (const p of DATA.players) {
      const h = p.acc[a] || [];
      if (h.length) { const l = h[h.length - 1]; rank[a].push({ name: p.name, v: l.v, p: l.p || 0, mine: !!me && me.id === p.id }); }
    }
  }
  return { rank, me: me ? { name: me.name, acc: me.acc } : null };
}

const accOk = a => Number.isInteger(a) && a >= 1 && a <= 5;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
      return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    if (req.method === 'GET' && p === '/api/public') return send(res, 200, publicData(url.searchParams.get('t') || ''));
    if (req.method === 'GET' && p === '/api/session') return send(res, 200, { admin: isAdmin(req) });

    if (req.method === 'POST') {
      if (!String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { error: 'Nur JSON erlaubt' });
      const b = await readBody(req);

      if (p === '/api/login') {
        const ip = ipOf(req), f = fails.get(ip) || { n: 0, until: 0 };
        if (f.until > Date.now()) return send(res, 429, { error: 'Zu viele Versuche. Bitte in 15 Minuten erneut versuchen.' });
        const ok = same(b.user || '', ADMIN_USER) & same(b.pass || '', ADMIN_PASS);
        if (!ok) {
          f.n++; if (f.n >= 5) { f.n = 0; f.until = Date.now() + 15 * 60 * 1000; }
          fails.set(ip, f);
          return send(res, 401, { error: 'Benutzername oder Passwort falsch.' });
        }
        fails.delete(ip);
        const sid = crypto.randomBytes(24).toString('hex');
        sessions.set(sid, Date.now() + SESSION_MS);
        const secure = (req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https') ? '; Secure' : '';
        return send(res, 200, { ok: true }, { 'Set-Cookie': `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
      }
      if (p === '/api/logout') {
        sessions.delete(cookie(req, 'sid'));
        return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
      }

      if (!isAdmin(req)) return send(res, 401, { error: 'Nicht angemeldet.' });

      if (p === '/api/admin/player') {
        const name = String(b.name || '').trim().slice(0, 40);
        if (!name) return send(res, 400, { error: 'Name fehlt.' });
        DATA.players.push({ id: 'p' + Date.now(), name, token: crypto.randomBytes(8).toString('hex'), acc: {} });
        save(); return send(res, 200, { ok: true });
      }
      if (p === '/api/admin/remove-player') {
        DATA.players = DATA.players.filter(x => x.id !== b.id);
        save(); return send(res, 200, { ok: true });
      }
      if (p === '/api/admin/value') {
        const pl = DATA.players.find(x => x.id === b.id), a = Number(b.acc), v = Number(b.v), pr = Number(b.p || 0);
        if (!pl || !accOk(a) || !Number.isFinite(v) || !Number.isInteger(pr) || pr < 0 || pr > 20) return send(res, 400, { error: 'Ungültige Eingabe.' });
        (pl.acc[a] = pl.acc[a] || []).push({ v, p: pr, t: Date.now() });
        save(); return send(res, 200, { ok: true });
      }
      if (p === '/api/admin/delete-last') {
        const pl = DATA.players.find(x => x.id === b.id), a = Number(b.acc);
        if (!pl || !accOk(a) || !(pl.acc[a] || []).length) return send(res, 400, { error: 'Nichts zu löschen.' });
        pl.acc[a].pop(); save(); return send(res, 200, { ok: true });
      }
    }
    if (req.method === 'GET' && p === '/api/admin/data') {
      if (!isAdmin(req)) return send(res, 401, { error: 'Nicht angemeldet.' });
      return send(res, 200, DATA);
    }
    send(res, 404, { error: 'Nicht gefunden' });
  } catch (e) {
    send(res, 400, { error: e.message || 'Fehler' });
  }
});

server.listen(PORT, () => console.log(`Läuft auf http://localhost:${PORT}  (Admin: ${ADMIN_USER})`));
