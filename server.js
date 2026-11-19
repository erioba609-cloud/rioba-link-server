// RIOBA LINK pairing + signalling server. Zero dependencies (Node 18+).
// It never sees your files: it only introduces devices (5-digit code, approval, WebRTC signals).
'use strict';
const http = require('node:http');
const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');

const PORT = Number(process.env.PORT || 8080);
const SESSION_TTL = 5 * 60 * 1000;
const ATTEMPT_WINDOW = 10 * 60 * 1000;
const MAX_DEVICE_FAILS = 8;
const MAX_GLOBAL_FAILS_PER_MINUTE = 120;
const SLOTS = ['guest0', 'guest1', 'guest2', 'guest3'];

const TRUST_PROXY = process.env.TRUST_PROXY === '1';   // set when behind Render/Fly/nginx so the real client IP is used
const MAX_SESSIONS = 5000;
const MAX_SIGNALS_PER_SESSION = 400;
const ipHits = new Map();   // ip -> [timestamps]
function clientIp(req) {
  if (TRUST_PROXY) { const f = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(); if (f) return f; }
  return req.socket.remoteAddress || 'unknown';
}
// Sliding-window limit per IP: 120 requests/minute overall, 20 session creations per 10 minutes.
function rateLimited(ip, key, max, windowMs) {
  const k = ip + '|' + key, now = Date.now();
  const arr = (ipHits.get(k) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { ipHits.set(k, arr); return true; }
  arr.push(now); ipHits.set(k, arr); return false;
}

const sessions = new Map();   // id -> session
const signals = [];           // {sessionId, fromDeviceId, toDeviceId, signal, createdAt}
let attempts = [];            // {deviceId, ip, at}

const hash = v => createHash('sha256').update(String(v)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
function cleanProfile(p) {
  const name = String((p && p.name) || 'RIOBA LINK User').trim().replace(/[<>]/g, '').slice(0, 28);
  const avatar = String((p && p.avatar) || '🟢').slice(0, 8);
  return { name: name || 'RIOBA LINK User', avatar };
}
const guests = s => SLOTS.flatMap(slot => s[slot] ? [{ ...s[slot], slot }] : []);
const findGuest = (s, id) => SLOTS.find(slot => s[slot] && s[slot].deviceId === id);
const isHost = (s, key) => Boolean(key && safeEq(s.hostControlHash, hash(key)));
const modeOf = s => (s.mode === 'individual' ? 'individual' : 'group');

function authorized(id, token) {
  if (!id || !token) return null;
  const s = sessions.get(String(id));
  if (!s || !safeEq(s.tokenHash, hash(token))) return null;
  if (s.expiresAt < Date.now()) s.status = 'expired';
  return s;
}
const live = s => s && s.status !== 'expired';

function sweep() {
  const now = Date.now();
  for (const [id, s] of sessions) if (s.expiresAt < now - 10 * 60 * 1000 || (s.status === 'expired' && s.expiresAt < now - 60000)) sessions.delete(id);
  attempts = attempts.filter(a => now - a.at <= ATTEMPT_WINDOW);
  for (let i = signals.length - 1; i >= 0; i--) if (now - signals[i].createdAt > 2 * 60 * 1000 || !sessions.has(signals[i].sessionId)) signals.splice(i, 1);
}
setInterval(sweep, 30000).unref();

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };

const routes = {
  'GET /api/_healthcheck': () => ({ ok: true, uptimeSeconds: Math.round((Date.now() - stats.started) / 1000), liveRooms: sessions.size, requests: stats.requests, errors: stats.errors, roomsCreated: stats.rooms, service: 'RIOBA LINK', fileStorage: 'none', transferMode: 'direct-peer-to-peer', maxDevices: 5, accountRequired: false }),

  // Remote control: change these env vars on the host and every app sees it within minutes, no app update needed.
  'GET /api/config': () => ({
    minAppVersion: Number(process.env.MIN_APP_VERSION || 1),      // apps older than this show "please update"
    latestAppVersion: Number(process.env.LATEST_APP_VERSION || 1),
    farAwayEnabled: process.env.FAR_AWAY_ENABLED !== '0',         // set to 0 to switch far-away sharing off
    message: String(process.env.NOTICE || '').slice(0, 200)       // optional notice shown in the app
  }),

  'POST /api/pair-sessions': (b, ip) => {
    if (rateLimited(ip, 'create', 20, 10 * 60 * 1000)) fail(429, 'Too many rooms created. Try again later.');
    if (sessions.size >= MAX_SESSIONS) fail(503, 'Pairing is busy right now. Please try again.');
    const hostDeviceId = String(b.deviceId || '').slice(0, 80);
    if (!hostDeviceId) fail(400, 'A device ID is required.');
    stats.rooms++;
    const now = Date.now();
    const used = new Set([...sessions.values()].filter(s => s.expiresAt > now && s.status !== 'expired').map(s => s.pairingCode));
    let code = '';
    for (let i = 0; i < 25 && (!code || used.has(code)); i++) code = String(10000 + (randomBytes(4).readUInt32BE(0) % 90000));
    if (used.has(code)) fail(503, 'Pairing is busy right now. Please try again.');
    const id = randomBytes(16).toString('hex');
    const token = randomBytes(32).toString('base64url');
    const hostControlKey = randomBytes(32).toString('base64url');
    const s = {
      id, tokenHash: hash(token), tokenValue: token, pairingCode: code, hostControlHash: hash(hostControlKey),
      hostDeviceId, hostProfile: cleanProfile(b.profile), mode: b.mode === 'individual' ? 'individual' : 'group',
      status: 'waiting', createdAt: now, expiresAt: now + SESSION_TTL
    };
    sessions.set(id, s);
    return [201, { session: { id, token, status: s.status, createdAt: now, expiresAt: s.expiresAt, hostDeviceId, hostProfile: s.hostProfile, mode: s.mode, pairingCode: code, guests: [] }, pairCode: code, hostControlKey }];
  },

  'POST /api/pair-sessions/lookup-code': (b, ip) => {
    const code = String(b.code || '').replace(/\D/g, '').slice(0, 5);
    if (!/^\d{5}$/.test(code)) fail(400, 'Enter a valid five-digit pairing code.');
    const deviceId = String(b.deviceId || '').slice(0, 80);
    if (!deviceId) fail(400, 'A device ID is required.');
    const now = Date.now();
    const mine = attempts.filter(a => (a.deviceId === deviceId || a.ip === ip) && now - a.at <= ATTEMPT_WINDOW).length;
    const minute = attempts.filter(a => now - a.at <= 60000).length;
    if (mine >= MAX_DEVICE_FAILS) fail(429, 'Too many wrong codes. Wait a few minutes, then try again.');
    if (minute >= MAX_GLOBAL_FAILS_PER_MINUTE) fail(429, 'Pairing is busy right now. Please try again in a minute.');
    const m = [...sessions.values()].find(s => s.pairingCode === code && s.expiresAt > now && s.status !== 'expired' && guests(s).length < (modeOf(s) === 'individual' ? 1 : 4));
    if (!m) { attempts.push({ deviceId, ip, at: now }); fail(404, 'That five-digit code is invalid, full or has expired.'); }
    return { id: m.id, token: m.tokenValue, mode: modeOf(m) };
  },

  'POST /api/pair-sessions/join': b => {
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(404, 'Invitation is invalid or has expired.');
    const mode = modeOf(s);
    if (b.mode && b.mode !== mode) fail(409, 'This invitation is for ' + mode + ' sharing.');
    const deviceId = String(b.deviceId || '').slice(0, 80);
    if (!deviceId || deviceId === s.hostDeviceId) fail(400, 'A different device is required to join this session.');
    const view = (status) => ({ id: s.id, status, createdAt: s.createdAt, expiresAt: s.expiresAt, hostDeviceId: s.hostDeviceId, hostProfile: s.hostProfile, mode, guestDeviceId: deviceId, guests: guests(s) });
    const slot = findGuest(s, deviceId);
    if (slot) {
      const g = s[slot];
      return { session: view(g.status), message: g.status === 'approved' ? 'This device is already approved.' : 'Your request is awaiting host approval.' };
    }
    if (guests(s).length >= (mode === 'individual' ? 1 : 4)) fail(409, 'This ' + mode + ' invitation is full.');
    const p = cleanProfile(b.profile);
    const free = SLOTS.find(k => !s[k]);
    if (!free) fail(409, 'This group is full. RIOBA LINK allows one host and four guests.');
    s[free] = { deviceId, deviceName: p.name, avatar: p.avatar, status: 'pending', joinedAt: Date.now() };
    return { session: view('pending'), message: 'Request sent. Waiting for host approval.' };
  },

  'POST /api/pair-sessions/refresh': b => {
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(404, 'Session not found or invitation expired.');
    if (String(b.deviceId || '') !== s.hostDeviceId || !isHost(s, b.hostControlKey)) fail(403, 'Only the host device can refresh this invitation.');
    s.expiresAt = Date.now() + SESSION_TTL;
    return { session: { id: s.id, status: s.status, mode: modeOf(s), createdAt: s.createdAt, expiresAt: s.expiresAt, hostDeviceId: s.hostDeviceId, hostProfile: s.hostProfile, guests: guests(s) } };
  },

  'POST /api/pair-sessions/profile': b => {
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(404, 'The group session is no longer active.');
    const deviceId = String(b.deviceId || '');
    const p = cleanProfile(b.profile);
    if (deviceId === s.hostDeviceId) {
      if (!isHost(s, b.hostControlKey)) fail(403, 'Only the host device can update this profile.');
      s.hostProfile = p;
    } else {
      const slot = findGuest(s, deviceId);
      if (!slot || s[slot].status === 'denied') fail(403, 'This device is not an active group member.');
      s[slot] = { ...s[slot], deviceName: p.name, avatar: p.avatar };
    }
    return { session: { id: s.id, hostProfile: s.hostProfile, guests: guests(s) } };
  },

  'POST /api/pair-sessions/decision': b => {
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(404, 'Session not found or invitation expired.');
    if (!isHost(s, b.hostControlKey)) fail(403, 'Only the host device can approve requests.');
    const slot = findGuest(s, b.guestDeviceId || '');
    if (!slot) fail(404, 'That device is not a member of this group.');
    if (s[slot].status !== 'pending') fail(409, 'There is no pending request for that device.');
    s[slot] = { ...s[slot], status: b.allow === true ? 'approved' : 'denied' };
    return { session: { id: s.id, status: s.status, hostProfile: s.hostProfile, guests: guests(s) } };
  },

  'POST /api/pair-sessions/close': b => {
    const s = authorized(b.id, b.token);
    if (!s) fail(404, 'Session not found or invitation expired.');
    if (!isHost(s, b.hostControlKey)) fail(403, 'Only the host device can close this session.');
    s.status = 'expired';
    return { ok: true };
  },

  // Real-time push is replaced by polling (refresh / join / signals pull), so this is a harmless no-op kept for the web app.
  'POST /api/subscriptions': () => ({ ok: true }),

  'POST /api/peer/signals/push': b => {
    if ((b.role !== 'host' && b.role !== 'guest') || !b.signal) fail(400, 'Invalid peer signal.');
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(403, 'A live group session is required.');
    const from = String(b.fromDeviceId || ''), to = String(b.toDeviceId || '');
    if (!from || !to || from === to) fail(403, 'No approved peer is available.');
    if (b.role === 'host') {
      if (!isHost(s, b.hostControlKey) || s.hostDeviceId !== from) fail(403, 'Host device is not authorised.');
      if (!guests(s).find(g => g.deviceId === to && g.status === 'approved')) fail(403, 'The receiving guest is not approved.');
    } else {
      if (!guests(s).find(g => g.deviceId === from && g.status === 'approved') || to !== s.hostDeviceId) fail(403, 'This guest device is not approved for the group.');
    }
    if (JSON.stringify(b.signal).length > 100000) fail(413, 'Peer signal is too large.');
    if (signals.filter(x => x.sessionId === s.id).length >= MAX_SIGNALS_PER_SESSION) fail(429, 'Too many pending signals.');
    signals.push({ sessionId: s.id, fromDeviceId: from, toDeviceId: to, signal: b.signal, createdAt: Date.now() });
    return { ok: true };
  },

  'POST /api/peer/signals/pull': b => {
    if (b.role !== 'host' && b.role !== 'guest') fail(400, 'Invalid device identity.');
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(403, 'A live group session is required.');
    const deviceId = String(b.deviceId || '');
    if (!deviceId) fail(400, 'A device ID is required.');
    if (b.role === 'host') {
      if (!isHost(s, b.hostControlKey) || s.hostDeviceId !== deviceId) fail(403, 'Host device is not authorised.');
    } else if (!guests(s).find(g => g.deviceId === deviceId && g.status === 'approved')) fail(403, 'This guest device is not approved.');
    const out = [];
    for (let i = 0; i < signals.length; i++) {
      const x = signals[i];
      if (x.sessionId === s.id && x.toDeviceId === deviceId) { out.push({ fromDeviceId: x.fromDeviceId, signal: x.signal }); signals.splice(i--, 1); }
    }
    return { signals: out };
  },

  'POST /api/ice-config': async b => {
    if (b.role !== 'host' && b.role !== 'guest') fail(400, 'Invalid device identity.');
    const s = authorized(b.id, b.token);
    if (!s || !live(s)) fail(403, 'A live sharing session is required.');
    const deviceId = String(b.deviceId || '');
    if (b.role === 'host') {
      if (!isHost(s, b.hostControlKey) || s.hostDeviceId !== deviceId) fail(403, 'Host device is not authorised.');
    } else if (!guests(s).find(g => g.deviceId === deviceId && g.status === 'approved')) fail(403, 'This guest is not approved for the session.');
    const keyId = process.env.CF_TURN_KEY_ID || '', apiToken = process.env.CF_TURN_API_TOKEN || '';
    if (!keyId || !apiToken) return { relayAvailable: false, iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }, { urls: 'stun:stun.l.google.com:19302' }] };
    try {
      const r = await fetch('https://rtc.live.cloudflare.com/v1/turn/keys/' + encodeURIComponent(keyId) + '/credentials/generate-ice-servers', {
        method: 'POST', headers: { Authorization: 'Bearer ' + apiToken, 'Content-Type': 'application/json' }, body: JSON.stringify({ ttl: 3600 })
      });
      if (!r.ok) fail(503, 'Relay credentials could not be issued. Please retry shortly.');
      const p = await r.json();
      const iceServers = Array.isArray(p.iceServers) ? p.iceServers : [];
      if (!iceServers.length) fail(502, 'Relay provider returned no ICE servers.');
      return { relayAvailable: true, iceServers };
    } catch (e) {
      if (e instanceof HttpError) throw e;
      fail(503, 'Relay service is temporarily unavailable.');
    }
  }
};

// The phone apps do not need CORS, so no cross-origin website can call this server from a browser.
const SEC = { 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'Referrer-Policy': 'no-referrer', 'Strict-Transport-Security': 'max-age=31536000' };
function send(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data), 'Cache-Control': 'no-store', ...SEC });
  res.end(data);
}

const stats = { started: Date.now(), requests: 0, errors: 0, rooms: 0 };
function log(obj) { console.log(JSON.stringify({ t: new Date().toISOString(), ...obj })); }

const server = http.createServer((req, res) => {
  const t0 = Date.now(); stats.requests++;
  res.on('finish', () => { if (res.statusCode >= 400) stats.errors++; if (res.statusCode >= 500 || res.statusCode === 429) log({ level: 'warn', method: req.method, path: (req.url || '').split('?')[0], status: res.statusCode, ms: Date.now() - t0 }); });
  const ip = clientIp(req);
  if (rateLimited(ip, 'all', 240, 60 * 1000)) return send(res, 429, { error: 'Too many requests. Slow down.' });
  if (req.method === 'OPTIONS') { res.writeHead(204, SEC); return res.end(); }
  const path = (req.url || '').split('?')[0].replace(/\/+$/, '') || '/';
  if (path === '/' && req.method === 'GET') return send(res, 200, { ok: true, service: 'RIOBA LINK server' });
  const handler = routes[req.method + ' ' + path];
  if (!handler) return send(res, 404, { error: 'Not found' });
  const chunks = []; let size = 0;
  req.on('data', c => { size += c.length; if (size > 200000) { send(res, 413, { error: 'Request too large.' }); req.destroy(); } else chunks.push(c); });
  req.on('end', async () => {
    let body = {};
    if (chunks.length) { try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) || {}; } catch { return send(res, 400, { error: 'Invalid JSON.' }); } }
    try {
      const out = await handler(body, ip);
      if (Array.isArray(out)) send(res, out[0], out[1]); else send(res, 200, out);
    } catch (e) {
      if (e instanceof HttpError) send(res, e.status, { error: e.message });
      else { console.error(e); send(res, 500, { error: 'Server error.' }); }
    }
  });
});
server.headersTimeout = 15000; server.requestTimeout = 20000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 50;
setInterval(() => { const now = Date.now(); for (const [k, v] of ipHits) { const f = v.filter(t => now - t < 10 * 60 * 1000); if (f.length) ipHits.set(k, f); else ipHits.delete(k); } }, 60000).unref();
server.listen(PORT, '0.0.0.0', () => console.log('RIOBA LINK server listening on :' + PORT));
