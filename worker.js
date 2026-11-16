// DC SH!FTZ server: one Cloudflare Worker serves the app (from /public) and its API (/api/*),
// backed by one D1 (SQLite) database. Records are stored as JSON documents in a single table,
// so the app keeps the same data shapes it had as a Claude artifact.
//
// Security model
// - Login codes are hashed (SHA-256 with a per-person salt) and only ever checked here.
// - Every API call needs a session token from /api/login or /api/setup.
// - Reads are filtered by role (employees never receive login hashes, other people's direct
//   messages, other people's alerts, the audit log, or manager-only notes and no-show details).
// - Writes go through per-collection rules below. Test-mode data ("t_" collections) is open to
//   managers and admins only, and never touches live data.

const LIVE_COLS = ["staff", "settings", "requests", "volunteers", "inbox", "shift_audit_logs", "messages", "chatread"];
const TEST_PREFIX = "t_";
const SESSION_DAYS = 30;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 10;
const MAX_OPS = 200;

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code || "error"; }
}
const fail = (status, message, code) => { throw new HttpError(status, message, code); };

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});

// ---------- crypto helpers ----------
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function sha256(text) { return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))); }
const hashPin = (salt, pin) => sha256("shiftz:" + salt + ":" + pin); // same scheme as the artifact version, so existing codes keep working
const randomHex = (bytes) => hex(crypto.getRandomValues(new Uint8Array(bytes)));
const newId = () => { const a = "abcdefghijklmnopqrstuvwxyz0123456789", r = crypto.getRandomValues(new Uint8Array(20)); return [...r].map(x => a[x % 36]).join(""); };
const isCode = (v) => typeof v === "string" && /^\d{5}$/.test(v);
// constant-time string compare for hashes
function same(a, b) { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }

// ---------- document store ----------
async function getDoc(env, col, id) {
  const r = await env.DB.prepare("SELECT data, version FROM docs WHERE col = ?1 AND id = ?2 AND deleted = 0").bind(col, id).first();
  return r ? { ...JSON.parse(r.data), __v: r.version } : null;
}
async function listCol(env, col) {
  const { results } = await env.DB.prepare("SELECT id, data FROM docs WHERE col = ?1 AND deleted = 0").bind(col).all();
  return results.map(r => ({ id: r.id, ...JSON.parse(r.data) }));
}
const strip = (d) => { if (!d) return d; const { __v, ...rest } = d; return rest; };
function putStmt(env, col, id, data, now) {
  return env.DB.prepare(
    "INSERT INTO docs (col, id, data, version, updated_at, deleted) VALUES (?1, ?2, ?3, 1, ?4, 0) " +
    "ON CONFLICT(col, id) DO UPDATE SET data = excluded.data, version = docs.version + 1, updated_at = excluded.updated_at, deleted = 0"
  ).bind(col, id, JSON.stringify(data), now);
}
function delStmt(env, col, id, now) {
  return env.DB.prepare("UPDATE docs SET deleted = 1, data = '{}', version = version + 1, updated_at = ?3 WHERE col = ?1 AND id = ?2").bind(col, id, now);
}

// ---------- sessions ----------
async function createSession(env, staffId) {
  const token = randomHex(32), now = Date.now();
  await env.DB.prepare("INSERT INTO sessions (token, staff_id, created_at, last_seen) VALUES (?1, ?2, ?3, ?3)").bind(await sha256(token), staffId, now).run();
  return token;
}
async function authed(req, env) {
  const h = req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) fail(401, "Please log in.", "auth");
  const key = await sha256(token);
  const s = await env.DB.prepare("SELECT staff_id, last_seen FROM sessions WHERE token = ?1").bind(key).first();
  if (!s || Date.now() - s.last_seen > SESSION_DAYS * 864e5) fail(401, "Your session ended. Please log in again.", "auth");
  const me = await getDoc(env, "staff", s.staff_id);
  if (!me || me.active === false) fail(401, "This account is no longer active.", "auth");
  if (Date.now() - s.last_seen > 3600e3) await env.DB.prepare("UPDATE sessions SET last_seen = ?2 WHERE token = ?1").bind(key, Date.now()).run();
  me.id = s.staff_id; me.__key = key;
  return me;
}
const isAdmin = (s) => s && s.role === "admin";
const isMgr = (s) => s && (s.role === "admin" || s.role === "management");
const isLead = (s) => s && s.role === "lead";
const sees = (s) => isMgr(s) || isLead(s); // managers and leads see full shift data for reports

// ---------- login rate limit (per IP) ----------
async function checkRate(env, req) {
  const ip = req.headers.get("cf-connecting-ip") || "local";
  const r = await env.DB.prepare("SELECT count, window_start FROM login_attempts WHERE key = ?1").bind(ip).first();
  if (r && Date.now() - r.window_start < LOGIN_WINDOW_MS && r.count >= LOGIN_MAX_FAILS)
    fail(429, "Too many wrong codes. Wait 15 minutes and try again.", "rate");
  return ip;
}
async function noteFail(env, ip) {
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO login_attempts (key, count, window_start) VALUES (?1, 1, ?2) ON CONFLICT(key) DO UPDATE SET " +
    "count = CASE WHEN ?2 - window_start > ?3 THEN 1 ELSE count + 1 END, window_start = CASE WHEN ?2 - window_start > ?3 THEN ?2 ELSE window_start END"
  ).bind(ip, now, LOGIN_WINDOW_MS).run();
}

async function findByPin(env, pin, includeInactive) {
  for (const s of await listCol(env, "staff")) {
    if (!includeInactive && s.active === false) continue;
    if (s.pinSalt && same(await hashPin(s.pinSalt, pin), s.pinHash)) return s;
  }
  return null;
}
async function uniqueCode(env) {
  for (let i = 0; i < 50; i++) {
    const c = String(crypto.getRandomValues(new Uint32Array(1))[0] % 100000).padStart(5, "0");
    if (!(await findByPin(env, c, true))) return c;
  }
  fail(500, "Couldn't make a unique code. Try again.");
}
async function pinFields(pin) { const pinSalt = randomHex(12); return { pinSalt, pinHash: await hashPin(pinSalt, pin) }; }

// ---------- read filtering ----------
function filterDoc(me, col, id, d) {
  if (col === "staff") {
    const { pinHash, pinSalt, ...rest } = d;
    if (!isMgr(me) && id !== me.id) { delete rest.email; delete rest.emailAlerts; delete rest.hideMgmt; }
    return rest;
  }
  if (col === "requests") {
    if (sees(me) || d.requesterId === me.id) return d;
    const { note, outcome, outcomeBy, outcomeAt, excused, decidedBy, ...rest } = d;
    if (d.assignedTo === me.id) Object.assign(rest, { outcome, outcomeAt, excused });
    return rest;
  }
  return d;
}
// returns false to hide the document from this person entirely
function canRead(me, col, id, d) {
  switch (col) {
    case "staff": case "settings": case "requests": return true;
    case "volunteers": return sees(me) || d.staffId === me.id;
    case "inbox": return d.to === me.id;
    case "messages": return d.conv === "team" || (typeof d.conv === "string" && d.conv.startsWith("dm:") && d.conv.split(":").slice(1).includes(me.id));
    case "chatread": return id === me.id;
    case "shift_audit_logs": return isMgr(me);
    default: return false;
  }
}

async function handleSync(env, me, url) {
  const test = url.searchParams.get("ns") === "test";
  if (test && !isMgr(me)) fail(403, "Test mode is for managers.", "forbidden");
  const since = Math.max(0, Number(url.searchParams.get("since")) || 0);
  const cols = test ? LIVE_COLS.map(c => TEST_PREFIX + c) : LIVE_COLS;
  const marks = cols.map((_, i) => "?" + (i + 2)).join(",");
  const sql = "SELECT col, id, data, deleted, updated_at FROM docs WHERE updated_at > ?1 AND col IN (" + marks + ")" + (since ? "" : " AND deleted = 0");
  const { results } = await env.DB.prepare(sql).bind(since, ...cols).all();
  let cursor = since; const docs = [];
  let offersChanged = !since;
  for (const r of results) {
    cursor = Math.max(cursor, r.updated_at);
    const col = test ? r.col.slice(TEST_PREFIX.length) : r.col;
    if (col === "volunteers" || col === "requests") offersChanged = true;
    if (r.deleted) {
      // a withdrawn offer's id names who offered: only send it to that person and to managers/leads
      if (test || col !== "volunteers" || sees(me) || r.id.endsWith("__" + me.id)) docs.push({ col: r.col, id: r.id, deleted: true });
      continue;
    }
    let d = JSON.parse(r.data);
    if (!test) {
      if (!canRead(me, col, r.id, d)) continue; // never send hidden records, not even their ids (offer ids contain who offered)
      d = filterDoc(me, col, r.id, d);
    }
    docs.push({ col: r.col, id: r.id, data: d });
  }
  // Employees can't see who offered on their requests, only how many. Recounted only when offers or
  // requests changed since their last check, so routine polling stays cheap on the free plan.
  let offerCounts;
  if (!test && !sees(me) && offersChanged) {
    const { results: rows } = await env.DB.prepare(
      "SELECT json_extract(v.data, '$.reqId') AS req, COUNT(*) AS n FROM docs v JOIN docs r ON r.col = 'requests' AND r.deleted = 0 AND r.id = json_extract(v.data, '$.reqId') " +
      "WHERE v.col = 'volunteers' AND v.deleted = 0 AND json_extract(r.data, '$.requesterId') = ?1 GROUP BY req"
    ).bind(me.id).all();
    offerCounts = {}; for (const x of rows) offerCounts[x.req] = x.n;
  }
  return json({ cursor, docs, offerCounts, me: me.id });
}

// "Mon Nov 9, 3:00p–9:30p", matching the app's wording
function shiftWords(r) {
  const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"], MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const t12 = (hm) => { let [h, m] = String(hm || "0:0").split(":").map(Number); const ap = h >= 12 ? "p" : "a"; h = h % 12 || 12; return h + ":" + String(m).padStart(2, "0") + ap; };
  const [y, mo, d] = String(r.date || "").split("-").map(Number); const dt = new Date(Date.UTC(y, mo - 1, d));
  return DOW[dt.getUTCDay()] + " " + MON[mo - 1] + " " + d + ", " + t12(r.start) + "–" + t12(r.end);
}

// ---------- write rules ----------
const onlyKeys = (patch, allowed) => Object.keys(patch).every(k => allowed.includes(k));
const PIN_KEYS = ["pinHash", "pinSalt", "pinTemp"];
function checkWrite(me, op, col, id, cur, patch, next) {
  const mgr = isMgr(me);
  switch (col) {
    case "staff":
      if (op === "delete" || op === "add" || op === "set") fail(403, "Use the staff screen to add people.", "forbidden");
      if (Object.keys(patch).some(k => PIN_KEYS.includes(k))) fail(403, "Login codes change through the code screens only.", "forbidden");
      if (!cur) fail(404, "That person doesn't exist.", "missing");
      if (id === me.id && onlyKeys(patch, ["email", "emailAlerts", "hideMgmt", "chatTermsV", "chatTermsAt", "pushOpen"])) return;
      if (!mgr) fail(403, "Only managers can change staff.", "forbidden");
      if ((isAdmin(cur) || next.role === "admin") && !isAdmin(me)) fail(403, "Only an admin can change an admin account.", "forbidden");
      if (id === me.id && patch.active === false) fail(403, "You can't deactivate yourself.", "forbidden");
      return;
    case "settings":
      if (!mgr) fail(403, "Only managers can change settings.", "forbidden");
      return;
    case "requests":
      if (op === "delete") fail(403, "Requests can't be deleted.", "forbidden");
      if (op === "add") {
        if (next.requesterId !== me.id) fail(403, "You can only request cover for yourself.", "forbidden");
        if (!["open", "confirming"].includes(next.status) || next.assignedTo) fail(400, "New requests start open.", "invalid");
        return;
      }
      if (!cur) fail(404, "That request doesn't exist.", "missing");
      if (mgr) return;
      if (cur.requesterId === me.id && onlyKeys(patch, ["status", "updatedAt"]) && patch.status === "cancelled" && ["open", "confirming", "review"].includes(cur.status)) return;
      if (cur.arrangedWith === me.id && cur.status === "confirming" && onlyKeys(patch, ["status", "arrangedWith", "arrangedDeclinedBy", "updatedAt"]) && ["review", "open"].includes(patch.status)) return;
      fail(403, "You can't change this request.", "forbidden");
    case "volunteers":
      if (op === "delete") { if (mgr || (cur && cur.staffId === me.id)) return; fail(403, "You can only withdraw your own offer.", "forbidden"); }
      if (op !== "set" || id !== next.reqId + "__" + me.id || next.staffId !== me.id) fail(403, "You can only offer for yourself.", "forbidden");
      return;
    case "inbox":
      if (op === "add") { if (typeof next.to !== "string" || !next.text) fail(400, "Alerts need a person and text.", "invalid"); return; }
      if (op === "update" && cur && cur.to === me.id && onlyKeys(patch, ["read"])) return;
      fail(403, "You can only mark your own alerts read.", "forbidden");
    case "messages":
      if (op === "add") {
        if (next.from !== me.id) fail(403, "You can only send as yourself.", "forbidden");
        const ok = next.conv === "team" || (typeof next.conv === "string" && next.conv.startsWith("dm:") && next.conv.split(":").slice(1).includes(me.id));
        if (!ok || typeof next.text !== "string" || !next.text.trim() || next.text.length > 1000) fail(400, "That message can't be sent.", "invalid");
        return;
      }
      if (op === "delete" && cur && (cur.from === me.id || (mgr && cur.conv === "team"))) return;
      fail(403, "You can only delete your own messages.", "forbidden");
    case "chatread":
      if (op === "set" && id === me.id) return;
      fail(403, "Not allowed.", "forbidden");
    case "shift_audit_logs":
      if (op === "add") return;
      fail(403, "The audit log can't be changed.", "forbidden");
    default:
      fail(400, "Unknown record type.", "invalid");
  }
}

async function handleWrite(env, me, body, ctx, origin) {
  const ops = Array.isArray(body && body.ops) ? body.ops : null;
  if (!ops || !ops.length || ops.length > MAX_OPS) fail(400, "Send between 1 and " + MAX_OPS + " changes.", "invalid");
  const now = Date.now(), stmts = [], results = [], pushes = [];
  for (const o of ops) {
    const op = o.op, rawCol = String(o.col || "");
    if (!["add", "set", "update", "delete"].includes(op)) fail(400, "Unknown change type.", "invalid");
    const test = rawCol.startsWith(TEST_PREFIX), col = test ? rawCol.slice(TEST_PREFIX.length) : rawCol;
    if (!LIVE_COLS.includes(col)) fail(400, "Unknown record type.", "invalid");
    const id = op === "add" ? newId() : String(o.id || "");
    if (!/^[A-Za-z0-9_\-.:@+~]{1,200}$/.test(id)) fail(400, "Bad record id.", "invalid");
    const cur = op === "add" ? null : strip(await getDoc(env, rawCol, id));
    const patch = o.data && typeof o.data === "object" && !Array.isArray(o.data) ? o.data : {};
    let next = op === "update" ? { ...(cur || {}), ...patch } : op === "delete" ? null : { ...patch };
    if (op === "update" && !cur) fail(404, "That record no longer exists.", "missing");
    if (test) { if (!isMgr(me)) fail(403, "Test mode is for managers.", "forbidden"); }
    else {
      checkWrite(me, op, col, id, cur, patch, next || {});
      if (col === "shift_audit_logs") Object.assign(next, { actorId: me.id, actorName: me.name, ts: now });
      if (col === "messages") next.ts = now;
      if (col === "volunteers" && op === "set") {
        const rq = strip(await getDoc(env, "requests", String(next.reqId)));
        if (!rq || rq.status !== "open") fail(409, "This shift no longer needs to be covered.", "closed");
        if (rq.requesterId === me.id) fail(400, "You can't offer on your own shift.", "invalid");
      }
      // An employee can't see who offered on their request, so the server tells those people it closed.
      if (col === "requests" && op === "update" && next.status === "cancelled" && cur.status !== "cancelled" && !isMgr(me)) {
        const { results: vs } = await env.DB.prepare("SELECT data FROM docs WHERE col = 'volunteers' AND deleted = 0 AND json_extract(data, '$.reqId') = ?1").bind(id).all();
        const tell = new Set(vs.map(v => JSON.parse(v.data).staffId)); if (cur.arrangedWith) tell.add(cur.arrangedWith);
        const when = shiftWords(cur);
        for (const to of tell) {
          const note = { to, kind: "closed", reqId: id, text: "The " + when + " shift no longer needs to be covered.", ts: now, read: false };
          stmts.push(putStmt(env, "inbox", newId(), note, now));
          pushes.push({ to, data: { title: "DC SH!FTZ", body: note.text, tag: "inbox-" + id, view: "mine" } });
        }
      }
    }
    if (next && JSON.stringify(next).length > 20000) fail(400, "That record is too large.", "invalid");
    if (!test) pushes.push(...(await pushesFor(env, me, op, col, id, cur, next)));
    stmts.push(op === "delete" ? delStmt(env, rawCol, id, now) : putStmt(env, rawCol, id, next, now));
    results.push(op === "delete" ? { col: rawCol, id, deleted: true } : { col: rawCol, id, data: test ? next : filterDoc(me, col, id, next) });
  }
  await env.DB.batch(stmts);
  if (pushes.length) await later(ctx, deliverPushes(env, pushes, origin)); // sent after the reply, so saving never waits on phones
  return json({ results });
}

// ---------- push notifications (Web Push, RFC 8291 + VAPID RFC 8292) ----------
// The server makes its own VAPID key pair the first time it's needed and keeps it in the kv table,
// so there's nothing to paste into Cloudflare settings. Phones subscribe from My account.
const MAX_PUSHES = 40; // stays under the free plan's 50 outgoing requests per call
const b64u = {
  enc(bytes) { let s = ""; const u = new Uint8Array(bytes); for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
  dec(str) { const s = atob(String(str).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(str).length + 3) % 4)); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
};
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const utf8 = (s) => new TextEncoder().encode(s);
async function hmac(key, data) { const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", k, data)); }

let vapidCache = null;
async function getVapid(env) {
  if (vapidCache) return vapidCache;
  let row = await env.DB.prepare("SELECT value FROM kv WHERE key = 'vapid'").first();
  if (!row) {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const pub = b64u.enc(await crypto.subtle.exportKey("raw", pair.publicKey));
    await env.DB.prepare("INSERT OR IGNORE INTO kv (key, value) VALUES ('vapid', ?1)").bind(JSON.stringify({ pub, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d } })).run();
    row = await env.DB.prepare("SELECT value FROM kv WHERE key = 'vapid'").first(); // another request may have won the race
  }
  const v = JSON.parse(row.value);
  v.key = await crypto.subtle.importKey("jwk", { ...v.jwk, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return (vapidCache = v);
}
async function vapidJwt(v, aud, subject) {
  const head = b64u.enc(utf8(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u.enc(utf8(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, v.key, utf8(head + "." + body));
  return head + "." + body + "." + b64u.enc(sig);
}
// aes128gcm content encoding for one subscription (RFC 8291 section 3.4)
async function encryptFor(sub, plain, server) {
  const uaPublic = b64u.dec(sub.p256dh), authSecret = b64u.dec(sub.auth);
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, server.privateKey, 256));
  const ikm = await hmac(await hmac(authSecret, ecdh), cat(utf8("WebPush: info\0"), uaPublic, server.publicRaw, new Uint8Array([1])));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, cat(utf8("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, cat(utf8("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, cat(plain, new Uint8Array([2]))));
  const header = new Uint8Array(21); header.set(salt, 0); new DataView(header.buffer).setUint32(16, 4096); header[20] = 65;
  return cat(header, server.publicRaw, sealed);
}
// pushes: [{ to: staffId, data: { title, body, tag, view } }]
async function deliverPushes(env, pushes, origin) {
  if (!pushes.length) return;
  const ids = [...new Set(pushes.map(p => p.to))];
  const marks = ids.map((_, i) => "?" + (i + 1)).join(",");
  const { results: subs } = await env.DB.prepare("SELECT endpoint, staff_id, p256dh, auth FROM push_subs WHERE staff_id IN (" + marks + ")").bind(...ids).all();
  if (!subs.length) return;
  const v = await getVapid(env);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const server = { privateKey: eph.privateKey, publicRaw: new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)) };
  const jwts = new Map(); let sent = 0;
  for (const p of pushes) {
    for (const s of subs.filter(x => x.staff_id === p.to)) {
      if (sent >= MAX_PUSHES) return;
      sent++;
      try {
        const aud = new URL(s.endpoint).origin;
        if (!jwts.has(aud)) jwts.set(aud, await vapidJwt(v, aud, origin.startsWith("https:") ? origin : "https://" + new URL(origin).host)); // push services require an https: or mailto: contact
        const body = await encryptFor(s, utf8(JSON.stringify(p.data)), server);
        const r = await fetch(s.endpoint, { method: "POST", body, headers: {
          "content-encoding": "aes128gcm", "content-type": "application/octet-stream", ttl: "86400", urgency: "high",
          authorization: "vapid t=" + jwts.get(aud) + ", k=" + v.pub } });
        if (r.status === 404 || r.status === 410) await env.DB.prepare("DELETE FROM push_subs WHERE endpoint = ?1").bind(s.endpoint).run(); // phone unsubscribed or reinstalled
      } catch (e) { console.error("push failed", e); }
    }
  }
}
// Who hears about each change. Only live data; test mode never sends notifications.
async function pushesFor(env, me, op, col, id, cur, next) {
  const out = [];
  if (col === "inbox" && op === "add") {
    const view = next.kind === "confirm" ? "alerts" : "mine";
    out.push({ to: next.to, data: { title: next.kind === "confirm" ? "Please confirm a cover" : "DC SH!FTZ", body: next.text, tag: "inbox-" + (next.reqId || id), view } });
  }
  if (col === "requests" && next && next.status === "open" && (op === "add" || (cur && cur.status !== "open"))) {
    const all = await listCol(env, "staff");
    const who = all.find(s => s.id === next.requesterId);
    for (const s of all) if (s.active !== false && s.id !== next.requesterId && s.pushOpen !== false)
      out.push({ to: s.id, data: { title: "Shift needs cover", body: shiftWords(next) + " · " + next.position + (who ? " · " + who.name : ""), tag: "open-" + id, view: "open" } });
  }
  if (col === "messages" && op === "add" && String(next.conv).startsWith("dm:")) {
    const other = next.conv.split(":").slice(1).find(x => x !== me.id);
    if (other) out.push({ to: other, data: { title: me.name, body: next.text.length > 140 ? next.text.slice(0, 137) + "…" : next.text, tag: "dm-" + next.conv, view: "chat" } });
  }
  if (col === "volunteers" && op === "set") {
    const rq = strip(await getDoc(env, "requests", String(next.reqId)));
    const all = await listCol(env, "staff");
    const asker = rq && all.find(s => s.id === rq.requesterId);
    for (const s of all) if (s.active !== false && isMgr(s) && s.id !== me.id)
      out.push({ to: s.id, data: { title: "New offer to approve", body: me.name + " offered on " + (asker ? asker.name + "'s " : "") + (rq ? shiftWords(rq) : "a shift"), tag: "offer-" + next.reqId, view: "manage" } });
  }
  return out;
}
function later(ctx, promise) { if (ctx && ctx.waitUntil) ctx.waitUntil(promise.catch(e => console.error(e))); else return promise; }

// ---------- account endpoints ----------
async function liveStaffCount(env) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM docs WHERE col = 'staff' AND deleted = 0").first();
  return r ? r.n : 0;
}
async function audit(env, me, action, text) {
  await putStmt(env, "shift_audit_logs", newId(), { action, reqId: null, actorId: me.id, actorName: me.name, accountId: null, ts: Date.now(), date: null, start: null, end: null, position: null, text }, Date.now()).run();
}
async function readBody(req) { try { return await req.json(); } catch (e) { fail(400, "Bad request.", "invalid"); } }

async function route(req, env, url, ctx) {
  const path = url.pathname, method = req.method;

  if (path === "/api/status" && method === "GET") return json({ needsSetup: (await liveStaffCount(env)) === 0 });

  if (path === "/api/setup" && method === "POST") {
    const b = await readBody(req);
    if ((await liveStaffCount(env)) > 0) fail(409, "DC SH!FTZ is already set up. Log in with your code.", "exists");
    const name = String(b.name || "").trim().slice(0, 30);
    if (!name) fail(400, "Add your name.", "invalid");
    if (!isCode(b.code)) fail(400, "Your code needs exactly 5 digits.", "invalid");
    const id = newId(), now = Date.now();
    const doc = { name, role: "admin", main: "Budtender", cross: [], positions: ["Budtender"], ...(await pinFields(b.code)), pinTemp: false, active: true, createdAt: now, createdBy: null };
    await putStmt(env, "staff", id, doc, now).run();
    const me = { ...doc, id };
    await audit(env, me, "staff_added", name + " set up DC SH!FTZ as the first admin");
    return json({ token: await createSession(env, id), staffId: id });
  }

  if (path === "/api/login" && method === "POST") {
    const ip = await checkRate(env, req);
    const b = await readBody(req);
    if (!isCode(b.code)) fail(400, "Codes are 5 digits.", "invalid");
    const s = await findByPin(env, b.code, false);
    if (!s) { await noteFail(env, ip); fail(401, "That code doesn't match anyone. Try again.", "badcode"); }
    return json({ token: await createSession(env, s.id), staffId: s.id, pinTemp: !!s.pinTemp });
  }

  const me = await authed(req, env);

  if (path === "/api/logout" && method === "POST") {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(me.__key).run();
    return json({ ok: true });
  }
  if (path === "/api/sync" && method === "GET") return handleSync(env, me, url);
  if (path === "/api/write" && method === "POST") return handleWrite(env, me, await readBody(req), ctx, url.origin);

  if (path === "/api/push/key" && method === "GET") return json({ key: (await getVapid(env)).pub });
  if (path === "/api/push/subscribe" && method === "POST") {
    const b = await readBody(req), k = b.keys || {};
    if (typeof b.endpoint !== "string" || !b.endpoint.startsWith("https://") || b.endpoint.length > 1000 || typeof k.p256dh !== "string" || typeof k.auth !== "string") fail(400, "That phone's notification details look wrong.", "invalid");
    await env.DB.prepare("INSERT INTO push_subs (endpoint, staff_id, p256dh, auth, created_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(endpoint) DO UPDATE SET staff_id = excluded.staff_id, p256dh = excluded.p256dh, auth = excluded.auth")
      .bind(b.endpoint, me.id, k.p256dh, k.auth, Date.now()).run();
    return json({ ok: true });
  }
  if (path === "/api/push/unsubscribe" && method === "POST") {
    const b = await readBody(req);
    await env.DB.prepare("DELETE FROM push_subs WHERE endpoint = ?1 AND staff_id = ?2").bind(String(b.endpoint || ""), me.id).run();
    return json({ ok: true });
  }
  if (path === "/api/push/test" && method === "POST") {
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM push_subs WHERE staff_id = ?1").bind(me.id).first();
    if (!n || !n.n) fail(404, "Notifications aren't on for this account yet.", "missing");
    await later(ctx, deliverPushes(env, [{ to: me.id, data: { title: "DC SH!FTZ", body: "Notifications are on. You'll hear about shifts here.", tag: "test", view: "open" } }], url.origin));
    return json({ ok: true });
  }

  if (path === "/api/pin" && method === "POST") { // set or change your own code
    const b = await readBody(req);
    if (!isCode(b.code)) fail(400, "Your code needs exactly 5 digits.", "invalid");
    if (!me.pinTemp && !(isCode(b.current) && same(await hashPin(me.pinSalt, b.current), me.pinHash))) fail(403, "Your current code isn't right.", "badcode");
    if (same(await hashPin(me.pinSalt, b.code), me.pinHash)) fail(400, "Pick a different code from your current one.", "invalid");
    const taken = await findByPin(env, b.code, true);
    if (taken && taken.id !== me.id) fail(409, "That code is taken. Pick another one.", "taken");
    const { __v, __key, id, ...doc } = me;
    await putStmt(env, "staff", me.id, { ...doc, ...(await pinFields(b.code)), pinTemp: false }, Date.now()).run();
    await audit(env, me, "code_set", me.name + (me.pinTemp ? " set their own login code" : " changed their login code"));
    return json({ ok: true });
  }

  if (path === "/api/new-code" && method === "GET") {
    if (!isMgr(me)) fail(403, "Only managers can make codes.", "forbidden");
    return json({ code: await uniqueCode(env) });
  }

  if (path === "/api/staff" && method === "POST") { // add a person with a one-time code
    if (!isMgr(me)) fail(403, "Only managers can add staff.", "forbidden");
    const b = await readBody(req), d = b.data || {};
    const name = String(d.name || "").trim().slice(0, 30);
    if (!name) fail(400, "Add a name or nickname.", "invalid");
    const role = ["employee", "lead", "management", "admin"].includes(d.role) ? d.role : "employee";
    if (role === "admin" && !isAdmin(me)) fail(403, "Only an admin can add an admin.", "forbidden");
    const code = isCode(b.code) ? b.code : await uniqueCode(env);
    if (await findByPin(env, code, true)) fail(409, "That code is already in use. Tap New for another.", "taken");
    const main = String(d.main || "Budtender"), cross = Array.isArray(d.cross) ? d.cross.map(String).filter(p => p !== main) : [];
    const id = newId(), now = Date.now();
    await putStmt(env, "staff", id, { name, role, main, cross, positions: [main, ...cross], ...(await pinFields(code)), pinTemp: true, active: true, createdAt: now, createdBy: me.id }, now).run();
    await audit(env, me, "staff_added", me.name + " added " + name);
    return json({ id, code });
  }

  const reset = path.match(/^\/api\/staff\/([A-Za-z0-9_\-]+)\/reset-code$/);
  if (reset && method === "POST") {
    if (!isMgr(me)) fail(403, "Only managers can reset codes.", "forbidden");
    const s = strip(await getDoc(env, "staff", reset[1]));
    if (!s) fail(404, "That person doesn't exist.", "missing");
    if (isAdmin(s) && !isAdmin(me)) fail(403, "Only an admin can change an admin account.", "forbidden");
    const code = await uniqueCode(env);
    await putStmt(env, "staff", reset[1], { ...s, ...(await pinFields(code)), pinTemp: true }, Date.now()).run();
    await env.DB.prepare("DELETE FROM sessions WHERE staff_id = ?1").bind(reset[1]).run(); // signs them out everywhere
    await audit(env, me, "code_reset", me.name + " reset the login code for " + s.name);
    return json({ code });
  }

  if (path === "/api/test/reset" && method === "POST") {
    if (!isMgr(me)) fail(403, "Test mode is for managers.", "forbidden");
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare("UPDATE docs SET deleted = 1, data = '{}', version = version + 1, updated_at = ?1 WHERE col LIKE 't\\_%' ESCAPE '\\' AND deleted = 0").bind(now),
      env.DB.prepare("DELETE FROM docs WHERE deleted = 1 AND updated_at < ?1").bind(now - 30 * 864e5)
    ]);
    return json({ ok: true });
  }

  fail(404, "Not found.", "missing");
}

// Daily cleanup (Cron Trigger in wrangler.jsonc): old chat, old tombstones, stale sessions and login counters.
async function cleanup(env) {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("UPDATE docs SET deleted = 1, data = '{}', version = version + 1, updated_at = ?1 WHERE col = 'messages' AND deleted = 0 AND json_extract(data, '$.ts') < ?2").bind(now, now - 90 * 864e5),
    env.DB.prepare("DELETE FROM docs WHERE deleted = 1 AND updated_at < ?1").bind(now - 30 * 864e5),
    env.DB.prepare("DELETE FROM sessions WHERE last_seen < ?1").bind(now - SESSION_DAYS * 864e5),
    env.DB.prepare("DELETE FROM login_attempts WHERE window_start < ?1").bind(now - LOGIN_WINDOW_MS)
  ]);
}

// Creates the tables on first use, so a phone-only setup never needs a terminal.
// Same statements as schema.sql; runs once per server instance and costs nothing once the tables exist.
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS docs (col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (col, id))",
  "CREATE INDEX IF NOT EXISTS docs_updated ON docs (updated_at)",
  "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, staff_id TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS sessions_staff ON sessions (staff_id)",
  "CREATE TABLE IF NOT EXISTS login_attempts (key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, staff_id TEXT NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS push_subs_staff ON push_subs (staff_id)",
  "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
];
let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) schemaReady = env.DB.batch(SCHEMA.map(s => env.DB.prepare(s))).catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try { await ensureSchema(env); return await route(req, env, url, ctx); }
    catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, code: e.code }, e.status);
      console.error(e);
      return json({ error: "Something went wrong on the server. Try again.", code: "server" }, 500);
    }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(ensureSchema(env).then(() => cleanup(env))); }
};
