// OSINT CTF API — Cloudflare Worker (module syntax)
// Bindings : env.DB (D1)
// Secrets  : BOOTSTRAP_KEY (optional; admin-token recovery — delete it after first run)
// Vars     : MAX_USERS (default 300), ALLOWED_ORIGIN (optional; only if the API is called cross-origin)
// NOTE: answers are stored as editable plaintext on the challenge row. They are
// returned ONLY by GET /api/admin/challenges (bearer-token protected) and never
// to any player endpoint. The answer key is therefore as secret as the admin token.
// The site is same-origin (Worker route ctf.<domain>/api/*), so CORS is off unless ALLOWED_ORIGIN is set.

const MAX_PUBLIC_BODY = 16 * 1024;
const MAX_ADMIN_BODY = 1024 * 1024;
const PLAYER_ID_RE = /^[A-Za-z0-9._-]{8,64}$/;        // UUIDs, plus ids minted by very old browsers (keeps existing players working)
const ID_RE = /^[^\u0000-\u001f\u007f\/\\]{1,64}$/;   // challenge ids: anything except control chars and slashes
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{1,23}$/; // ASCII only: blocks homoglyph / bidi / zero-width spoofing; first char alnum also blocks CSV formula injection
const RESERVED = new Set(["admin", "administrator", "root", "instructor", "moderator", "system"]);
const NAME_MSG = "name must be 2-24 chars: letters, numbers, space . _ -";
const FAR_FUTURE = 4102444800000; // 2100-01-01
const BIG = Number.MAX_SAFE_INTEGER;

// Default per-category icons (tiny hand-authored SVGs as data URIs). Admins can override any
// of these via /admin/category-icons; unknown categories fall back to _DEFAULT.
const DEFAULT_ICONS = {
  "APIS": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48Y2lyY2xlIGN4PSI2IiBjeT0iNiIgcj0iMi41Ii8+PGNpcmNsZSBjeD0iMTgiIGN5PSI2IiByPSIyLjUiLz48Y2lyY2xlIGN4PSIxMiIgY3k9IjE4IiByPSIyLjUiLz48bGluZSB4MT0iOCIgeTE9IjcuNSIgeDI9IjEwLjUiIHkyPSIxNiIvPjxsaW5lIHgxPSIxNiIgeTE9IjcuNSIgeDI9IjEzLjUiIHkyPSIxNiIvPjxsaW5lIHgxPSI4LjUiIHkxPSI2IiB4Mj0iMTUuNSIgeTI9IjYiLz48L3N2Zz4=",
  "CALLER ID": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNSA0aDRsMiA1LTIuNSAxLjVhMTEgMTEgMCAwIDAgNSA1TDE1IDEzbDUgMnY0YTIgMiAwIDAgMS0yIDJBMTYgMTYgMCAwIDEgMyA2YTIgMiAwIDAgMSAyLTJ6Ii8+PC9zdmc+",
  "CRACKING": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cmVjdCB4PSI1IiB5PSIxMSIgd2lkdGg9IjE0IiBoZWlnaHQ9IjkiIHJ4PSIyIi8+PHBhdGggZD0iTTggMTFWN2E0IDQgMCAwIDEgNy41LTIiLz48L3N2Zz4=",
  "DEEP WEB": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSI4Ii8+PGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iNSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjIiLz48L3N2Zz4=",
  "DOMAIN": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSI5Ii8+PHBhdGggZD0iTTMgMTJoMThNMTIgM2ExNCAxNCAwIDAgMSAwIDE4TTEyIDNhMTQgMTQgMCAwIDAgMCAxOCIvPjwvc3ZnPg==",
  "GEO": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTIgMjFzNy03LjIgNy0xMmE3IDcgMCAwIDAtMTQgMGMwIDQuOCA3IDEyIDcgMTJ6Ii8+PGNpcmNsZSBjeD0iMTIiIGN5PSI5IiByPSIyLjQiLz48L3N2Zz4=",
  "GOV": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNCAxMGw4LTUgOCA1Ii8+PHBhdGggZD0iTTUgMTB2OU05IDEwdjlNMTUgMTB2OU0xOSAxMHY5Ii8+PHBhdGggZD0iTTMgMTloMTgiLz48L3N2Zz4=",
  "IMAGE": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cmVjdCB4PSIzIiB5PSI0IiB3aWR0aD0iMTgiIGhlaWdodD0iMTYiIHJ4PSIyIi8+PGNpcmNsZSBjeD0iOC41IiBjeT0iOS41IiByPSIxLjYiLz48cGF0aCBkPSJNMjEgMTZsLTUuNS01LjVMOSAxNyIvPjwvc3ZnPg==",
  "MAPS": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNOSA0TDMgNnYxNGw2LTIgNiAyIDYtMlY0bC02IDItNi0yeiIvPjxwYXRoIGQ9Ik05IDR2MTRNMTUgNnYxNCIvPjwvc3ZnPg==",
  "METADATA": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMjAgMTJsLTggOC05LTlWNGg3eiIvPjxjaXJjbGUgY3g9IjcuNSIgY3k9IjcuNSIgcj0iMS40IiBmaWxsPSIjNGFhM2ZmIiBzdHJva2U9Im5vbmUiLz48L3N2Zz4=",
  "NETWORK": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMiA4LjVhMTYgMTYgMCAwIDEgMjAgME01LjUgMTIuNWExMSAxMSAwIDAgMSAxMyAwTTkgMTYuNWE2IDYgMCAwIDEgNiAwIi8+PGNpcmNsZSBjeD0iMTIiIGN5PSIyMCIgcj0iMSIgZmlsbD0iIzRhYTNmZiIgc3Ryb2tlPSJub25lIi8+PC9zdmc+",
  "SOCIAL": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjgiIHI9IjMuNSIvPjxwYXRoIGQ9Ik01IDIwYzAtMy45IDMuMS03IDctN3M3IDMuMSA3IDciLz48L3N2Zz4=",
  "VEHICLES": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNCAxNmwxLjUtNUEyIDIgMCAwIDEgNy40IDkuNWg5LjJBMiAyIDAgMCAxIDE4LjUgMTFMMjAgMTYiLz48cmVjdCB4PSIzIiB5PSIxNiIgd2lkdGg9IjE4IiBoZWlnaHQ9IjQiIHJ4PSIxLjUiLz48Y2lyY2xlIGN4PSI3LjUiIGN5PSIyMCIgcj0iMS40Ii8+PGNpcmNsZSBjeD0iMTYuNSIgY3k9IjIwIiByPSIxLjQiLz48L3N2Zz4=",
  "_DEFAULT": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGFhM2ZmIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMyA3YTIgMiAwIDAgMSAyLTJoNGwyIDJoOGEyIDIgMCAwIDEgMiAydjhhMiAyIDAgMCAxLTIgMkg1YTIgMiAwIDAgMS0yLTJ6Ii8+PC9zdmc+",
};

// ---------- response helpers ----------
const BASE_HEADERS = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};
const json = (o, s = 200, extra = {}) =>
  new Response(JSON.stringify(o), { status: s, headers: { ...BASE_HEADERS, ...extra } });
const err = (msg, s = 400, extra = {}) => json({ error: msg, ...extra }, s);

// ---------- crypto / validation helpers ----------
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha256hex(str) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(str))); }
function safeEq(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
// constant-time comparison of two secrets (hash both so the lengths match)
const secretEq = async (a, b) => safeEq(await sha256hex(String(a ?? "")), await sha256hex(String(b ?? "")));

function clampInt(v, def, lo, hi) {
  if (v === undefined || v === null || v === "") return def;
  const n = Math.trunc(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def;
}
const str = (v, max) => String(v ?? "").slice(0, max);

// Answer normalization for matching. Keep predictable; use multiple accepted
// answers for real variants. (Storage keeps the admin's original text; both
// stored and submitted values are normalized only at compare time.)
function normalize(s) {
  return str(s, 512)
    .normalize("NFKC").trim().toLowerCase()
    .replace(/^flag\{(.*)\}$/i, "$1")
    .replace(/\s+/g, " ")
    .replace(/[.\s]+$/g, "");
}
const answersArray = (txt) => String(txt || "").split("\n").map((x) => x.trim()).filter(Boolean);

function cleanName(raw, allowReserved = false) {
  const n = String(raw ?? "").normalize("NFKC").trim().replace(/\s+/g, " ");
  if (!NAME_RE.test(n)) return null;
  if (!allowReserved && RESERVED.has(n.toLowerCase())) return null;
  return n;
}
// player id: header (preferred) or legacy ?uuid= query param (kept so an older cached page keeps working)
function playerId(req) {
  const v = req.headers.get("X-Player-Id") || new URL(req.url).searchParams.get("uuid") || "";
  return PLAYER_ID_RE.test(v) ? v : "";
}
function audit(req, action, extra = {}) {
  console.log(JSON.stringify({ t: new Date().toISOString(), ip: req.headers.get("CF-Connecting-IP") || "", action, ...extra }));
}
// category icon: data:image/* URI or an https URL; anything else is refused instead of stored
const iconOK = (v) => typeof v === "string" && v.length <= 20000 && (/^data:image\/(svg\+xml|png|jpe?g|gif|webp|x-icon)[;,]/i.test(v) || (/^https:\/\/\S+$/i.test(v) && v.length <= 2000));

// ---------- config / phase ----------
async function cfg(env, key, def = null) {
  const r = await env.DB.prepare("SELECT value FROM config WHERE key=?").bind(key).first();
  return r ? r.value : def;
}
const setCfgStmt = (env, key, value) =>
  env.DB.prepare("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, String(value));
const setCfg = (env, key, value) => setCfgStmt(env, key, value).run();
// Read several config keys in ONE query. Missing keys are simply absent from the map;
// use cfgGet() to apply the same default/null semantics as cfg().
async function getConfig(env, keys) {
  const marks = keys.map(() => "?").join(",");
  const rows = (await env.DB.prepare(`SELECT key, value FROM config WHERE key IN (${marks})`).bind(...keys).all()).results;
  const m = {};
  rows.forEach((r) => (m[r.key] = r.value));
  return m;
}
const cfgGet = (m, key, def = null) => (key in m ? m[key] : def);
function phaseFrom(start, end, now) {
  if (!start || !end) return "unset";
  if (now < start) return "pre";
  if (now > end) return "post";
  return "live";
}
async function phaseOf(env, now) {
  const c = await getConfig(env, ["event_start", "event_end"]);
  return phaseFrom(Number(cfgGet(c, "event_start", 0)), Number(cfgGet(c, "event_end", 0)), now);
}

// ---------- scoring ----------
function currentValue(ch, scoredSolves) {
  const d = Math.max(1, ch.decay);
  const v = Math.ceil(((ch.minimum - ch.initial) / (d * d)) * (scoredSolves * scoredSolves) + ch.initial);
  return Math.max(ch.minimum, v);
}
async function scoreMaps(env) {
  const [chs, solves] = (await env.DB.batch([
    env.DB.prepare("SELECT * FROM challenges WHERE active=1"),
    env.DB.prepare("SELECT challenge_id, COUNT(*) n FROM solves WHERE scored=1 GROUP BY challenge_id"),
  ])).map((r) => r.results);
  const nBy = {}; solves.forEach((r) => (nBy[r.challenge_id] = r.n));
  const valBy = {}, chBy = {};
  for (const ch of chs) { chBy[ch.id] = ch; valBy[ch.id] = currentValue(ch, nBy[ch.id] || 0); }
  return { chBy, valBy, nBy };
}

async function getLeaderboard(env) {
  const [chs, cnts, solves, hints, users] = (await env.DB.batch([
    env.DB.prepare("SELECT id,initial,minimum,decay FROM challenges WHERE active=1"),
    env.DB.prepare("SELECT challenge_id, COUNT(*) n FROM solves WHERE scored=1 GROUP BY challenge_id"),
    env.DB.prepare("SELECT uuid, challenge_id, ts_ms FROM solves WHERE scored=1"),
    env.DB.prepare("SELECT h.uuid, SUM(c.hint_cost) c FROM hint_unlocks h JOIN challenges c ON c.id=h.challenge_id GROUP BY h.uuid"),
    env.DB.prepare("SELECT uuid, name FROM users"),
  ])).map((r) => r.results);
  const n = {}; cnts.forEach((r) => (n[r.challenge_id] = r.n));
  const val = {}; chs.forEach((c) => (val[c.id] = currentValue(c, n[c.id] || 0)));
  const score = {}, last = {}, cnt = {};
  users.forEach((u) => { score[u.uuid] = 0; last[u.uuid] = 0; cnt[u.uuid] = 0; });
  for (const s of solves) {
    if (!(s.uuid in score) || !(s.challenge_id in val)) continue;
    score[s.uuid] += val[s.challenge_id]; cnt[s.uuid]++;
    if (s.ts_ms > last[s.uuid]) last[s.uuid] = s.ts_ms;
  }
  hints.forEach((h) => { if (h.uuid in score) score[h.uuid] -= h.c || 0; });
  return users
    .map((u) => ({ name: u.name, score: score[u.uuid], solves: cnt[u.uuid], last: last[u.uuid] }))
    .sort((a, b) => b.score - a.score || (a.last || BIG) - (b.last || BIG) || a.name.localeCompare(b.name));
}

// ---------- public ----------
async function getState(env) {
  const now = Date.now();
  // one D1 query instead of six (this endpoint is polled by every open tab)
  const c = await getConfig(env, ["event_name", "event_start", "event_end", "join_code"]);
  const start = Number(cfgGet(c, "event_start", 0));
  const end = Number(cfgGet(c, "event_end", 0));
  return json({
    name: cfgGet(c, "event_name", ""),
    start,
    end,
    now, phase: phaseFrom(start, end, now),
    code_required: !!String(cfgGet(c, "join_code", "") || "").trim(),
  });
}

async function getMe(req, env) {
  const uuid = playerId(req);
  if (!uuid) return err("bad player id");
  const u = await env.DB.prepare("SELECT name FROM users WHERE uuid=?").bind(uuid).first();
  // `registered:false` is what the page keys on (a bare 404 from an older Worker must never wipe a player's identity)
  return u ? json({ name: u.name, registered: true }) : err("not registered", 404, { registered: false });
}

async function getTimeline(env) {
  const now = Date.now();
  const c = await getConfig(env, ["event_start", "event_end"]);
  const start = Number(cfgGet(c, "event_start", 0)), end = Number(cfgGet(c, "event_end", 0));
  const phase = phaseFrom(start, end, now);
  if (phase === "pre" || phase === "unset") return { phase, event: {}, solves: [] };
  const [{ valBy }, rows] = await Promise.all([
    scoreMaps(env),
    env.DB.prepare("SELECT u.name, s.challenge_id, s.ts_ms FROM solves s JOIN users u ON u.uuid=s.uuid WHERE s.scored=1 ORDER BY s.ts_ms").all(),
  ]);
  return {
    phase,
    event: { start, end },
    solves: rows.results.map((s) => ({ name: s.name, ts_ms: s.ts_ms, points: valBy[s.challenge_id] || 0 })),
  };
}

function iconFor(category, overrides) {
  const key = String(category || "").toUpperCase();
  return overrides[key] || DEFAULT_ICONS[key] || DEFAULT_ICONS._DEFAULT;
}
const parseOverrides = (raw) => { try { return raw ? JSON.parse(raw) : {}; } catch { return {}; } };
const iconOverrides = async (env) => parseOverrides(await cfg(env, "category_icons", null));

async function getChallenges(req, env) {
  const now = Date.now();
  const phase = await phaseOf(env, now);
  if (phase === "pre" || phase === "unset") return json({ phase, challenges: [], icons: {} });
  const uuid = playerId(req);
  const stmts = [
    env.DB.prepare("SELECT * FROM challenges WHERE active=1"),
    env.DB.prepare("SELECT challenge_id, COUNT(*) n FROM solves WHERE scored=1 GROUP BY challenge_id"),
    env.DB.prepare("SELECT value FROM config WHERE key='category_icons'"),
  ];
  if (uuid) {
    stmts.push(
      env.DB.prepare("SELECT challenge_id FROM solves WHERE uuid=?").bind(uuid),
      env.DB.prepare("SELECT challenge_id,count,last_ms FROM attempts WHERE uuid=?").bind(uuid),
      env.DB.prepare("SELECT challenge_id FROM hint_unlocks WHERE uuid=?").bind(uuid),
      env.DB.prepare("SELECT 1 x FROM users WHERE uuid=?").bind(uuid),
    );
  }
  const res = (await env.DB.batch(stmts)).map((r) => r.results);
  // While the event is live, only registered players (who had to pass the access code) get the question text.
  // Everyone else still gets title/category/points/solve counts, so the cards and leaderboard keep working.
  // After the event ends the questions are public (the answers are revealed then anyway).
  const registered = !!(res[6] && res[6].length);
  const locked = phase === "live" && !registered;
  const nBy = {}; res[1].forEach((r) => (nBy[r.challenge_id] = r.n));
  const overrides = parseOverrides(res[2][0] && res[2][0].value);
  const solved = new Set((res[3] || []).map((r) => r.challenge_id));
  const att = {}; (res[4] || []).forEach((r) => (att[r.challenge_id] = r));
  const hinted = new Set((res[5] || []).map((r) => r.challenge_id));
  const list = res[0]
    .sort((a, b) => a.category.localeCompare(b.category) || a.sort - b.sort || a.title.localeCompare(b.title))
    .map((ch) => {
      const at = att[ch.id];
      return { // NOTE: no `answers`/`solution` here — never sent to players
        id: ch.id, category: ch.category, title: ch.title, prompt: locked ? "" : ch.prompt,
        value: currentValue(ch, nBy[ch.id] || 0), solves: nBy[ch.id] || 0,
        has_hint: !!(ch.hint && ch.hint.trim()), hint_cost: ch.hint_cost,
        hint: ch.hint && (hinted.has(ch.id) || phase === "post") ? ch.hint : null, // hints are free once the event is over
        solved: solved.has(ch.id),
        attempts_left: Math.max(0, ch.attempts_max - (at ? at.count : 0)),
        holdoff_until: at ? at.last_ms + ch.holdoff_ms : 0,
      };
    });
  const icons = {};
  list.forEach((c) => { icons[c.category] = iconFor(c.category, overrides); });
  return json({ phase, challenges: list, icons, locked });
}

async function joinCode(env) {
  return String((await cfg(env, "join_code", "")) || "").trim();
}

async function register(env, bust, b) {
  const uuid = String(b.uuid ?? "");
  if (!PLAYER_ID_RE.test(uuid)) return err("bad player id");
  const name = cleanName(b.name);
  if (!name) return err(NAME_MSG);
  const lc = name.toLowerCase();
  const clash = await env.DB.prepare("SELECT uuid FROM users WHERE name_lc=? AND uuid<>?").bind(lc, uuid).first();
  if (clash) return err("username taken", 409);
  const exists = await env.DB.prepare("SELECT uuid FROM users WHERE uuid=?").bind(uuid).first();
  if (!exists) {
    // access code only gates first-time join, not renaming an already-registered player
    const required = await joinCode(env);
    if (required && !(await secretEq(String(b.code ?? "").trim().toLowerCase(), required.toLowerCase()))) {
      return err("wrong access code", 403);
    }
    const { n } = await env.DB.prepare("SELECT COUNT(*) n FROM users").first();
    if (n >= (Number(env.MAX_USERS) || 300)) return err("event is full", 403);
  }
  try {
    if (exists) await env.DB.prepare("UPDATE users SET name=?, name_lc=? WHERE uuid=?").bind(name, lc, uuid).run();
    else await env.DB.prepare("INSERT INTO users(uuid,name,name_lc,created_ms) VALUES(?,?,?,?)").bind(uuid, name, lc, Date.now()).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) return err("username taken", 409); // lost a race with another player
    throw e;
  }
  await bust();
  return json({ ok: true, name });
}

const deleteUser = (env, uuid) =>
  env.DB.batch([
    env.DB.prepare("DELETE FROM solves WHERE uuid=?").bind(uuid),
    env.DB.prepare("DELETE FROM attempts WHERE uuid=?").bind(uuid),
    env.DB.prepare("DELETE FROM hint_unlocks WHERE uuid=?").bind(uuid),
    env.DB.prepare("DELETE FROM users WHERE uuid=?").bind(uuid),
  ]);

async function unregister(env, bust, b) {
  const uuid = String(b.uuid ?? "");
  if (!PLAYER_ID_RE.test(uuid)) return err("bad player id");
  await deleteUser(env, uuid);
  await bust();
  return json({ ok: true });
}

async function submit(env, bust, b) {
  const uuid = String(b.uuid ?? ""), cid = String(b.challenge_id ?? "");
  if (!PLAYER_ID_RE.test(uuid) || !ID_RE.test(cid)) return err("bad request");
  if (!(await env.DB.prepare("SELECT uuid FROM users WHERE uuid=?").bind(uuid).first())) return err("register a username first", 403);
  const ch = await env.DB.prepare("SELECT * FROM challenges WHERE id=? AND active=1").bind(cid).first();
  if (!ch) return err("no such challenge", 404);
  const now = Date.now();
  const phase = await phaseOf(env, now);
  if (phase === "pre" || phase === "unset") return err("event not started", 403);
  if (await env.DB.prepare("SELECT 1 FROM solves WHERE uuid=? AND challenge_id=?").bind(uuid, cid).first()) return err("already solved", 409);

  // Atomic attempt claim: the UPDATE itself enforces max-attempts and the cooldown, so parallel
  // requests cannot bypass either (only one statement can satisfy the WHERE clause).
  await env.DB.prepare("INSERT OR IGNORE INTO attempts(uuid,challenge_id,count,last_ms) VALUES(?,?,0,0)").bind(uuid, cid).run();
  const claim = await env.DB.prepare(
    "UPDATE attempts SET count=count+1, last_ms=? WHERE uuid=? AND challenge_id=? AND count<? AND last_ms+?<=? RETURNING count"
  ).bind(now, uuid, cid, ch.attempts_max, ch.holdoff_ms, now).first();
  if (!claim) {
    const at = (await env.DB.prepare("SELECT count,last_ms FROM attempts WHERE uuid=? AND challenge_id=?").bind(uuid, cid).first()) || { count: 0, last_ms: 0 };
    if (at.count >= ch.attempts_max) return err("out of attempts", 429, { attempts_left: 0 });
    return err("cooling down", 429, { correct: false, holdoff_until: at.last_ms + ch.holdoff_ms, attempts_left: ch.attempts_max - at.count });
  }

  const accepted = new Set(answersArray(ch.answers).map(normalize));
  if (!accepted.has(normalize(b.answer))) {
    return json({ correct: false, attempts_left: ch.attempts_max - claim.count, holdoff_until: now + ch.holdoff_ms });
  }
  const scored = phase === "live" ? 1 : 0;
  const ins = await env.DB.prepare("INSERT OR IGNORE INTO solves(uuid,challenge_id,ts_ms,scored) VALUES(?,?,?,?)").bind(uuid, cid, now, scored).run();
  if (!ins.meta.changes) return err("already solved", 409);
  await bust();
  const { valBy } = await scoreMaps(env);
  return json({ correct: true, scored: !!scored, points: scored ? (valBy[cid] || ch.minimum) : 0 });
}

async function buyHint(env, bust, b) {
  const uuid = String(b.uuid ?? ""), cid = String(b.challenge_id ?? "");
  if (!PLAYER_ID_RE.test(uuid) || !ID_RE.test(cid)) return err("bad request");
  const phase = await phaseOf(env, Date.now());
  if (phase === "pre" || phase === "unset") return err("event not started", 403); // ids are guessable, so hints must not leak before the start
  if (!(await env.DB.prepare("SELECT uuid FROM users WHERE uuid=?").bind(uuid).first())) return err("register a username first", 403);
  const ch = await env.DB.prepare("SELECT hint,hint_cost FROM challenges WHERE id=? AND active=1").bind(cid).first();
  if (!ch || !ch.hint) return err("no hint", 404);
  if (phase === "post") return json({ hint: ch.hint, cost: 0 }); // free after the event; nothing recorded, so no score change
  await env.DB.prepare("INSERT OR IGNORE INTO hint_unlocks(uuid,challenge_id) VALUES(?,?)").bind(uuid, cid).run();
  await bust();
  return json({ hint: ch.hint, cost: ch.hint_cost });
}

async function getSolutions(env) {
  if ((await phaseOf(env, Date.now())) !== "post") return err("solutions reveal after the event ends", 403);
  const rows = (await env.DB.prepare("SELECT id,category,title,solution FROM challenges WHERE active=1 ORDER BY category,sort,title").all()).results;
  return json({ solutions: rows });
}

// ---------- admin ----------
async function adminOK(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer\s+(\S{1,256})$/i); // no minimum length here: tokens set before the 20-char rule keep working
  if (!m) return false;
  const row = await env.DB.prepare("SELECT value FROM config WHERE key='admin_token_hash'").first();
  return !!row && safeEq(await sha256hex(m[1]), row.value);
}

function validateChallenge(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return { error: "not an object" };
  const id = String(c.id ?? "");
  if (!ID_RE.test(id)) return { error: "bad id (1-64 chars, no slashes/control chars)" };
  const category = str(c.category, 60).trim(), title = str(c.title, 200).trim();
  if (!category || !title) return { error: "category and title required" };
  const list = (Array.isArray(c.answers) ? c.answers : [c.answers]).flatMap((a) => String(a ?? "").split("\n"));
  const answers = [...new Set(list.map((a) => str(a, 512).trim()).filter(Boolean))].slice(0, 50);
  if (!answers.length) return { error: "at least one answer required" };
  const initial = clampInt(c.initial, 100, 1, 100000);
  return {
    row: {
      id, category, title, prompt: str(c.prompt, 8000),
      initial, minimum: Math.min(initial, clampInt(c.minimum, 50, 1, 100000)),
      decay: clampInt(c.decay, 20, 1, 10000),
      attempts_max: clampInt(c.attempts_max, 10, 1, 1000),
      holdoff_ms: clampInt(c.holdoff_ms, 30000, 0, 3600000),
      hint: str(c.hint, 2000).trim() || null,
      hint_cost: clampInt(c.hint_cost, 0, 0, 100000),
      answers: answers.join("\n"), solution: str(c.solution, 4000) || null,
      sort: clampInt(c.sort, 0, -100000, 100000),
    },
  };
}

async function adminChallenges(env, bust, body) {
  const items = Array.isArray(body) ? body : body.challenges;
  if (!Array.isArray(items) || items.length > 500) return err("expected an array of up to 500 challenges");
  const stmts = [], skipped = [];
  for (const c of items) {
    const v = validateChallenge(c);
    if (v.error) { skipped.push(`${str(c && c.id, 64) || "(no id)"}: ${v.error}`); continue; }
    const r = v.row;
    stmts.push(env.DB.prepare(
      `INSERT INTO challenges(id,category,title,prompt,initial,minimum,decay,attempts_max,holdoff_ms,hint,hint_cost,answers,solution,sort,active)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
       ON CONFLICT(id) DO UPDATE SET category=excluded.category,title=excluded.title,prompt=excluded.prompt,
         initial=excluded.initial,minimum=excluded.minimum,decay=excluded.decay,attempts_max=excluded.attempts_max,
         holdoff_ms=excluded.holdoff_ms,hint=excluded.hint,hint_cost=excluded.hint_cost,answers=excluded.answers,
         solution=excluded.solution,sort=excluded.sort,active=1`
    ).bind(r.id, r.category, r.title, r.prompt, r.initial, r.minimum, r.decay, r.attempts_max, r.holdoff_ms, r.hint, r.hint_cost, r.answers, r.solution, r.sort));
  }
  for (let i = 0; i < stmts.length; i += 25) await env.DB.batch(stmts.slice(i, i + 25));
  await bust();
  return json({ upserted: stmts.length, skipped });
}

async function adminDeleteChallenge(env, bust, id) {
  if (!ID_RE.test(id)) return err("bad id");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM solves WHERE challenge_id=?").bind(id),
    env.DB.prepare("DELETE FROM attempts WHERE challenge_id=?").bind(id),
    env.DB.prepare("DELETE FROM hint_unlocks WHERE challenge_id=?").bind(id),
    env.DB.prepare("DELETE FROM challenges WHERE id=?").bind(id),
  ]);
  await bust();
  return json({ ok: true });
}

async function adminListChallenges(env) {
  const rows = (await env.DB.prepare("SELECT * FROM challenges ORDER BY category,sort,title").all()).results;
  // return answers as an array for the editor (plaintext — admin only)
  rows.forEach((r) => (r.answers = answersArray(r.answers)));
  return json({ challenges: rows });
}

async function adminUsers(env) {
  const rows = (await env.DB.prepare("SELECT uuid,name,created_ms FROM users ORDER BY created_ms").all()).results;
  return json({ users: rows });
}

async function adminReset(env, bust) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM solves"),
    env.DB.prepare("DELETE FROM attempts"),
    env.DB.prepare("DELETE FROM hint_unlocks"),
    env.DB.prepare("DELETE FROM users"),
  ]);
  await bust();
  return json({ ok: true });
}

async function adminEvent(env, bust, b) {
  const c = await getConfig(env, ["event_name", "event_start", "event_end"]);
  const name = b.name != null ? str(b.name, 80).trim() : cfgGet(c, "event_name", "");
  const start = b.start != null ? clampInt(b.start, 0, 0, FAR_FUTURE) : Number(cfgGet(c, "event_start", 0));
  const end = b.end != null ? clampInt(b.end, 0, 0, FAR_FUTURE) : Number(cfgGet(c, "event_end", 0));
  if (start && end && end <= start) return err("end must be after start");
  await env.DB.batch([setCfgStmt(env, "event_name", name), setCfgStmt(env, "event_start", start), setCfgStmt(env, "event_end", end)]);
  await bust();
  return await getState(env);
}

async function adminRenameUser(env, bust, b) {
  const uuid = String(b.uuid ?? "");
  const name = cleanName(b.name, true); // admin may use reserved names
  if (!PLAYER_ID_RE.test(uuid) || !name) return err(NAME_MSG);
  const lc = name.toLowerCase();
  if (await env.DB.prepare("SELECT uuid FROM users WHERE name_lc=? AND uuid<>?").bind(lc, uuid).first()) return err("username taken", 409);
  try {
    await env.DB.prepare("UPDATE users SET name=?, name_lc=? WHERE uuid=?").bind(name, lc, uuid).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) return err("username taken", 409);
    throw e;
  }
  await bust();
  return json({ ok: true });
}

async function adminExport(env) {
  const board = await getLeaderboard(env);
  const { valBy } = await scoreMaps(env);
  const c = await getConfig(env, ["event_name", "event_start", "event_end"]);
  const solves = (await env.DB.prepare(
    "SELECT u.name, s.challenge_id, s.ts_ms, s.scored FROM solves s JOIN users u ON u.uuid=s.uuid ORDER BY s.ts_ms"
  ).all()).results;
  return json({
    generated: new Date().toISOString(),
    event: {
      name: cfgGet(c, "event_name", ""),
      start: Number(cfgGet(c, "event_start", 0)),
      end: Number(cfgGet(c, "event_end", 0)),
    },
    leaderboard: board.map((b, i) => ({
      rank: i + 1, name: b.name, score: b.score, solves: b.solves,
      last_solve: b.last ? new Date(b.last).toISOString() : "",
    })),
    solves: solves.map((s) => ({
      name: s.name, challenge_id: s.challenge_id, ts_ms: s.ts_ms,
      ts: new Date(s.ts_ms).toISOString(), scored: !!s.scored,
      points: s.scored ? (valBy[s.challenge_id] || 0) : 0,
    })),
  });
}

async function admin(req, env, bust, p, body) {
  const m = req.method;
  if (m === "POST" && p === "/admin/rotate-token") { // valid current token OR bootstrap key
    const viaBootstrap = !!env.BOOTSTRAP_KEY && (await secretEq(req.headers.get("X-Bootstrap-Key"), env.BOOTSTRAP_KEY));
    if (!viaBootstrap && !(await adminOK(req, env))) { audit(req, "admin_auth_fail", { path: p }); return err("unauthorized", 401); }
    const nt = String(body.new_token ?? "");
    if (nt.length < 20 || nt.length > 256) return err("new_token must be 20-256 chars");
    await setCfg(env, "admin_token_hash", await sha256hex(nt));
    audit(req, "rotate_token", { via: viaBootstrap ? "bootstrap" : "token" });
    return json({ ok: true });
  }
  if (!(await adminOK(req, env))) { audit(req, "admin_auth_fail", { path: p }); return err("unauthorized", 401); }
  audit(req, "admin", { m, path: p });

  if (m === "POST" && p === "/admin/challenges") return await adminChallenges(env, bust, body);
  if (m === "GET" && p === "/admin/challenges") return await adminListChallenges(env);
  if (m === "DELETE" && p.startsWith("/admin/challenge/")) return await adminDeleteChallenge(env, bust, decodeURIComponent(p.slice("/admin/challenge/".length)));
  if (m === "POST" && p === "/admin/challenges/clear") { // remove EVERY challenge (+ their solves/attempts/hint unlocks); players, join code, icons and the event are kept
    const { n } = await env.DB.prepare("SELECT COUNT(*) n FROM challenges").first();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM solves"),
      env.DB.prepare("DELETE FROM attempts"),
      env.DB.prepare("DELETE FROM hint_unlocks"),
      env.DB.prepare("DELETE FROM challenges"),
    ]);
    await bust();
    audit(req, "challenges_cleared", { removed: n });
    return json({ ok: true, removed: n });
  }
  if (m === "GET" && p === "/admin/users") return await adminUsers(env);
  if (m === "POST" && p === "/admin/user/rename") return await adminRenameUser(env, bust, body);
  if (m === "DELETE" && p.startsWith("/admin/user/")) return await unregister(env, bust, { uuid: decodeURIComponent(p.slice("/admin/user/".length)) });
  if (m === "POST" && p === "/admin/reset") return await adminReset(env, bust);
  if (m === "POST" && p === "/admin/event") return await adminEvent(env, bust, body);
  if (m === "GET" && p === "/admin/export") return await adminExport(env);
  if (m === "GET" && p === "/admin/category-icons") {
    return json({ overrides: await iconOverrides(env), defaults: DEFAULT_ICONS });
  }
  if (m === "POST" && p === "/admin/category-icons") {
    const patch = body.icons && typeof body.icons === "object" ? body.icons : {};
    const cur = await iconOverrides(env);
    for (const [cat, dataUri] of Object.entries(patch)) {
      const key = String(cat || "").toUpperCase();
      if (!key) continue;
      if (!dataUri) delete cur[key]; // empty value clears the override, reverting to default
      else if (iconOK(String(dataUri))) cur[key] = String(dataUri);
      else return err("icon must be a data:image/... URI (or an https URL), max 20 KB");
    }
    await setCfg(env, "category_icons", JSON.stringify(cur));
    await bust(); // the timeline/board don't carry icons, but keep the rule simple: any admin write busts the cache
    return json({ ok: true, overrides: cur });
  }
  if (m === "GET" && p === "/admin/join-code") {
    return json({ code: await joinCode(env) });
  }
  if (m === "POST" && p === "/admin/join-code") {
    const code = String(body.code ?? "").trim().slice(0, 64);
    await setCfg(env, "join_code", code);
    return json({ ok: true, code });
  }
  return err("not found", 404);
}

// ---------- router ----------
// Edge cache (Cache API) for the two public, all-player endpoints. Busted on any change so a
// join / solve / rename shows up immediately; browsers always get no-store so a refetch is never stale.
const cacheKey = (req, path) => new Request(new URL("/api" + path, req.url).href);
const CACHED = ["/leaderboard", "/timeline"];

async function cachedJson(req, ctx, path, produce) {
  const key = cacheKey(req, path);
  const hit = await caches.default.match(key);
  if (hit) return new Response(hit.body, { status: 200, headers: { ...BASE_HEADERS, "X-Edge-Cache": "hit" } });
  const data = JSON.stringify(await produce());
  ctx.waitUntil(caches.default.put(key, new Response(data, { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=5" } })));
  return new Response(data, { status: 200, headers: { ...BASE_HEADERS, "X-Edge-Cache": "miss" } });
}

async function handle(req, env, ctx) {
  const p = new URL(req.url).pathname.replace(/^\/api/, "") || "/";
  const m = req.method;
  const bust = () => Promise.all(CACHED.map((x) => caches.default.delete(cacheKey(req, x))));

  let body = {};
  if (m === "POST") {
    if (!/^application\/json/i.test(req.headers.get("Content-Type") || "")) return err("content-type must be application/json", 415);
    const max = p.startsWith("/admin/") ? MAX_ADMIN_BODY : MAX_PUBLIC_BODY;
    if (Number(req.headers.get("Content-Length") || 0) > max) return err("payload too large", 413);
    const txt = await req.text();
    if (txt.length > max) return err("payload too large", 413);
    try { body = txt ? JSON.parse(txt) : {}; } catch { return err("invalid JSON"); }
    if (body === null || typeof body !== "object") body = {};
  }

  if (m === "GET") {
    if (p === "/state") return await getState(env);
    if (p === "/me") return await getMe(req, env);
    if (p === "/leaderboard") return await cachedJson(req, ctx, p, async () => ({ board: await getLeaderboard(env) }));
    if (p === "/timeline") return await cachedJson(req, ctx, p, () => getTimeline(env));
    if (p === "/challenges") return await getChallenges(req, env);
    if (p === "/solutions") return await getSolutions(env);
  }
  if (m === "POST") {
    if (p === "/register" || p === "/rename") return await register(env, bust, body);
    if (p === "/unregister") return await unregister(env, bust, body);
    if (p === "/submit") return await submit(env, bust, body);
    if (p === "/hint") return await buyHint(env, bust, body);
  }
  if (p.startsWith("/admin/")) return await admin(req, env, bust, p, body);
  return err("not found", 404);
}

export default {
  async fetch(req, env, ctx) {
    // CORS is off (same-origin) unless ALLOWED_ORIGIN is set and matches the caller
    const origin = req.headers.get("Origin");
    const cors = env.ALLOWED_ORIGIN && origin === env.ALLOWED_ORIGIN ? {
      "Access-Control-Allow-Origin": origin, "Vary": "Origin",
      "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Bootstrap-Key,X-Player-Id",
      "Access-Control-Max-Age": "86400",
    } : null;
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors || {} });
    let res;
    try {
      res = await handle(req, env, ctx);
    } catch (e) {
      console.error("unhandled", e && e.stack ? e.stack : String(e)); // detail stays in logs, never in the response
      res = err("server error", 500);
    }
    if (!cors) return res;
    const r = new Response(res.body, res);
    Object.entries(cors).forEach(([k, v]) => r.headers.set(k, v));
    return r;
  },
};
