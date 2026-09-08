// OSINT CTF API — Cloudflare Worker (module syntax)
// Bindings: env.DB (D1), env.BOOTSTRAP_KEY (secret, admin-token recovery)
// NOTE: answers are stored as editable plaintext on the challenge row. They are
// returned ONLY by GET /api/admin/challenges (bearer-token protected) and never
// to any player endpoint. The answer key is therefore as secret as the admin token.

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Bootstrap-Key",
  "Access-Control-Max-Age": "86400",
};
const json = (o, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", ...CORS } });
const err = (msg, s = 400) => json({ error: msg }, s);

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha256hex(str) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(str))); }

// Answer normalization for matching. Keep predictable; use multiple accepted
// answers for real variants. (Storage keeps the admin's original text; both
// stored and submitted values are normalized only at compare time.)
function normalize(s) {
  return String(s ?? "")
    .normalize("NFKC").trim().toLowerCase()
    .replace(/^flag\{(.*)\}$/i, "$1")
    .replace(/\s+/g, " ")
    .replace(/[.\s]+$/g, "");
}
const answersArray = (txt) => String(txt || "").split("\n").map((x) => x.trim()).filter(Boolean);

async function cfg(env, key, def = null) {
  const r = await env.DB.prepare("SELECT value FROM config WHERE key=?").bind(key).first();
  return r ? r.value : def;
}
async function setCfg(env, key, value) {
  await env.DB.prepare("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .bind(key, String(value)).run();
}
async function phaseOf(env, now) {
  const start = Number(await cfg(env, "event_start", 0));
  const end = Number(await cfg(env, "event_end", 0));
  if (!start || !end) return "unset";
  if (now < start) return "pre";
  if (now > end) return "post";
  return "live";
}

function currentValue(ch, scoredSolves) {
  const v = Math.ceil(((ch.minimum - ch.initial) / (ch.decay * ch.decay)) * (scoredSolves * scoredSolves) + ch.initial);
  return Math.max(ch.minimum, v);
}
async function scoreMaps(env) {
  const chs = (await env.DB.prepare("SELECT * FROM challenges WHERE active=1").all()).results;
  const solves = (await env.DB.prepare("SELECT challenge_id, COUNT(*) n FROM solves WHERE scored=1 GROUP BY challenge_id").all()).results;
  const nBy = {}; solves.forEach((r) => (nBy[r.challenge_id] = r.n));
  const valBy = {}, chBy = {};
  for (const ch of chs) { chBy[ch.id] = ch; valBy[ch.id] = currentValue(ch, nBy[ch.id] || 0); }
  return { chBy, valBy, nBy };
}

async function adminOK(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  const stored = await cfg(env, "admin_token_hash");
  if (!stored) return false;
  return (await sha256hex(m[1])) === stored;
}

// ---------- public ----------
async function getState(env) {
  const now = Date.now();
  return json({
    name: await cfg(env, "event_name", ""),
    start: Number(await cfg(env, "event_start", 0)),
    end: Number(await cfg(env, "event_end", 0)),
    now, phase: await phaseOf(env, now),
  });
}

async function getLeaderboard(env) {
  const { valBy } = await scoreMaps(env);
  const solves = (await env.DB.prepare("SELECT uuid, challenge_id, ts_ms, scored FROM solves").all()).results;
  const hints = (await env.DB.prepare("SELECT h.uuid, c.hint_cost FROM hint_unlocks h JOIN challenges c ON c.id=h.challenge_id").all()).results;
  const users = (await env.DB.prepare("SELECT uuid, name FROM users").all()).results;
  const score = {}, last = {}, cnt = {};
  users.forEach((u) => { score[u.uuid] = 0; last[u.uuid] = 0; cnt[u.uuid] = 0; });
  for (const s of solves) {
    if (score[s.uuid] === undefined) continue;
    if (s.scored) { score[s.uuid] += valBy[s.challenge_id] || 0; cnt[s.uuid]++; last[s.uuid] = Math.max(last[s.uuid], s.ts_ms); }
  }
  for (const h of hints) if (score[h.uuid] !== undefined) score[h.uuid] -= h.hint_cost || 0;
  const board = users.map((u) => ({ name: u.name, score: score[u.uuid], solves: cnt[u.uuid], last: last[u.uuid] }))
    .sort((a, b) => b.score - a.score || (a.last || Infinity) - (b.last || Infinity));
  return board;
}

async function getChallenges(env, uuid) {
  const now = Date.now();
  const phase = await phaseOf(env, now);
  if (phase === "pre" || phase === "unset") return json({ phase, challenges: [] });
  const { chBy, valBy, nBy } = await scoreMaps(env);
  const mine = { solves: {}, attempts: {}, hints: {} };
  if (uuid) {
    (await env.DB.prepare("SELECT challenge_id FROM solves WHERE uuid=?").bind(uuid).all()).results.forEach((r) => (mine.solves[r.challenge_id] = 1));
    (await env.DB.prepare("SELECT challenge_id,count,last_ms FROM attempts WHERE uuid=?").bind(uuid).all()).results.forEach((r) => (mine.attempts[r.challenge_id] = r));
    (await env.DB.prepare("SELECT challenge_id FROM hint_unlocks WHERE uuid=?").bind(uuid).all()).results.forEach((r) => (mine.hints[r.challenge_id] = 1));
  }
  const list = Object.values(chBy)
    .sort((a, b) => a.category.localeCompare(b.category) || a.sort - b.sort || a.title.localeCompare(b.title))
    .map((ch) => {
      const at = mine.attempts[ch.id];
      const hintUnlocked = !!mine.hints[ch.id];
      return { // NOTE: no `answers`/`solution` here — never sent to players
        id: ch.id, category: ch.category, title: ch.title, prompt: ch.prompt,
        value: valBy[ch.id], solves: nBy[ch.id] || 0,
        has_hint: !!(ch.hint && ch.hint.trim()), hint_cost: ch.hint_cost,
        hint: hintUnlocked ? ch.hint : null,
        solved: !!mine.solves[ch.id],
        attempts_left: Math.max(0, ch.attempts_max - (at ? at.count : 0)),
        holdoff_until: at ? at.last_ms + ch.holdoff_ms : 0,
      };
    });
  return json({ phase, challenges: list });
}

async function register(env, b) {
  const uuid = String(b.uuid || "").slice(0, 64);
  const name = String(b.name || "").trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 24);
  if (!uuid || !name) return err("uuid and name required");
  const lc = name.toLowerCase();
  const clash = await env.DB.prepare("SELECT uuid FROM users WHERE name_lc=? AND uuid<>?").bind(lc, uuid).first();
  if (clash) return err("username taken", 409);
  const exists = await env.DB.prepare("SELECT uuid FROM users WHERE uuid=?").bind(uuid).first();
  if (exists) await env.DB.prepare("UPDATE users SET name=?, name_lc=? WHERE uuid=?").bind(name, lc, uuid).run();
  else await env.DB.prepare("INSERT INTO users(uuid,name,name_lc,created_ms) VALUES(?,?,?,?)").bind(uuid, name, lc, Date.now()).run();
  return json({ ok: true, name });
}

async function unregister(env, b) {
  const uuid = String(b.uuid || "");
  if (!uuid) return err("uuid required");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM solves WHERE uuid=?").bind(uuid),
    env.DB.prepare("DELETE FROM attempts WHERE uuid=?").bind(uuid),
    env.DB.prepare("DELETE FROM hint_unlocks WHERE uuid=?").bind(uuid),
    env.DB.prepare("DELETE FROM users WHERE uuid=?").bind(uuid),
  ]);
  return json({ ok: true });
}

async function submit(env, b) {
  const uuid = String(b.uuid || ""), cid = String(b.challenge_id || ""), answer = b.answer;
  if (!uuid || !cid) return err("uuid and challenge_id required");
  if (!(await env.DB.prepare("SELECT uuid FROM users WHERE uuid=?").bind(uuid).first())) return err("register a username first", 403);
  const ch = await env.DB.prepare("SELECT * FROM challenges WHERE id=? AND active=1").bind(cid).first();
  if (!ch) return err("no such challenge", 404);
  const now = Date.now();
  const phase = await phaseOf(env, now);
  if (phase === "pre" || phase === "unset") return err("event not started", 403);
  if (await env.DB.prepare("SELECT 1 FROM solves WHERE uuid=? AND challenge_id=?").bind(uuid, cid).first()) return err("already solved", 409);

  let at = await env.DB.prepare("SELECT count,last_ms FROM attempts WHERE uuid=? AND challenge_id=?").bind(uuid, cid).first();
  at = at || { count: 0, last_ms: 0 };
  if (at.count >= ch.attempts_max) return err("out of attempts", 429);
  if (at.last_ms + ch.holdoff_ms > now) return json({ correct: false, holdoff_until: at.last_ms + ch.holdoff_ms, attempts_left: ch.attempts_max - at.count }, 429);

  const accepted = new Set(answersArray(ch.answers).map(normalize));
  const match = accepted.has(normalize(answer));

  if (!match) {
    await env.DB.prepare("INSERT INTO attempts(uuid,challenge_id,count,last_ms) VALUES(?,?,1,?) ON CONFLICT(uuid,challenge_id) DO UPDATE SET count=count+1, last_ms=?")
      .bind(uuid, cid, now, now).run();
    return json({ correct: false, attempts_left: ch.attempts_max - (at.count + 1), holdoff_until: now + ch.holdoff_ms });
  }
  const scored = phase === "live" ? 1 : 0;
  await env.DB.prepare("INSERT INTO solves(uuid,challenge_id,ts_ms,scored) VALUES(?,?,?,?)").bind(uuid, cid, now, scored).run();
  const { valBy } = await scoreMaps(env);
  return json({ correct: true, scored: !!scored, points: scored ? (valBy[cid] || ch.minimum) : 0 });
}

async function buyHint(env, b) {
  const uuid = String(b.uuid || ""), cid = String(b.challenge_id || "");
  if (!(await env.DB.prepare("SELECT uuid FROM users WHERE uuid=?").bind(uuid).first())) return err("register a username first", 403);
  const ch = await env.DB.prepare("SELECT hint,hint_cost FROM challenges WHERE id=? AND active=1").bind(cid).first();
  if (!ch || !ch.hint) return err("no hint", 404);
  await env.DB.prepare("INSERT OR IGNORE INTO hint_unlocks(uuid,challenge_id) VALUES(?,?)").bind(uuid, cid).run();
  return json({ hint: ch.hint, cost: ch.hint_cost });
}

async function getSolutions(env) {
  if ((await phaseOf(env, Date.now())) !== "post") return err("solutions reveal after the event ends", 403);
  const rows = (await env.DB.prepare("SELECT id,category,title,solution FROM challenges WHERE active=1 ORDER BY category,sort,title").all()).results;
  return json({ solutions: rows });
}

// ---------- admin ----------
async function adminChallenges(env, body) {
  const items = Array.isArray(body) ? body : body.challenges;
  if (!Array.isArray(items)) return err("expected an array of challenges");
  let n = 0; const skipped = [];
  for (const c of items) {
    if (!c.id || !c.category || !c.title) { skipped.push(c.id || "(no id)"); continue; }
    // answers accepted as array or newline string
    const ansList = Array.isArray(c.answers) ? c.answers : answersArray(c.answers);
    const answers = ansList.map((a) => String(a).trim()).filter(Boolean);
    if (answers.length === 0) { skipped.push(c.id + " (no answers)"); continue; }
    await env.DB.prepare(
      `INSERT INTO challenges(id,category,title,prompt,initial,minimum,decay,attempts_max,holdoff_ms,hint,hint_cost,answers,solution,sort,active)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
       ON CONFLICT(id) DO UPDATE SET category=excluded.category,title=excluded.title,prompt=excluded.prompt,
         initial=excluded.initial,minimum=excluded.minimum,decay=excluded.decay,attempts_max=excluded.attempts_max,
         holdoff_ms=excluded.holdoff_ms,hint=excluded.hint,hint_cost=excluded.hint_cost,answers=excluded.answers,
         solution=excluded.solution,sort=excluded.sort,active=1`
    ).bind(
      c.id, c.category, c.title, c.prompt || "",
      c.initial ?? 100, c.minimum ?? 50, c.decay ?? 20, c.attempts_max ?? 10, c.holdoff_ms ?? 30000,
      c.hint || null, c.hint_cost ?? 0, answers.join("\n"), c.solution || null, c.sort ?? 0
    ).run();
    n++;
  }
  return json({ upserted: n, skipped });
}

async function adminDeleteChallenge(env, id) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM solves WHERE challenge_id=?").bind(id),
    env.DB.prepare("DELETE FROM attempts WHERE challenge_id=?").bind(id),
    env.DB.prepare("DELETE FROM hint_unlocks WHERE challenge_id=?").bind(id),
    env.DB.prepare("DELETE FROM challenges WHERE id=?").bind(id),
  ]);
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

async function adminReset(env) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM solves"),
    env.DB.prepare("DELETE FROM attempts"),
    env.DB.prepare("DELETE FROM hint_unlocks"),
    env.DB.prepare("DELETE FROM users"),
  ]);
  return json({ ok: true });
}

async function adminEvent(env, b) {
  if (b.name != null) await setCfg(env, "event_name", b.name);
  if (b.start != null) await setCfg(env, "event_start", Number(b.start));
  if (b.end != null) await setCfg(env, "event_end", Number(b.end));
  return getState(env);
}

async function adminRenameUser(env, b) {
  const name = String(b.name || "").trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 24);
  if (!b.uuid || !name) return err("uuid and name required");
  const lc = name.toLowerCase();
  if (await env.DB.prepare("SELECT uuid FROM users WHERE name_lc=? AND uuid<>?").bind(lc, b.uuid).first()) return err("username taken", 409);
  await env.DB.prepare("UPDATE users SET name=?, name_lc=? WHERE uuid=?").bind(name, lc, b.uuid).run();
  return json({ ok: true });
}

async function adminExport(env) {
  const board = await getLeaderboard(env);
  const solves = (await env.DB.prepare(
    "SELECT u.name, s.challenge_id, s.ts_ms, s.scored FROM solves s JOIN users u ON u.uuid=s.uuid ORDER BY s.ts_ms"
  ).all()).results;
  return json({
    generated: new Date().toISOString(),
    event: {
      name: await cfg(env, "event_name", ""),
      start: Number(await cfg(env, "event_start", 0)),
      end: Number(await cfg(env, "event_end", 0)),
    },
    leaderboard: board.map((b, i) => ({
      rank: i + 1, name: b.name, score: b.score, solves: b.solves,
      last_solve: b.last ? new Date(b.last).toISOString() : "",
    })),
    solves: solves.map((s) => ({
      name: s.name, challenge_id: s.challenge_id,
      ts: new Date(s.ts_ms).toISOString(), scored: !!s.scored,
    })),
  });
}

// ---------- router ----------
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const p = url.pathname.replace(/^\/api/, "");
    let body = {};
    if (req.method === "POST") { try { body = await req.json(); } catch { body = {}; } }

    try {
      if (req.method === "GET" && p === "/state") return await getState(env);
      if (req.method === "GET" && p === "/leaderboard") return json({ board: await getLeaderboard(env) });
      if (req.method === "GET" && p === "/challenges") return await getChallenges(env, url.searchParams.get("uuid"));
      if (req.method === "GET" && p === "/solutions") return await getSolutions(env);
      if (req.method === "POST" && p === "/register") return await register(env, body);
      if (req.method === "POST" && p === "/rename") return await register(env, body);
      if (req.method === "POST" && p === "/unregister") return await unregister(env, body);
      if (req.method === "POST" && p === "/submit") return await submit(env, body);
      if (req.method === "POST" && p === "/hint") return await buyHint(env, body);

      if (req.method === "POST" && p === "/admin/rotate-token") {
        const boot = req.headers.get("X-Bootstrap-Key");
        const ok = (await adminOK(req, env)) || (env.BOOTSTRAP_KEY && boot === env.BOOTSTRAP_KEY);
        if (!ok) return err("unauthorized", 401);
        if (!body.new_token || String(body.new_token).length < 12) return err("new_token must be >= 12 chars");
        await setCfg(env, "admin_token_hash", await sha256hex(String(body.new_token)));
        return json({ ok: true });
      }

      if (p.startsWith("/admin/")) {
        if (!(await adminOK(req, env))) return err("unauthorized", 401);
        if (req.method === "POST" && p === "/admin/challenges") return await adminChallenges(env, body);
        if (req.method === "GET" && p === "/admin/challenges") return await adminListChallenges(env);
        if (req.method === "DELETE" && p.startsWith("/admin/challenge/")) return await adminDeleteChallenge(env, decodeURIComponent(p.split("/").pop()));
        if (req.method === "GET" && p === "/admin/users") return await adminUsers(env);
        if (req.method === "POST" && p === "/admin/user/rename") return await adminRenameUser(env, body);
        if (req.method === "DELETE" && p.startsWith("/admin/user/")) return await unregister(env, { uuid: decodeURIComponent(p.split("/").pop()) });
        if (req.method === "POST" && p === "/admin/reset") return await adminReset(env);
        if (req.method === "POST" && p === "/admin/event") return await adminEvent(env, body);
        if (req.method === "GET" && p === "/admin/export") return await adminExport(env);
        return err("not found", 404);
      }
      return err("not found", 404);
    } catch (e) {
      return err("server error: " + e.message, 500);
    }
  },
};
