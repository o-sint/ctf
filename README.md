# OSINT CTF (GitHub Pages + Cloudflare Worker + D1)

Static frontend on GitHub Pages, all logic in one Cloudflare Worker backed by D1 (SQLite).
No accounts, no third-party DB. Answers are graded server-side and never shipped to players.

```
docs/index.html     player page (leaderboard + challenges)  [GitHub Pages root]
docs/admin.html     admin page (event, challenges, users, export, token, reset)
docs/CNAME          your subdomain
docs/.nojekyll      serve files as-is
worker.js           API + grading + admin
schema.sql          D1 tables
wrangler.toml       Worker + D1 + route config
challenges.sample.json  your 20 challenges, ready to bulk-load
```

## Architecture
- **Identity:** client UUID in `localStorage` is the real identity; username is a mutable label. Clear site data => lose your seat (by design).
- **Answers:** stored as editable plaintext on the challenge row (one accepted answer per line), returned only by `GET /api/admin/challenges` behind the bearer token. Grading is server-side, so players never receive answers. See **Answer exposure** below.
- **Scoring:** CTFd dynamic decay -- `value = max(min, ceil((min-init)/decay^2 * solves^2 + init))`. Everyone holding a solve shows the challenge's *current* value.
- **Gate:** before `start`, `/challenges` is empty and `/submit` refused. After `end`, submissions still validate for practice but score 0; the Reveal button serves `solution` text.
- **Anti-brute:** per-user `attempts_max` (default 10) + `holdoff_ms` cooldown after each wrong answer, per challenge. Add Cloudflare rate-limiting on top (below).

## Answer exposure (read this)
Answers are plaintext in D1, so **the answer key is exactly as secret as your admin token.** Anyone with the token -- or who can read it from a machine where you've opened `admin.html` (it's in `sessionStorage`, visible via devtools) -- can call `GET /api/admin/challenges` and read all answers. Players hitting the site/devtools/network still see nothing; only the admin endpoint exposes them. Practices: use a strong token, rotate it after class, and never open admin on machines students use. (Hashing would have kept a leaked token from revealing answers; you chose editable plaintext, which trades that wall for in-place editing.)

## Deploy -- Cloudflare
```bash
npm i -g wrangler && wrangler login
wrangler d1 create osint_ctf          # copy database_id into wrangler.toml
wrangler d1 execute osint_ctf --file=./schema.sql --remote
wrangler secret put BOOTSTRAP_KEY     # random string; admin-token recovery (openssl rand -hex 32)
# edit wrangler.toml: set routes pattern + zone_name to your subdomain
wrangler deploy
```
(No `ANSWER_PEPPER` -- answers aren't hashed anymore.)

## Deploy -- GitHub Pages
1. Repo Settings -> Pages -> Source: **Deploy from a branch**, branch `main`, folder **/docs**.
2. Edit `docs/CNAME` to your subdomain (currently `ctf.example.com`).
3. Cloudflare DNS: proxied (orange-cloud) `CNAME ctf -> o-sint.github.io`. The Worker route `ctf.example.com/api/*` intercepts the API; everything else falls through to Pages. No CORS.

> Separate-subdomain option: run the API on `ctf-api.example.com`, set that route in `wrangler.toml`, and change `const API` at the top of both files in `docs/` to `https://ctf-api.example.com/api`.

## First run
1. Open `admin.html`. Under the gate, enter `BOOTSTRAP_KEY` + a new admin token (>=12 chars) -> **Set token via bootstrap**, then unlock with it.
2. **Bulk load challenges** -> paste/pick `challenges.sample.json` -> Upload.
3. **Event** -> name + start/end -> Save.

## Admin ops
- **Start/stop:** adjust start/end in the Event panel.
- **Edit answers:** load a challenge (edit), answers show one per line, change and Save.
- **Export:** Export panel -> Leaderboard CSV (rank, name, score, solves, last solve) or Full JSON (adds every solve + timestamps).
- **Reset scoreboard:** Danger zone (keeps challenges + event).
- **Rename/remove player, rotate token:** as labelled. Lost token -> re-set via bootstrap key on the gate.

## Cloudflare rate limiting (Security -> WAF -> Rate limiting rules)
- `/api/submit` -- 10 req / 1 min per IP -> Block.
- `/api/register` -- 5 req / 10 min per IP -> Block.
- optional `/api/*` -- 60 / min per IP. Add Bot Fight Mode.

## Threat model
No auth, but no forged solves (grading is server-side). A determined student can multi-account via fresh UUIDs -- acceptable for a class. Attempt caps + cooldown + rate limiting bound guessing of low-entropy answers. Classroom trainer, not a hardened public CTF.

## Challenge JSON schema
```json
{
  "id": "p3-02",
  "category": "GEO",
  "title": "What does it say",
  "prompt": "question text; include any target URL",
  "initial": 150, "minimum": 75, "decay": 20,
  "attempts_max": 10, "holdoff_ms": 30000,
  "hint": "optional", "hint_cost": 30,
  "answers": ["accepted", "variants"],
  "solution": "shown after the event ends"
}
```
Matching normalization: NFKC -> trim -> lowercase -> collapse whitespace -> strip `flag{...}` -> drop trailing dots/spaces. Add variants (e.g. a trailing `?`) to `answers` as needed.

## Push to your repo (o-sint/ctf)
```bash
git clone https://github.com/o-sint/ctf.git && cd ctf
# copy these files in, keeping public/ as-is
git add worker.js schema.sql wrangler.toml challenges.sample.json README.md docs/
git commit -m "OSINT CTF: Worker + D1 + static frontend"
git push origin main
```

## Data notes
- 20 graded challenges (Part 1 x12, Part 3 x8). Add ~10 more for ~30.
- Part 1 Q12 (crypto USD) had no answer -- omitted.
- p1-13 (latest gophish contributor) is time-sensitive -- re-verify before each class.
- Several answers rely on live third-party sites that rot; spot-check first.

```
wrangler dev --local --port 8787 --assets ./.local-assets

```