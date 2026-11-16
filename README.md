# DC SH!FTZ on Cloudflare (free)

DC SH!FTZ v2.1.1: the same app the team uses now, moved off the Claude-hosted page onto its own free server and database.

- **App + server:** one Cloudflare Worker (`src/worker.js`) serves the screens (`public/`) and the API (`/api/*`).
- **Database:** Cloudflare D1, a SQLite database (`schema.sql`).
- **Cost:** $0 on Cloudflare's free plan, at `https://shiftz.dacut.workers.dev`. A custom domain is optional (about $10 a year).

## What's better than the Claude version

| | Claude-hosted page | This version |
|---|---|---|
| Who can open it | Only people with a claude.ai account you share it with | Anyone with the link; the 5-digit code is the login |
| Login codes | Checked in the browser | Checked on the server, 10 wrong tries per 15 minutes per network |
| Roles | Enforced by the app's screens | Enforced by the server on every read and write |
| Privacy | Anyone technical with page access could read everything | Employees never receive login hashes, the audit log, other people's alerts or direct messages, manager-only notes, or who offered on their shift |
| Home screen | No | Installs like an app ("Add to Home Screen") |
| History | Newest 1,000 records | Everything, within D1's 5 GB free storage |
| Chat cleanup | When a manager opens the app | Automatic every night (older than 90 days) |

**One thing works differently:** **Email to HR** now downloads the Excel report and opens a new email in your mail app with the summary filled in. You attach the downloaded file and send it. Sending straight from Gmail with the file attached would need a paid email service and a domain.

## Free plan limits (and how much DC SH!FTZ uses)

| Limit (per day, resets at midnight UTC: 6 pm Central in winter, 7 pm in summer) | Free plan | DC SH!FTZ, about 30 staff |
|---|---|---|
| Requests to the Worker | 100,000 | Each open screen checks for updates every 15 seconds and stops when the app is in the background. 3 workstation screens open all day plus phones ≈ 10,000–30,000 |
| D1 rows read | 5,000,000 | Well under 1 million: update checks read only what changed |
| D1 rows written | 100,000 | A few hundred |
| D1 storage | 5 GB total | Years of history fit in a few MB |
| Builds from GitHub | 3,000 minutes a month | About 1 minute per update |

If a daily limit is ever hit, the app stops saving until the reset. Nothing is charged. Cloudflare emails the account owner when that happens. Sources: [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/), [Workers pricing](https://developers.cloudflare.com/workers/about/pricing), [Builds limits](https://developers.cloudflare.com/workers/ci-cd/builds/limits-and-pricing/).

## Setup (about 30 minutes, once)

You need a computer with a terminal. Every command runs inside this folder.

1. **Install Node.js** (the "LTS" version) from [nodejs.org](https://nodejs.org).
2. **Make a free Cloudflare account** at [dash.cloudflare.com](https://dash.cloudflare.com/sign-up).
3. **Install the tools and sign in:**
   ```sh
   npm install
   npx wrangler login
   ```
   A browser window opens. Allow access to your Cloudflare account.
4. **Create the database:**
   ```sh
   npx wrangler d1 create dc-shiftz
   ```
   It prints a `database_id`. Paste it into `wrangler.jsonc` in place of `REPLACE_WITH_YOUR_DATABASE_ID`.
5. **Set up the tables and bring over your current data:**
   ```sh
   npm run db:schema
   npm run db:import
   ```
   `db:import` loads `migration/live-data.sql`: Alex (Admin), Kyle (Manager), the settings, the audit log and your 3 old requests. Everyone's login code stays the same, and Kyle's one-time code still works. If the team keeps using the Claude version before you switch, ask Claude for a fresh export first.
   **Starting empty instead?** Skip `db:import`. The first person to open the app creates the Admin account.
6. **Put it online:**
   ```sh
   npm run deploy
   ```
   If asked for a workers.dev subdomain, enter `dacut` (or `dacut-nb` if it's taken). It prints the app's address, `https://shiftz.dacut.workers.dev`. Open it on your phone and log in with your usual code.
7. **Share it with the team.** Send them the link and tell them to use "Add to Home Screen". On iPhone that's in Safari's Share menu; on Android it's in Chrome's menu.

## Auto-update from GitHub (optional, recommended)

1. Make a **private** repository on GitHub and push this folder to it. The `migration/` folder stays out on purpose (see `.gitignore`), because it holds login code hashes.
2. In the Cloudflare dashboard: **Workers & Pages** → **shiftz** → **Settings** → **Builds** → **Connect**, then pick the repository.
3. From then on, every push to the main branch deploys automatically. The Worker's name in Cloudflare must stay `shiftz`, matching `wrangler.jsonc`.

## Everyday commands

| Task | Command |
|---|---|
| Run it on your computer (uses a separate local database) | `npm run db:schema:local` once, then `npm run dev` |
| Deploy changes by hand | `npm run deploy` |
| Back up the live database | `npx wrangler d1 export dc-shiftz --remote --output=backup.sql` |
| See live errors | `npx wrangler tail` |
| Run the automated tests | `npm test` (needs `npx playwright install chromium` once) |

## How it fits together

```
public/index.html        the whole app (screens, styles, logic), served as-is
public/manifest...       home-screen name and icons
src/worker.js            the server: login, sessions, permissions, live updates, nightly cleanup
schema.sql               database tables (docs, sessions, login_attempts)
migration/live-data.sql  your data exported from the Claude version (don't commit)
test/                    local test server + 59 automated checks
```

Every record is stored as a JSON document in the `docs` table (`col` = record type, `id` = record id). This keeps the same data shapes the Claude version used. Test-mode records live in the same table with a `t_` prefix and are only visible to managers.

### Who can do what (enforced by the server)

| Role | Can |
|---|---|
| Employee | See open shifts and their own history, request cover, offer on shifts, confirm arranged covers, chat, change their own code |
| Lead | Everything an employee can, plus Reports (Excel download, email to HR) |
| Manager | Everything: approvals, worked/no-show, staff, settings, audit log, test mode. Can't change the Admin account |
| Admin | Everything a manager can, plus editing Admin accounts and making Admins |

## Phone notifications

Each person turns them on in **My account → Phone notifications**. On iPhone, the app has to be added to the Home Screen first (iOS 16.4 or later). The server makes its own notification keys the first time they're needed, so there's nothing to set up in Cloudflare. They notify:

- **Everyone:** a new shift needing cover (each person can switch this one off), a coworker asking them to confirm a cover, their request approved or denied, being given a shift, a shift they offered on closing, and direct messages.
- **Managers:** a new offer waiting for approval.

One change notifies at most 40 phones, which stays inside the free plan's limit of 50 outgoing requests per call.

## Not done yet

- **Multiple stores:** see the DC SH!FTZ Multi-Store Plan doc. The `docs` table already makes adding a `storeId` straightforward.
