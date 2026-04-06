# 🛡️ SC Newspaper

**India's Daily Cybersecurity Newspaper — Automated. Open Source. Free.**

A community project by [Security Circuit](https://securitycircuit.in).

---

## What it does

Every morning at **10 AM IST**, SC Newspaper automatically sends a curated cybersecurity digest to subscribers containing:

| Section | Source |
|---|---|
| 🚨 CERT-In Advisories | cert-in.org.in (direct probe) |
| 🐛 Bug Bounty Disclosures | HackerOne Hacktivity, Bugcrowd, Project Zero |
| 🔥 Top 5 Threats | The Hacker News, BleepingComputer, Google News |
| 🧠 Daily Learning Nugget | OWASP Web/API/Mobile, MITRE ATT&CK, Kill Chain, NIST, ISO 27001 |
| ⚠️ Audit Red Flag | 15 rotating findings from real-world audits |

**100% free. No paid APIs. Runs on GitHub Actions.**

---

## Subscribe

👉 [newspaper.securitycircuit.in](https://newspaper.securitycircuit.in)

---

## Self-host in 5 minutes

### 1. Fork this repo

### 2. Add GitHub Secrets

Go to **Settings → Secrets → Actions** and add:

| Secret | Value |
|---|---|
| `RESEND_API_KEY` | Your key from resend.com |
| `FROM_EMAIL` | `info@yourdomain.com` (verified in Resend) |
| `EMAIL_TO` | Comma-separated recipient list |

### 3. That's it

The workflow runs daily at 10 AM IST via `.github/workflows/digest.yml`.
Manual trigger: **Actions → Daily Cyber Digest → Run workflow**

---

## Project Structure

```
sc-newspaper/
├── digest.py              # Main script
├── requirements.txt       # Python dependencies
├── .env.example           # Local development config
├── .gitignore
├── .github/
│   └── workflows/
│       └── digest.yml     # GitHub Actions schedule
├── web/
│   ├── index.html         # Subscription landing page
│   ├── worker.js          # Cloudflare Worker (subscription backend)
│   └── wrangler.toml      # Worker deployment config
└── README.md
```

---

## Deploy the subscription page

The landing page (`web/index.html`) is a static file — host it anywhere:

- **GitHub Pages** — free, zero config
- **Cloudflare Pages** — free, automatic deploys from this repo
- **Your existing site** — embed as a section

The subscription backend (`web/worker.js`) runs as a **Cloudflare Worker** (free tier: 100k requests/day):

```bash
npm install -g wrangler
wrangler secret put RESEND_API_KEY
wrangler secret put RESEND_AUDIENCE_ID
wrangler secret put FROM_EMAIL
wrangler deploy
```

Then update the fetch URL in `index.html` to your worker URL.

---

## Tech Stack

- **Python 3.11** — digest script
- **GitHub Actions** — free daily scheduler
- **Resend** — email delivery (free: 100 emails/day, 3000/month)
- **Cloudflare Workers** — subscription API (free)
- **Cloudflare Pages** — landing page hosting (free)

---

## Roadmap

- [ ] Bug bounty RSS integration (HackerOne, Bugcrowd)
- [ ] Weekly digest option
- [ ] Telegram channel support
- [ ] Web archive of past editions
- [ ] Subscriber count badge

---

## Contributing

PRs welcome. Ideas for new nuggets, red flags, or feed sources — open an issue.

---

## License

MIT — free to use, modify, and distribute.

---

**Built with ❤️ by [Security Circuit](https://securitycircuit.in) — India's Cybersecurity Community**
