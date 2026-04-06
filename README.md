# 🛡️ SC Newspaper

**Daily Cybersecurity Newspaper — Automated. Open Source. Free.**

A community project by [Security Circuit](https://securitycircuit.in).

---

## What it does

SC Newspaper sends a daily cybersecurity digest to subscribers with a minimal structure:

| Section | Source |
|---|---|
| 🐛 Bug Bounty Reports & Public Disclosures | HackerOne, Bugcrowd, huntr, Google Project Zero, NVD |
| 🔥 Cybersecurity News | The Hacker News, BleepingComputer, Google News |
| 🚨 CERT-In Alerts | cert-in.org.in (direct advisory probe) |

The subscription flow is handled by a **Cloudflare Worker**, subscribers are stored in **Resend**, and the daily digest is sent by **GitHub Actions**.

**100% free stack. No paid infrastructure required.**

---

## Live Setup

- Frontend: `news.securitycircuit.in`
- Subscription API: Cloudflare Worker (`workers.dev` or custom subdomain)
- Daily sender: GitHub Actions
- Email platform: Resend

---

## Subscribe

Host the landing page from `web/index.html`.

If you use a custom domain, update this section to your real URL, for example:

👉 [https://news.securitycircuit.in](https://news.securitycircuit.in)

---

## How it works

1. A user enters an email on the website.
2. `web/worker.js` sends that email to Resend Contacts and adds it to your subscriber segment.
3. The Worker sends a welcome email.
4. GitHub Actions runs `digest.py` on schedule.
5. `digest.py` fetches all active subscribers from Resend and sends the daily digest.
6. Every email contains a real unsubscribe link handled by the Worker.

---

## Required Resend setup

Before deploying, create these in Resend:

### 1. API key
Create an API key with permissions for:
- sending emails
- contacts
- segments / audience management

### 2. Verified sending domain
Verify your domain in Resend, for example:

- `news@securitycircuit.in`
- `info@securitycircuit.in`

### 3. Subscriber segment
Create a segment, for example:

- `SC Newspaper Subscribers`

Copy its ID. This is used as:

- `RESEND_AUDIENCE_ID`

Note: the code still uses the name `RESEND_AUDIENCE_ID`, but it should contain your **Resend segment ID**.

---

## GitHub deployment

Upload this project as its own GitHub repository, with these files at the repo root:

```text
digest.py
requirements.txt
.env.example
.gitignore
README.md
.github/workflows/digest.yml
web/index.html
web/worker.js
web/wrangler.toml
