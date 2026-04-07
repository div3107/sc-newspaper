"""
Security Circuit Newspaper Digest — v3
Guaranteed 5 bug bounty writeups/disclosures daily with zero repetition.

Bug Bounty Sources (in priority order):
  1. rix4uni/medium-writeups GitHub repo  — updates every 10 min, real writeups
  2. medium.com/feed/bugbountywriteup     — InfoSec Write-ups official feed
  3. medium.com/feed/tag/bug-bounty-writeup
  4. medium.com/feed/tag/bugbounty-writeup
  5. medium.com/feed/tag/bug-bounty-tips
  6. medium.com/feed/tag/hackerone
  7. medium.com/feed/tag/bugcrowd
  8. intigriti.com/blog/feed               — Intigriti blog (real disclosures)
  9. portswigger.net/research/rss          — PortSwigger Research
 10. h1rss.badtech.xyz/rss                 — HackerOne Hacktivity RSS
 11. tldrsec.com/feed.xml                  — tl;dr sec weekly
 12. Google News RSS for bug bounty terms  — fallback with real titles
 13. NVD API v2                            — high/critical CVEs

News sources: THN, BleepingComputer, Google News
CERT-In: direct parallel probe
"""

from __future__ import annotations

import html as html_lib
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus
from zoneinfo import ZoneInfo

import feedparser
import requests
from bs4 import BeautifulSoup

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# =============================================================================
# CONFIG
# =============================================================================
IST        = ZoneInfo("Asia/Kolkata")
BASE_DIR   = Path(__file__).resolve().parent
CACHE_FILE = BASE_DIR / "seen_cache.json"

EMAIL_TO             = [v.strip() for v in os.getenv("EMAIL_TO", "").split(",") if v.strip()]
RESEND_KEY           = os.getenv("RESEND_API_KEY", "").strip()
FROM_EMAIL           = os.getenv("FROM_EMAIL", "").strip()
RESEND_AUDIENCE_ID   = os.getenv("RESEND_AUDIENCE_ID", "").strip()
UNSUBSCRIBE_BASE_URL = os.getenv("UNSUBSCRIBE_BASE_URL", "").strip()

BUG_BOUNTY_TARGET   = 5
NEWS_TARGET         = 3
CERTIN_TARGET       = 3
CACHE_EXPIRE_DAYS   = 30
BATCH_DELAY         = 0.6

CERTIN_BASE = "https://www.cert-in.org.in"
RESEND_API  = "https://api.resend.com"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

FEED_T   = 12
CERTIN_T = 12
SEND_T   = 15

def now_ist() -> datetime:
    return datetime.now(IST)

def validate_config() -> None:
    errors = []
    if not RESEND_KEY:
        errors.append("RESEND_API_KEY missing")
    if not FROM_EMAIL:
        errors.append("FROM_EMAIL missing")
    if not RESEND_AUDIENCE_ID and not EMAIL_TO:
        errors.append("Either RESEND_AUDIENCE_ID or EMAIL_TO must be set")
    if errors:
        for e in errors:
            log.error("CONFIG ERROR: %s", e)
        sys.exit(1)
    mode = f"Audience {RESEND_AUDIENCE_ID}" if RESEND_AUDIENCE_ID else f"Static list ({len(EMAIL_TO)})"
    log.info("Config OK — FROM: %s | TO: %s", FROM_EMAIL, mode)

# =============================================================================
# ROTATING LEARNING NUGGETS + RED FLAGS
# =============================================================================
NUGGETS = [
    {"tag":"OWASP Web #1","title":"Broken Access Control","body":"The #1 web risk (OWASP 2021). Test every endpoint as a low-privilege user — try admin URLs, other users' data, hidden functions. Common failures: missing function-level access control, CORS misconfiguration, IDOR. Present in 94% of applications tested by OWASP."},
    {"tag":"OWASP Web #2","title":"Cryptographic Failures","body":"Check: Is data encrypted in transit (TLS 1.2+) and at rest? Are MD5, SHA-1, or DES still in use? Hardcoded credentials in source code? Use AES-256, bcrypt/scrypt for passwords. A single exposed plaintext database can compromise millions of accounts."},
    {"tag":"OWASP Web #3","title":"Injection (SQLi, XSS, Command)","body":"Use parameterised queries, validate all input with allowlists, never concatenate user input into SQL or shell commands. Injection flaws are trivially exploitable — automated scanners find them in minutes. One line of unsafe code = full database dump."},
    {"tag":"OWASP Web #4","title":"Insecure Design","body":"Security must be designed in, not bolted on. Perform threat modelling (STRIDE) at design phase, use security user stories, enforce rate limiting, transaction limits, and resource quotas from day one."},
    {"tag":"OWASP Web #5","title":"Security Misconfiguration","body":"Most common issue in practice. Default credentials unchanged, verbose error messages exposing stack traces, missing CSP/HSTS/X-Frame-Options headers, open S3 buckets, unpatched software. Automate hardening with Lynis or Prowler and scan regularly."},
    {"tag":"OWASP Web #6","title":"Vulnerable & Outdated Components","body":"Scan every dependency with OWASP Dependency-Check, Snyk, or npm audit. Subscribe to CVE feeds for your stack. Remove unused dependencies. CERT-In mandates patching critical CVEs within defined timelines — unpatched libraries = direct compliance failure."},
    {"tag":"OWASP Web #7","title":"Authentication & Session Failures","body":"Enforce MFA on all privileged accounts, account lockout after failed attempts, secure password reset flows, session token invalidation on logout. Never expose session IDs in URLs. Use proven auth libraries — don't build auth from scratch."},
    {"tag":"OWASP Web #8","title":"Software & Data Integrity Failures","body":"Insecure CI/CD pipelines, unsigned software updates, deserialization of untrusted data. The SolarWinds attack was an integrity failure. Use code signing, verify checksums on dependencies, add secrets scanning and branch protection to CI/CD."},
    {"tag":"OWASP Web #9","title":"Security Logging & Monitoring","body":"Log authentication events, access failures, input validation failures, high-value transactions. Ship to SIEM — logs on source systems can be wiped. CERT-In mandates 6-hour incident reporting and 180-day log retention under India's 2022 directions."},
    {"tag":"OWASP Web #10","title":"Server-Side Request Forgery (SSRF)","body":"Attackers make the server fetch arbitrary URLs — internal services, cloud metadata at 169.254.169.254, firewall bypasses. Use allowlists of permitted domains, disable HTTP redirects, block metadata services at the network level in cloud environments."},
    {"tag":"OWASP API #1","title":"BOLA — Broken Object Level Authorization","body":"Most critical API vulnerability. Attackers increment IDs: GET /api/orders/1234 → try /1233, /1235. Every API call must verify the authenticated user owns the requested object. BOLA was behind Peloton, T-Mobile, and Optus breaches affecting millions."},
    {"tag":"OWASP API #2","title":"Broken API Authentication","body":"Watch for JWTs with 'alg:none', tokens that never expire, API keys hardcoded in mobile apps or JS files, missing rate limiting on auth endpoints. Use short-lived tokens, refresh token rotation. Revoke compromised keys immediately — treat all shipped keys as compromised."},
    {"tag":"OWASP API #3","title":"Broken Object Property Authorization","body":"APIs returning more data than needed (Excessive Data Exposure) or accepting more properties than intended (Mass Assignment). Sending isAdmin=true in JSON body shouldn't work. Define explicit input schemas. Return only fields the client actually needs."},
    {"tag":"OWASP API #4","title":"Unrestricted Resource Consumption","body":"No rate limits = financial damage and DoS. Attackers trigger expensive DB queries, SMS OTPs, or cloud billing. Enforce rate limits per user/IP, max payload size, GraphQL query complexity limits, and operation timeouts across all API endpoints."},
    {"tag":"OWASP API #5","title":"Broken Function Level Authorization","body":"Regular users accessing admin API functions. APIs have predictable patterns: /api/user/profile vs /api/admin/users. Never rely on obscurity — every function must check the caller's role. Use an API gateway to enforce RBAC centrally at the entry point."},
    {"tag":"OWASP Mobile #1","title":"Improper Credential Usage","body":"Hardcoded credentials and API keys in mobile binaries are trivially extractable with jadx (Android) or class-dump (iOS). Never hardcode secrets. Use Android Keystore or iOS Secure Enclave. Any key ever shipped in a binary must be rotated — assume compromised."},
    {"tag":"OWASP Mobile #2","title":"Supply Chain Security (Mobile)","body":"Mobile apps embed many third-party SDKs — analytics, ads, crash reporting. Each is a potential backdoor. Vet every SDK's data collection, pin versions, verify checksums. SparkCat malware in 2025 hid in legitimate-looking SDKs on the official App Store."},
    {"tag":"OWASP Mobile #3","title":"Insecure Data Storage","body":"Sensitive data in SharedPreferences, SQLite, log files, or temp directories is readable on rooted devices via ADB. Use Android EncryptedSharedPreferences or iOS Data Protection. Never log PII, tokens, or passwords — check what your app leaves in /data/data/ and crash logs."},
    {"tag":"MITRE ATT&CK","title":"The ATT&CK Framework Explained","body":"14 Tactics (the 'why'): Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact. Hundreds of Techniques (the 'how'). Use it to map your defences and find detection gaps."},
    {"tag":"MITRE ATT&CK","title":"Initial Access — How Attackers Get In","body":"Phishing (T1566) — #1 in India. Exploit Public-Facing App (T1190) — unpatched web apps. Supply Chain (T1195) — SolarWinds, XZ Utils. Valid Accounts (T1078) — dark web credentials. Drive-by Compromise (T1189) — malicious websites. Map each technique to your existing detection controls."},
    {"tag":"MITRE ATT&CK","title":"Persistence & Privilege Escalation","body":"Persistence: Registry Run Keys (T1547), Scheduled Tasks (T1053), Web Shells (T1505.003), New Admin Accounts (T1136). Privilege Escalation: Sudo abuse (T1548.003), Token Impersonation (T1134), Local exploit (T1068). Hunt for unexpected scheduled tasks and new admin accounts daily."},
    {"tag":"Cyber Kill Chain","title":"Lockheed Martin's 7 Stages","body":"1) Reconnaissance — OSINT/LinkedIn research. 2) Weaponisation — building exploit/payload. 3) Delivery — phishing email, USB, watering hole. 4) Exploitation — triggering the vulnerability. 5) Installation — dropping malware/backdoor. 6) C2 — attacker controls implant. 7) Actions — data theft, ransomware. Break the chain at stage 3 — it's cheapest there."},
    {"tag":"Cyber Kill Chain","title":"Defender's Playbook","body":"Recon → monitor brand abuse, OSINT yourself first. Delivery → email filtering, SPF/DKIM/DMARC, awareness training. Exploitation → patch management, WAF, EDR. Installation → application allowlisting, disable macros. C2 → DNS filtering, proxy inspection, block C2 IPs. Exfiltration → DLP, outbound anomaly detection."},
    {"tag":"Diamond Model","title":"Structuring Threat Intelligence","body":"Every intrusion has 4 features: Adversary (who attacks), Capability (tools/malware used), Infrastructure (IPs, domains, C2 servers), Victim (who is targeted). Disrupting infrastructure is often cheaper than attributing the adversary. Use it to pivot between indicators and build a fuller picture of the threat."},
    {"tag":"Zero Trust","title":"Never Trust, Always Verify","body":"Zero Trust assumes breach — no implicit trust based on network location. Every request must be authenticated, authorised, and continuously validated. Core pillars: strong identity (MFA everywhere), least-privilege access, micro-segmentation, device health verification, continuous monitoring."},
    {"tag":"NIST CSF 2.0","title":"The 6 Core Functions","body":"GOVERN — policies, risk strategy. IDENTIFY — assets, risk assessment. PROTECT — access control, data security. DETECT — monitoring, anomaly detection. RESPOND — incident response, communications. RECOVER — recovery planning, improvements. Released 2024. Use it to assess maturity and prioritise where to spend your security budget."},
    {"tag":"STRIDE Threat Model","title":"Microsoft's STRIDE Framework","body":"S — Spoofing (strong auth). T — Tampering (integrity controls, digital signatures). R — Repudiation (tamper-proof audit logs). I — Information Disclosure (encrypt, least privilege). D — Denial of Service (rate limiting, redundancy). E — Elevation of Privilege (authorisation at every layer). Apply to every data flow in your architecture."},
    {"tag":"ISO 27001:2022","title":"11 New Controls You Must Implement","body":"Threat intelligence (5.7), Cloud security (5.23), ICT continuity (5.30), Web filtering (8.23), Secure coding (8.28), Data masking (8.11), Data leakage prevention (8.12), Monitoring activities (8.16), Configuration management (8.9), Information deletion (8.10), Physical security monitoring (7.4)."},
    {"tag":"Incident Response","title":"CERT-In 6-Hour Reporting Mandate","body":"India's CERT-In directions (April 2022): report cyber incidents within 6 hours of detection. Covered: data breaches, ransomware, unauthorised access, DDoS, phishing, attacks on critical infrastructure. Build your IR playbook now — define detection triggers, escalation paths, report template. Report to incident@cert-in.org.in."},
    {"tag":"India DPDP Act 2023","title":"Digital Personal Data Protection","body":"Key obligations: obtain valid consent before collecting data, process only for stated purposes, maintain data accuracy, implement appropriate security safeguards, delete data when no longer needed, report breaches to the Data Protection Board. Penalties up to ₹250 crore. Appoint a Data Protection Officer if processing significant personal data."},
]

RED_FLAGS = [
    {"title":"Patch Management Not Documented","body":"Undocumented patches = unverifiable compliance. Every patch must be logged with: date applied, applied-by, approver name, and change-reference ID. Without this your organisation cannot demonstrate due diligence to auditors or regulators."},
    {"title":"No MFA on Privileged Accounts","body":"Admin accounts without MFA are a critical finding in every security audit. Password-only access to admin consoles, cloud root accounts, or domain controllers is indefensible. Enable MFA immediately — even SMS-based MFA is better than none, though TOTP or hardware keys are strongly preferred."},
    {"title":"Flat Network — No Segmentation","body":"If an attacker compromises one machine and can reach every other machine, you have a flat network. Segment: separate OT/IT, isolate payment systems, put servers in dedicated VLANs, restrict lateral movement with firewall rules. Test: can a user workstation ping the domain controller directly?"},
    {"title":"Default Credentials Not Changed","body":"Routers, firewalls, printers, cameras, and server management interfaces (iDRAC, iLO) shipped with default admin/admin credentials. Shodan and Censys index millions of such devices publicly. Run a credential audit across all network devices — default passwords are an immediate critical finding."},
    {"title":"No Data Classification Policy","body":"Without knowing what data you have and how sensitive it is, you can't protect it appropriately. Implement at minimum: Public, Internal, Confidential. DPDP Act 2023 makes appropriate security safeguards legally mandatory for personal data in India — penalties up to ₹250 crore."},
    {"title":"Logs Not Centralised or Retained","body":"Logs stored only on source systems can be wiped by attackers during an intrusion. CERT-In mandates log retention for 180 days. Ship all logs to a centralised SIEM. Ensure NTP clock sync across all systems so logs can be correlated for forensic investigation."},
    {"title":"Third-Party Vendor Access Not Reviewed","body":"Many breaches originate from vendors with excessive or dormant access. Audit: which third parties have VPN/RDP/API access? When did they last use it? Terminate dormant accounts immediately. Require vendors to use MFA. The Target breach (110M records) started with an HVAC vendor's credentials."},
    {"title":"No DR Plan Tested","body":"A DR plan that has never been tested is not a DR plan — it's a document. Ransomware assumes you have no working backups. Test restoration quarterly. Verify backups are offline or immutable — ransomware encrypts network-connected backups too. Define RPO and RTO per system and test against them."},
    {"title":"API Keys Hardcoded in Source Code","body":"Developers commit API keys and credentials directly into git repos — even private ones get leaked. Scan with truffleHog or git-secrets now. Rotate any exposed key immediately (assume already scraped). Use AWS Secrets Manager, HashiCorp Vault, or GitHub Secrets for CI/CD."},
    {"title":"No Vulnerability Disclosure Policy","body":"Without a VDP, security researchers who find bugs have no safe channel — so they may go public or sell to threat actors. Publish security.txt at /.well-known/security.txt with a contact email. CERT-In encourages responsible disclosure. A VDP shows security maturity and prevents embarrassing public disclosures."},
    {"title":"Excessive User Privileges","body":"Users having more access than their role requires is one of the most common audit findings. Run a privilege audit: how many users have local admin rights? Domain admin? Who can read HR or finance shares? Apply least privilege — remove what isn't needed. Review permissions quarterly."},
    {"title":"No Security Awareness Training","body":"Phishing is the #1 initial access vector in India. If staff can't recognise a phishing email, all technical controls are undermined. Run phishing simulations quarterly, mandatory awareness training annually, and targeted training for high-risk roles. A click rate above 10% is an immediate red flag."},
    {"title":"Unencrypted Sensitive Data at Rest","body":"PII, financial records, and credentials in plaintext databases or file shares is a critical finding. Encrypt sensitive columns (TDE or column-level). Encrypt laptops (BitLocker/FileVault). Under DPDP Act 2023, failure to protect personal data with appropriate security measures carries penalties up to ₹250 crore."},
    {"title":"No Asset Inventory","body":"You can't protect what you don't know you have. Shadow IT assets are common breach entry points. Build a CMDB: every server, laptop, network device, cloud instance, and SaaS application. CERT-In expects organisations to have visibility of all internet-facing assets before an incident occurs."},
    {"title":"Weak Password Policy","body":"Minimum 8 characters with complexity is outdated. NIST SP 800-63B recommends 12-15+ characters, no forced rotation (unless compromised), and blocking of known-breached passwords. Length beats complexity. Block 'Password@123' — it meets old complexity rules but is trivially cracked by dictionary attacks."},
]

def get_nugget() -> dict:
    return NUGGETS[now_ist().timetuple().tm_yday % len(NUGGETS)]

def get_redflag() -> dict:
    return RED_FLAGS[(now_ist().timetuple().tm_yday + 7) % len(RED_FLAGS)]

# =============================================================================
# HELPERS
# =============================================================================
def clean_text(val: str) -> str:
    text = BeautifulSoup(val or "", "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", text).strip()

def truncate(text: str, limit: int = 260) -> str:
    text = clean_text(text)
    if not text or len(text) <= limit:
        return text
    clipped = text[:limit]
    m = re.search(r"[.!?](?=\s|$)", clipped)
    if m:
        return clipped[:m.end()].strip()
    return clipped.rsplit(" ", 1)[0] + "..."

def norm_key(v: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", v.lower()).strip("-")[:120]

def entry_dt(entry) -> datetime:
    st = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
    if st:
        return datetime(st.tm_year, st.tm_mon, st.tm_mday,
                        st.tm_hour, st.tm_min, st.tm_sec,
                        tzinfo=timezone.utc).astimezone(IST)
    raw = getattr(entry, "published", None) or getattr(entry, "updated", None)
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(IST)
        except ValueError:
            pass
    return now_ist()

def is_recent(dt: datetime, days: int = 7) -> bool:
    return dt >= now_ist() - timedelta(days=days)

def parse_feed(url: str, timeout: int = FEED_T):
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    return feedparser.parse(r.content)

def resend_hdr() -> dict:
    return {
        "Authorization": f"Bearer {RESEND_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "sc-newspaper/3.0",
    }

def unsub_url(email: str) -> str:
    base = (UNSUBSCRIBE_BASE_URL or "https://subscribe.securitycircuit.in").rstrip("/")
    from urllib.parse import quote_plus
    return f"{base}/unsubscribe?email={quote_plus(email)}"

# =============================================================================
# CACHE
# =============================================================================
def load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            c = json.loads(CACHE_FILE.read_text())
            log.info("Cache: %d bounty, %d news, %d certin",
                     len(c.get("bounty", {})), len(c.get("news", {})), len(c.get("certin", {})))
            return c
        except Exception as e:
            log.warning("Cache error: %s — fresh start", e)
    return {"bounty": {}, "news": {}, "certin": {}}

def save_cache(cache: dict) -> None:
    cutoff = (now_ist() - timedelta(days=CACHE_EXPIRE_DAYS)).strftime("%Y-%m-%d")
    for s in ("bounty", "news", "certin"):
        cache[s] = {k: v for k, v in cache.get(s, {}).items() if v >= cutoff}
    CACHE_FILE.write_text(json.dumps(cache, indent=2))
    log.info("Cache saved.")

def mark_sent(cache: dict, section: str, key: str) -> None:
    cache.setdefault(section, {})[key] = now_ist().strftime("%Y-%m-%d")

def already_sent(cache: dict, section: str, key: str) -> bool:
    return key in cache.get(section, {})

# =============================================================================
# BUG BOUNTY — GUARANTEED 5 DAILY
# =============================================================================

# Source 1: GitHub repo that updates every 10 min with fresh Medium writeups
GITHUB_WRITEUPS_URL = (
    "https://raw.githubusercontent.com/rix4uni/medium-writeups/main/writeups.json"
)

# Source 2: Real Medium RSS feeds that work from GitHub Actions IPs
MEDIUM_FEEDS = [
    ("InfoSec Write-ups",   "https://infosecwriteups.com/feed"),
    ("BB Write-up pub",     "https://medium.com/feed/bugbountywriteup"),
    ("tag/bug-bounty-writeup", "https://medium.com/feed/tag/bug-bounty-writeup"),
    ("tag/bugbounty-writeup",  "https://medium.com/feed/tag/bugbounty-writeup"),
    ("tag/bug-bounty-tips",    "https://medium.com/feed/tag/bug-bounty-tips"),
    ("tag/hackerone",          "https://medium.com/feed/tag/hackerone"),
    ("tag/bugcrowd",           "https://medium.com/feed/tag/bugcrowd"),
    ("tag/bug-bounty-hunter",  "https://medium.com/feed/tag/bug-bounty-hunter"),
    ("tag/bug-bounty-program", "https://medium.com/feed/tag/bug-bounty-program"),
    ("tag/ethical-hacking",    "https://medium.com/feed/tag/ethical-hacking"),
    ("tag/pentesting",         "https://medium.com/feed/tag/pentesting"),
    ("tag/xss-attack",         "https://medium.com/feed/tag/xss-attack"),
]

# Source 3: Platform / research blogs with real public disclosures
DISCLOSURE_FEEDS = [
    ("Intigriti Blog",       "https://www.intigriti.com/blog/feed"),
    ("PortSwigger Research", "https://portswigger.net/research/rss"),
    ("HackerOne Hacktivity", "https://h1rss.badtech.xyz/rss"),
    ("tl;dr sec",            "https://tldrsec.com/feed.xml"),
    ("Bugcrowd Blog",        "https://www.bugcrowd.com/blog/feed/"),
    ("YesWeHack Blog",       "https://blog.yeswehack.com/feed/"),
    ("huntr Disclosures",    "https://huntr.com/bounties/feed"),
    ("Immunefi",             "https://medium.com/feed/immunefi"),
    ("Daily Swig BB",        "https://portswigger.net/daily-swig/bug-bounty/rss"),
]

# Source 4: Google News RSS — real article titles, even if summaries are short
GNEWS_BOUNTY_FEEDS = [
    ("GNews BB writeup",
     "https://news.google.com/rss/search?q=" +
     quote_plus("bug bounty writeup vulnerability disclosed") +
     "&hl=en-IN&gl=IN&ceid=IN:en"),
    ("GNews BB hackerone",
     "https://news.google.com/rss/search?q=" +
     quote_plus("hackerone disclosed vulnerability bug bounty") +
     "&hl=en-IN&gl=IN&ceid=IN:en"),
    ("GNews CVE exploit",
     "https://news.google.com/rss/search?q=" +
     quote_plus("CVE exploit writeup security researcher") +
     "&hl=en-IN&gl=IN&ceid=IN:en"),
    ("GNews IDOR XSS RCE",
     "https://news.google.com/rss/search?q=" +
     quote_plus("IDOR OR XSS OR RCE OR SSRF bug bounty writeup 2026") +
     "&hl=en-IN&gl=IN&ceid=IN:en"),
]

BB_KEYWORDS = [
    "bug bounty", "vulnerability", "exploit", "cve-", "xss", "idor", "rce",
    "csrf", "ssrf", "auth bypass", "disclosure", "writeup", "write-up",
    "hackerone", "bugcrowd", "intigriti", "security researcher", "bounty",
    "sql injection", "sqli", "lfi", "rfi", "privilege escalation", "p1", "p2",
    "subdomain takeover", "open redirect", "idor", "race condition",
]

NOISE_TITLES = {
    "home", "about", "archive", "contact", "latest posts",
    "subscribe", "newsletter", "tagged", "stories",
}


def _item_from_entry(entry, source: str, recent_days: int = 60) -> dict | None:
    title = clean_text(getattr(entry, "title", ""))
    link  = getattr(entry, "link", "").strip()
    if not title or not link or title.lower() in NOISE_TITLES or len(title) < 12:
        return None
    if not is_recent(entry_dt(entry), days=recent_days):
        return None
    combined = f"{title} {clean_text(getattr(entry, 'summary', ''))}".lower()
    if not any(k in combined for k in BB_KEYWORDS):
        return None
    summary = truncate(clean_text(getattr(entry, "summary", "")) or title, 240)
    return {
        "title":   title,
        "link":    link,
        "summary": summary,
        "source":  source,
        "_key":    norm_key(f"{source}-{link}"),
    }


def _fetch_github_writeups(cache: dict) -> list[dict]:
    """
    Fetch rix4uni/medium-writeups JSON (updates every 10 min).
    Returns unseen writeups sorted newest first.
    """
    log.info("Fetching GitHub medium-writeups repo...")
    try:
        r = requests.get(GITHUB_WRITEUPS_URL, headers=HEADERS, timeout=FEED_T)
        r.raise_for_status()
        data = r.json()  # list of {title, link, pubDate, ...} or dict
        # Handle both list and dict formats
        if isinstance(data, dict):
            items_raw = list(data.values())
        else:
            items_raw = data
    except Exception as e:
        log.warning("GitHub writeups fetch error: %s", e)
        return []

    items = []
    for raw in items_raw:
        if not isinstance(raw, dict):
            continue
        title = clean_text(raw.get("title", ""))
        link  = (raw.get("link") or raw.get("url") or raw.get("guid") or "").strip()
        if not title or not link or len(title) < 12:
            continue

        # Parse date
        pub_str = raw.get("pubDate") or raw.get("published") or ""
        try:
            pub_dt = datetime.fromisoformat(
                pub_str.replace("Z", "+00:00")
            ).astimezone(IST) if pub_str else now_ist()
        except Exception:
            pub_dt = now_ist()

        if not is_recent(pub_dt, days=60):
            continue

        key = norm_key(f"github-writeups-{link}")
        if already_sent(cache, "bounty", key):
            continue

        items.append({
            "title":     title,
            "link":      link,
            "summary":   truncate(clean_text(raw.get("summary", "")) or title, 240),
            "source":    "Medium (via GitHub)",
            "published": pub_dt,
            "_key":      key,
        })

    items.sort(key=lambda x: x["published"].timestamp(), reverse=True)
    log.info("  GitHub writeups: %d new items", len(items))
    return items


def _fetch_feed_bounty(name: str, url: str, cache: dict,
                       recent_days: int = 60) -> list[dict]:
    try:
        feed  = parse_feed(url)
        items = []
        for entry in getattr(feed, "entries", []):
            item = _item_from_entry(entry, name, recent_days)
            if not item:
                continue
            if already_sent(cache, "bounty", item["_key"]):
                continue
            items.append(item)
        return items
    except Exception as e:
        log.debug("Feed error (%s): %s", name, e)
        return []


def fetch_bug_bounty(cache: dict) -> list[dict]:
    """
    Aggregates from all sources in parallel.
    Guarantees up to BUG_BOUNTY_TARGET items.
    Falls back through sources until quota filled.
    """
    log.info("=== Fetching Bug Bounty content ===")
    collected: list[dict] = []
    seen_keys: set[str]   = set()

    def add(items: list[dict]) -> None:
        for item in items:
            if len(collected) >= BUG_BOUNTY_TARGET * 4:
                break
            k = item["_key"]
            if k not in seen_keys and not already_sent(cache, "bounty", k):
                seen_keys.add(k)
                collected.append(item)

    # -- Phase 1: GitHub writeups repo (freshest, most reliable) --
    gh = _fetch_github_writeups(cache)
    add(gh)
    log.info("After GitHub: %d collected", len(collected))

    if len(collected) >= BUG_BOUNTY_TARGET:
        return collected[:BUG_BOUNTY_TARGET]

    # -- Phase 2: Medium RSS + Disclosure feeds in parallel --
    all_feeds = [(n, u, 60) for n, u in MEDIUM_FEEDS] + \
                [(n, u, 30) for n, u in DISCLOSURE_FEEDS]

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fetch_feed_bounty, n, u, cache, d): (n, u)
                   for n, u, d in all_feeds}
        for f in as_completed(futures):
            add(f.result())

    log.info("After feeds: %d collected", len(collected))

    if len(collected) >= BUG_BOUNTY_TARGET:
        return collected[:BUG_BOUNTY_TARGET]

    # -- Phase 3: Google News RSS (guaranteed fresh titles) --
    log.info("Falling back to Google News for bug bounty...")
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_fetch_feed_bounty, n, u, cache, 7): (n, u)
                   for n, u in GNEWS_BOUNTY_FEEDS}
        for f in as_completed(futures):
            add(f.result())

    log.info("After Google News: %d collected", len(collected))

    if len(collected) >= BUG_BOUNTY_TARGET:
        return collected[:BUG_BOUNTY_TARGET]

    # -- Phase 4: NVD API v2 (high/critical CVEs — always fresh) --
    if len(collected) < BUG_BOUNTY_TARGET:
        log.info("Filling remaining slots from NVD CVE feed...")
        nvd = _fetch_nvd(cache, limit=BUG_BOUNTY_TARGET - len(collected))
        add(nvd)

    log.info("Final bug bounty count: %d", len(collected))
    return collected[:BUG_BOUNTY_TARGET]


def _fetch_nvd(cache: dict, limit: int = 3) -> list[dict]:
    """NVD API v2 — replaces deprecated JSON feed."""
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        "?cvssV3Severity=HIGH&resultsPerPage=20"
        "&pubStartDate=" +
        (now_ist() - timedelta(days=14)).strftime("%Y-%m-%dT00:00:00.000")
    )
    try:
        r = requests.get(url, headers=HEADERS, timeout=FEED_T)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.warning("NVD API error: %s", e)
        return []

    items = []
    for vuln in data.get("vulnerabilities", []):
        cve    = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        key = norm_key(f"nvd-{cve_id}")
        if already_sent(cache, "bounty", key):
            continue

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available."
        )

        # Severity from CVSS v3
        sev = ""
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                sev = metrics[0].get("cvssData", {}).get("baseSeverity", "")
                break

        items.append({
            "title":   cve_id,
            "link":    f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "summary": f"[{sev}] {truncate(desc, 220)}" if sev else truncate(desc, 220),
            "source":  "NVD / CVE",
            "_key":    key,
        })
        if len(items) >= limit:
            break

    log.info("  NVD: %d items", len(items))
    return items

# =============================================================================
# ARTICLE SCRAPER — used when RSS summary is truncated (BleepingComputer etc.)
# =============================================================================
def _scrape_article_summary(url: str) -> str:
    """Fetch article page and extract first 2 real paragraphs."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["nav","footer","script","style","aside",
                          "header","form","figure","noscript","iframe"]):
            tag.decompose()
        body = None
        for sel in ["article .post-body","article .entry-content",
                    "div.article-content","div.post-content",
                    "div.entry-content","article","main"]:
            body = soup.select_one(sel)
            if body:
                break
        skip = ["cookie","subscribe","newsletter","advertisement",
                "follow us","related post","sign up","read more"]
        paras = []
        for p in (body or soup).find_all("p"):
            t = p.get_text(" ", strip=True)
            if len(t) > 60 and not any(s in t.lower() for s in skip):
                paras.append(t)
        if paras:
            combined = " ".join(paras[:2])
            return truncate(combined, 240)
    except Exception:
        pass
    return ""

# =============================================================================
# NEWS
# =============================================================================
NEWS_FEEDS = [
    ("The Hacker News",  "https://thehackernews.com/feeds/posts/default",  2),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/",          2),
    ("Google News India",
     "https://news.google.com/rss/search?q=" +
     quote_plus("cybersecurity india OR cert-in OR vulnerability attack") +
     "&hl=en-IN&gl=IN&ceid=IN:en", 2),
]

NEWS_KW = [
    "ransomware", "critical", "vulnerability", "exploit", "breach",
    "zero-day", "malware", "phishing", "attack", "cert-in", "india",
    "microsoft", "apple", "google", "fortinet", "ivanti", "chrome", "android",
]

def fetch_news(cache: dict) -> list[dict]:
    log.info("Fetching news...")
    items, seen = [], set()
    for name, url, limit in NEWS_FEEDS:
        try:
            feed = parse_feed(url)
            count = 0
            for entry in feed.entries:
                title = clean_text(getattr(entry, "title", ""))
                link  = getattr(entry, "link", "").strip()
                if not title or not link:
                    continue
                if not is_recent(entry_dt(entry), days=4):
                    continue
                combined = f"{title} {clean_text(getattr(entry,'summary',''))}".lower()
                if not any(k in combined for k in NEWS_KW):
                    continue
                key = norm_key(f"news-{title}")
                if key in seen or already_sent(cache, "news", key):
                    continue
                seen.add(key)
                raw_summary = clean_text(getattr(entry, "summary", ""))
                # BleepingComputer RSS truncates with '[...]' — scrape full page
                if not raw_summary or raw_summary.endswith("[...]") or len(raw_summary) < 60:
                    raw_summary = _scrape_article_summary(link) or raw_summary or title
                items.append({
                    "title":   title,
                    "link":    link,
                    "summary": truncate(raw_summary, 240),
                    "source":  name,
                    "_key":    key,
                })
                count += 1
                if count >= limit:
                    break
        except Exception as e:
            log.warning("News feed error (%s): %s", name, e)
    items.sort(key=lambda x: x.get("_key", ""), reverse=False)
    log.info("News: %d items", len(items[:NEWS_TARGET]))
    return items[:NEWS_TARGET]

# =============================================================================
# CERT-IN — parallel probe
# =============================================================================
def _fetch_one_advisory(args: tuple) -> dict | None:
    n, year = args
    code = f"CIAD-{year}-{n:04d}"
    url  = f"{CERTIN_BASE}/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE={code}"
    try:
        r    = requests.get(url, headers=HEADERS, timeout=CERTIN_T)
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text(" ", strip=True)
        if code not in text and "Severity" not in text:
            return None

        sev = "High"
        m   = re.search(r"Severity Rating\s*[:\-]?\s*(\w+)", text, re.I)
        if m and m.group(1).capitalize() in ("Critical","High","Medium","Low"):
            sev = m.group(1).capitalize()

        desc = ""
        for marker in ("Overview", "Description"):
            if marker in text:
                chunk = text.split(marker, 1)[1].strip()
                for stop in ("Target Audience","Risk Assessment","Impact","Solution","References"):
                    if stop in chunk:
                        chunk = chunk.split(stop)[0].strip()
                desc = truncate(chunk, 260)
                break

        affected = ""
        if "Software Affected" in text:
            chunk = text.split("Software Affected", 1)[1]
            chunk = re.split(r"Overview|Description|Target|Risk|Impact", chunk)[0]
            prod_items = []
            for l in chunk.splitlines():
                l = l.strip()
                # Remove garbled unicode, PGP noise, empty lines
                l = re.sub(r"[---�¿]", "", l).strip()
                if len(l) > 3 and not l.startswith("---") and not l.startswith("Hash:"):
                    prod_items.append(l)
            if prod_items:
                affected = ", ".join(prod_items[:4])
                if len(prod_items) > 4:
                    affected += f" +{len(prod_items)-4} more"

        return {
            "code":     code,
            "url":      url,
            "severity": sev,
            "affected": affected,
            "desc":     desc or "Multiple vulnerabilities reported. Apply vendor patches immediately.",
            "_key":     code,
        }
    except Exception as e:
        log.debug("Advisory %s error: %s", code, e)
        return None


def fetch_certin(cache: dict) -> list[dict]:
    log.info("Fetching CERT-In advisories...")
    year = now_ist().year
    latest = 20

    try:
        r = requests.get(
            f"{CERTIN_BASE}/s2cMainServlet?pageid=PUBADVLIST02&year={year}",
            headers=HEADERS, timeout=CERTIN_T
        )
        nums = re.findall(rf"CIAD-{year}-(\d+)", r.text)
        if nums:
            latest = max(int(x) for x in nums)
            log.info("Latest CERT-In: CIAD-%d-%04d", year, latest)
    except Exception as e:
        log.warning("CERT-In list error: %s", e)

    # Only look back 10 advisories — avoids surfacing old January advisories
    candidates = []
    for n in range(latest, max(0, latest - 10), -1):
        code = f"CIAD-{year}-{n:04d}"
        if not already_sent(cache, "certin", code):
            candidates.append((n, year))
        if len(candidates) >= CERTIN_TARGET * 2:
            break

    # If all recent ones sent, look back another 10 — but never more than 20 total
    if not candidates:
        for n in range(latest - 10, max(0, latest - 20), -1):
            code = f"CIAD-{year}-{n:04d}"
            if not already_sent(cache, "certin", code):
                candidates.append((n, year))
            if len(candidates) >= CERTIN_TARGET * 2:
                break

    if not candidates:
        log.info("All recent CERT-In advisories already sent.")
        return []

    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_fetch_one_advisory, c): c for c in candidates}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
                log.info("  ✓ %s (%s)", r["code"], r["severity"])

    results.sort(key=lambda x: x["code"], reverse=True)
    return results[:CERTIN_TARGET]

# =============================================================================
# RECIPIENTS
# =============================================================================
def get_recipients() -> list[str] | None:
    if not RESEND_AUDIENCE_ID:
        return EMAIL_TO

    log.info("Fetching recipients from Resend audience %s...", RESEND_AUDIENCE_ID)
    emails: list[str] = []
    after = None

    while True:
        params = {}
        if after:
            params["after"] = after
        try:
            r = requests.get(
                f"{RESEND_API}/audiences/{RESEND_AUDIENCE_ID}/contacts",
                headers=resend_hdr(), params=params or None, timeout=FEED_T
            )
            if not r.ok:
                log.error("Resend contacts error %d: %s", r.status_code, r.text)
                return None
            payload = r.json()
            contacts = payload.get("data", [])
            if not contacts:
                break
            for c in contacts:
                e = (c.get("email") or "").strip().lower()
                if e and not c.get("unsubscribed"):
                    emails.append(e)
            if not payload.get("has_more"):
                break
            after = contacts[-1].get("id")
            if not after:
                break
        except Exception as ex:
            log.error("Audience fetch error: %s", ex)
            return None

    unique = list(dict.fromkeys(emails))
    log.info("Found %d subscribers", len(unique))
    return unique

# =============================================================================
# EMAIL TEMPLATE
# =============================================================================
SEV_COLOR = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#ca8a04", "Low": "#16a34a"}

def format_email(bounty: list[dict], news: list[dict], certin: list[dict]) -> tuple[str, str]:
    today    = now_ist()
    date_str = today.strftime("%d %B %Y")
    weekday  = today.strftime("%A")
    ts       = today.strftime("%I:%M %p IST").lstrip("0")
    subject  = f"Security Circuit Newspaper | {date_str}"

    nugget  = get_nugget()
    redflag = get_redflag()
    log.info("Nugget: [%s] %s", nugget["tag"], nugget["title"])
    log.info("Red flag: %s", redflag["title"])

    def e(s: str) -> str:
        return html_lib.escape(s or "")

    def render_bounty_cards(items: list[dict]) -> str:
        if not items:
            return '<p style="color:rgba(255,255,255,0.5);font-size:14px;">No new writeups today — check back tomorrow.</p>'
        blocks = []
        for item in items:
            blocks.append(f"""
            <div style="border-top:1px solid rgba(255,255,255,0.08);padding:18px 0 6px;">
              <div style="font-size:11px;font-weight:700;letter-spacing:0.12em;
                          text-transform:uppercase;color:#e8212b;margin-bottom:8px;">
                {e(item['source'])}
              </div>
              <div style="font-size:22px;line-height:1.2;margin:0 0 10px;
                          font-family:Georgia,'Times New Roman',serif;">
                <a href="{e(item['link'])}" style="color:#fff;text-decoration:none;">
                  {e(item['title'])}
                </a>
              </div>
              <p style="margin:0 0 10px;font-size:14px;line-height:1.75;color:rgba(255,255,255,0.65);">
                {e(item['summary'])}
              </p>
              <a href="{e(item['link'])}"
                 style="font-size:12px;font-weight:600;letter-spacing:0.08em;
                        color:#e8212b;text-decoration:none;text-transform:uppercase;">
                Read writeup →
              </a>
            </div>""")
        return "".join(blocks)

    def render_news_cards(items: list[dict]) -> str:
        if not items:
            return '<p style="color:rgba(255,255,255,0.5);font-size:14px;">No new stories today.</p>'
        blocks = []
        for item in items:
            blocks.append(f"""
            <div style="border-top:1px solid rgba(255,255,255,0.08);padding:18px 0 6px;">
              <div style="font-size:11px;font-weight:700;letter-spacing:0.12em;
                          text-transform:uppercase;color:#9ca3af;margin-bottom:8px;">
                {e(item['source'])}
              </div>
              <div style="font-size:20px;line-height:1.25;margin:0 0 10px;
                          font-family:Georgia,'Times New Roman',serif;">
                <a href="{e(item['link'])}" style="color:#fff;text-decoration:none;">
                  {e(item['title'])}
                </a>
              </div>
              <p style="margin:0 0 10px;font-size:14px;line-height:1.75;color:rgba(255,255,255,0.65);">
                {e(item['summary'])}
              </p>
            </div>""")
        return "".join(blocks)

    def render_certin_cards(items: list[dict]) -> str:
        if not items:
            return '<p style="color:rgba(255,255,255,0.5);font-size:14px;">No new advisories — all recent ones already sent.</p>'
        blocks = []
        for item in items:
            sev   = item.get("severity", "High")
            color = SEV_COLOR.get(sev, "#e67e22")
            aff   = f'<div style="font-size:12px;color:rgba(255,255,255,0.5);margin:4px 0 8px;"><b style="color:rgba(255,255,255,0.8);">Affects:</b> {e(item["affected"])}</div>' if item.get("affected") else ""
            blocks.append(f"""
            <div style="border-left:3px solid {color};padding:14px 0 6px 16px;margin-bottom:14px;">
              <div style="margin-bottom:6px;">
                <code style="background:{color};color:#fff;font-size:10px;font-weight:800;
                             padding:2px 8px;border-radius:4px;">{e(item['code'])}</code>
                <span style="font-size:10px;color:{color};font-weight:700;
                             margin-left:8px;text-transform:uppercase;">{sev}</span>
              </div>
              {aff}
              <p style="margin:0 0 8px;font-size:14px;line-height:1.7;color:rgba(255,255,255,0.7);">
                {e(item['desc'])}
              </p>
              <a href="{e(item['url'])}"
                 style="font-size:12px;color:{color};font-weight:600;
                        text-decoration:none;text-transform:uppercase;letter-spacing:0.06em;">
                View advisory →
              </a>
            </div>""")
        return "".join(blocks)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#000;font-family:'Segoe UI',Arial,sans-serif;color:#fff;">
<div style="max-width:720px;margin:0 auto;padding:24px 14px 36px;">

  <!-- MASTHEAD -->
  <div style="border:1px solid rgba(255,255,255,0.08);padding:28px 28px 22px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:0.22em;
                text-transform:uppercase;color:#666;margin-bottom:12px;">
      Security Circuit
    </div>
    <div style="font-size:clamp(36px,8vw,56px);line-height:0.95;color:#fff;
                font-family:Georgia,'Times New Roman',serif;font-weight:700;margin-bottom:16px;">
      Security Circuit Newspaper
    </div>
    <div style="height:1px;background:rgba(255,255,255,0.1);margin-bottom:14px;"></div>
    <div style="font-size:11px;font-weight:700;letter-spacing:0.16em;
                text-transform:uppercase;color:#666;">
      {weekday} &nbsp;·&nbsp; {date_str} &nbsp;·&nbsp; Generated at {ts}
    </div>
  </div>

  <!-- BUG BOUNTY -->
  <div style="border:1px solid rgba(255,255,255,0.08);border-top:none;
              background:#050505;padding:22px 24px 12px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:0.2em;
                text-transform:uppercase;color:#666;margin-bottom:6px;">
      Section 01
    </div>
    <div style="font-size:28px;line-height:1;color:#fff;margin-bottom:6px;
                font-family:Georgia,'Times New Roman',serif;">
      Bug Bounty &amp; Disclosures
    </div>
    <div style="font-size:13px;color:rgba(255,255,255,0.45);margin-bottom:4px;">
      Latest writeups, public disclosures, and CVE research
    </div>
    {render_bounty_cards(bounty)}
  </div>

  <!-- NEWS -->
  <div style="border:1px solid rgba(255,255,255,0.08);border-top:none;
              background:#030303;padding:22px 24px 12px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:0.2em;
                text-transform:uppercase;color:#666;margin-bottom:6px;">
      Section 02
    </div>
    <div style="font-size:28px;line-height:1;color:#fff;margin-bottom:6px;
                font-family:Georgia,'Times New Roman',serif;">
      Cybersecurity News
    </div>
    <div style="font-size:13px;color:rgba(255,255,255,0.45);margin-bottom:4px;">
      Top stories worth reading today
    </div>
    {render_news_cards(news)}
  </div>

  <!-- CERT-IN -->
  <div style="border:1px solid rgba(255,255,255,0.08);border-top:none;
              background:#050505;padding:22px 24px 14px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:0.2em;
                text-transform:uppercase;color:#666;margin-bottom:6px;">
      Section 03
    </div>
    <div style="font-size:28px;line-height:1;color:#fff;margin-bottom:6px;
                font-family:Georgia,'Times New Roman',serif;">
      CERT-In Advisories
    </div>
    <div style="font-size:13px;color:rgba(255,255,255,0.45);margin-bottom:4px;">
      Official Indian Computer Emergency Response Team alerts
    </div>
    {render_certin_cards(certin)}
  </div>

  <!-- LEARNING -->
  <div style="border:1px solid rgba(255,255,255,0.08);border-top:none;
              background:#030303;padding:22px 24px 18px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:0.2em;
                text-transform:uppercase;color:#15803d;margin-bottom:6px;">
      {e(nugget['tag'])}
    </div>
    <div style="font-size:22px;line-height:1.1;color:#fff;margin-bottom:12px;
                font-family:Georgia,'Times New Roman',serif;">
      🧠 {e(nugget['title'])}
    </div>
    <p style="margin:0;font-size:14px;color:rgba(255,255,255,0.7);line-height:1.8;">
      {e(nugget['body'])}
    </p>
  </div>

  <!-- RED FLAG -->
  <div style="border:1px solid rgba(255,255,255,0.08);border-top:none;
              background:#050505;padding:22px 24px 18px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:0.2em;
                text-transform:uppercase;color:#e67e22;margin-bottom:6px;">
      Audit Red Flag
    </div>
    <div style="font-size:22px;line-height:1.1;color:#fff;margin-bottom:12px;
                font-family:Georgia,'Times New Roman',serif;">
      ⚠️ {e(redflag['title'])}
    </div>
    <p style="margin:0;font-size:14px;color:rgba(255,255,255,0.7);line-height:1.8;">
      {e(redflag['body'])}
    </p>
  </div>

  <!-- FOOTER -->
  <div style="border-top:1px solid rgba(255,255,255,0.06);margin-top:16px;
              padding-top:16px;text-align:center;">
    <p style="margin:0 0 6px;font-size:12px;color:#555;">
      Security Circuit Newspaper &nbsp;·&nbsp; {date_str}
    </p>
    <p style="margin:0;font-size:11px;color:#3a3a3a;line-height:1.7;">
      Sources: Medium, Intigriti, PortSwigger, HackerOne Hacktivity, tl;dr sec,
      BleepingComputer, The Hacker News, NVD, CERT-In<br>
      <a href="__UNSUB__" style="color:#555;">Unsubscribe</a>
    </p>
  </div>

</div>
</body>
</html>"""

    return html, subject

# =============================================================================
# SEND
# =============================================================================
def send_email(html: str, subject: str, recipients: list[str]) -> bool:
    unique = list(dict.fromkeys(recipients))
    log.info("Sending to %d recipients...", len(unique))
    sent = 0

    for i, email in enumerate(unique, 1):
        personalized = html.replace("__UNSUB__",
            html_lib.escape(unsub_url(email), quote=True))
        try:
            r = requests.post(
                f"{RESEND_API}/emails",
                headers=resend_hdr(),
                json={"from": FROM_EMAIL, "to": [email],
                      "subject": subject, "html": personalized},
                timeout=SEND_T,
            )
            if r.status_code in (200, 201):
                log.info("  ✅ %d/%d → %s (ID: %s)", i, len(unique), email,
                         r.json().get("id", "?"))
                sent += 1
            else:
                log.error("  ❌ %s → %d: %s", email, r.status_code, r.text[:200])
        except Exception as ex:
            log.error("  ❌ %s → Exception: %s", email, ex)

        if i < len(unique):
            time.sleep(BATCH_DELAY)

    return sent > 0

# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    log.info("=== Security Circuit Newspaper v3 ===")
    validate_config()

    cache  = load_cache()
    bounty = fetch_bug_bounty(cache)
    news   = fetch_news(cache)
    certin = fetch_certin(cache)

    html, subject = format_email(bounty, news, certin)
    recipients    = get_recipients()

    if recipients is None:
        log.error("Failed to fetch recipients.")
        sys.exit(1)

    if not recipients:
        log.info("No subscribers yet. Skipping send.")
        sys.exit(0)

    ok = send_email(html, subject, recipients)

    if ok:
        for item in bounty:
            mark_sent(cache, "bounty", item["_key"])
        for item in news:
            mark_sent(cache, "news", item["_key"])
        for item in certin:
            mark_sent(cache, "certin", item["_key"])
        save_cache(cache)
        sys.exit(0)

    sys.exit(1)
