"""
Security Circuit Newspaper Digest

Priority order:
1. Bug bounty reports and public disclosures
2. Cybersecurity news
3. CERT-In alerts

The digest is intentionally minimal and front-loads the highest-signal disclosures.
"""

from __future__ import annotations

import json
import gzip
import html as html_lib
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus, urljoin
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
IST = ZoneInfo("Asia/Kolkata")
BASE_DIR = Path(__file__).resolve().parent
CACHE_FILE = BASE_DIR / "seen_cache.json"

EMAIL_TO = [value.strip() for value in os.getenv("EMAIL_TO", "").split(",") if value.strip()]
RESEND_KEY = os.getenv("RESEND_API_KEY", "").strip()
FROM_EMAIL = os.getenv("FROM_EMAIL", "").strip()
RESEND_AUDIENCE_ID = os.getenv("RESEND_AUDIENCE_ID", "").strip()
UNSUBSCRIBE_BASE_URL = os.getenv("UNSUBSCRIBE_BASE_URL", "").strip()

BUG_BOUNTY_TARGET = 5
NEWS_TARGET = 3
CERTIN_TARGET = 3
CACHE_EXPIRE_DAYS = 30
RESEND_RECIPIENT_BATCH_SIZE = 50
BATCH_DELAY_SECONDS = 0.6
MEDIUM_RECENT_DAYS = 45
NVD_RECENT_DAYS = 14

CERTIN_BASE = "https://www.cert-in.org.in"
PROJECT_ZERO_URL = "https://projectzero.google/"
NVD_RECENT_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
RESEND_API_BASE = "https://api.resend.com"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

FEED_TIMEOUT = 12
CERTIN_TIMEOUT = 12
SEND_TIMEOUT = 15

BUG_BOUNTY_KEYWORDS = [
    "vulnerability",
    "exploit",
    "cve-",
    "xss",
    "idor",
    "rce",
    "csrf",
    "auth bypass",
    "ssrf",
    "bug bounty",
    "security issue",
]

NEWS_KEYWORDS = [
    "ransomware",
    "critical",
    "vulnerability",
    "exploit",
    "breach",
    "zero-day",
    "malware",
    "phishing",
    "attack",
    "cert-in",
    "india",
    "microsoft",
    "apple",
    "google",
    "fortinet",
    "ivanti",
    "chrome",
]

BUG_BOUNTY_FEEDS = [
    {
        "name": "HackerOne Hacktivity",
        "url": "https://news.google.com/rss/search?q="
        + quote_plus("site:hackerone.com/reports vulnerability OR exploit")
        + "&hl=en-IN&gl=IN&ceid=IN:en",
        "limit": 2,
    },
    {
        "name": "huntr",
        "url": "https://news.google.com/rss/search?q="
        + quote_plus("site:huntr.com CVE OR vulnerability OR disclosure")
        + "&hl=en-IN&gl=IN&ceid=IN:en",
        "limit": 2,
    },
]

MEDIUM_BOUNTY_FEEDS = [
    {"name": "@dhxrxx", "url": "https://medium.com/feed/@dhxrxx", "limit": 1},
    {"name": "sudoaman", "url": "https://sudoaman.medium.com/feed", "limit": 1},
    {"name": "@uday637", "url": "https://medium.com/feed/@uday637", "limit": 1},
    {"name": "@bugitrix", "url": "https://medium.com/feed/@bugitrix", "limit": 1},
    {"name": "@0xuserm9", "url": "https://medium.com/feed/@0xuserm9", "limit": 1},
    {"name": "@sonuoffsec", "url": "https://medium.com/feed/@sonuoffsec", "limit": 1},
    {"name": "varnith", "url": "https://varnith.medium.com/feed", "limit": 1},
    {"name": "v3n0m", "url": "https://v3n0m.medium.com/feed", "limit": 1},
    {"name": "@HackerMD", "url": "https://medium.com/feed/@HackerMD", "limit": 1},
    {"name": "@contact.us1320", "url": "https://medium.com/feed/@contact.us1320", "limit": 1},
]

CURATED_MEDIUM_ARTICLES = [
    {
        "title": "CVE-2026-22812: How I Got RCE on a 71k-Star AI Coding Tool With Zero Authentication",
        "link": "https://medium.com/@dhxrxx/cve-2026-22812-how-i-got-rce-on-a-71k-star-ai-coding-tool-with-zero-authentication-7524fbc3317f",
        "summary": "Medium write-up on unauthenticated RCE in a popular AI coding tool.",
        "source_detail": "@dhxrxx",
    },
    {
        "title": "The $0 Supply Chain Hack: Hijacking Microsoft's Setup.exe (And Broke Their Bounty Policy)",
        "link": "https://sudoaman.medium.com/the-0-supply-chain-hack-hijacking-microsofts-setup-exe-and-broke-their-bounty-policy-f05eb6fedcff",
        "summary": "Supply-chain write-up on hijacking Microsoft's Setup.exe and the related bounty-policy issue.",
        "source_detail": "sudoaman",
    },
    {
        "title": "Why You're Not Finding Bugs (And How to Find Your First P1 Bug)",
        "link": "https://medium.com/@uday637/why-youre-not-finding-bugs-and-how-hackers-actually-do-with-idor-8b456bacfaf6",
        "summary": "Practical primer on finding first serious bug bounty wins with IDOR methodology.",
        "source_detail": "@uday637",
    },
    {
        "title": "Google Dorking: The Most Underrated Bug Bounty Skill",
        "link": "https://medium.com/@bugitrix/google-dorking-the-most-underrated-bug-bounty-skill-bd548cac235c",
        "summary": "Guide to using Google dorks as a bug bounty reconnaissance skill.",
        "source_detail": "@bugitrix",
    },
    {
        "title": "The Hidden Weapon: How I Turn Mass Assignment into Bounties",
        "link": "https://medium.com/@0xuserm9/the-hidden-weapon-how-i-turn-mass-assignment-into-bounties-459d7c35a727",
        "summary": "Mass-assignment methodology write-up focused on turning insecure defaults into bounty findings.",
        "source_detail": "@0xuserm9",
    },
    {
        "title": "How I Find the Real IP Behind Cloudflare (When It's Not Supposed to Be Visible)",
        "link": "https://medium.com/@sonuoffsec/how-i-find-the-real-ip-behind-cloudflare-when-its-not-supposed-to-be-visible-cd48e2ce5e62",
        "summary": "Technique breakdown for identifying origin IPs that sit behind Cloudflare.",
        "source_detail": "@sonuoffsec",
    },
    {
        "title": "Everyone Told Me DNS is a Phonebook. They Lied.",
        "link": "https://varnith.medium.com/everyone-told-me-dns-is-a-phonebook-they-lied-0ff7a1023248",
        "summary": "Offensive-security deep dive on DNS from a bug bounty and recon perspective.",
        "source_detail": "varnith",
    },
    {
        "title": "From Logs to Rootkits: A Complete Linux Forensic Analysis Breakdown",
        "link": "https://v3n0m.medium.com/from-logs-to-rootkits-a-complete-linux-forensic-analysis-breakdown-48a011d7ce0c",
        "summary": "Linux forensic workflow that moves from host logs to deeper compromise analysis.",
        "source_detail": "v3n0m",
    },
    {
        "title": "HackerMD Elite Bug Bounty Recon Toolkit: The Only Tool You Need in 2026",
        "link": "https://medium.com/@HackerMD/hackermd-elite-bug-bounty-recon-toolkit-the-only-tool-you-need-in-2026-63a8945318f4",
        "summary": "Recon tooling roundup aimed at modern bug bounty workflows.",
        "source_detail": "@HackerMD",
    },
    {
        "title": "Wireless Attack with Aircrack-ng: A Complete Guide from A to Z",
        "link": "https://medium.com/@contact.us1320/wireless-attack-with-aircrack-ng-a-complete-guide-from-a-to-z-17b5a3de94f6",
        "summary": "Hands-on wireless attack lab guide built around Aircrack-ng.",
        "source_detail": "@contact.us1320",
    },
]

NEWS_FEEDS = [
    {"name": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "limit": 2},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "limit": 2},
    {
        "name": "Google News",
        "url": "https://news.google.com/rss/search?q="
        + quote_plus("cybersecurity india OR cert-in OR vulnerability")
        + "&hl=en-IN&gl=IN&ceid=IN:en",
        "limit": 2,
    },
]

SOURCE_PRIORITY = {
    "Medium": 0,
    "HackerOne Hacktivity": 1,
    "huntr": 2,
    "Google Project Zero": 3,
    "NVD": 4,
}


def now_ist() -> datetime:
    return datetime.now(IST)


def validate_config() -> None:
    errors = []
    if not RESEND_KEY:
        errors.append("RESEND_API_KEY secret is missing or empty")
    if not FROM_EMAIL:
        errors.append("FROM_EMAIL secret is missing or empty")
    if not RESEND_AUDIENCE_ID and not EMAIL_TO:
        errors.append("Either RESEND_AUDIENCE_ID or EMAIL_TO must be configured")
    if errors:
        for error in errors:
            log.error("CONFIG ERROR: %s", error)
        log.error("Add secrets in GitHub → Settings → Secrets and variables → Actions")
        sys.exit(1)
    recipient_mode = (
        f"Resend segment/audience {RESEND_AUDIENCE_ID}"
        if RESEND_AUDIENCE_ID
        else f"Static EMAIL_TO list ({len(EMAIL_TO)})"
    )
    log.info("Config OK — FROM: %s | RECIPIENT SOURCE: %s", FROM_EMAIL, recipient_mode)


# =============================================================================
# HELPERS
# =============================================================================
def clean_text(value: str) -> str:
    text = BeautifulSoup(value or "", "html.parser").get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def truncate_sentence(text: str, limit: int = 240) -> str:
    text = clean_text(text)
    if not text:
        return ""
    if len(text) <= limit:
        return text
    clipped = text[:limit]
    matches = list(re.finditer(r"[.!?](?=\s|$)", clipped))
    if matches:
        return clipped[: matches[-1].end()].strip()
    return clipped.rsplit(" ", 1)[0].strip() + "..."


def truncate_text(text: str, limit: int = 160) -> str:
    text = clean_text(text)
    if not text or len(text) <= limit:
        return text
    return text[: limit - 3].rsplit(" ", 1)[0].strip() + "..."


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def parse_iso_datetime(value: str | None) -> datetime:
    if not value:
        return now_ist()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(IST)
    except ValueError:
        return now_ist()


def entry_datetime(entry) -> datetime:
    struct_time = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
    if struct_time:
        return datetime(
            struct_time.tm_year,
            struct_time.tm_mon,
            struct_time.tm_mday,
            struct_time.tm_hour,
            struct_time.tm_min,
            struct_time.tm_sec,
            tzinfo=timezone.utc,
        ).astimezone(IST)
    published = getattr(entry, "published", None) or getattr(entry, "updated", None)
    return parse_iso_datetime(published)


def feed_summary(entry, fallback: str = "") -> str:
    summary = clean_text(getattr(entry, "summary", "") or getattr(entry, "description", ""))
    if not summary:
        summary = fallback
    return truncate_sentence(summary, 220)


def parse_feed(url: str):
    response = requests.get(url, headers=HEADERS, timeout=FEED_TIMEOUT)
    response.raise_for_status()
    return feedparser.parse(response.content)


def is_recent(value: datetime, days: int = 7) -> bool:
    return value >= now_ist() - timedelta(days=days)


def score_cvss(metrics: dict) -> tuple[str, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        metric = values[0]
        cvss = metric.get("cvssData", {})
        score = cvss.get("baseScore") or metric.get("baseScore")
        severity = metric.get("baseSeverity") or cvss.get("baseSeverity")
        if score is not None:
            try:
                score_text = f"{float(score):.1f}"
            except (TypeError, ValueError):
                score_text = str(score)
        else:
            score_text = ""
        if severity:
            return str(severity).title(), score_text
    return "", ""


def source_rank(source: str) -> int:
    return SOURCE_PRIORITY.get(source, 99)


def resend_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {RESEND_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "sc-newspaper-digest/1.0",
    }


def chunked(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def build_unsubscribe_url(email_address: str) -> str:
    base_url = (UNSUBSCRIBE_BASE_URL or "https://sc-newspaper-subscribe.cyberpunk060594.workers.dev").rstrip("/")
    return f"{base_url}/unsubscribe?email={quote_plus(email_address)}"


# =============================================================================
# CACHE
# =============================================================================
def load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            cache = json.loads(CACHE_FILE.read_text())
            log.info(
                "Cache: %d bounty, %d news, %d cert-in remembered",
                len(cache.get("bounty", {})),
                len(cache.get("news", {})),
                len(cache.get("certin", {})),
            )
            return cache
        except Exception as exc:
            log.warning("Cache read error: %s — starting fresh", exc)
    return {"bounty": {}, "news": {}, "certin": {}}


def save_cache(cache: dict) -> None:
    cutoff = (now_ist() - timedelta(days=CACHE_EXPIRE_DAYS)).strftime("%Y-%m-%d")
    for section in ("bounty", "news", "certin"):
        cache[section] = {key: value for key, value in cache.get(section, {}).items() if value >= cutoff}
    CACHE_FILE.write_text(json.dumps(cache, indent=2))
    log.info("Cache saved to %s", CACHE_FILE)


def mark_sent(cache: dict, section: str, key: str) -> None:
    cache.setdefault(section, {})[key] = now_ist().strftime("%Y-%m-%d")


def already_sent(cache: dict, section: str, key: str) -> bool:
    return key in cache.get(section, {})


# =============================================================================
# BUG BOUNTY REPORTS AND DISCLOSURES
# =============================================================================
def fetch_bounty_feed_items(cache: dict) -> list[dict]:
    log.info("Fetching public bug bounty/disclosure feeds...")
    items = []
    seen = set()

    for config in BUG_BOUNTY_FEEDS:
        try:
            feed = parse_feed(config["url"])
        except Exception as exc:
            log.warning("Feed error (%s): %s", config["name"], exc)
            continue

        source_count = 0
        for entry in getattr(feed, "entries", []):
            title = clean_text(getattr(entry, "title", ""))
            link = getattr(entry, "link", "").strip()
            if not title or not link:
                continue
            published = entry_datetime(entry)
            if not is_recent(published):
                continue

            combined = f"{title} {getattr(entry, 'summary', '')}".lower()
            if not any(keyword in combined for keyword in BUG_BOUNTY_KEYWORDS):
                continue

            key = normalize_key(f"{config['name']} {title}")[:140]
            if key in seen or already_sent(cache, "bounty", key):
                continue

            items.append(
                {
                    "title": title,
                    "link": link,
                    "summary": feed_summary(entry, fallback=title),
                    "source": config["name"],
                    "published": published,
                    "_key": key,
                }
            )
            seen.add(key)
            source_count += 1
            if source_count >= config["limit"]:
                break

    return items


def fetch_medium_bounty_articles(cache: dict) -> list[dict]:
    log.info("Fetching Medium bug bounty write-ups...")
    items = []
    seen = set()

    for config in MEDIUM_BOUNTY_FEEDS:
        try:
            feed = parse_feed(config["url"])
        except Exception as exc:
            log.warning("Medium feed error (%s): %s", config["name"], exc)
            continue

        source_count = 0
        for entry in getattr(feed, "entries", []):
            title = clean_text(getattr(entry, "title", ""))
            link = getattr(entry, "link", "").strip()
            if not title or not link:
                continue

            published = entry_datetime(entry)
            if not is_recent(published, days=MEDIUM_RECENT_DAYS):
                continue

            lowered = title.lower()
            if lowered in {"home", "about", "archive"}:
                continue

            key = normalize_key(f"medium {link}")[:140]
            if key in seen or already_sent(cache, "bounty", key):
                continue

            items.append(
                {
                    "title": title,
                    "link": link,
                    "summary": feed_summary(entry, fallback=title),
                    "source": "Medium",
                    "source_detail": config["name"],
                    "published": published,
                    "priority": 0,
                    "_key": key,
                }
            )
            seen.add(key)
            source_count += 1
            if source_count >= config["limit"]:
                break

    items.sort(key=lambda item: item["published"].timestamp(), reverse=True)
    return items


def curated_medium_fallback(cache: dict) -> list[dict]:
    items = []
    current = now_ist()

    for index, article in enumerate(CURATED_MEDIUM_ARTICLES):
        key = normalize_key(f"medium {article['link']}")[:140]
        if already_sent(cache, "bounty", key):
            continue

        items.append(
            {
                "title": article["title"],
                "link": article["link"],
                "summary": article["summary"],
                "source": "Medium",
                "source_detail": article["source_detail"],
                "published": current - timedelta(minutes=index),
                "priority": 0,
                "_key": key,
            }
        )

    return items


def fetch_project_zero_disclosures(cache: dict) -> list[dict]:
    log.info("Fetching Google Project Zero disclosures...")
    items = []
    seen = set()
    try:
        response = requests.get(PROJECT_ZERO_URL, headers=HEADERS, timeout=FEED_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as exc:
        log.warning("Project Zero fetch error: %s", exc)
        return items

    skip_fragments = (
        "blog archive",
        "about",
        "working",
        "reporting transparency",
        "vulnerability disclosure policy",
        "read more",
    )
    interesting = ("cve-", "exploit", "bypass", "0-click", "0day", "vulnerability", "kernel", "sandbox")

    for link in soup.select("a[href]"):
        title = clean_text(link.get_text(" ", strip=True))
        href = urljoin(PROJECT_ZERO_URL, link.get("href", "").strip())
        lowered = title.lower()
        if not title or len(title) < 16 or any(fragment in lowered for fragment in skip_fragments):
            continue
        if not any(token in lowered for token in interesting):
            continue

        key = normalize_key(f"project-zero {href}")[:140]
        if href in seen or already_sent(cache, "bounty", key):
            continue

        items.append(
            {
                "title": title,
                "link": href,
                "summary": "New public vulnerability research and disclosure from Google Project Zero.",
                "source": "Google Project Zero",
                "published": now_ist(),
                "_key": key,
            }
        )
        seen.add(href)
        if len(items) >= 2:
            break

    return items


def fetch_nvd_recent_disclosures(cache: dict) -> list[dict]:
    log.info("Fetching NVD recent disclosures...")
    items = []
    try:
        response = requests.get(NVD_RECENT_FEED, headers=HEADERS, timeout=FEED_TIMEOUT)
        response.raise_for_status()
        payload = json.loads(gzip.decompress(response.content).decode("utf-8"))
    except Exception as exc:
        log.warning("NVD fetch error: %s", exc)
        return items

    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", [])
        description = next(
            (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
            "",
        )
        published = parse_iso_datetime(cve.get("published"))
        if not is_recent(published, days=NVD_RECENT_DAYS):
            continue

        severity, score = score_cvss(cve.get("metrics", {}))
        if severity not in {"Critical", "High"} and (not score or float(score) < 7.0):
            continue

        key = normalize_key(f"nvd {cve_id}")[:140]
        if already_sent(cache, "bounty", key):
            continue

        summary = truncate_sentence(description, 220) or "New high-severity public CVE published in the NVD."
        items.append(
            {
                "title": cve_id,
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": summary,
                "source": "NVD",
                "published": published,
                "severity": severity,
                "score": score,
                "_key": key,
            }
        )

    items.sort(
        key=lambda item: (
            0 if item.get("severity") == "Critical" else 1,
            -(item["published"].timestamp()),
        )
    )
    return items[:5]


def fetch_bug_bounty_reports(cache: dict) -> list[dict]:
    items = []
    items.extend(fetch_medium_bounty_articles(cache))
    items.extend(curated_medium_fallback(cache))
    items.extend(fetch_bounty_feed_items(cache))
    items.extend(fetch_project_zero_disclosures(cache))
    items.extend(fetch_nvd_recent_disclosures(cache))

    deduped = []
    seen = set()
    for item in sorted(
        items,
        key=lambda value: (value.get("priority", source_rank(value["source"])), -value["published"].timestamp()),
    ):
        key = item["_key"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= BUG_BOUNTY_TARGET:
            break

    log.info("Using %d bug bounty/disclosure items", len(deduped))
    return deduped


# =============================================================================
# CYBERSECURITY NEWS
# =============================================================================
def fetch_news(cache: dict) -> list[dict]:
    log.info("Fetching cybersecurity news...")
    items = []
    seen = set()

    for config in NEWS_FEEDS:
        try:
            feed = parse_feed(config["url"])
        except Exception as exc:
            log.warning("News feed error (%s): %s", config["name"], exc)
            continue

        source_count = 0
        for entry in getattr(feed, "entries", []):
            title = clean_text(getattr(entry, "title", ""))
            link = getattr(entry, "link", "").strip()
            if not title or not link:
                continue
            published = entry_datetime(entry)
            if not is_recent(published, days=4):
                continue

            combined = f"{title} {getattr(entry, 'summary', '')}".lower()
            if not any(keyword in combined for keyword in NEWS_KEYWORDS):
                continue

            key = normalize_key(f"{config['name']} {title}")[:140]
            if key in seen or already_sent(cache, "news", key):
                continue

            items.append(
                {
                    "title": title,
                    "link": link,
                    "summary": feed_summary(entry, fallback=title),
                    "source": config["name"],
                    "published": published,
                    "_key": key,
                }
            )
            seen.add(key)
            source_count += 1
            if source_count >= config["limit"]:
                break

    items.sort(key=lambda item: item["published"].timestamp(), reverse=True)
    selected = items[:NEWS_TARGET]
    log.info("Using %d news items", len(selected))
    return selected


# =============================================================================
# CERT-IN
# =============================================================================
def clean_certin_description(text: str) -> str:
    for marker in (
        "Target Audience",
        "Risk Assessment",
        "Impact Assessment",
        "Solution",
        "References",
        "Vendor Information",
    ):
        if marker in text:
            text = text.split(marker)[0].strip()
    return truncate_sentence(text, 260)


def fetch_single_certin_advisory(args: tuple[int, int]) -> dict | None:
    number, year = args
    code = f"CIAD-{year}-{number:04d}"
    url = f"{CERTIN_BASE}/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE={code}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=CERTIN_TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text(" ", strip=True)
        if code not in text and "Severity" not in text:
            return None

        severity = "High"
        severity_match = re.search(r"Severity Rating\s*[:\-]?\s*(\w+)", text, re.I)
        if severity_match and severity_match.group(1).capitalize() in ("Critical", "High", "Medium", "Low"):
            severity = severity_match.group(1).capitalize()

        description = ""
        for marker in ("Overview", "Description"):
            if marker in text:
                description = clean_certin_description(text.split(marker, 1)[1].strip())
                if description:
                    break

        affected = ""
        if "Software Affected" in text:
            chunk = text.split("Software Affected", 1)[1]
            chunk = re.split(r"Overview|Description|Target|Risk|Impact", chunk)[0]
            items = [line.strip() for line in chunk.splitlines() if len(line.strip()) > 3 and not line.strip().startswith("---")]
            if items:
                affected = ", ".join(items[:3])
                if len(items) > 3:
                    affected += f" +{len(items) - 3} more"
                affected = truncate_text(affected, 180)

        return {
            "code": code,
            "title": code,
            "link": url,
            "summary": description or "Multiple vulnerabilities reported. Apply vendor patches immediately.",
            "source": "CERT-In",
            "severity": severity,
            "affected": affected,
            "published": now_ist(),
            "_key": code,
        }
    except Exception as exc:
        log.debug("CERT-In probe failed for %s: %s", code, exc)
        return None


def fetch_certin(cache: dict) -> list[dict]:
    year = now_ist().year
    latest = 20
    list_url = f"{CERTIN_BASE}/s2cMainServlet?pageid=PUBADVLIST02&year={year}"

    try:
        response = requests.get(list_url, headers=HEADERS, timeout=CERTIN_TIMEOUT)
        matches = re.findall(rf"CIAD-{year}-(\d+)", response.text)
        if matches:
            latest = max(int(value) for value in matches)
            log.info("Latest CERT-In advisory number: %04d", latest)
    except Exception as exc:
        log.warning("CERT-In list page error: %s", exc)

    candidates = []
    for number in range(latest, max(0, latest - 25), -1):
        code = f"CIAD-{year}-{number:04d}"
        if already_sent(cache, "certin", code):
            continue
        candidates.append((number, year))
        if len(candidates) >= CERTIN_TARGET * 3:
            break

    if not candidates:
        log.info("No unsent CERT-In advisories in recent range.")
        return []

    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fetch_single_certin_advisory, candidate): candidate for candidate in candidates}
        for future in as_completed(futures):
            item = future.result()
            if item:
                results.append(item)

    results.sort(key=lambda item: item["code"], reverse=True)
    selected = results[:CERTIN_TARGET]
    log.info("Using %d CERT-In advisories", len(selected))
    return selected


# =============================================================================
# RECIPIENTS
# =============================================================================
def fetch_segment_recipients() -> list[str] | None:
    if not RESEND_AUDIENCE_ID:
        return []

    log.info("Fetching recipients from Resend segment/audience %s...", RESEND_AUDIENCE_ID)
    recipients: list[str] = []
    after: str | None = None

    while True:
        params = {}
        if after:
            params["after"] = after

        response = requests.get(
            f"{RESEND_API_BASE}/segments/{RESEND_AUDIENCE_ID}/contacts",
            headers=resend_headers(),
            params=params or None,
            timeout=FEED_TIMEOUT,
        )

        if not response.ok:
            log.error("Resend segment contacts error %s: %s", response.status_code, response.text)
            return None

        payload = response.json()
        contacts = payload.get("data", [])
        if not contacts:
            break

        for contact in contacts:
            email = (contact.get("email") or "").strip().lower()
            if email and not contact.get("unsubscribed", False):
                recipients.append(email)

        if not payload.get("has_more"):
            break

        last_id = contacts[-1].get("id")
        if not last_id:
            break
        after = last_id

    unique = list(dict.fromkeys(recipients))
    log.info("Found %d website subscribers in Resend", len(unique))
    return unique


def get_recipients() -> list[str] | None:
    if RESEND_AUDIENCE_ID:
        return fetch_segment_recipients()
    return EMAIL_TO


# =============================================================================
# EMAIL
# =============================================================================
def format_email(bounty: list[dict], news: list[dict], certin: list[dict]) -> tuple[str, str]:
    today = now_ist()
    today_human = today.strftime("%d %B %Y")
    weekday = today.strftime("%A")
    generated_at = today.strftime("%I:%M %p IST").lstrip("0")
    subject = f"Security Circuit Newspaper | {today_human}"

    def item_meta(item: dict) -> str:
        parts = []
        if item["source"] == "Medium" and item.get("source_detail"):
            parts.extend(["Medium", item["source_detail"]])
        else:
            parts.append(item["source"])
        if item.get("severity"):
            parts.append(item["severity"].upper())
        if item.get("score"):
            parts.append(f"CVSS {item['score']}")
        return " · ".join(parts)

    def render_items(items: list[dict], accent: str) -> str:
        blocks = []
        for item in items:
            title = html_lib.escape(item["title"])
            link = html_lib.escape(item["link"], quote=True)
            meta = html_lib.escape(item_meta(item))
            summary = html_lib.escape(item["summary"])

            affected = ""
            if item.get("affected"):
                affected = (
                    f'<div style="font-size:12px;color:rgba(255,255,255,0.55);margin:0 0 8px;">'
                    f'<strong style="color:#fff;">Affects:</strong> {html_lib.escape(item["affected"])}</div>'
                )

            blocks.append(
                f"""
                <div style="border-top:1px solid rgba(255,255,255,0.08);padding:18px 0 2px;">
                  <div style="font-size:11px;font-weight:700;letter-spacing:0.12em;
                              text-transform:uppercase;color:{accent};margin-bottom:10px;">
                    {meta}
                  </div>
                  <div style="font-size:24px;line-height:1.15;margin:0 0 10px;
                              font-family:Georgia,'Times New Roman',serif;">
                    <a href="{link}" style="color:#ffffff;text-decoration:none;">{title}</a>
                  </div>
                  {affected}
                  <p style="margin:0 0 14px;font-size:15px;line-height:1.8;color:rgba(255,255,255,0.72);">
                    {summary}
                  </p>
                </div>
                """
            )
        return "".join(blocks)

    sections = []
    if bounty:
        sections.append(
            f"""
            <div style="border:1px solid rgba(255,255,255,0.08);background:#050505;padding:22px 24px 8px;margin-top:18px;">
              <div style="font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#9ca3af;margin-bottom:8px;">
                Bug Bounty
              </div>
              <div style="font-size:34px;line-height:1;margin:0 0 8px;color:#ffffff;font-family:Georgia,'Times New Roman',serif;">
                Reports &amp; Write-ups
              </div>
              <div style="font-size:14px;line-height:1.7;color:rgba(255,255,255,0.58);margin-bottom:2px;">
                Latest public bug bounty research, recon notes, exploit write-ups, and disclosures worth opening.
              </div>
              {render_items(bounty, "#e8212b")}
            </div>
            """
        )

    if news:
        sections.append(
            f"""
            <div style="border:1px solid rgba(255,255,255,0.08);background:#050505;padding:22px 24px 8px;margin-top:18px;">
              <div style="font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#9ca3af;margin-bottom:8px;">
                Cybersecurity News
              </div>
              <div style="font-size:34px;line-height:1;margin:0 0 8px;color:#ffffff;font-family:Georgia,'Times New Roman',serif;">
                News That Matters
              </div>
              <div style="font-size:14px;line-height:1.7;color:rgba(255,255,255,0.58);margin-bottom:2px;">
                Minimal roundup of the security stories worth reading today.
              </div>
              {render_items(news, "#f5f5f5")}
            </div>
            """
        )

    if certin:
        sections.append(
            f"""
            <div style="border:1px solid rgba(255,255,255,0.08);background:#050505;padding:22px 24px 8px;margin-top:18px;">
              <div style="font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#9ca3af;margin-bottom:8px;">
                CERT-In
              </div>
              <div style="font-size:34px;line-height:1;margin:0 0 8px;color:#ffffff;font-family:Georgia,'Times New Roman',serif;">
                Official Alerts
              </div>
              <div style="font-size:14px;line-height:1.7;color:rgba(255,255,255,0.58);margin-bottom:2px;">
                Official Indian Computer Emergency Response Team advisories.
              </div>
              {render_items(certin, "#e8212b")}
            </div>
            """
        )

    if not sections:
        sections.append(
            """
            <div style="border:1px solid rgba(255,255,255,0.08);background:#050505;padding:22px 24px;margin-top:18px;">
              <p style="margin:0;font-size:15px;line-height:1.8;color:rgba(255,255,255,0.72);">
                No fresh items were selected today across the configured sources.
              </p>
            </div>
            """
        )

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#000000;font-family:'Segoe UI',Arial,sans-serif;color:#ffffff;">
  <div style="max-width:760px;margin:0 auto;padding:28px 16px 34px;">
    <div style="border:1px solid rgba(255,255,255,0.08);background:#000000;padding:30px 28px 26px;">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.22em;text-transform:uppercase;color:#777777;margin-bottom:14px;">
        Security Circuit
      </div>
      <div style="font-size:58px;line-height:0.92;margin:0;color:#ffffff;font-family:Georgia,'Times New Roman',serif;">
        Security Circuit Newspaper
      </div>
      <div style="height:1px;background:rgba(255,255,255,0.12);margin:22px 0 18px;"></div>
      <div style="font-size:12px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#8b8b8b;">
        {weekday} · {today_human}
      </div>
    </div>

    {''.join(sections)}

    <div style="border-top:1px solid rgba(255,255,255,0.08);margin-top:22px;padding:18px 2px 0;">
      <p style="margin:0 0 6px;font-size:12px;color:#8b8b8b;">
        Auto-generated on {today_human} at {generated_at}
      </p>
      <p style="margin:0 0 8px;font-size:11px;color:#5f5f5f;line-height:1.7;">
        Sources include Medium write-ups, public disclosure feeds, cybersecurity RSS feeds, CERT-In, Project Zero, and NVD.
      </p>
      <p style="margin:0;font-size:11px;color:#5f5f5f;line-height:1.7;">
        You are receiving this because you subscribed to Security Circuit Newspaper.
        <a href="__UNSUBSCRIBE_URL__" style="color:#d0d0d0;">Unsubscribe instantly</a>.
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
    unique_recipients = list(dict.fromkeys(recipients))
    log.info("Sending via Resend — %d recipient(s)", len(unique_recipients))

    sent = 0
    failed: list[str] = []

    for index, recipient in enumerate(unique_recipients, start=1):
        personalized_html = html.replace(
            "__UNSUBSCRIBE_URL__", html_lib.escape(build_unsubscribe_url(recipient), quote=True)
        )

        try:
            response = requests.post(
                f"{RESEND_API_BASE}/emails",
                headers=resend_headers(),
                json={
                    "from": FROM_EMAIL,
                    "to": [recipient],
                    "subject": subject,
                    "html": personalized_html,
                },
                timeout=SEND_TIMEOUT,
            )
        except Exception as exc:
            log.error("Send exception for %s: %s", recipient, exc)
            failed.append(recipient)
            continue

        if response.status_code not in (200, 201):
            log.error("Resend failed for %s (%s): %s", recipient, response.status_code, response.text)
            failed.append(recipient)
            continue

        sent += 1
        log.info("Sent %d/%d to %s. Resend ID: %s", index, len(unique_recipients), recipient, response.json().get("id", "?"))

        if index < len(unique_recipients):
            time.sleep(BATCH_DELAY_SECONDS)

    if failed:
        log.warning("Failed recipients: %s", ", ".join(failed))

    return sent > 0


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    log.info("=== Security Circuit Newspaper Digest ===")
    validate_config()

    cache = load_cache()
    bounty_items = fetch_bug_bounty_reports(cache)
    news_items = fetch_news(cache)
    certin_items = fetch_certin(cache)

    html, subject = format_email(bounty_items, news_items, certin_items)
    recipients = get_recipients()

    if recipients is None:
        log.error("Failed to fetch website subscribers from Resend.")
        sys.exit(1)

    if not recipients:
        log.info("No website subscribers found yet. Skipping send without consuming cache.")
        sys.exit(0)

    ok = send_email(html, subject, recipients)

    if ok:
        for item in bounty_items:
            mark_sent(cache, "bounty", item["_key"])
        for item in news_items:
            mark_sent(cache, "news", item["_key"])
        for item in certin_items:
            mark_sent(cache, "certin", item["_key"])
        save_cache(cache)
        sys.exit(0)

    sys.exit(1)
