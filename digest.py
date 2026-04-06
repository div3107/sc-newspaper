"""
SC Newspaper Digest

Priority order:
1. Bug bounty reports and public disclosures
2. Cybersecurity news
3. CERT-In alerts

The digest is intentionally minimal and front-loads the highest-signal disclosures.
"""

from __future__ import annotations

import json
import gzip
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

BUG_BOUNTY_TARGET = 5
NEWS_TARGET = 3
CERTIN_TARGET = 3
CACHE_EXPIRE_DAYS = 30
RESEND_RECIPIENT_BATCH_SIZE = 50
BATCH_DELAY_SECONDS = 0.6

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
        "limit": 3,
    },
    {
        "name": "Bugcrowd Disclosure",
        "url": "https://news.google.com/rss/search?q="
        + quote_plus('site:bugcrowd.com disclosed vulnerability OR crowdstream')
        + "&hl=en-IN&gl=IN&ceid=IN:en",
        "limit": 3,
    },
    {
        "name": "huntr",
        "url": "https://news.google.com/rss/search?q="
        + quote_plus("site:huntr.com CVE OR vulnerability OR disclosure")
        + "&hl=en-IN&gl=IN&ceid=IN:en",
        "limit": 3,
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
    "HackerOne Hacktivity": 0,
    "Bugcrowd Disclosure": 1,
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
        severity, score = score_cvss(cve.get("metrics", {}))
        if severity not in {"Critical", "High"} and (not score or float(score) < 7.0):
            continue

        key = normalize_key(f"nvd {cve_id}")[:140]
        if already_sent(cache, "bounty", key):
            continue

        summary = truncate_sentence(description, 220) or "New high-severity public CVE published in the NVD."
        items.append(
            {
                "title": f"{cve_id} — {summary[:80]}{'...' if len(summary) > 80 else ''}",
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": summary,
                "source": "NVD",
                "published": parse_iso_datetime(cve.get("published")),
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
    items.extend(fetch_bounty_feed_items(cache))
    items.extend(fetch_project_zero_disclosures(cache))
    items.extend(fetch_nvd_recent_disclosures(cache))

    deduped = []
    seen = set()
    for item in sorted(
        items,
        key=lambda value: (source_rank(value["source"]), -value["published"].timestamp()),
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

    top_story = "Daily Cybersecurity Briefing"
    for bucket in (bounty, news, certin):
        if bucket:
            top_story = bucket[0]["title"]
            break

    subject = f"🛡️ {today_human} — {top_story[:68]}{'...' if len(top_story) > 68 else ''}"

    bug_styles = {
        "Critical": "#b91c1c",
        "High": "#c2410c",
        "Medium": "#a16207",
        "Low": "#15803d",
    }

    def render_item_cards(items: list[dict], accent: str, minimal: bool = False) -> str:
        cards = []
        for item in items:
            meta = [item["source"]]
            if item.get("severity"):
                meta.append(item["severity"].upper())
            if item.get("score"):
                meta.append(f"CVSS {item['score']}")

            affected = ""
            if item.get("affected"):
                affected = (
                    f'<div style="font-size:12px;color:#6b7280;margin:0 0 8px;">'
                    f"<strong>Affects:</strong> {item['affected']}</div>"
                )

            cards.append(
                f"""
                <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;
                            padding:16px 18px;margin-bottom:12px;">
                  <div style="font-size:11px;font-weight:800;letter-spacing:0.08em;
                              text-transform:uppercase;color:{accent};margin-bottom:8px;">
                    {' · '.join(meta)}
                  </div>
                  <div style="font-size:16px;font-weight:700;line-height:1.45;margin-bottom:8px;">
                    <a href="{item['link']}" style="color:#111827;text-decoration:none;">{item['title']}</a>
                  </div>
                  {affected}
                  <p style="margin:0;font-size:14px;line-height:1.75;color:#374151;">
                    {item['summary']}
                  </p>
                </div>
                """
            )

        if not cards and minimal:
            return ""
        return "".join(cards)

    cert_cards = []
    for item in certin:
        accent = bug_styles.get(item.get("severity", "High"), "#c2410c")
        cert_cards.append(
            f"""
            <div style="background:#ffffff;border:1px solid #e5e7eb;border-left:4px solid {accent};
                        border-radius:0 12px 12px 0;padding:16px 18px;margin-bottom:12px;">
              <div style="font-size:11px;font-weight:800;letter-spacing:0.08em;
                          text-transform:uppercase;color:{accent};margin-bottom:8px;">
                CERT-In · {item.get('severity', 'High').upper()}
              </div>
              <div style="font-size:16px;font-weight:700;line-height:1.45;margin-bottom:8px;">
                <a href="{item['link']}" style="color:#111827;text-decoration:none;">{item['code']}</a>
              </div>
              {f'<div style="font-size:12px;color:#6b7280;margin:0 0 8px;"><strong>Affects:</strong> {item["affected"]}</div>' if item.get('affected') else ''}
              <p style="margin:0;font-size:14px;line-height:1.75;color:#374151;">
                {item['summary']}
              </p>
            </div>
            """
        )

    sections = []
    if bounty:
        sections.append(
            f"""
            <div style="background:#f8fafc;border:1px solid #dbeafe;border-radius:16px;padding:22px;margin-bottom:18px;">
              <div style="font-size:20px;font-weight:800;color:#1d4ed8;margin-bottom:4px;">
                🐛 Bug Bounty Reports &amp; Public Disclosures
              </div>
              <div style="font-size:12px;color:#64748b;margin-bottom:16px;">
                HackerOne Hacktivity · Bugcrowd · huntr · Google Project Zero · NVD
              </div>
              {render_item_cards(bounty, "#1d4ed8")}
            </div>
            """
        )

    if news:
        sections.append(
            f"""
            <div style="background:#fff7ed;border:1px solid #fdba74;border-radius:16px;padding:22px;margin-bottom:18px;">
              <div style="font-size:20px;font-weight:800;color:#c2410c;margin-bottom:4px;">
                🔥 Cybersecurity News
              </div>
              <div style="font-size:12px;color:#7c2d12;margin-bottom:16px;">
                Minimal roundup of the stories worth opening today
              </div>
              {render_item_cards(news, "#c2410c")}
            </div>
            """
        )

    if cert_cards:
        sections.append(
            f"""
            <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:16px;padding:22px;">
              <div style="font-size:20px;font-weight:800;color:#b91c1c;margin-bottom:4px;">
                🚨 CERT-In Alerts
              </div>
              <div style="font-size:12px;color:#7f1d1d;margin-bottom:16px;">
                Official Indian Computer Emergency Response Team advisories
              </div>
              {''.join(cert_cards)}
            </div>
            """
        )

    if not sections:
        sections.append(
            """
            <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;padding:22px;">
              <p style="margin:0;font-size:14px;line-height:1.75;color:#374151;">
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
<body style="margin:0;padding:0;background:#edf2f7;font-family:Segoe UI,Helvetica,Arial,sans-serif;">
  <div style="max-width:760px;margin:0 auto;padding:20px 12px;">
    <div style="background:#0f172a;border-radius:18px 18px 0 0;padding:28px 30px;color:#ffffff;">
      <div style="font-size:28px;font-weight:800;letter-spacing:-0.02em;">🛡️ SC Newspaper</div>
      <div style="font-size:13px;color:#cbd5e1;margin-top:6px;">
        {weekday}, {today_human} · Bug bounty first, then news, then CERT-In
      </div>
      <div style="font-size:12px;color:#94a3b8;margin-top:14px;">
        {len(bounty)} disclosures · {len(news)} news items · {len(certin)} CERT-In alerts
      </div>
    </div>

    <div style="background:#f8fafc;border-radius:0 0 18px 18px;padding:22px 18px 18px;">
      {''.join(sections)}
    </div>

    <div style="padding:16px 6px 0;text-align:center;">
      <p style="margin:0 0 4px;font-size:12px;color:#64748b;">
        Auto-generated on {today_human} at 10:00 AM IST
      </p>
      <p style="margin:0;font-size:11px;color:#94a3b8;">
        Sources include public disclosures, cybersecurity RSS feeds, CERT-In, Project Zero, and NVD.
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
    batches = chunked(recipients, RESEND_RECIPIENT_BATCH_SIZE)
    log.info("Sending via Resend — %d recipient(s) across %d batch(es)", len(recipients), len(batches))

    for index, batch in enumerate(batches, start=1):
        try:
            response = requests.post(
                f"{RESEND_API_BASE}/emails",
                headers=resend_headers(),
                json={
                    "from": FROM_EMAIL,
                    "to": batch,
                    "subject": subject,
                    "html": html,
                },
                timeout=SEND_TIMEOUT,
            )
        except Exception as exc:
            log.error("Send exception on batch %d: %s", index, exc)
            return False

        if response.status_code not in (200, 201):
            log.error("Resend batch %d failed (%s): %s", index, response.status_code, response.text)
            return False

        log.info("Batch %d/%d sent. Resend ID: %s", index, len(batches), response.json().get("id", "?"))

        if index < len(batches):
            time.sleep(BATCH_DELAY_SECONDS)

    return True


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    log.info("=== SC Newspaper Digest ===")
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
