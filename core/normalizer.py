"""
Normalizer — takes raw IOCs from all ingestors, enriches, deduplicates,
and writes clean records to the database.
"""
import sqlite3
import hashlib
import ipaddress
import logging
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

DB_PATH = "data/ticluster.db"

# ---------------------------------------------------------------------------
# ASN / GEO enrichment  (ip-api.com — free, no key, 45 req/min)
# ---------------------------------------------------------------------------

def _enrich_ip(ip: str) -> dict:
    """Return ASN, org, country for an IP. Returns empty dict on failure."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5,
            params={"fields": "status,country,countryCode,org,as"}
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "asn":          data.get("as", ""),
                "org":          data.get("org", ""),
            }
    except Exception as e:
        logger.debug(f"ASN lookup failed for {ip}: {e}")
    return {}


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

def _detect_type(value: str) -> str:
    """Detect IOC type if ingestor didn't already set one cleanly."""
    value = value.strip()
    # MD5 / SHA1 / SHA256
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "sha256"
    # CVE
    if re.fullmatch(r"CVE-\d{4}-\d+", value, re.IGNORECASE):
        return "cve"
    # URL
    if value.startswith(("http://", "https://", "ftp://")):
        return "url"
    # IP (v4 or v6)
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    # Domain fallback
    return "domain"


def _extract_ip_from_url(url: str) -> str | None:
    """If a URL's host is a bare IP, return it — useful for enrichment."""
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Fingerprint for deduplication
# ---------------------------------------------------------------------------

def _fingerprint(ioc_type: str, value: str) -> str:
    key = f"{ioc_type}:{value.strip().lower()}"
    return hashlib.sha256(key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# DB write
# ---------------------------------------------------------------------------

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _upsert_ioc(conn, record: dict) -> bool:
    """
    Insert IOC. If fingerprint already exists, append the new source tag
    and return False (duplicate). Returns True if new row inserted.
    """
    cur = conn.cursor()
    cur.execute("SELECT id, sources FROM iocs WHERE fingerprint = ?",
                (record["fingerprint"],))
    row = cur.fetchone()

    if row:
        # Merge source tags so we know it came from multiple feeds
        existing_sources = set(row["sources"].split(","))
        existing_sources.add(record["source"])
        cur.execute("UPDATE iocs SET sources = ? WHERE id = ?",
                    (",".join(sorted(existing_sources)), row["id"]))
        conn.commit()
        return False

    cur.execute("""
        INSERT INTO iocs
            (fingerprint, ioc_type, value, source, sources,
             tags, malware_family, country, country_code, asn, org,
             first_seen, last_seen, raw_context)
        VALUES
            (:fingerprint, :ioc_type, :value, :source, :source,
             :tags, :malware_family, :country, :country_code, :asn, :org,
             :first_seen, :last_seen, :raw_context)
    """, record)
    conn.commit()
    return True


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def normalize_and_store(raw_iocs: list[dict], enrich_ips: bool = True) -> dict:
    """
    Takes raw IOC dicts from any ingestor, normalizes, optionally enriches,
    deduplicates, and writes to DB.

    Returns a summary dict: {total, inserted, duplicates, errors}
    """
    conn = _get_conn()
    stats = {"total": len(raw_iocs), "inserted": 0, "duplicates": 0, "errors": 0}
    now = datetime.utcnow().isoformat()

    for raw in raw_iocs:
        try:
            value = raw.get("value", "").strip()
            if not value:
                stats["errors"] += 1
                continue

            ioc_type = raw.get("ioc_type") or _detect_type(value)

            # --- Enrichment ---
            country = country_code = asn = org = ""
            if enrich_ips:
                target_ip = None
                if ioc_type == "ip":
                    target_ip = value
                elif ioc_type == "url":
                    target_ip = _extract_ip_from_url(value)

                if target_ip:
                    geo = _enrich_ip(target_ip)
                    country      = geo.get("country", "")
                    country_code = geo.get("country_code", "")
                    asn          = geo.get("asn", "")
                    org          = geo.get("org", "")
                    time.sleep(0.08)   # stay under 45 req/min free tier

            record = {
                "fingerprint":    _fingerprint(ioc_type, value),
                "ioc_type":       ioc_type,
                "value":          value,
                "source":         raw.get("source", "unknown"),
                "tags":           raw.get("tags", ""),
                "malware_family": raw.get("malware_family", ""),
                "country":        country,
                "country_code":   country_code,
                "asn":            asn,
                "org":            org,
                "first_seen":     raw.get("first_seen", now),
                "last_seen":      now,
                "raw_context":    raw.get("raw_context", ""),
            }

            inserted = _upsert_ioc(conn, record)
            if inserted:
                stats["inserted"] += 1
            else:
                stats["duplicates"] += 1

        except Exception as e:
            logger.error(f"Normalizer error on {raw}: {e}")
            stats["errors"] += 1

    conn.close()
    logger.info(f"[Normalizer] {stats}")
    return stats