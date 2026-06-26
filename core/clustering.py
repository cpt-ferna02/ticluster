"""
Clustering engine — groups IOCs into probable threat actor campaigns
using TF-IDF vectorization + cosine similarity + DBSCAN.
"""
import sqlite3
import logging
import json
from datetime import datetime

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import normalize

logger = logging.getLogger(__name__)

DB_PATH = "data/ticluster.db"


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def _build_feature_string(row: dict) -> str:
    """
    Convert a raw IOC row into a text blob for TF-IDF.
    The model sees behavioral signals, not the raw IP/URL value.
    """
    parts = []

    # ASN / hosting provider — biggest signal for campaign attribution
    if row.get("asn"):
        # Normalize: "AS14061 DigitalOcean, LLC" -> "AS14061 digitalocean"
        asn_clean = row["asn"].lower().replace(",", "").replace(".", "")
        parts.append(f"asn_{asn_clean.replace(' ', '_')}")

    if row.get("org"):
        org_clean = row["org"].lower().replace(" ", "_").replace(",", "")
        parts.append(f"org_{org_clean}")

    # Country
    if row.get("country_code"):
        parts.append(f"country_{row['country_code'].lower()}")

    # IOC type
    if row.get("ioc_type"):
        parts.append(f"type_{row['ioc_type']}")

    # Malware family — strong campaign signal when present
    if row.get("malware_family"):
        for family in row["malware_family"].replace(",", " ").split():
            parts.append(f"family_{family.lower().strip()}")

    # Tags
    if row.get("tags"):
        for tag in row["tags"].replace(",", " ").split():
            parts.append(f"tag_{tag.lower().strip()}")

    # Source feed
    if row.get("sources"):
        for src in row["sources"].split(","):
            parts.append(f"source_{src.strip()}")

    # URL path patterns (strip domain, keep path structure)
    if row.get("ioc_type") == "url" and row.get("value"):
        try:
            from urllib.parse import urlparse
            path = urlparse(row["value"]).path
            # Grab directory depth and extension as signals
            depth = path.count("/")
            parts.append(f"url_depth_{min(depth, 5)}")
            if "." in path.split("/")[-1]:
                ext = path.split(".")[-1].lower()[:8]
                parts.append(f"url_ext_{ext}")
        except Exception:
            pass

    return " ".join(parts) if parts else "unknown"


# ---------------------------------------------------------------------------
# Load IOCs from DB
# ---------------------------------------------------------------------------

def _load_iocs() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT id, value, ioc_type, sources, tags, malware_family,
               country, country_code, asn, org
        FROM iocs
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Write clusters back to DB
# ---------------------------------------------------------------------------

def _save_clusters(clusters: dict[int, list[dict]]) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    campaign_count = 0

    for cluster_id, members in clusters.items():
        # Derive label from most common malware family or ASN
        families = [m["malware_family"] for m in members if m.get("malware_family")]
        asns     = [m["asn"] for m in members if m.get("asn")]
        countries = [m["country_code"] for m in members if m.get("country_code")]
        label = families[0] if families else (asns[0].split()[0] if asns else f"cluster_{cluster_id}")

        ioc_count   = len(members)
        source_set  = set()
        family_set  = set()
        for m in members:
            for s in (m.get("sources") or "").split(","):
                source_set.add(s.strip())
            if m.get("malware_family"):
                family_set.add(m["malware_family"].strip())

        primary_country = countries[0] if countries else ""
        primary_asn     = asns[0].split()[0] if asns else ""  # just "AS14061"

        cur.execute("""
            INSERT OR IGNORE INTO campaigns
                (name, confidence, ioc_count, first_seen, last_updated,
                 primary_country, primary_asn, malware_families, basis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Campaign-{cluster_id}: {label}",
            0.0,                               # scorer will fill this in Phase 3
            ioc_count,
            now,
            now,
            primary_country,
            primary_asn,
            ",".join(sorted(family_set)),
            f"{ioc_count} IOCs across {len(source_set)} feed(s): {', '.join(sorted(source_set))}",
        ))
        campaign_id = cur.lastrowid

        for member in members:
            cur.execute("UPDATE iocs SET campaign_id = ? WHERE id = ?",
                        (campaign_id, member["id"]))

        campaign_count += 1

    conn.commit()
    conn.close()
    return campaign_count


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_clustering(eps: float = 0.4, min_samples: int = 2) -> dict:
    """
    Load all IOCs, build feature vectors, run DBSCAN, save campaigns.

    eps         — DBSCAN neighborhood radius (lower = tighter clusters)
    min_samples — minimum IOCs to form a cluster (noise if below)

    Returns summary dict.
    """
    iocs = _load_iocs()
    if not iocs:
        logger.warning("[Clustering] No IOCs in DB.")
        return {"error": "no iocs"}

    # Build feature strings
    feature_strings = [_build_feature_string(row) for row in iocs]

    # TF-IDF vectorization
    vectorizer = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"[^\s]+",   # keep our prefixed tokens intact
        min_df=1,
    )
    X = vectorizer.fit_transform(feature_strings)
    X_normed = normalize(X)        # cosine similarity via dot product

    # DBSCAN
    db = DBSCAN(eps=eps, min_samples=min_samples, metric="cosine", n_jobs=-1)
    labels = db.fit_predict(X_normed)

    # Group results
    clusters: dict[int, list[dict]] = {}
    noise_count = 0

    for ioc, label in zip(iocs, labels):
        if label == -1:
            noise_count += 1
            continue
        clusters.setdefault(label, []).append(ioc)

    # Clear previous campaign assignments before writing new ones
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE iocs SET campaign_id = NULL")
    conn.execute("DELETE FROM campaigns")
    conn.commit()
    conn.close()

    campaign_count = _save_clusters(clusters)

    stats = {
        "iocs_processed": len(iocs),
        "campaigns_found": campaign_count,
        "noise_iocs": noise_count,
        "cluster_sizes": {f"Campaign-{k}": len(v) for k, v in clusters.items()},
    }
    logger.info(f"[Clustering] {stats}")
    return stats