"""
Scorer — computes a confidence float (0.0–1.0) per campaign based on
four weighted signals: IOC volume, source diversity, ASN concentration,
and malware family consistency.
"""
import sqlite3
import logging
from collections import Counter

logger = logging.getLogger(__name__)

DB_PATH = "data/ticluster.db"

# Signal weights — must sum to 1.0
W_VOLUME    = 0.25   # more IOCs = more confidence
W_SOURCES   = 0.25   # seen in multiple feeds = more confidence
W_ASN       = 0.30   # tight ASN concentration = strong infrastructure signal
W_FAMILY    = 0.20   # consistent malware family = strongest attribution signal


def _score_volume(ioc_count: int) -> float:
    """Logarithmic scale: 2 IOCs → ~0.15, 10 → ~0.5, 50+ → ~1.0"""
    import math
    return min(1.0, math.log(ioc_count + 1) / math.log(51))


def _score_sources(sources_str: str) -> float:
    """1 feed → 0.3, 2 feeds → 0.65, 3+ feeds → 1.0"""
    if not sources_str:
        return 0.0
    feeds = set(s.strip() for s in sources_str.split(",") if s.strip())
    return min(1.0, len(feeds) * 0.33)


def _score_asn_concentration(asns: list[str]) -> float:
    """What fraction of IOCs share the top ASN."""
    if not asns:
        return 0.0
    top_count = Counter(asns).most_common(1)[0][1]
    return top_count / len(asns)


def _score_family_consistency(families: list[str]) -> float:
    """
    1.0 if all IOCs share the same family,
    0.5 if mixed but present,
    0.0 if no family data.
    """
    non_empty = [f for f in families if f and f.lower() not in ("", "none", "malware_download")]
    if not non_empty:
        return 0.0
    top_count = Counter(non_empty).most_common(1)[0][1]
    consistency = top_count / len(non_empty)
    return consistency * (len(non_empty) / len(families))  # penalise sparse data


def score_campaign(campaign_id: int, members: list[dict]) -> float:
    """Compute and return confidence score for one campaign."""
    ioc_count   = len(members)
    sources_str = ",".join(set(
        s.strip()
        for m in members
        for s in (m.get("sources") or "").split(",")
    ))
    asns     = [m.get("asn", "") for m in members]
    families = [m.get("malware_family", "") for m in members]

    score = (
        W_VOLUME  * _score_volume(ioc_count) +
        W_SOURCES * _score_sources(sources_str) +
        W_ASN     * _score_asn_concentration(asns) +
        W_FAMILY  * _score_family_consistency(families)
    )
    return round(min(1.0, score), 4)


def run_scorer() -> dict:
    """Score all campaigns and write confidence back to DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id, name FROM campaigns")
    campaigns = [dict(r) for r in cur.fetchall()]

    results = {}
    for campaign in campaigns:
        cid = campaign["id"]
        cur.execute("""
            SELECT sources, asn, malware_family
            FROM iocs WHERE campaign_id = ?
        """, (cid,))
        members = [dict(r) for r in cur.fetchall()]

        if not members:
            continue

        confidence = score_campaign(cid, members)
        cur.execute("UPDATE campaigns SET confidence = ? WHERE id = ?",
                    (confidence, cid))
        results[campaign["name"]] = confidence

    conn.commit()
    conn.close()

    logger.info(f"[Scorer] Scored {len(results)} campaigns")
    return results


if __name__ == "__main__":
    scores = run_scorer()
    for name, score in sorted(scores.items(), key=lambda x: -x[1]):
        bar = "█" * int(score * 20)
        print(f"{score:.4f} {bar:<20} {name}")