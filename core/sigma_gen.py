"""
Sigma rule generator — produces YAML detection rules per campaign.
https://github.com/SigmaHQ/sigma
"""
import sqlite3
import logging
import re
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)

DB_PATH = "data/ticluster.db"


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")


def _get_campaign_iocs(cur, campaign_id: int) -> list[dict]:
    cur.execute("""
        SELECT value, ioc_type, asn, country_code, malware_family, sources
        FROM iocs WHERE campaign_id = ?
    """, (campaign_id,))
    return [dict(r) for r in cur.fetchall()]


def _top_values(items: list[str], n: int = 10) -> list[str]:
    return [v for v, _ in Counter(items).most_common(n) if v]


def _generate_rule(campaign: dict, members: list[dict]) -> str:
    name        = campaign["name"]
    confidence  = campaign.get("confidence") or 0.0
    slug        = _slugify(name)
    from datetime import timezone
    now = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    # Partition IOCs by type
    ips   = [m["value"] for m in members if m["ioc_type"] == "ip"]
    urls  = [m["value"] for m in members if m["ioc_type"] == "url"]
    hashes = [m["value"] for m in members
              if m["ioc_type"] in ("md5", "sha1", "sha256")]
    cves  = [m["value"] for m in members if m["ioc_type"] == "cve"]

    families = _top_values([m["malware_family"] for m in members if m.get("malware_family")])
    sources  = sorted(set(
        s.strip()
        for m in members
        for s in (m.get("sources") or "").split(",")
    ))
    countries = _top_values([m["country_code"] for m in members if m.get("country_code")])
    asns      = _top_values([m["asn"].split()[0] for m in members if m.get("asn")])

    # Confidence → Sigma level mapping
    if confidence >= 0.75:
        level = "high"
    elif confidence >= 0.55:
        level = "medium"
    else:
        level = "low"

    # Build detection block
    detection_lines = []

    if ips:
        detection_lines.append("        dst_ip|cidr:")
        for ip in _top_values(ips, 20):
            detection_lines.append(f"            - '{ip}/32'")

    if urls:
        detection_lines.append("        http_url|contains:")
        for url in _top_values(urls, 20):
            # Use path only to avoid FPs on unrelated domains
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path
                if path and path != "/":
                    detection_lines.append(f"            - '{path}'")
                else:
                    detection_lines.append(f"            - '{url}'")
            except Exception:
                detection_lines.append(f"            - '{url}'")

    if hashes:
        detection_lines.append("        file_hash|contains:")
        for h in _top_values(hashes, 20):
            detection_lines.append(f"            - '{h}'")

    if not detection_lines:
        # CVE-only or metadata-only cluster — generate a generic rule
        detection_lines = [
            "        keywords:",
            f"            - '{name}'",
        ]

    condition = "selection"

    tags_block = ""
    if cves:
        cve_tags = "\n".join(f"        - '{c}'" for c in cves[:5])
        tags_block = f"    cve:\n{cve_tags}\n"

    family_comment = ""
    if families:
        family_comment = f"# Malware families: {', '.join(families)}\n"

    rule = f"""title: TICluster - {name}
id: ticluster_{slug}
status: experimental
description: >
    Auto-generated detection rule from TICluster attribution engine.
    {len(members)} IOCs clustered from feeds: {', '.join(sources)}.
    Primary countries: {', '.join(countries[:3]) or 'unknown'}.
    Primary ASNs: {', '.join(asns[:3]) or 'unknown'}.
{family_comment}date: {now}
author: TICluster (auto-generated)
references:
    - https://github.com/your-handle/ticluster
tags:
    - attack.command_and_control
{tags_block}confidence: {confidence:.4f}
logsource:
    category: network
    product: zeek
detection:
    selection:
{chr(10).join(detection_lines)}
    condition: {condition}
falsepositives:
    - Unknown — review before deploying
level: {level}
"""
    return rule.strip()


def run_sigma_gen() -> dict:
    """Generate Sigma rules for all scored campaigns, store in DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id, name, confidence FROM campaigns ORDER BY confidence DESC")
    campaigns = [dict(r) for r in cur.fetchall()]

    generated = 0
    skipped   = 0

    for campaign in campaigns:
        members = _get_campaign_iocs(cur, campaign["id"])
        if not members:
            skipped += 1
            continue

        rule_yaml = _generate_rule(campaign, members)

        cur.execute("UPDATE campaigns SET sigma_rule = ? WHERE id = ?",
                    (rule_yaml, campaign["id"]))
        generated += 1

    conn.commit()
    conn.close()

    stats = {"generated": generated, "skipped": skipped}
    logger.info(f"[SigmaGen] {stats}")
    return stats


if __name__ == "__main__":
    stats = run_sigma_gen()
    print(f"Generated {stats['generated']} Sigma rules")

    # Print the highest-confidence rule as a sample
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT name, sigma_rule FROM campaigns ORDER BY confidence DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if row:
        print(f"\n--- Top Rule: {row['name']} ---\n")
        print(row["sigma_rule"])