"""
Open threat feeds — no API key required.
Sources: URLhaus CSV, Feodo alternate, Blocklist.de
"""
import requests
import csv
import io

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
BLOCKLIST_DE = "https://lists.blocklist.de/lists/all.txt"


def fetch_urlhaus_csv(limit=100):
    resp = requests.get(URLHAUS_CSV, timeout=15)
    resp.raise_for_status()

    results = []
    lines = [l for l in resp.text.splitlines() if not l.startswith("#") and l.strip()]

    # No header row in this CSV — assign column names manually
    HEADERS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]

    if lines:
        reader = csv.reader(lines)
        for i, row in enumerate(reader):
            if i >= limit:
                break
            row_dict = dict(zip(HEADERS, row))
            results.append({
                "value":          row_dict.get("url", "").strip('"'),
                "ioc_type":       "url",
                "source":         "urlhaus_csv",
                "tags":           row_dict.get("tags", "").strip('"'),
                "malware_family": row_dict.get("threat", "").strip('"'),
                "first_seen":     row_dict.get("dateadded", "").strip('"'),
                "raw_context":    str(row_dict),
            })
    return results


def fetch_blocklist_de(limit=200):
    """Blocklist.de — IPs reported for brute force, malware, etc."""
    resp = requests.get(BLOCKLIST_DE, timeout=15)
    resp.raise_for_status()

    results = []
    for line in resp.text.splitlines()[:limit]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append({
            "value":          line,
            "ioc_type":       "ip",
            "source":         "blocklist_de",
            "tags":           "brute-force,malicious",
            "malware_family": "",
            "first_seen":     "",
            "raw_context":    line,
        })
    return results


if __name__ == "__main__":
    print("Testing URLhaus CSV...")
    urls = fetch_urlhaus_csv(5)
    print(f"  Fetched {len(urls)} URLs")
    for ioc in urls:
        print(f"  {ioc['ioc_type']} | {ioc['value'][:60]}")

    print("\nTesting Blocklist.de...")
    ips = fetch_blocklist_de(5)
    print(f"  Fetched {len(ips)} IPs")
    for ioc in ips:
        print(f"  {ioc['ioc_type']} | {ioc['value']}")