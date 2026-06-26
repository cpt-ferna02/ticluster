"""CISA Known Exploited Vulnerabilities — free JSON feed, no key needed."""
import requests

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev(limit=100):
    resp = requests.get(CISA_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    results = []
    for entry in data.get("vulnerabilities", [])[:limit]:
        results.append({
            "value":          entry.get("cveID", ""),
            "ioc_type":       "cve",
            "source":         "cisa_kev",
            "tags":           "exploited-in-wild",
            "malware_family": entry.get("product", ""),
            "first_seen":     entry.get("dateAdded", ""),
            "raw_context":    str(entry),
        })
    return results


if __name__ == "__main__":
    print("Testing CISA KEV...")
    cves = fetch_cisa_kev(5)
    for ioc in cves:
        print(f"  {ioc['ioc_type']} | {ioc['value']} | {ioc['malware_family']}")