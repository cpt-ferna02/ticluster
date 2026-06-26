"""Feodo Tracker — botnet C2 IPs. No API key needed."""
import requests

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch_feodo(limit=200):
    resp = requests.get(FEODO_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    # API returns either a list directly or {"blocklist": [...]}
    if isinstance(data, list):
        blocklist = data
    else:
        blocklist = data.get("blocklist", [])

    results = []
    for entry in blocklist[:limit]:
        results.append({
            "value":          entry.get("ip_address", ""),
            "ioc_type":       "ip",
            "source":         "feodo",
            "port":           entry.get("port"),
            "malware_family": entry.get("malware", ""),
            "country":        entry.get("country", ""),
            "first_seen":     entry.get("first_seen", ""),
            "tags":           "c2,botnet",
            "raw_context":    str(entry),
        })
    return results


if __name__ == "__main__":
    print("Testing Feodo Tracker...")
    ips = fetch_feodo(5)
    for ioc in ips:
        print(f"  {ioc['ioc_type']} | {ioc['value']} | {ioc['malware_family']} | {ioc['country']}")