"""AlienVault OTX — requires free API key from otx.alienvault.com"""
import requests, os, time
from dotenv import load_dotenv
load_dotenv()

OTX_KEY  = os.getenv("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS  = {"X-OTX-API-KEY": OTX_KEY}

TYPE_MAP = {
    "ipv4":            "ip",
    "ipv6":            "ip",
    "domain":          "domain",
    "hostname":        "domain",
    "url":             "url",
    "filehash-md5":    "hash",
    "filehash-sha1":   "hash",
    "filehash-sha256": "hash",
}


def fetch_otx_pulses(limit=10):
    if not OTX_KEY or OTX_KEY == "paste_your_otx_key_here":
        print("  OTX skipped — no API key in .env")
        return []

    resp = requests.get(
        f"{BASE_URL}/pulses/subscribed?limit={limit}",
        headers=HEADERS,
        timeout=15
    )
    resp.raise_for_status()
    pulses  = resp.json().get("results", [])
    results = []

    for pulse in pulses:
        tags   = ",".join(pulse.get("tags", []))
        family = ",".join(pulse.get("malware_families", []))
        for indicator in pulse.get("indicators", []):
            itype    = indicator.get("type", "").lower()
            ioc_type = TYPE_MAP.get(itype, itype)
            results.append({
                "value":          indicator.get("indicator", ""),
                "ioc_type":       ioc_type,
                "source":         "otx",
                "tags":           tags,
                "malware_family": family,
                "first_seen":     indicator.get("created", ""),
                "raw_context":    str(indicator),
            })
        time.sleep(0.3)

    return results


if __name__ == "__main__":
    if not OTX_KEY or OTX_KEY == "paste_your_otx_key_here":
        print("❌ Add your OTX_API_KEY to .env first")
    else:
        iocs = fetch_otx_pulses(3)
        print(f"Fetched {len(iocs)} IOCs from OTX")
        for ioc in iocs[:5]:
            print(f"  {ioc['ioc_type']} | {ioc['value'][:60]}")