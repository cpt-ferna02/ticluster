#!/usr/bin/env python3
"""
TICluster pipeline — runs the full chain:
  ingest → normalize → cluster → score → generate Sigma rules
"""
import logging
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline")


def banner(msg: str):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def run():
    start = time.time()

    # ------------------------------------------------------------------
    # Phase 1 — Ingest
    # ------------------------------------------------------------------
    banner("Phase 1 — Ingestion")

    from core.ingestion.feodo     import fetch_feodo
    from core.ingestion.abusech   import fetch_urlhaus_csv, fetch_blocklist_de
    from core.ingestion.cisa_kev  import fetch_cisa_kev

    raw_iocs = []

    sources = [
        ("Feodo",        lambda: fetch_feodo(limit=100)),
        ("URLhaus",      lambda: fetch_urlhaus_csv(limit=100)),
        ("Blocklist.de", lambda: fetch_blocklist_de(limit=200)),
        ("CISA KEV",     lambda: fetch_cisa_kev(limit=100)),
    ]

    for name, fn in sources:
        try:
            result = fn()
            raw_iocs += result
            print(f"  ✅ {name:<15} {len(result):>4} IOCs")
        except Exception as e:
            print(f"  ❌ {name:<15} failed: {e}")

    print(f"\n  Total raw IOCs: {len(raw_iocs)}")

    # ------------------------------------------------------------------
    # Phase 2 — Normalize
    # ------------------------------------------------------------------
    banner("Phase 2 — Normalize & Enrich")

    from core.normalizer import normalize_and_store
    stats = normalize_and_store(raw_iocs, enrich_ips=True)
    print(f"  Inserted:    {stats['inserted']}")
    print(f"  Duplicates:  {stats['duplicates']}")
    print(f"  Errors:      {stats['errors']}")

    # ------------------------------------------------------------------
    # Phase 3 — Cluster
    # ------------------------------------------------------------------
    banner("Phase 3 — ML Clustering")

    from core.clustering import run_clustering
    cluster_stats = run_clustering(eps=0.4, min_samples=2)
    print(f"  IOCs processed:   {cluster_stats['iocs_processed']}")
    print(f"  Campaigns found:  {cluster_stats['campaigns_found']}")
    print(f"  Noise IOCs:       {cluster_stats['noise_iocs']}")

    # ------------------------------------------------------------------
    # Phase 4 — Score
    # ------------------------------------------------------------------
    banner("Phase 4 — Confidence Scoring")

    from core.scorer import run_scorer
    scores = run_scorer()
    for name, score in sorted(scores.items(), key=lambda x: -x[1])[:5]:
        bar = "█" * int(score * 20)
        print(f"  {score:.4f} {bar:<20} {name}")
    if len(scores) > 5:
        print(f"  ... and {len(scores) - 5} more campaigns")

    # ------------------------------------------------------------------
    # Phase 5 — Sigma rules
    # ------------------------------------------------------------------
    banner("Phase 5 — Sigma Rule Generation")

    from core.sigma_gen import run_sigma_gen
    sigma_stats = run_sigma_gen()
    print(f"  Rules generated: {sigma_stats['generated']}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    elapsed = time.time() - start
    banner(f"Pipeline complete in {elapsed:.1f}s")
    print(f"  Raw IOCs ingested:   {len(raw_iocs)}")
    print(f"  Clean IOCs in DB:    {stats['inserted'] + stats['duplicates']}")
    print(f"  Campaigns:           {cluster_stats['campaigns_found']}")
    print(f"  Sigma rules:         {sigma_stats['generated']}")
    print(f"  Top campaign:        {max(scores, key=scores.get)}")
    print()


if __name__ == "__main__":
    run()