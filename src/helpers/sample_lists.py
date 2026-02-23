#!/usr/bin/env python3
"""
Extract sample extension lists for manual evaluation datasets D1 and D2.

D1 (failed verifications, RQ2):
    For each category: first 4 extensions (alphabetical) where
    status == "failed" and at least one vulnerability has
    verification_status == "no_detection".
    Pick the first such vulnerability per extension.

D2 (verified, RQ1):
    For each category: first 4 extensions (alphabetical) where
    status == "verified" and at least one vulnerability has
    verification_status == "verified".
    Pick the first such vulnerability per extension.
"""

import json
from pathlib import Path

VERIF_BASE = (
    Path(__file__).parent.parent
    / "results_verification"
)
RUN = "results_gemini_2026-02-18_02-09-50"

# folder_name -> list of vulnerability_category values to match
CATEGORY_FOLDERS = {
    "code_execution":   ["code_execution"],
    "data_exfiltration":["data_exfiltration"],
    "download":         ["download"],
    "request":          ["1way_request", "2way_request"],
    "storage":          ["storage"],
}

N = 4  # samples per category


def scan(folder: Path, status_filter: str, vuln_status_filter: str,
         cat_filter: list[str]) -> list[dict]:
    """Return first N matching entries from folder, sorted alphabetically."""
    results = []
    for f in sorted(folder.glob("*_verification.json")):
        if len(results) >= N:
            break
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("status") != status_filter:
            continue
        for v in data.get("vulnerabilities_verified", []):
            if v.get("verification_status") == vuln_status_filter:
                cat = v.get("vulnerability_category", "")
                if cat not in cat_filter:
                    continue
                results.append({
                    "ext_id":   data["extension_id"],
                    "category": cat,
                    "rule_id":  v.get("rule_id", ""),
                    "attacker_source": v.get("attacker_source", ""),
                    "specific_domain": (v.get("verification_details") or {}).get("specific_domain"),
                    "verification_status": v.get("verification_status"),
                    "error": v.get("error"),
                })
                break  # only first matching vuln per extension
    return results


def print_table(title: str, rows: list[dict], extra_cols: list[str] = None) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")
    cols = ["ext_id", "category", "rule_id", "attacker_source", "specific_domain"]
    if extra_cols:
        cols += extra_cols
    for r in rows:
        print(f"  ext:      {r['ext_id']}")
        print(f"  cat:      {r['category']}")
        print(f"  rule:     {r['rule_id']}")
        print(f"  attacker: {r['attacker_source']}")
        print(f"  domain:   {r.get('specific_domain')}")
        if extra_cols:
            for c in extra_cols:
                print(f"  {c}: {r.get(c)}")
        print()


def main() -> None:
    d1_all: list[dict] = []
    d2_all: list[dict] = []

    for folder_name, cats in CATEGORY_FOLDERS.items():
        folder = VERIF_BASE / f"{RUN}_{folder_name}" / "codeql_2026_final"
        if not folder.exists():
            print(f"WARNING: folder not found: {folder}")
            continue

        # For request folder, split per sub-category
        sub_cats = cats if len(cats) == 1 else cats

        for cat in sub_cats:
            cat_filter = [cat]

            d1 = scan(folder, "failed", "no_detection", cat_filter)
            d2 = scan(folder, "verified", "verified", cat_filter)

            if not d1:
                print(f"WARNING D1: no results for category '{cat}' in {folder_name}")
            if not d2:
                print(f"WARNING D2: no results for category '{cat}' in {folder_name}")

            d1_all.extend(d1)
            d2_all.extend(d2)

    print("\n" + "=" * 70)
    print("  DATASET 1 — Failed verifications (Analyzer=TP, Verifier=no_detection)")
    print("  For RQ2: why did verification fail?")
    print("=" * 70)
    print(f"  {'#':<3} {'category':<20} {'ext_id':<36} {'attacker':<10} {'domain'}")
    print("  " + "-" * 100)
    for i, r in enumerate(d1_all, 1):
        dom = r["specific_domain"] or "-"
        print(f"  {i:<3} {r['category']:<20} {r['ext_id']:<36} {r['attacker_source']:<10} {dom}")
    print()
    print(f"  {'#':<3} {'rule_id'}")
    print("  " + "-" * 80)
    for i, r in enumerate(d1_all, 1):
        print(f"  {i:<3} {r['rule_id']}")

    print("\n" + "=" * 70)
    print("  DATASET 2 — Verified (status=verified)")
    print("  For RQ1: are verified results really TP?")
    print("=" * 70)
    print(f"  {'#':<3} {'category':<20} {'ext_id':<36} {'attacker':<10} {'domain'}")
    print("  " + "-" * 100)
    for i, r in enumerate(d2_all, 1):
        dom = r["specific_domain"] or "-"
        print(f"  {i:<3} {r['category']:<20} {r['ext_id']:<36} {r['attacker_source']:<10} {dom}")
    print()
    print(f"  {'#':<3} {'rule_id'}")
    print("  " + "-" * 80)
    for i, r in enumerate(d2_all, 1):
        print(f"  {i:<3} {r['rule_id']}")


if __name__ == "__main__":
    main()
