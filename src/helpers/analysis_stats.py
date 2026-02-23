#!/usr/bin/env python3
"""
Statistics over a completed analysis run.

Usage:
    python analysis_stats.py
    python analysis_stats.py <results_dir> <dataset_dir>

Outputs two breakdowns, both summing to the dataset total:

1. Extensions breakdown:
  - Skipped (token limit exceeded)
  - Parse errors (result JSON malformed)
  - Error field (LLM could not build payload due to insufficient context)
  - Empty vulnerabilities array
  - Only FPs (no TP)
  - At least one TP
    - of which: verifier will skip (>5 TPs)
    - of which: verifier will verify (1-5 TPs)

2. CodeQL results breakdown:
  - From skipped extensions
  - From extensions with parse errors
  - From extensions with LLM error field
  - From extensions with empty vulnerabilities[]
  - Grouped/deduplicated (multiple same-rule results merged into one vuln entry)
  - Classified as TP
  - Classified as FP
"""

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# Defaults – adjust to point at the desired run
DEFAULT_RESULTS_DIR = (
    Path(__file__).parent.parent
    / "results_analysis"
    / "results_gemini_2026-02-18_02-09-50"
    / "codeql_2026_final"
)
DEFAULT_DATASET_DIR = (
    Path(__file__).parent.parent / "datasets" / "codeql_2026_final"
)

VERIFIER_MAX_VULNERABILITIES = 5  # matches VERIFIER_FILTER["max_vulnerabilities"] in config.py


def normalize_domain(raw: str) -> str:
    """Normalise a URL or hostname to its base domain (eTLD+1 heuristic)."""
    if not raw:
        return ""
    raw = raw.strip()
    if raw.startswith("*."):
        raw = raw[2:]
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urlparse(raw).hostname or ""
    except Exception:
        return ""
    if not host:
        return ""
    if "localhost" in host:
        return "localhost"
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def load_skipped_ids(log_file: Path) -> set[str]:
    skipped: set[str] = set()
    if not log_file.exists():
        return skipped
    for line in log_file.read_text(encoding="utf-8").splitlines():
        m = re.search(r"SKIPPED: (\w+) - Tokens:", line)
        if m:
            skipped.add(m.group(1))
    return skipped


def classify_results(results_dir: Path) -> tuple[dict[str, set], list]:
    groups: dict[str, set] = {
        "parse_error": set(),
        "error_field": set(),
        "empty_vulns": set(),
        "only_fp": set(),
        "has_tp": set(),
    }

    for f in results_dir.glob("*_result.json"):
        ext_id = f.stem.replace("_result", "")
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            data = json.loads(text)
            vulns = data.get("vulnerabilities", [])
            results = [v.get("result", "").strip().upper() for v in vulns]
            if "TP" in results:
                groups["has_tp"].add(ext_id)
            elif "error" in data:
                groups["error_field"].add(ext_id)
            elif vulns == []:
                groups["empty_vulns"].add(ext_id)
            elif "FP" in results:
                groups["only_fp"].add(ext_id)
            else:
                groups["only_fp"].add(ext_id)  # unknown result values → treat as no TP
        except Exception:
            groups["parse_error"].add(ext_id)

    return groups


def codeql_results_breakdown(
    results_dir: Path,
    dataset_dir: Path,
    skipped_ids: set[str],
    groups: dict[str, set],
) -> dict[str, int]:
    """Break down all CodeQL results from the dataset by analyzer outcome."""
    dataset_counts = {
        p.stem: len(json.loads(p.read_text(encoding="utf-8")).get("results", []))
        for p in dataset_dir.glob("*.json")
    }

    def dataset_sum(ids: set) -> int:
        return sum(dataset_counts.get(i, 0) for i in ids)

    tp_count = fp_count = grouped = 0
    for f in results_dir.glob("*_result.json"):
        ext_id = f.stem.replace("_result", "")
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            data = json.loads(text)
            vulns = data.get("vulnerabilities", [])
            results = [v.get("result", "").strip().upper() for v in vulns]
            if "TP" in results or "FP" in results:
                tp_count += results.count("TP")
                fp_count += results.count("FP")
                grouped += dataset_counts.get(ext_id, 0) - len(vulns)
        except Exception:
            pass

    return {
        "skipped":     dataset_sum(skipped_ids),
        "parse_error": dataset_sum(groups["parse_error"]),
        "error_field": dataset_sum(groups["error_field"]),
        "empty_vulns": dataset_sum(groups["empty_vulns"]),
        "grouped":     grouped,
        "tp":          tp_count,
        "fp":          fp_count,
    }


def count_verifier_scope(results_dir: Path) -> tuple[int, int, int, int]:
    """Among extensions with >=1 TP, split into verified vs. skipped by verifier.

    Returns:
        (ext_verify, ext_skip, tp_verify, tp_skip)
        ext_*: number of extensions
        tp_*:  number of individual TP vulnerability entries
    """
    ext_verify = ext_skip = tp_verify = tp_skip = 0
    for f in results_dir.glob("*_result.json"):
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            data = json.loads(text)
            tp_count = sum(
                1 for v in data.get("vulnerabilities", [])
                if v.get("result", "").strip().upper() == "TP"
            )
            if tp_count == 0:
                continue
            if tp_count > VERIFIER_MAX_VULNERABILITIES:
                ext_skip += 1
                tp_skip += tp_count
            else:
                ext_verify += 1
                tp_verify += tp_count
        except Exception:
            pass
    return ext_verify, ext_skip, tp_verify, tp_skip


ORDERED_CATS = [
    "1way_request", "2way_request", "data_exfiltration",
    "download", "code_execution", "storage",
]
SHORT_CAT = {
    "1way_request":     "1way_req",
    "2way_request":     "2way_req",
    "data_exfiltration": "data_exfil",
    "download":         "download",
    "code_execution":   "code_exec",
    "storage":          "storage",
}


def vuln_category_breakdown(results_dir: Path) -> dict[str, dict]:
    """Per recognised category: tp, fp, tp_website, tp_extension, tp_has_domain, tp_no_domain.

    Entries with unknown/malformed vulnerability_category are counted separately
    and excluded from the per-category rows.
    """
    data: dict[str, dict] = {
        c: {"tp": 0, "fp": 0, "tp_website": 0, "tp_extension": 0,
            "tp_has_domain": 0, "tp_no_domain": 0}
        for c in ORDERED_CATS
    }
    anomalies: dict[str, int] = {}

    for f in results_dir.glob("*_result.json"):
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            for v in json.loads(text).get("vulnerabilities", []):
                result = v.get("result", "").strip().upper()
                if result not in ("TP", "FP"):
                    continue
                cat = v.get("vulnerability_category") or ""
                if cat not in ORDERED_CATS:
                    key = f"category={cat!r}, result={result}"
                    anomalies[key] = anomalies.get(key, 0) + 1
                    continue
                d = data[cat]
                if result == "TP":
                    d["tp"] += 1
                    src = (v.get("attacker_source") or "").strip().lower()
                    if src == "website":
                        d["tp_website"] += 1
                    else:
                        d["tp_extension"] += 1
                    has_domain = bool((v.get("verification_details") or {}).get("specific_domain"))
                    if has_domain:
                        d["tp_has_domain"] += 1
                    else:
                        d["tp_no_domain"] += 1
                else:
                    d["fp"] += 1
        except Exception:
            pass

    return {"data": data, "anomalies": anomalies}


def ext_category_breakdown(results_dir: Path) -> dict:
    """Extension-level statistics per vulnerability category.

    For each extension, tracks per-category TP/FP counts, attacker source, and domain flag.
    Aggregates to per-category extension counts; each TP extension is assigned to the
    attacker-source / domain group that accounts for the majority of its TPs in that category.

    Returns:
        cat_agg:          per-category dict with ext_tp, ext_fp_only, ext_tp_website,
                          ext_tp_extension, ext_tp_has_domain, ext_tp_no_domain,
                          total_vulns, ext_count
        global_tp_ext:    extensions with >= 1 TP in any valid category
        global_fp_only_ext: extensions with no TP but >= 1 FP in valid categories
        global_total_ext: sum of above two
        domain_ext_counts: domain -> number of unique extensions with >= 1 TP there
    """
    ext_data: dict[str, dict] = {}
    domain_to_exts: dict[str, set] = {}

    for f in results_dir.glob("*_result.json"):
        ext_id = f.stem.replace("_result", "")
        per_cat: dict = {}
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            for v in json.loads(text).get("vulnerabilities", []):
                result = v.get("result", "").strip().upper()
                if result not in ("TP", "FP"):
                    continue
                cat = v.get("vulnerability_category") or ""
                if cat not in ORDERED_CATS:
                    continue
                if cat not in per_cat:
                    per_cat[cat] = {"tp": 0, "fp": 0, "website": 0, "ext_atk": 0,
                                    "has_domain": 0, "no_domain": 0}
                d = per_cat[cat]
                if result == "TP":
                    d["tp"] += 1
                    if (v.get("attacker_source") or "").strip().lower() == "website":
                        d["website"] += 1
                    else:
                        d["ext_atk"] += 1
                    raw_dom = ((v.get("verification_details") or {}).get("specific_domain") or "")
                    if raw_dom:
                        d["has_domain"] += 1
                        dom = normalize_domain(raw_dom)
                        if dom:
                            domain_to_exts.setdefault(dom, set()).add(ext_id)
                    else:
                        d["no_domain"] += 1
                else:
                    d["fp"] += 1
        except Exception:
            pass
        if per_cat:
            ext_data[ext_id] = per_cat

    cat_agg: dict = {
        c: {"ext_tp": 0, "ext_fp_only": 0,
            "ext_tp_website": 0, "ext_tp_extension": 0,
            "ext_tp_has_domain": 0, "ext_tp_no_domain": 0,
            "total_vulns": 0, "ext_count": 0}
        for c in ORDERED_CATS
    }
    global_tp_exts: set = set()
    global_fp_only_exts: set = set()

    for ext_id, per_cat in ext_data.items():
        has_any_tp = any(d["tp"] > 0 for d in per_cat.values())
        if has_any_tp:
            global_tp_exts.add(ext_id)
        else:
            global_fp_only_exts.add(ext_id)

        for cat, d in per_cat.items():
            total = d["tp"] + d["fp"]
            if total == 0:
                continue
            a = cat_agg[cat]
            a["total_vulns"] += total
            a["ext_count"] += 1
            if d["tp"] > 0:
                a["ext_tp"] += 1
                a["ext_tp_website" if d["website"] >= d["ext_atk"] else "ext_tp_extension"] += 1
                a["ext_tp_has_domain" if d["has_domain"] >= d["no_domain"] else "ext_tp_no_domain"] += 1
            else:
                a["ext_fp_only"] += 1

    return {
        "cat_agg": cat_agg,
        "global_tp_ext": len(global_tp_exts),
        "global_fp_only_ext": len(global_fp_only_exts),
        "global_total_ext": len(global_tp_exts) + len(global_fp_only_exts),
        "domain_ext_counts": {d: len(s) for d, s in domain_to_exts.items()},
    }


def print_category_table(breakdown: dict) -> None:
    data: dict = breakdown["data"]
    anomalies: dict = breakdown["anomalies"]

    col_w = 10
    lbl_w = 12

    header = (f"  {'Category':<{lbl_w}} | {'TP':>{col_w}} | {'FP':>{col_w}} |"
              f" {'TP Website':>{col_w}} | {'TP Ext.':>{col_w}} |"
              f" {'TP w/ dom.':>{col_w}} | {'TP w/o dom.':>{col_w+1}}")
    sep = "  " + "-" * lbl_w + "-+-" + ("-" * col_w + "-+-") * 5 + "-" * (col_w + 1)

    print()
    print("=" * len(header))
    print("  VULNERABILITY CATEGORY BREAKDOWN")
    print("=" * len(header))
    print(header)
    print(sep)

    total_tp = total_fp = 0
    for cat in ORDERED_CATS:
        d = data[cat]
        total_tp += d["tp"]
        total_fp += d["fp"]
        print(f"  {SHORT_CAT[cat]:<{lbl_w}} |"
              f" {d['tp']:>{col_w},} | {d['fp']:>{col_w},} |"
              f" {d['tp_website']:>{col_w},} | {d['tp_extension']:>{col_w},} |"
              f" {d['tp_has_domain']:>{col_w},} | {d['tp_no_domain']:>{col_w+1},}")

    print(sep)
    print(f"  {'Total':<{lbl_w}} | {total_tp:>{col_w},} | {total_fp:>{col_w},}")
    print(f"\n  Grand total (TP+FP): {total_tp + total_fp:,}")

    if anomalies:
        print("\n  Data-quality anomalies (excluded above):")
        for key, count in sorted(anomalies.items()):
            print(f"    {key}: {count} entries")


def write_category_csv(breakdown: dict, csv_path: Path) -> None:
    """Write per-category data to a CSV file for use in LaTeX pgfplots charts."""
    data = breakdown["data"]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        f.write("category,tp,fp,tp_website,tp_extension,tp_has_domain,tp_no_domain\n")
        for cat in ORDERED_CATS:
            d = data[cat]
            f.write(f"{SHORT_CAT[cat]},"
                    f"{d['tp']},{d['fp']},"
                    f"{d['tp_website']},{d['tp_extension']},"
                    f"{d['tp_has_domain']},{d['tp_no_domain']}\n")
    print(f"\n  CSV written to: {csv_path}")


def write_ext_category_csv(ext_breakdown: dict, csv_path: Path) -> None:
    """Write per-category extension-level data to CSV for LaTeX pgfplots."""
    cat_agg = ext_breakdown["cat_agg"]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        f.write("category,ext_tp,ext_fp_only,ext_tp_website,ext_tp_extension,"
                "ext_tp_has_domain,ext_tp_no_domain\n")
        for cat in ORDERED_CATS:
            a = cat_agg[cat]
            f.write(f"{SHORT_CAT[cat]},"
                    f"{a['ext_tp']},{a['ext_fp_only']},"
                    f"{a['ext_tp_website']},{a['ext_tp_extension']},"
                    f"{a['ext_tp_has_domain']},{a['ext_tp_no_domain']}\n")
    print(f"\n  Ext-category CSV written to: {csv_path}")


def write_avg_vulns_csv(ext_breakdown: dict, csv_path: Path) -> None:
    """Write average vulnerabilities per extension per category to CSV."""
    cat_agg = ext_breakdown["cat_agg"]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        f.write("category,total_vulns,ext_count,avg_vulns\n")
        for cat in ORDERED_CATS:
            a = cat_agg[cat]
            n = a["ext_count"]
            avg = a["total_vulns"] / n if n > 0 else 0.0
            f.write(f"{SHORT_CAT[cat]},{a['total_vulns']},{n},{avg:.2f}\n")
    print(f"\n  Avg-vulns CSV written to: {csv_path}")


def storage_api_breakdown(results_dir: Path) -> dict[str, int]:
    """Count verification_details.storage_api values for TP vulnerabilities
    in the 'storage' and 'data_exfiltration' categories."""
    counts: dict[str, int] = {}
    for f in results_dir.glob("*_result.json"):
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            for v in json.loads(text).get("vulnerabilities", []):
                if v.get("result", "").strip().upper() != "TP":
                    continue
                if v.get("vulnerability_category") not in ("storage", "data_exfiltration"):
                    continue
                api = (v.get("verification_details") or {}).get("storage_api")
                if api:
                    counts[api] = counts.get(api, 0) + 1
        except Exception:
            pass
    return counts


def domain_restriction_source_counts(results_dir: Path) -> dict[str, int]:
    """Count domain_restriction_source values among TP vulns that have a specific domain."""
    counts: dict[str, int] = {"manifest": 0, "code": 0, "both": 0, "unknown": 0}
    for f in results_dir.glob("*_result.json"):
        try:
            text = f.read_text(encoding="utf-8").strip()
            if text.startswith("```"):
                lines = text.splitlines()
                text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
            for v in json.loads(text).get("vulnerabilities", []):
                if v.get("result", "").strip().upper() != "TP":
                    continue
                vd = v.get("verification_details") or {}
                if not vd.get("specific_domain"):
                    continue
                src = (vd.get("domain_restriction_source") or "").strip().lower()
                if src in counts:
                    counts[src] += 1
                else:
                    counts["unknown"] += 1
        except Exception:
            pass
    return counts


def write_domain_restriction_source_csv(counts: dict, csv_path: Path) -> None:
    """Write domain_restriction_source distribution to CSV."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        f.write("source,count\n")
        for src in ("manifest", "code", "both"):
            f.write(f"{src},{counts[src]}\n")
    print(f"\n  Domain-restriction-source CSV written to: {csv_path}")


def write_ext_domain_top10_csv(ext_breakdown: dict, csv_path: Path, n: int = 10) -> None:
    """Write top-N specific domains by extension count to CSV."""
    counts = ext_breakdown["domain_ext_counts"]
    ranked = sorted(counts.items(), key=lambda x: -x[1])
    top = ranked[:n]
    others = sum(c for _, c in ranked[n:])
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        f.write("domain,count\n")
        for dom, cnt in top:
            f.write(f"{dom},{cnt}\n")
        f.write(f"Other,{others}\n")
    print(f"\n  Ext-domain top-{n} CSV written to: {csv_path}")


def print_stats(results_dir: Path, dataset_dir: Path) -> None:
    dataset_ids = {p.stem for p in dataset_dir.glob("*.json")}
    skipped_ids = load_skipped_ids(results_dir / "log.txt")
    groups = classify_results(results_dir)
    ext_verify, ext_skip_verifier, tp_verify, tp_skip_verifier = count_verifier_scope(results_dir)
    codeql = codeql_results_breakdown(results_dir, dataset_dir, skipped_ids, groups)

    n_dataset     = len(dataset_ids)
    n_skipped     = len(skipped_ids)
    n_parse_err   = len(groups["parse_error"])
    n_error_field = len(groups["error_field"])
    n_empty       = len(groups["empty_vulns"])
    n_only_fp     = len(groups["only_fp"])
    n_has_tp      = len(groups["has_tp"])
    n_sum         = n_skipped + n_parse_err + n_error_field + n_empty + n_only_fp + n_has_tp

    def pct(n): return f"{n / n_dataset * 100:.1f}%"
    def pct_tp(n): return f"{n / n_has_tp * 100:.1f}%" if n_has_tp else "n/a"

    print("=" * 62)
    print("  ANALYSIS RUN - EXTENSION COVERAGE STATISTICS")
    print("=" * 62)
    print(f"  Dataset total:                        {n_dataset:>5}")
    print()
    print(f"  Skipped - token limit exceeded:       {n_skipped:>5}  ({pct(n_skipped)})")
    print(f"  Parse error - malformed result JSON:  {n_parse_err:>5}  ({pct(n_parse_err)})")
    print(f"  LLM error - insufficient context:     {n_error_field:>5}  ({pct(n_error_field)})")
    print(f"  LLM error - empty vulnerabilities[]:  {n_empty:>5}  ({pct(n_empty)})")
    print(f"  All FP - no true positive found:      {n_only_fp:>5}  ({pct(n_only_fp)})")
    print(f"  >= 1 TP:                              {n_has_tp:>5}  ({pct(n_has_tp)})")
    print(f"    of which verifier will verify:      {ext_verify:>5}  ({pct_tp(ext_verify)} of TP set)")
    print(f"    of which verifier will skip (>5):   {ext_skip_verifier:>5}  ({pct_tp(ext_skip_verifier)} of TP set)")
    print()
    print(f"  Sum of all groups:                    {n_sum:>5}  (should equal dataset total)")

    if n_sum != n_dataset:
        print(f"\n  WARNING: sum ({n_sum}) != dataset total ({n_dataset})!")
    else:
        print(f"  Check: {n_sum} == {n_dataset} OK")

    # --- CodeQL results breakdown ---
    n_codeql_total = sum(codeql.values())
    def pct_cq(n): return f"{n / n_codeql_total * 100:.1f}%" if n_codeql_total else "n/a"

    print()
    print("=" * 62)
    print("  CODEQL RESULTS BREAKDOWN")
    print("=" * 62)
    print(f"  Total CodeQL results in dataset:      {n_codeql_total:>6}")
    print()
    print(f"  From skipped extensions:              {codeql['skipped']:>6}  ({pct_cq(codeql['skipped'])})")
    print(f"  From parse-error extensions:          {codeql['parse_error']:>6}  ({pct_cq(codeql['parse_error'])})")
    print(f"  From LLM error-field extensions:      {codeql['error_field']:>6}  ({pct_cq(codeql['error_field'])})")
    print(f"  From empty vulnerabilities[]:         {codeql['empty_vulns']:>6}  ({pct_cq(codeql['empty_vulns'])})")
    print(f"  Grouped/deduplicated (same rule_id):  {codeql['grouped']:>6}  ({pct_cq(codeql['grouped'])})")
    print(f"  Classified as TP:                     {codeql['tp']:>6}  ({pct_cq(codeql['tp'])})")
    print(f"    of which verifier will verify:      {tp_verify:>6}  ({tp_verify/codeql['tp']*100:.1f}% of TPs)")
    print(f"    of which verifier will skip (>5):   {tp_skip_verifier:>6}  ({tp_skip_verifier/codeql['tp']*100:.1f}% of TPs)")
    print(f"  Classified as FP:                     {codeql['fp']:>6}  ({pct_cq(codeql['fp'])})")
    print()
    cq_sum = sum(codeql.values())
    print(f"  Sum:                                  {cq_sum:>6}  (should equal {n_codeql_total})")
    if cq_sum != n_codeql_total:
        print(f"\n  WARNING: sum ({cq_sum}) != total ({n_codeql_total})!")
    else:
        print(f"  Check: {cq_sum} == {n_codeql_total} OK")

    breakdown = vuln_category_breakdown(results_dir)
    print_category_table(breakdown)
    csv_path = Path(__file__).parent / "vuln_category_data.csv"
    write_category_csv(breakdown, csv_path)

    ext_breakdown = ext_category_breakdown(results_dir)
    n_pool       = ext_breakdown["global_total_ext"]
    n_pool_tp    = ext_breakdown["global_tp_ext"]
    n_pool_fp    = ext_breakdown["global_fp_only_ext"]

    print()
    print("=" * 62)
    print("  EXTENSION-LEVEL POOL STATISTICS")
    print("=" * 62)
    print(f"  Extensions in analysis pool:          {n_pool:>5}")
    if n_pool:
        print(f"    with >= 1 TP (valid category):      {n_pool_tp:>5}  ({n_pool_tp/n_pool*100:.1f}%)")
        print(f"    with only FP (valid category):      {n_pool_fp:>5}  ({n_pool_fp/n_pool*100:.1f}%)")

    cat_agg = ext_breakdown["cat_agg"]
    col_w, lbl_w = 10, 12
    hdr = (f"  {'Category':<{lbl_w}} | {'Ext-TP':>{col_w}} | {'Ext-FP only':>{col_w}} |"
           f" {'Ext-Web':>{col_w}} | {'Ext-Ext':>{col_w}} |"
           f" {'Ext-Dom':>{col_w}} | {'Ext-NoDom':>{col_w+1}} |"
           f" {'TotVulns':>{col_w}} | {'ExtCount':>{col_w}}")
    sep = "  " + "-" * lbl_w + ("-+-" + "-" * col_w) * 8
    print()
    print(hdr)
    print(sep)
    for cat in ORDERED_CATS:
        a = cat_agg[cat]
        n_e = a["ext_count"]
        avg = a["total_vulns"] / n_e if n_e else 0.0
        print(f"  {SHORT_CAT[cat]:<{lbl_w}} |"
              f" {a['ext_tp']:>{col_w},} | {a['ext_fp_only']:>{col_w},} |"
              f" {a['ext_tp_website']:>{col_w},} | {a['ext_tp_extension']:>{col_w},} |"
              f" {a['ext_tp_has_domain']:>{col_w},} | {a['ext_tp_no_domain']:>{col_w+1},} |"
              f" {a['total_vulns']:>{col_w},} | {n_e:>{col_w},}  (avg {avg:.1f})")
    print(sep)

    helpers = Path(__file__).parent
    thesis_images = Path(__file__).parent.parent.parent / "thesis" / "images"
    write_ext_category_csv(ext_breakdown, helpers / "ext_category_data.csv")
    write_avg_vulns_csv(ext_breakdown, helpers / "ext_avg_per_cat.csv")
    write_ext_domain_top10_csv(ext_breakdown, helpers / "ext_domain_top10.csv")

    storage_api_counts = storage_api_breakdown(results_dir)
    total_with_api = sum(storage_api_counts.values())
    print()
    print("=" * 62)
    print("  STORAGE API BREAKDOWN (TP, category: storage / data_exfiltration)")
    print("=" * 62)
    print(f"  {'storage_api':<48} {'count':>6}")
    print("  " + "-" * 56)
    for api, cnt in sorted(storage_api_counts.items(), key=lambda x: -x[1]):
        print(f"  {api:<48} {cnt:>6}")
    print(f"\n  Total with storage_api set: {total_with_api}")

    drs_counts = domain_restriction_source_counts(results_dir)
    total_drs = drs_counts["manifest"] + drs_counts["code"] + drs_counts["both"]
    print()
    print("=" * 62)
    print("  DOMAIN RESTRICTION SOURCE (TP + has specific_domain)")
    print("=" * 62)
    for src in ("manifest", "code", "both"):
        n = drs_counts[src]
        pct_val = f"{n / total_drs * 100:.1f}%" if total_drs else "n/a"
        print(f"  {src:<12}: {n:>6}  ({pct_val})")
    if drs_counts["unknown"]:
        print(f"  {'unknown':<12}: {drs_counts['unknown']:>6}")
    drs_csv = helpers / "domain_restriction_source.csv"
    write_domain_restriction_source_csv(drs_counts, drs_csv)
    if thesis_images.exists():
        import shutil
        shutil.copy2(drs_csv, thesis_images / "domain_restriction_source.csv")
        print(f"  Copied to thesis/images/")


def main() -> None:
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RESULTS_DIR
    dataset_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DATASET_DIR

    for p, name in [(results_dir, "results_dir"), (dataset_dir, "dataset_dir")]:
        if not p.exists():
            print(f"ERROR: {name} not found: {p}", file=sys.stderr)
            sys.exit(1)

    print_stats(results_dir, dataset_dir)


if __name__ == "__main__":
    main()
