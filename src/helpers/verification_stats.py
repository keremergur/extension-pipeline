#!/usr/bin/env python3
"""
Statistics over completed verification runs, broken down by vulnerability category.

Usage:
    python verification_stats.py [base_results_dir]

Reads the following result folders (relative to base_results_dir, which defaults
to src/results_verification/):
    - results_gemini_2026-02-18_02-09-50_request/          (1way_request, 2way_request)
    - results_gemini_2026-02-18_02-09-50_code_execution/   (code_execution)
    - results_gemini_2026-02-18_02-09-50_data_exfiltration/ (data_exfiltration)
    - results_gemini_2026-02-18_02-09-50_download/         (download)
    - results_gemini_2026-02-18_02-09-50_storage/          (storage)

If the request/code_execution split folders do not exist yet, the script
automatically performs the split from results_gemini_2026-02-18_02-09-50_request_code_execution/.

Outputs per category:
    Total | Verified | Not Verified | % Verified

For data_exfiltration and storage, also outputs a breakdown by storage_api.
"""

import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_RESULTS = (
    Path(__file__).parent.parent / "results_verification"
)

# Analysis results directory for cross-referencing (baseline of TP extensions)
ANALYSIS_RESULTS_DIR = (
    Path(__file__).parent.parent
    / "results_analysis"
    / "results_gemini_2026-02-18_02-09-50"
    / "codeql_2026_final"
)

# Folder names relative to BASE_RESULTS
FOLDER_REQUEST    = "results_gemini_2026-02-18_02-09-50_request"
FOLDER_CODE_EXEC  = "results_gemini_2026-02-18_02-09-50_code_execution"
FOLDER_DATA_EXFIL = "results_gemini_2026-02-18_02-09-50_data_exfiltration"
FOLDER_DOWNLOAD   = "results_gemini_2026-02-18_02-09-50_download"
FOLDER_STORAGE    = "results_gemini_2026-02-18_02-09-50_storage"

DATASET_SUBDIR = "codeql_2026_final"

# Categories considered "request" type
REQUEST_CATEGORIES = {"1way_request", "2way_request"}
CODE_EXEC_CATEGORIES = {"code_execution"}

# Ordered display of categories
ORDERED_CATEGORIES = [
    ("1way_request",      "request",        FOLDER_REQUEST),
    ("2way_request",      "request",        FOLDER_REQUEST),
    ("code_execution",    "code_execution", FOLDER_CODE_EXEC),
    ("data_exfiltration", "data_exfil",     FOLDER_DATA_EXFIL),
    ("download",          "download",       FOLDER_DOWNLOAD),
    ("storage",           "storage",        FOLDER_STORAGE),
]

# verification_status values that count as "verified"
VERIFIED_STATUS = {"verified"}

# Categories that get a storage_api sub-breakdown (order matters for output)
STORAGE_API_BREAKDOWN_CATS = ["data_exfiltration", "storage"]


# ---------------------------------------------------------------------------
# Folder splitting
# ---------------------------------------------------------------------------

def split_request_code_execution(base: Path) -> None:
    """
    Split results_gemini_..._request_code_execution/ into two separate folders:
        results_gemini_..._request/         (1way_request + 2way_request files)
        results_gemini_..._code_execution/  (code_execution files)

    Extension JSON files are copied (not moved) from the combined folder.
    The verification_summary.json is also copied to both new folders unchanged.

    Safe to call even if the combined folder is absent — will print a warning
    and return without raising.
    """
    combined = base / FOLDER_COMBINED / DATASET_SUBDIR
    if not combined.exists():
        print(f"  [split] Source folder not found: {combined}  – skipping split.")
        return

    req_dir  = base / FOLDER_REQUEST  / DATASET_SUBDIR
    code_dir = base / FOLDER_CODE_EXEC / DATASET_SUBDIR
    req_dir.mkdir(parents=True, exist_ok=True)
    code_dir.mkdir(parents=True, exist_ok=True)

    n_req = n_code = n_mixed = 0
    for json_file in sorted(combined.glob("*_verification.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  [split] Cannot parse {json_file.name}: {exc}")
            continue

        cats = {
            v.get("vulnerability_category", "")
            for v in data.get("vulnerabilities_verified", [])
        }
        is_req  = bool(cats & REQUEST_CATEGORIES)
        is_code = bool(cats & CODE_EXEC_CATEGORIES)

        if is_req:
            shutil.copy2(json_file, req_dir / json_file.name)
            n_req += 1
        if is_code:
            shutil.copy2(json_file, code_dir / json_file.name)
            n_code += 1
        if is_req and is_code:
            n_mixed += 1

    # Copy verification_summary.json to both new folders
    summary_src = base / FOLDER_COMBINED / "verification_summary.json"
    if summary_src.exists():
        shutil.copy2(summary_src, base / FOLDER_REQUEST  / "verification_summary.json")
        shutil.copy2(summary_src, base / FOLDER_CODE_EXEC / "verification_summary.json")

    print(f"  [split] Done: {n_req} request files -> {FOLDER_REQUEST}")
    print(f"          Done: {n_code} code_execution files -> {FOLDER_CODE_EXEC}")
    if n_mixed:
        print(f"          Note: {n_mixed} file(s) contained both categories "
              "(copied to both folders).")


def ensure_split(base: Path) -> None:
    """Perform the split only if the target folders do not yet exist."""
    req_dir  = base / FOLDER_REQUEST  / DATASET_SUBDIR
    code_dir = base / FOLDER_CODE_EXEC / DATASET_SUBDIR
    if not req_dir.exists() or not code_dir.exists():
        print("\nSplit folder(s) missing – performing split now …")
        split_request_code_execution(base)
        print()


# ---------------------------------------------------------------------------
# Stats collection
# ---------------------------------------------------------------------------

class CategoryStats:
    """Aggregated verification stats for one vulnerability category."""

    def __init__(self, name: str):
        self.name = name
        self.total    = 0
        self.verified = 0
        # storage_api → (total, verified)
        self.storage_api: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    def add(self, verification_status: str, storage_api: str | None) -> None:
        self.total += 1
        is_verified = verification_status in VERIFIED_STATUS
        if is_verified:
            self.verified += 1

        if self.name in STORAGE_API_BREAKDOWN_CATS:
            api_key = storage_api or "(none / unknown)"
            self.storage_api[api_key][0] += 1
            if is_verified:
                self.storage_api[api_key][1] += 1

    @property
    def not_verified(self) -> int:
        return self.total - self.verified

    @property
    def pct(self) -> float:
        return self.verified / self.total * 100 if self.total else 0.0


def collect_stats(base: Path) -> dict[str, CategoryStats]:
    """Read all verification JSON files and return per-category stats."""
    stats: dict[str, CategoryStats] = {}

    for cat, _label, folder_name in ORDERED_CATEGORIES:
        if cat not in stats:
            stats[cat] = CategoryStats(cat)

    folder_cats: dict[str, set[str]] = {
        FOLDER_REQUEST:    REQUEST_CATEGORIES,
        FOLDER_CODE_EXEC:  CODE_EXEC_CATEGORIES,
        FOLDER_DATA_EXFIL: {"data_exfiltration"},
        FOLDER_DOWNLOAD:   {"download"},
        FOLDER_STORAGE:    {"storage"},
    }

    for folder_name, expected_cats in folder_cats.items():
        data_dir = base / folder_name / DATASET_SUBDIR
        if not data_dir.exists():
            print(f"  [warn] Folder not found, skipping: {data_dir}")
            continue

        for json_file in data_dir.glob("*_verification.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"  [warn] Cannot parse {json_file}: {exc}")
                continue

            for vuln in data.get("vulnerabilities_verified", []):
                cat = vuln.get("vulnerability_category", "")
                if cat not in stats:
                    # unexpected category – create a slot so nothing is lost
                    stats[cat] = CategoryStats(cat)
                v_status = vuln.get("verification_status") or "no_detection"
                vd = vuln.get("verification_details") or {}
                storage_api = vd.get("storage_api") or None
                stats[cat].add(v_status, storage_api)

    return stats


# ---------------------------------------------------------------------------
# Extension-level stats (deduplicated across all category folders)
# ---------------------------------------------------------------------------

def collect_extension_stats(base: Path) -> dict:
    """
    Collect per-extension verification status, deduplicated across all folders.

    An extension can appear in multiple category folders (e.g., if it has both
    data_exfiltration and storage TPs). This function merges those appearances.

    Returns dict with:
        at_least_one_verified : set of ext_ids with >= 1 verified vulnerability
        attempted_none_verified: set of ext_ids attempted but none verified
        not_in_any_folder      : set of ext_ids with >= 1 TP in analysis but
                                 absent from every verification folder
    """
    ALL_FOLDERS = [
        FOLDER_REQUEST, FOLDER_CODE_EXEC, FOLDER_DATA_EXFIL,
        FOLDER_DOWNLOAD, FOLDER_STORAGE,
    ]

    # ext_id -> set of verification_status values seen across all folders
    ext_statuses: dict[str, set[str]] = {}

    for folder_name in ALL_FOLDERS:
        data_dir = base / folder_name / DATASET_SUBDIR
        if not data_dir.exists():
            continue
        for json_file in data_dir.glob("*_verification.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            ext_id = (data.get("extension_id")
                      or json_file.stem.replace("_verification", ""))
            if ext_id not in ext_statuses:
                ext_statuses[ext_id] = set()
            for vuln in data.get("vulnerabilities_verified", []):
                status = vuln.get("verification_status") or "no_detection"
                ext_statuses[ext_id].add(status)

    at_least_one_verified  = {eid for eid, s in ext_statuses.items() if "verified" in s}
    attempted_none_verified = set(ext_statuses.keys()) - at_least_one_verified

    # Cross-reference: which TP extensions from analysis never made it into any folder?
    # These were skipped in every category run because they exceeded max_vulnerabilities=5
    # in every category they had TPs in. Download failures still produce a JSON file,
    # so they show up as "attempted_none_verified" above, not here.
    skipped_all_runs: set[str] = set()
    if ANALYSIS_RESULTS_DIR.exists():
        all_in_folders = set(ext_statuses.keys())
        for f in ANALYSIS_RESULTS_DIR.glob("*_result.json"):
            ext_id = f.stem.replace("_result", "")
            if ext_id in all_in_folders:
                continue
            try:
                text = f.read_text(encoding="utf-8").strip()
                if text.startswith("```"):
                    lines = text.splitlines()
                    text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
                data = json.loads(text)
                has_tp = any(
                    v.get("result", "").strip().upper() == "TP"
                    for v in data.get("vulnerabilities", [])
                )
                if has_tp:
                    skipped_all_runs.add(ext_id)
            except Exception:
                pass

    return {
        "at_least_one_verified":   at_least_one_verified,
        "attempted_none_verified":  attempted_none_verified,
        "skipped_all_runs":         skipped_all_runs,
    }


def print_extension_stats(ext_stats: dict) -> None:
    verified  = len(ext_stats["at_least_one_verified"])
    attempted = len(ext_stats["attempted_none_verified"])
    skipped   = len(ext_stats["skipped_all_runs"])
    grand     = verified + attempted + skipped

    num_w = 8
    lbl_w = 50

    header = f"  {'Category':<{lbl_w}} | {'Extensions':>{num_w}}"
    sep    = "  " + "-" * lbl_w + "-+-" + "-" * num_w

    print()
    print("=" * (lbl_w + num_w + 7))
    print("  EXTENSION-LEVEL VERIFICATION STATS")
    print("=" * (lbl_w + num_w + 7))
    print(header)
    print(sep)

    def pct(n): return f"({n / grand * 100:.1f}%)" if grand else ""

    print(f"  {'>= 1 verified vulnerability':<{lbl_w}} | {verified:>{num_w},}  {pct(verified)}")
    print(f"  {'Attempted by verifier, none verified':<{lbl_w}} | {attempted:>{num_w},}  {pct(attempted)}")
    print(f"  {'Skipped in all runs (>5 TPs per category)':<{lbl_w}} | {skipped:>{num_w},}  {pct(skipped)}")
    print(sep)
    print(f"  {'Total (unique extensions with >= 1 TP)':<{lbl_w}} | {grand:>{num_w},}")


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _pct_str(n: int, total: int) -> str:
    if total == 0:
        return "  n/a"
    return f"{n / total * 100:5.1f}%"


def print_category_table(stats: dict[str, CategoryStats]) -> None:
    lbl_w  = 18
    num_w  = 10   # wide enough for "Not Verif." (10 chars)

    header = (f"  {'Category':<{lbl_w}} | {'Total':>{num_w}} | "
              f"{'Verified':>{num_w}} | {'Not Verif.':>{num_w}} | "
              f"{'% Verif.':>8}")
    sep    = "  " + "-" * lbl_w + "-+-" + ("-" * num_w + "-+-") * 3 + "-" * 8

    print()
    print("=" * len(header))
    print("  VERIFICATION STATS — PER CATEGORY")
    print("=" * len(header))
    print(header)
    print(sep)

    grand_total = grand_ver = 0
    for cat, _label, _folder in ORDERED_CATEGORIES:
        s = stats.get(cat)
        if s is None:
            continue
        grand_total += s.total
        grand_ver   += s.verified
        print(f"  {cat:<{lbl_w}} |"
              f" {s.total:>{num_w},} |"
              f" {s.verified:>{num_w},} |"
              f" {s.not_verified:>{num_w},} |"
              f" {_pct_str(s.verified, s.total):>8}")

    print(sep)
    grand_not_ver = grand_total - grand_ver
    print(f"  {'TOTAL':<{lbl_w}} |"
          f" {grand_total:>{num_w},} |"
          f" {grand_ver:>{num_w},} |"
          f" {grand_not_ver:>{num_w},} |"
          f" {_pct_str(grand_ver, grand_total):>8}")


def print_storage_api_table(stats: dict[str, CategoryStats], category: str) -> None:
    s = stats.get(category)
    if s is None or not s.storage_api:
        return

    lbl_w = 34
    num_w  = 10   # wide enough for "Not Verif." (10 chars)

    header = (f"  {'storage_api':<{lbl_w}} | {'Total':>{num_w}} | "
              f"{'Verified':>{num_w}} | {'Not Verif.':>{num_w}} | "
              f"{'% Verif.':>8}")
    sep    = "  " + "-" * lbl_w + "-+-" + ("-" * num_w + "-+-") * 3 + "-" * 8

    title = f"  VERIFICATION STATS — {category.upper()} PER STORAGE_API"
    width = max(len(header), len(title))
    print()
    print("=" * width)
    print(title)
    print("=" * width)
    print(header)
    print(sep)

    # Sort by total descending
    for api, (total, ver) in sorted(s.storage_api.items(), key=lambda x: -x[1][0]):
        not_ver = total - ver
        print(f"  {api:<{lbl_w}} |"
              f" {total:>{num_w},} |"
              f" {ver:>{num_w},} |"
              f" {not_ver:>{num_w},} |"
              f" {_pct_str(ver, total):>8}")

    print(sep)
    print(f"  {'TOTAL':<{lbl_w}} |"
          f" {s.total:>{num_w},} |"
          f" {s.verified:>{num_w},} |"
          f" {s.not_verified:>{num_w},} |"
          f" {_pct_str(s.verified, s.total):>8}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_RESULTS

    if not base.exists():
        print(f"ERROR: base results directory not found: {base}", file=sys.stderr)
        sys.exit(1)

    ensure_split(base)

    stats = collect_stats(base)

    print_category_table(stats)

    for cat in STORAGE_API_BREAKDOWN_CATS:
        print_storage_api_table(stats, cat)

    ext_stats = collect_extension_stats(base)
    print_extension_stats(ext_stats)

    print()


if __name__ == "__main__":
    main()
