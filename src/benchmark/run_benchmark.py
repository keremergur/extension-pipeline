#!/usr/bin/env python3
"""
Verifier Benchmark Harness (Phase 0)
============================================

Runs the Verifier over a curated ground-truth set (``ground_truth.json``) and prints a scoreboard
so verifier changes can be measured in isolation from Analyzer noise:

  * recall per category      = verified positives / total positives
  * precision guard          = number of negative controls that (wrongly) verified — MUST be 0
  * runtime + hang count     = per-entry timing and timeouts

It calls ``verify_extension`` directly (bypassing the SSH/results-directory plumbing of the full
run), so it depends only on the extension code being locally available for each ground-truth id.

Usage:
    python run_benchmark.py                # run whole set
    python run_benchmark.py --category storage
    python run_benchmark.py --spoof        # force domain spoofing on for this run

Compare two runs by diffing the emitted ``benchmark_result.json`` files.
"""

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SRC_DIR))

import config  # noqa: E402
from mock_server import get_mock_server  # noqa: E402
from domain_spoofing import get_spoof_server  # noqa: E402
from verifier.orchestrator import verify_extension  # noqa: E402

BENCH_DIR = Path(__file__).resolve().parent
GROUND_TRUTH = BENCH_DIR / "ground_truth.json"
GROUND_TRUTH_FIXTURES = BENCH_DIR / "ground_truth_fixtures.json"
FIXTURES_DIR = BENCH_DIR / "fixtures"
PER_EXTENSION_TIMEOUT_S = getattr(config, "PER_EXTENSION_TIMEOUT", 180) or 180


def load_ground_truth(category_filter=None, gt_path=None):
    data = json.loads((gt_path or GROUND_TRUTH).read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    if category_filter:
        filtered = []
        for e in entries:
            vulns = [v for v in e.get("vulnerabilities", [])
                     if v.get("vulnerability_category") == category_filter]
            if vulns:
                filtered.append({**e, "vulnerabilities": vulns})
        entries = filtered
    return entries


async def run_entry(entry):
    ext_id = entry["extension_id"]
    vulns = entry.get("vulnerabilities", [])
    start = time.time()
    hung = False
    try:
        result = await asyncio.wait_for(
            verify_extension(ext_id, vulns, debug_mode=False),
            timeout=PER_EXTENSION_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        hung = True
        result = {"extension_id": ext_id, "status": "error", "vulnerabilities_verified": [],
                  "errors": ["benchmark timeout"]}
    except Exception as exc:  # noqa: BLE001
        result = {"extension_id": ext_id, "status": "error", "vulnerabilities_verified": [],
                  "errors": [f"{type(exc).__name__}: {exc}"]}
    elapsed = time.time() - start
    return result, elapsed, hung


def score(entry, result):
    """Yield (category, expected, actual_verified, is_control) per vulnerability."""
    verified_map = {}
    for v in result.get("vulnerabilities_verified", []):
        key = (v.get("rule_id"), v.get("vulnerability_category"))
        verified_map[key] = bool(v.get("detection"))
    is_control = bool(entry.get("is_control"))
    for v in entry.get("vulnerabilities", []):
        key = (v.get("rule_id"), v.get("vulnerability_category"))
        yield (v.get("vulnerability_category"), v.get("expected", "verified"),
               verified_map.get(key, False), is_control)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", default=None, help="only run one vulnerability category")
    ap.add_argument("--spoof", action="store_true", help="force ENABLE_DOMAIN_SPOOFING on for this run")
    ap.add_argument("--fixtures", action="store_true",
                    help="run the bundled, offline fixture suite (fixtures/ + ground_truth_fixtures.json) "
                         "instead of ground_truth.json — no dataset/SSH/LLM needed")
    args = ap.parse_args()

    if args.spoof:
        config.ENABLE_DOMAIN_SPOOFING = True

    if args.fixtures:
        # Copy the committed test doubles to a scratch dir and run the verifier there — the verifier
        # rewrites manifests / drops verify_storage.html in place, so we keep the repo fixtures pristine.
        import shutil, tempfile
        work = Path(tempfile.mkdtemp(prefix="verifier_fixtures_"))
        shutil.copytree(FIXTURES_DIR, work, dirs_exist_ok=True)
        config.EXTENSION_CODE_DIR = work
        config.RESET_EXTENSION_CODE = False
        print(f"Fixtures (working copy): {work}")
        entries = load_ground_truth(args.category, gt_path=GROUND_TRUTH_FIXTURES)
        real = entries
        if not real:
            print("No fixture entries found in ground_truth_fixtures.json.")
            return
    else:
        entries = load_ground_truth(args.category)
        real = [e for e in entries if not str(e["extension_id"]).startswith("REPLACE_WITH_REAL_ID")]
        if not real:
            print("ground_truth.json contains only EXAMPLE placeholders — populate it with real "
                  "extension ids (and ensure their code is locally available) before benchmarking.")
            return

    mock = get_mock_server()
    mock.start()
    if getattr(config, "ENABLE_DOMAIN_SPOOFING", False):
        get_spoof_server(https_port=getattr(config, "DOMAIN_SPOOF_HTTPS_PORT", 3443)).start()

    per_cat = defaultdict(lambda: {"pos_total": 0, "pos_verified": 0})
    control_violations = []
    failure_reasons = defaultdict(int)
    hangs = 0
    details = []
    t0 = time.time()

    for i, entry in enumerate(real, 1):
        print(f"[{i}/{len(real)}] {entry['extension_id']} ...", end=" ", flush=True)
        result, elapsed, hung = await run_entry(entry)
        hangs += int(hung)
        for cat, expected, verified, is_control in score(entry, result):
            if is_control or expected == "not_verified":
                if verified:
                    control_violations.append((entry["extension_id"], cat))
            else:
                per_cat[cat]["pos_total"] += 1
                per_cat[cat]["pos_verified"] += int(verified)
        for v in result.get("vulnerabilities_verified", []):
            if not v.get("detection") and v.get("failure_reason"):
                failure_reasons[v["failure_reason"]] += 1
        details.append({"extension_id": entry["extension_id"], "elapsed_s": round(elapsed, 1),
                        "hung": hung, "status": result.get("status")})
        print(f"{result.get('status')} ({elapsed:.1f}s)")

    total_time = time.time() - t0
    mock.stop()

    # ---- Scoreboard ----
    print("\n" + "=" * 60)
    print("BENCHMARK SCOREBOARD" + ("  [spoofing ON]" if getattr(config, "ENABLE_DOMAIN_SPOOFING", False) else ""))
    print("=" * 60)
    print(f"{'category':20} {'verified':>9} {'total':>7} {'recall':>8}")
    overall_v = overall_t = 0
    for cat in sorted(per_cat):
        s = per_cat[cat]
        overall_v += s["pos_verified"]; overall_t += s["pos_total"]
        rec = (s["pos_verified"] / s["pos_total"] * 100) if s["pos_total"] else 0.0
        print(f"{cat:20} {s['pos_verified']:>9} {s['pos_total']:>7} {rec:>7.1f}%")
    overall_rec = (overall_v / overall_t * 100) if overall_t else 0.0
    print("-" * 60)
    print(f"{'OVERALL':20} {overall_v:>9} {overall_t:>7} {overall_rec:>7.1f}%")
    print(f"\nPrecision guard (control verifications, MUST be 0): {len(control_violations)}")
    for cid, cat in control_violations:
        print(f"  !! CONTROL VERIFIED: {cid} [{cat}]")
    print(f"Hangs/timeouts: {hangs}")
    if failure_reasons:
        print("\nFailure reasons:")
        for reason, n in sorted(failure_reasons.items(), key=lambda x: -x[1]):
            print(f"  {n:>4}  {reason}")
    print(f"\nTotal wall time: {total_time:.1f}s")

    out = {
        "timestamp": datetime.now().isoformat(),
        "spoofing_enabled": getattr(config, "ENABLE_DOMAIN_SPOOFING", False),
        "recall_by_category": {c: per_cat[c] for c in per_cat},
        "overall_recall_pct": round(overall_rec, 2),
        "control_violations": control_violations,
        "hangs": hangs,
        "failure_reasons": dict(failure_reasons),
        "total_time_s": round(total_time, 1),
        "entries": details,
    }
    out_path = Path(__file__).resolve().parent / "benchmark_result.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
