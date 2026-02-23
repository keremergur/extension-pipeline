#!/usr/bin/env python3
"""
Count storage_api values for TP vulnerabilities in categories 'storage' and 'data_exfiltration'.
storage_api is nested under verification_details.storage_api.
"""
import json
from pathlib import Path
from collections import Counter

results_dir = (
    Path(__file__).parent.parent
    / "results_analysis"
    / "results_gemini_2026-02-18_02-09-50"
    / "codeql_2026_final"
)

api_counter = Counter()
total_with_api = 0
total_without_api = 0

for f in results_dir.glob("*_result.json"):
    try:
        text = f.read_text(encoding="utf-8").strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        data = json.loads(text)
        for v in data.get("vulnerabilities", []):
            cat = v.get("vulnerability_category", "")
            res = v.get("result", "").strip().upper()
            if res == "TP" and cat in ("storage", "data_exfiltration"):
                api = (v.get("verification_details") or {}).get("storage_api")
                if api:
                    api_counter[api] += 1
                    total_with_api += 1
                else:
                    total_without_api += 1
    except Exception:
        pass

total = total_with_api + total_without_api
print(f"Total TP vulns in storage/data_exfiltration: {total}")
print(f"  with storage_api set:    {total_with_api}")
print(f"  without storage_api set: {total_without_api}")
print()
print(f"{'storage_api':<50} {'count':>6}")
print("-" * 58)
for api, count in sorted(api_counter.items(), key=lambda x: -x[1]):
    print(f"{api:<50} {count:>6}")
