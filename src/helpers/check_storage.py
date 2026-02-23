import json
from pathlib import Path

results_dir = (
    Path(__file__).parent.parent
    / "results_analysis"
    / "results_gemini_2026-02-18_02-09-50"
    / "codeql_2026_final"
)

# Step 1: Check what vulnerability_category values appear in TP results
cats = {}
storage_fields = {}

for f in list(results_dir.glob("*_result.json"))[:200]:
    try:
        text = f.read_text(encoding="utf-8").strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        data = json.loads(text)
        for v in data.get("vulnerabilities", []):
            res = v.get("result", "").strip().upper()
            cat = v.get("vulnerability_category", "MISSING")
            if res == "TP":
                cats[cat] = cats.get(cat, 0) + 1
                # If storage or data_exfiltration, show all keys
                if cat in ("storage", "data_exfiltration"):
                    for key in v.keys():
                        storage_fields[key] = storage_fields.get(key, 0) + 1
    except Exception as e:
        pass

print("=== TP Category counts (first 200 files) ===")
for k, v in sorted(cats.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

print("\n=== Fields in storage/data_exfiltration TPs ===")
for k, v in sorted(storage_fields.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

# Step 2: Show a sample storage/data_exfiltration TP entry
print("\n=== Sample storage/data_exfiltration TP entry ===")
for f in list(results_dir.glob("*_result.json"))[:500]:
    try:
        text = f.read_text(encoding="utf-8").strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        data = json.loads(text)
        for v in data.get("vulnerabilities", []):
            res = v.get("result", "").strip().upper()
            cat = v.get("vulnerability_category", "")
            if res == "TP" and cat in ("storage", "data_exfiltration"):
                print(json.dumps(v, indent=2))
                exit()
    except Exception:
        pass
print("(none found in first 500 files)")
