import json
from pathlib import Path

base = Path(__file__).parent.parent / "results_verification" / "results_gemini_2026-02-18_02-09-50_code_execution" / "codeql_2026_final"
for f in sorted(base.glob("*_verification.json"))[:50]:
    d = json.loads(f.read_text(encoding="utf-8"))
    if d.get("status") != "verified":
        print(json.dumps(d, indent=2)[:2000])
        break
