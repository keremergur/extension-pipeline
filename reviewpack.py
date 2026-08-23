#!/usr/bin/env python3
"""Generate a manual-audit review pack: for each verifier-confirmed finding that is
NOT in Matias's 7_select set, dump the attacker payload plus the relevant extension
source lines (dangerous sinks + message handlers) so a human can confirm the flow.

Run on kuria:  python3 reviewpack.py > review_pack.txt
"""
import json
import subprocess
from pathlib import Path

CODE = Path('/home/gobbi/experiment/CODE')
SELECT = Path('/home/gobbi/experiment/RESULTS/codeql/1778867646-results/7_select')
RESULTS = Path.home() / 'verifier' / 'verification_full2'

SINK = {
    '1way_request': r'fetch\(|XMLHttpRequest|\.open\(|\.ajax|chrome\.tabs\.create|sendBeacon',
    '2way_request': r'fetch\(|XMLHttpRequest|\.ajax|responseText|\.json\(',
    'code_execution': r'\beval\(|new Function|setTimeout\(|\.innerHTML|document\.write',
    'storage': r'chrome\.storage\.[a-z]+\.set|localStorage\.setItem|sessionStorage\.setItem',
    'data_exfiltration': r'chrome\.storage\.[a-z]+\.get|chrome\.cookies|chrome\.history|localStorage\.getItem',
    'download': r'chrome\.downloads',
}
MSG = r'onMessage|onMessageExternal|addEventListener\(.message'


def main():
    sel = {p.stem for p in SELECT.glob('*.json')}

    targets = []
    for f in RESULTS.rglob('results/*_result.json'):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        eid = d.get('extension_id')
        if eid in sel:
            continue
        for v in d.get('vulnerabilities_verified', []):
            if v.get('detection'):
                targets.append((eid, v.get('rule_id'), v.get('vulnerability_category'),
                                v.get('attacker_payload') or ''))

    print(f"### {len(targets)} verifier-confirmed findings NOT in 7_select\n")
    for eid, rid, cat, payload in targets:
        print("=" * 72)
        print(f"EXT {eid} | {cat} | {rid}")
        print("-- payload --")
        print(payload[:600])
        print("-- source: sinks & handlers --")
        d = CODE / eid
        if d.exists():
            pattern = SINK.get(cat, 'x') + '|' + MSG
            try:
                out = subprocess.run(
                    ['grep', '-rohIE', '-m', '8', pattern, str(d)],
                    capture_output=True, text=True, timeout=25).stdout
                print(out[:1400] if out.strip() else "(grep found nothing -- minified/dynamic)")
            except Exception as e:
                print(f"(grep error: {e})")
        else:
            print("(no CODE/ source for this extension)")
        print()


if __name__ == '__main__':
    main()
