#!/usr/bin/env python3
"""Pick 20 verifier-confirmed extensions that ARE ALSO in Matias/Kerem's 7_select set
(the agreement set), spread across vulnerability categories, and tar their source for
hand-verification.

Run on kuria:  python3 pick_overlap.py
Outputs:  ~/exts_overlap.tgz  (+ prints the chosen 20 ids and categories)
"""
import json, random, subprocess
from pathlib import Path
from collections import defaultdict

CODE    = Path('/home/gobbi/experiment/CODE')
SELECT  = Path('/home/gobbi/experiment/RESULTS/codeql/1778867646-results/7_select')
RESULTS = Path.home() / 'verifier' / 'verification_full2'
OUT     = Path.home() / 'exts_overlap.tgz'
N       = 20

def main():
    sel = {p.stem for p in SELECT.glob('*.json')}

    # verifier-confirmed extensions: id -> a representative category
    verified = {}
    for f in RESULTS.rglob('results/*_result.json'):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        eid = d.get('extension_id')
        if not eid:
            continue
        for v in d.get('vulnerabilities_verified', []):
            if v.get('detection'):
                verified.setdefault(eid, v.get('vulnerability_category') or '?')
                break

    overlap = [(eid, cat) for eid, cat in verified.items()
               if eid in sel and (CODE / eid).exists()]

    by_cat = defaultdict(list)
    for eid, cat in overlap:
        by_cat[cat].append(eid)

    print(f"verifier-confirmed & in 7_select (with source): {len(overlap)}")
    for cat, ids in sorted(by_cat.items()):
        print(f"  {cat}: {len(ids)}")

    # stratified pick: round-robin across categories for a spread
    random.seed(20)
    for ids in by_cat.values():
        random.shuffle(ids)
    picked = []
    cats = sorted(by_cat.keys())
    i = 0
    while len(picked) < min(N, len(overlap)):
        c = cats[i % len(cats)]
        if by_cat[c]:
            picked.append((by_cat[c].pop(), c))
        i += 1
        if all(not v for v in by_cat.values()):
            break

    print(f"\nPICKED {len(picked)}:")
    for eid, cat in picked:
        print(f"  {eid}  {cat}")

    ids = [eid for eid, _ in picked]
    subprocess.run(['tar', 'czhf', str(OUT), '-C', str(CODE)] + ids, check=True)
    print(f"\nwrote {OUT}")
    print("scp it down with:")
    print(f"  scp -P 54321 <user>@kuria.plai.ifi.lmu.de:{OUT} /mnt/c/Users/<you>/Desktop/")

if __name__ == '__main__':
    main()
