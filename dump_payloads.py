#!/usr/bin/env python3
"""Dump the verifier's recorded attacker payloads for a fixed set of extension IDs, so they
can be re-executed by hand in a real browser.

Run on kuria:  python3 dump_payloads.py
Writes:  ~/overlap_payloads.json   (id -> [{category, attacker_source, rule_id, attacker_payload,
                                            verification_details}])
"""
import json
from pathlib import Path

RESULTS = Path.home() / 'verifier' / 'verification_full2'
OUT = Path.home() / 'overlap_payloads.json'

IDS = {
 "fpebadocnijkabapochompcgjedcbgno","elmgkaljjdljiefagliifjhhhhaiodki",
 "klmeolbcejnhefkapdchfhlhhjgobhmo","dmlmenebejdemdbmgldkpckfbmijlchh",
 "cplolipedeinchadnhonpfnbhlacckpi","gfmaehgiefbpgcloaclcbdnlhggplpkd",
 "ibckhpijbdmdobhhhodkceffdngnglpk","bdiahcebghgckgbgmjhdbecjkedpcidn",
 "bflpmpggmkamcjjdjajcafkpcmjmgcfg","ljhelnenkgmaljgibhbaphnoapdinjpp",
 "kbbdibmbjngifdgbmlleelghocpeimhe","omohfhadnbkakganodaofplinheljnbd",
 "knbcefijhpdehpjpehndmpdfeegfckep","fdmhpfjkhlafmdjngdmeghdibliijiba",
 "mfpfeokebfgddkaemagjigbjkmohmpab","fioncmjmhceiogbpebahkakijnlldajg",
 "lgfbejfchjmlmoinjabomjkoomnekgko","abkbmnbcmfehcbfjkpagdmloiondlbne",
 "acblceepgdakhjhkmmkmafbbnhoobcef","gnhhdgbaldcilmgcpfddgdbkhjohddkj",
}

def main():
    out = {}
    for f in RESULTS.rglob('results/*_result.json'):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        eid = d.get('extension_id')
        if eid not in IDS:
            continue
        rows = []
        for v in d.get('vulnerabilities_verified', []):
            if not v.get('detection'):
                continue
            rows.append({
                "category": v.get('vulnerability_category'),
                "attacker_source": v.get('attacker_source'),
                "rule_id": v.get('rule_id'),
                "attacker_payload": v.get('attacker_payload'),
                "verification_details": v.get('verification_details'),
            })
        if rows:
            out[eid] = rows
    OUT.write_text(json.dumps(out, indent=2))
    print(f"wrote {OUT} with {len(out)} extensions")
    print("scp down:")
    print(f"  scp -P 54321 <user>@kuria.plai.ifi.lmu.de:{OUT} /mnt/c/Users/<you>/Desktop/")

if __name__ == '__main__':
    main()
