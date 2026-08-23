#!/usr/bin/env python3
"""Patch ONE unpacked extension so its message-triggered vulnerability can be exercised
from an arbitrary test page, and print the extension ID Chrome will assign.

These edits mirror what the automated verifier does and do NOT change the vulnerable
message handlers or sinks -- they only make the exploit reachable from a test origin:
  * content_scripts[].matches            -> ["<all_urls>"]   (inject on the test page)
  * web_accessible_resources[].matches   -> ["<all_urls>"]   (loader content scripts do
                                            import(chrome.runtime.getURL(...)); the module
                                            must be web-accessible for the test origin, or
                                            the listener never attaches)
  * externally_connectable.matches       -> example.com       (let a page use chrome.runtime
                                            .sendMessage for onMessageExternal findings)
  * host_permissions                     -> ["<all_urls>"]    (allow the request categories)
  * key (only if absent)                 -> a fixed pinning key so the ID is known/stable
                                            (needed to address the ext, or to build an
                                            iframe src=chrome-extension://<id>/...)

Usage:  python patch_manifest.py <ext_dir>
Prints: <id> | MV<n> | SW=<bool> | own_key=<bool>
"""
import json, base64, hashlib, sys
from pathlib import Path

# A fixed public key so no-key (unpacked) extensions get a KNOWN, stable ID.
# ID computed from it: nekdljaflldlhkhnmiflclddiepbehnf
PINNING_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1+J+FqSXvaTee4LIWl5Ml5+LEeHQAw7DUVCPwprK7U7ywx"
    "qMHnp/7pCc63SQ35flvzyJQe403yvYqMeZ8aHRRCj6Rxblia6+Jm0r5fHFXMLIkl+oKVHbrOyeDMpd+U5JuCT4dkszE"
    "9Iq81tfdx0Y4VJQws8PiMWg06/lhsYilP0gZeKUsWbXYGrTW33/tbD0pM3SRuSKEIl9okvXsF/cl5SRoDAm1sjREqFl"
    "rwfwmb9UE2jKHyBT+aeprLRPW2/hDzJFgpEERo69K+ya8uEBhzK+nI/PdGwxIJCEK/9T59iCuROI7iUtAWhpW6NSoUb"
    "mWlyzq/ZxB0FK1+asxQWfQIDAQAB")


def ext_id_from_key(key_b64: str) -> str:
    der = base64.b64decode(key_b64)
    h = hashlib.sha256(der).hexdigest()[:32]
    return ''.join(chr(ord('a') + int(c, 16)) for c in h)


def patch(ext_dir: str) -> str:
    mf = Path(ext_dir) / "manifest.json"
    m = json.loads(mf.read_text(encoding="utf-8-sig"))
    for c in (m.get("content_scripts") or []):
        c["matches"] = ["<all_urls>"]
    war = m.get("web_accessible_resources")
    if isinstance(war, list):
        for e in war:
            if isinstance(e, dict) and "matches" in e:
                e["matches"] = ["<all_urls>"]
    m["externally_connectable"] = {"matches": ["*://example.com/*", "*://*.example.com/*"]}
    m["host_permissions"] = ["<all_urls>"]
    own = bool(m.get("key"))
    if not own:
        m["key"] = PINNING_KEY
    eid = ext_id_from_key(m["key"])
    bg = m.get("background") or {}
    sw = bool(bg.get("service_worker") or bg.get("scripts"))
    mf.write_text(json.dumps(m, indent=2), encoding="utf-8")
    print(f"{eid} | MV{m.get('manifest_version')} | SW={sw} | own_key={own}")
    return eid


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python patch_manifest.py <ext_dir>"); sys.exit(2)
    patch(sys.argv[1])
