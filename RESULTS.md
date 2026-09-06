# Verifier — Results

Chrome-extension vulnerability verifier. All runs on the same corpus and runtime (100-way parallel
Docker, Chrome-for-Testing 126); only the verifier code differs between columns. All figures are
recomputed from run output. See `CHANGELOG.md` for the per-change history and flags.

## Summary

- **Reproduction:** the unmodified thesis-baseline verifier reproduces the published numbers
  (15.5% vs 16.1%) → the harness is sound.
- **Improvement (thesis corpus, same cap):** vulnerabilities **15.5% → 26.3%**; extensions
  **19.1% → 32.2%**. Strict gains (nothing lost).
- **With all recent fixes (full dataset, no cap):** **25.2%** of vulnerabilities / **34.4%** of
  extensions; storage **23.8% → 35.9%**; download **0% → 14.4%** (a category revived from 0).
- **Precision:** 50 findings independently reproduced by hand in a real browser (0 false); every
  lever validated by a no-op negative control (0 false positives).
- **Coverage:** full threat model — **0 skipped** (the baseline skipped 1,555).

## 1. Head-to-head — baseline vs improved verifier (capped, like-for-like)

Same corpus, same cap (5 vulns/extension), 4,789 extensions / 7,944 vulns — identical denominator,
only the verifier differs. Cells are verified / total (rate).

| Category | Baseline verifier | Improved verifier |
|---|---|---|
| 1way_request | 18/1115 (1.6%) | 253/1115 (22.7%) |
| 2way_request | 17/444 (3.8%) | 83/444 (18.7%) |
| code_execution | 6/128 (4.7%) | 7/128 (5.5%) |
| data_exfiltration | 252/2123 (11.9%) | 297/2123 (14.0%) |
| download | 0/87 (0%) | 0/87 (0%) |
| storage | 935/4047 (23.1%) | 1449/4047 (35.8%) |
| **TOTAL vulns** | **1228/7944 (15.5%)** | **2089/7944 (26.3%)** |
| **Extensions (>=1 detection)** | **915/4789 (19.1%)** | **1541/4789 (32.2%)** |

The biggest lifts (storage, 1way, 2way) are exactly where the fixes landed. This capped comparison
predates the storage-poll / page-origin / download levers below; those add on top.

## 2. Full dataset, no cap — all recent fixes on

Run denominators 10,510 vulns / 5,026 extensions (canonical full set 10,640 / 5,071; the difference is
17 corrupted-ID analyzer records plus run-to-run shard variance). Cells are detected / total (rate).

| Category | Vulnerabilities | Extensions |
|---|---|---|
| 1way_request | 300/1374 (21.8%) | 269/1103 (24.4%) |
| 2way_request | 100/543 (18.4%) | 91/478 (19.0%) |
| code_execution | 8/131 (6.1%) | 8/122 (6.6%) |
| data_exfiltration | 424/3347 (12.7%) | 321/1905 (16.9%) |
| download | 15/104 (14.4%) | 15/100 (15.0%) |
| storage | 1797/5011 (35.9%) | 1343/3189 (42.1%) |
| **TOTAL** | **2644/10510 (25.2%)** | **1727/5026 (34.4%)** |

Extensions are deduplicated in the TOTAL (one extension can have findings in several categories).

## 3. Thesis reproduction (untouched baseline verifier)

Unmodified verifier on the original thesis dataset, thesis cap. Rates match — total within 0.6 pp;
1way and download exact — confirming the improvement deltas rest on a trustworthy baseline.

| Category | Thesis (published) | Reproduced |
|---|---|---|
| 1way_request | 1.6% | 1.6% |
| 2way_request | 3.3% | 3.8% |
| code_execution | 6.1% | 4.7% |
| data_exfiltration | 13.4% | 11.9% |
| download | 0% | 0% |
| storage | 23.8% | 23.1% |
| **TOTAL** | **16.1%** | **15.5%** |
| **Extensions** | **20.2%** | **19.1%** |

## 4. What we improved

Each change is gated (default off) and validated by its own no-op negative control, so precision
stays 100%. Details and flags in `CHANGELOG.md`.

| Lever | Problem | Fix | Result |
|---|---|---|---|
| Parallelism | 180s timeout is wall-clock; heavy extensions dropped out under load (counts swung 98–150) | raise to 600s | swing gone (coverage, not precision) |
| Storage read polling | single-shot read missed late async writes | poll the read | +55 findings |
| Web-storage page origin | content-script web storage is on the page origin, not chrome-extension:// | read/seed page origin too | +24 findings |
| Download | chrome.downloads bypasses the detectors → 0% forever | confirm via chrome.downloads.search outcome | 0 → 15 findings |
| API coverage | baseline skipped 1,555 findings | handler for every API | 0 skipped |
| Domain spoofing | — | investigated | ~0 gain → rejected |

## 5. API coverage

Every API in the threat model now has a verification path. Of 40 distinct storage APIs present in the
dataset, 39 are routed; the one exception (`chrome.runtime.setUninstallURL`) has no read-back API and
is structurally unverifiable.

- **Storage (write):** chrome.storage.local/sync/session (set, remove, clear); localStorage /
  sessionStorage (setItem, removeItem, clear); chrome.cookies (set, remove); chrome.bookmarks
  (create, remove, removeTree); chrome.history (addUrl, deleteUrl, deleteAll, deleteRange);
  chrome.management (uninstall, uninstallSelf, setEnabled); chrome.declarativeNetRequest
  (updateDynamicRules).
- **Data exfiltration (read):** chrome.storage.local/sync/session (get); localStorage /
  sessionStorage (getItem); chrome.cookies (get, getAll); chrome.bookmarks (get, getRecent, getTree,
  search); chrome.history (getVisits, search); chrome.management (get, getAll, getSelf);
  chrome.topSites (get).
- **Requests (1way / 2way):** any request to a URL from the extension context (fetch, XMLHttpRequest,
  etc.); attribution via the unforgeable `Sec-Fetch-Site: none` header.
- **Code execution:** eval, chrome.tabs.executeScript, setTimeout, setInterval.
- **Download:** chrome.downloads.download (detected via the chrome.downloads.search outcome).

## 6. Manual verification

Method (per finding): load the extension alone in a real Chrome, fire the attacker payload from an
ordinary web page (postMessage / sendMessage / dispatchEvent, as a malicious site would), and confirm
the real effect — a request reaching a mock server with the unforgeable `Sec-Fetch-Site: none` header
(proves the extension, not the page, made it), data returned to the page (`[EXFIL]` / `[2WAY]`), or an
attacker marker written into the extension's chrome.storage.

**Result: 50 findings hand-verified — 48 reproduced live, 1 source-confirmed (Manifest V2), 1 partial;
0 shown false.** Negative control: a trusted extension hit with the same payloads → nothing. Extension
IDs in `manually_verified_findings.md`.

## 7. Reproduce

Runner `run_parallel.sh` (subcommands shard / run / score / all) with per-lever flags `--timeout`,
`--storage-poll`, `--web-storage-page-origin`, `--verify-downloads`, `--extra-verify-apis`, `--spoof`.
Canonical config: 100-way, 600s, all recall levers on. Chrome for Testing 126.0.6478.126.
