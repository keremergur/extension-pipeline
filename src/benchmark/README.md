# Verifier Benchmark Harness (Phase 0)

Measures the **Verifier** in isolation so improvements can be proven, not guessed.

## Why

The thesis's per-category verification rates (Table 6.2) are polluted by Analyzer errors — ~54% of
failures are wrong TP classifications or wrong output fields the verifier can't fix. To know whether
a *verifier* change actually helps, you must run it on inputs where the Analysis JSON is known
correct. That's what `ground_truth.json` provides.

## Quick start: the bundled fixture suite (no dataset needed)

Before touching real extensions, run the **self-contained fixture suite** — a set of committed
*test-double* extensions under `fixtures/` (two genuinely vulnerable, two benign controls) described
in `ground_truth_fixtures.json`. It needs **no dataset, SSH, or LLM** — only a working Chrome binary.

```bash
# Locally (Windows/dev): point at a Playwright-bundled Chromium, which loads unpacked extensions.
#   NOTE: modern stable Google Chrome silently ignores --load-extension; use Chrome-for-Testing ~126
#   (as on kuria) or a Playwright Chromium build (…/ms-playwright/chromium-*/chrome-win64/chrome.exe).
CHROME_BINARY_PATH=".../chromium-1228/chrome-win64/chrome.exe" \
USE_LOCAL_VERIFICATION_SERVER=true PAYLOAD_EXECUTION_TIMEOUT=8 \
python run_benchmark.py --fixtures
```

Expected scoreboard: `1way_request` and `code_execution` at **100% recall**, **precision guard = 0**
(both benign controls rejected), **0 hangs**. The fixtures model the detection signal the real
pipeline uses — a privileged outbound request tagged with `chrome.runtime.id` — so this exercises the
real `verify_extension` code path end-to-end. `--fixtures` runs against a temp copy, so the committed
fixtures stay pristine. Covered today: `1way_request`, `code_execution` + controls; `data_exfiltration`
/ `storage` / `download` fixtures are a documented follow-up (they need seeding/storage plumbing).

## Setup (real extensions)

1. **Populate `ground_truth.json`** with real cases:
   - *Positives*: confirmed-vulnerable extensions (e.g. the thesis S1 list, Appendix D.1.1), each
     with hand-verified Analysis-JSON vulnerability objects and `"expected": "verified"`.
   - *Negative controls*: safe extensions that must **not** verify (`"is_control": true`,
     `"expected": "not_verified"`). These guard the ~100% precision — the crown jewel.
2. **Make each extension's code locally available** (the same directory the verifier reads via
   `get_extension_code_dir`), since the harness calls `verify_extension` directly.
3. Ensure `config.CHROME_BINARY_PATH` points at Chrome for Testing 126.

## Run

```bash
python run_benchmark.py                 # whole set
python run_benchmark.py --category storage
python run_benchmark.py --spoof         # force domain spoofing on
```

## Read the scoreboard

- **recall per category** — the number to move up vs. the thesis baseline.
- **Precision guard** — controls that verified. **Must stay 0.** If a leniency change (Phase 3)
  makes a control verify, that change is rejected.
- **Failure reasons** — aggregated `failure_reason` slugs (Phase 1) telling you *why* positives
  failed, so you know which phase to work on next.
- **Hangs/timeouts** — should be 0 once Phase 1's per-extension timeout is in effect.

Each run writes `benchmark_result.json`; diff two of them to see the effect of a change.
