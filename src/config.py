"""
Configuration file for the Chrome Extension vulnerability report analyzer.
"""

import os
from pathlib import Path
import tempfile
from dotenv import load_dotenv
load_dotenv()


def _env_seconds(name: str, default: float) -> float:
    """Read a timeout (in seconds) from the environment, falling back to `default`.

    The environment variable (typically supplied via .env) is only used when it
    is set AND non-empty; otherwise the hard-coded default is returned.
    """
    value = os.getenv(name)
    return float(value) if value else default


def _env_str(name: str, default):
    """Read a string from the environment, falling back to `default`.

    Used so a Docker run (e.g. `docker run --env-file .env.config1`) can override
    settings without editing config.py. Empty/unset values fall back to `default`.
    """
    value = os.getenv(name)
    return value if value else default


def _env_path(name: str, default: Path) -> Path:
    """Read a filesystem path from the environment, falling back to `default`.

    Lets Docker point these directories at mounted volumes via --env-file. Empty
    or unset values fall back to the hard-coded default below.
    """
    value = os.getenv(name)
    return Path(value) if value else default


def _env_path_or_tmp(name: str, default_suffix: str) -> Path:
    """Read a writable cache path from the environment, defaulting to tmp."""
    value = os.getenv(name)
    if value:
        return Path(value)
    return Path(tempfile.gettempdir()) / default_suffix


def _env_list(name: str, default):
    """Read a comma-separated list (or single value) from the environment.

    - Unset/empty            -> `default` (unchanged)
    - "none"/"null"          -> None (explicitly disable the filter)
    - "a"                    -> "a"  (single string, matching the in-file style)
    - "a, b , c"             -> ["a", "b", "c"]
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    if value.strip().lower() in ("none", "null"):
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else parts


def _env_int_or_none(name: str, default):
    """Read an int (or an explicit None) from the environment.

    - Unset/empty   -> `default` (unchanged)
    - "none"/"null" -> None (explicitly disable the limit)
    - otherwise     -> int(value)
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    if value.strip().lower() in ("none", "null"):
        return None
    return int(value)


def _env_int(name: str, default: int) -> int:
    """Read an int from the environment; unset/empty/unparseable -> `default`."""
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    """Read a float from the environment; unset/empty/unparseable -> `default`."""
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value.strip())
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean feature flag from the environment.

    Unset/empty falls back to `default`. Truthy: 1/true/yes/on. Falsy:
    0/false/no/off. Used for the optional analyzer feature toggles below so a
    Docker run can flip a feature on/off without editing config.py.
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_step_set(name: str, all_steps: frozenset, default: bool) -> frozenset:
    """Read a per-step feature flag: off, on for every step, or a chosen subset.

    Unset/empty falls back to `all_steps if default else frozenset()`. Falsy
    (0/false/no/off/none) -> frozenset() (disabled everywhere). Truthy
    (1/true/yes/on/all) -> `all_steps` (enabled everywhere, matching the plain
    boolean this replaces). Anything else is parsed as a comma-separated subset
    of `all_steps`, e.g. "categorize,payload" -- an unknown step name is a
    config typo, so it raises rather than silently doing nothing.
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return all_steps if default else frozenset()
    v = value.strip().lower()
    if v in ("0", "false", "no", "off", "none"):
        return frozenset()
    if v in ("1", "true", "yes", "on", "all"):
        return all_steps
    steps = frozenset(p.strip().lower() for p in value.split(",") if p.strip())
    unknown = steps - all_steps
    if unknown:
        raise ValueError(f"{name}: unknown step(s) {sorted(unknown)}; "
                         f"expected a subset of {sorted(all_steps)}")
    return steps


# ============================================================================
# GENERAL / SHARED CONFIGURATION
# ============================================================================

# Paths (used by both analyzer and verifier)
# Each may be overridden by an environment variable of the same name (e.g. supplied
# via `docker run --env-file .env.config1`). Unset/empty falls back to the default.
BASE_DIR = Path(__file__).parent # Use this as a variable if all folders are inside the same parent folder
RESULTS_ANALYSIS_DIR = _env_path("RESULTS_ANALYSIS_DIR", BASE_DIR / "results_analysis")  # The Analyzer will save its result-JSONs and the verifier will search for his result-JSONs here
EXTENSION_CODE_DIR = _env_path("EXTENSION_CODE_DIR", BASE_DIR / "extension_code")  # "base source code directory" — Analyzer and Verifier will search for the original extension code here
BEAUTIFY_CACHE_DIR = _env_path_or_tmp("BEAUTIFY_CACHE_DIR", "chrome_extension_analyzer/.beautify_cache")
VERIFIER_EXTENSIONS_DIR = _env_path_or_tmp("VERIFIER_EXTENSIONS_DIR", "chrome_extension_analyzer/verifier_extensions")

# SSH Configuration for original extension code downloads
FILES_SSH_HOST = os.getenv("FILES_SSH_HOST")
FILES_SSH_PORT = int(os.getenv("FILES_SSH_PORT")) if os.getenv("FILES_SSH_PORT") else 22
FILES_SSH_USER = os.getenv("FILES_SSH_USER")
FILES_SSH_PASSWORD = os.getenv("FILES_SSH_PASSWORD")
FILES_SSH_EXTENSIONS_DATASET_DIR = os.getenv("FILES_SSH_EXTENSIONS_DATASET_DIR")

# Tar Download Configuration (for bulk extension downloads)
# If enabled, downloads all extensions as a single tar file instead of individual SFTP transfers
# This is MUCH faster for large datasets (8k+ extensions)
USE_TAR_DOWNLOAD = True  # Set to False to use individual SFTP downloads
FILES_SSH_TAR_PATH = os.getenv("FILES_SSH_TAR_PATH", "/path/to/extensions.tar.gz")  # Remote tar file path

# Extension Extraction Filter (for faster extraction and less storage)
# If enabled, only .js, .json, and .html files are extracted (analyzer only needs these for code context)
# IMPORTANT: Verifier needs all files to run extensions in browser, so this is analyzer-only
EXTRACT_ONLY_CODE_FILES = True  # Only extract .js, .json, .html files (faster, less storage)
EXTRACT_FILE_EXTENSIONS = ['.js', '.json', '.html']  # File types to extract when filtering is enabled


# ============================================================================
# ANALYZER CONFIGURATION (for analyze_extensions.py)
# ============================================================================

# Analysis options
INSPECTION_MODE = True  # Save prompts for manual review
DRY_RUN_MODE = False  # Build and save prompts but skip LLM calls for testing

# Resume an interrupted run instead of starting fresh
# Options:
# - None: Start a new run (default)
# - "latest": Resume the most recently created results directory
# - Custom directory name: e.g., "results_gemini_2026-02-18_10-30-00"
# Extensions that already have a *_result.json will be skipped automatically
RESUME_RUN = None  # e.g., "results_gemini_2026-02-18_10-30-00"

# Paths
DATASETS_DIR = _env_path("DATASETS_DIR", BASE_DIR / "datasets") # The Analyzer will search for CodeQL, CoCo or DoubleX datasets here

# Datasets to analyze
# Each dataset specifies:
# - name: Unique identifier and directory name
# - tool: Analysis tool type ("coco", "doublex", "codeql")
# - enabled: Whether to process this dataset
# - limit: Max number of extensions (None = all)
# - specific: List of extension IDs (None = all)
DATASETS = [
    {
        "name": "coco",
        "tool": "coco",
        "enabled": False,
        "limit": 10,
        "specific": None,
        "code_context_lines": 10
    },
    {
        "name": "coco_paper",
        "tool": "coco",
        "enabled": False,
        "limit": 10,
        "specific": None,
        "code_context_lines": 10
    },
    {
        "name": "doublex",
        "tool": "doublex",
        "enabled": False,
        "limit": 10,
        "specific": None,
        "code_context_lines": 10
    },
    {
        "name": "doublex_paper",
        "tool": "doublex",
        "enabled": False,
        "limit": 10,
        "specific": None,
        "code_context_lines": 10
    },
    {
        "name": "codeql_2025",
        "tool": "codeql",
        "enabled": False,
        "limit": 50,
        "specific": None,
        "code_context_lines": 1
    },
    {
        "name": "codeql_2026_final",
        "tool": "codeql",
        "enabled": True,
        "limit": None,
        "specific": None,
        "code_context_lines": 5
    },
{
        "name": "codeql_sample",
        "tool": "codeql",
        "enabled": False,
        "limit": None,
        "specific": None,
        "code_context_lines": 5
    },
]

# LLM Settings
PROMPT_FILE = BASE_DIR / "prompts" / "Prompt.md" # Legacy prompt template path (the
# modular analyzer now assembles prompts from analyzer/prompt_sections.py instead of
# reading this file; kept for reference/back-compat only).
LLM_PROVIDER = _env_str("LLM_PROVIDER", "ollama")  # Options: 'ollama', 'vllm', 'openai', 'anthropic', 'gemini', 'gemini_batch'

# Pipeline shape -- three points on one axis, "how much does one LLM call decide":
#   'single' - one structured call builds the WHOLE-EXTENSION result: every finding,
#              every step, one answer (the original behaviour). Alias:
#              'single_extension', which is what it actually is now that a second
#              single-call mode exists. 'single' stays the canonical name so existing
#              env files, results folders and cited runs keep their label.
#   'single_vulnerability' - one structured call per FINDING, still deciding
#              everything about it at once (category + TP/FP + payload). Same
#              candidate split as 'multi', so the two differ only in the number of
#              calls; same whole-task prompt as 'single', so those two differ only in
#              the unit of work. Alias: 'single_vuln'.
#   'multi'  - per-finding chain (categorize -> classify -> payload); smallest prompts,
#              for a local model with a small context window.
# An unknown value now RAISES at startup (analyzer.pipeline.canonical_pipeline_mode)
# instead of quietly falling back to 'multi'.
#
# Notes for 'single_vulnerability':
#   * logprob confidence, the loopback and the NA fallback all apply (one decisive
#     `result` token per call), unlike 'single';
#   * PAYLOAD_THINKING / PAYLOAD_THINKING_BUDGET do NOT apply -- there is no separate
#     payload call, so every request carries VLLM_THINKING_TOKEN_BUDGET;
#   * a payload is generated even for findings that end up FP/NA. It is not written
#     into the payload fields; it is kept under `discarded_payload` so that cost can
#     be measured.
PIPELINE_MODE = _env_str("PIPELINE_MODE", "multi")

# Optional vulnerability-category filter for prompt composition and output schema.
# None  -> include every category (default; feature "not enabled for now").
# list  -> only include the sections/enum values for these categories, e.g.
#          ["data_exfiltration", "storage"]. Env: ANALYZER_VULNERABILITY_CATEGORIES
ANALYZER_VULNERABILITY_CATEGORIES = _env_list("ANALYZER_VULNERABILITY_CATEGORIES", None)

# ----------------------------------------------------------------------------
# OPTIONAL ANALYZER FEATURES (each toggles between the "old" and a "new" behaviour)
# ----------------------------------------------------------------------------
# Every flag below defaults to the ORIGINAL behaviour, so an unmodified run is
# byte-for-byte identical to before. Flip any of them on via an env var / .env
# entry (also works through `docker run --env-file ...`). They are independent.

# (1) Prompt: explain the Chrome `externally_connectable` manifest nuance -- that
#     an ABSENT block lets ALL other extensions connect, whereas a declared-but-
#     partial block (no `ids`/`matches`) actually blocks them. Helps the model
#     judge whether an "Extension" attacker_source is viable.
#     Env: PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE (default off)
PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE = _env_bool("PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE", True)

# (2) Prompt: include a small set of worked TP/FP result examples (few-shot) to
#     calibrate the model's decision boundary.
#     Env: PROMPT_INCLUDE_RESULT_EXAMPLES (default off)
PROMPT_INCLUDE_RESULT_EXAMPLES = _env_bool("PROMPT_INCLUDE_RESULT_EXAMPLES", True)

# (3) Code-context scope handed to the model for each finding, narrowest first
#     (medians are measured prompt tokens over 250 escalated candidates of the
#     08-23 run -- EXPERIMENTS.md 25.4):
#       "lines"    - N lines before/after the referenced range (ORIGINAL behaviour;
#                    N = the dataset's code_context_lines)                  ~5_909
#       "block"    - the enclosing brace block around each referenced range ~7_272
#       "callsites"- "block" PLUS the enclosing block of every textual call site of
#                    those blocks' declared names (1 hop, capped)          ~7_790
#       "symbols"  - "block" PLUS the definitions/uses of the identifiers the model
#                    itself asked for last attempt (CONTEXT_SYMBOL_REQUEST)
#       "module"   - the enclosing bundler module (webpack/browserify) instead of
#                    the whole bundle                                      ~8_434
#       "toplevel" - HIGH_TIER_CONTEXT_BASE PLUS every depth-0 statement of the
#                    file, where chrome.* listener/storage wiring lives   ~10_822
#       "skeleton" - "toplevel" PLUS every function-opening line: the file's shape
#                    without its bodies                                   ~17_514
#       "packed"   - "block" PLUS the best-matching chunks of the file that fit
#                    CONTEXT_PACK_BUDGET_TOKENS (rank-and-fill; never overflows)
#       "file"     - the entire file(s) that contain the finding           ~32_776
#       "used"     - every source file referenced anywhere in the report for this
#                    extension, in full (drops files the report never references)
#     Env: CODE_CONTEXT_MODE (default "file"). A dataset entry may override this
#     with its own "code_context_mode" key.
#
#     This is the STARTING scope only. It is independent of the escalation ladder
#     below, so a run may start in the middle of it -- or on a rung the ladder
#     leaves out entirely.
CODE_CONTEXT_MODE = _env_str("CODE_CONTEXT_MODE", "file")

#     The ladder a confidence loopback walks, narrowest first. Escalation steps
#     POSITIONALLY along this list, so it is an order and not a hint: a run may
#     deliberately skip rungs or visit them out of cost order. When CODE_CONTEXT_MODE
#     is not on the list, the walk enters at the first rung wider than it by the
#     canonical cost rank above.
#
#     The default is every scope in measured median-cost order. That is a real
#     behaviour change for a run with CONFIDENCE_MAX_LOOPBACKS=1 starting at
#     "block": one step now reaches "callsites" (a ~6% wider prompt) rather than
#     "file" (~5x, and unsendable a third of the time). To get the old single jump
#     back, set CONTEXT_ESCALATION_ORDER=block,file.
#     Env: CONTEXT_ESCALATION_ORDER (comma-separated, e.g. "function,toplevel,file")
CONTEXT_ESCALATION_ORDER = _env_list(
    "CONTEXT_ESCALATION_ORDER",
    ["lines", "block", "callsites", "module", "toplevel", "skeleton", "file", "used"])
if isinstance(CONTEXT_ESCALATION_ORDER, str):     # _env_list returns a bare string
    CONTEXT_ESCALATION_ORDER = [CONTEXT_ESCALATION_ORDER]   # for a single value
# "symbols" and "packed" are deliberately NOT in the default ladder: each needs its
# own feature flag below, so a default run is unchanged and an A/B is one env line.

#     Scope names were renamed after run results_vllm_2026-08-26_23-58-37:
#       function -> block       (it is the enclosing brace BLOCK; the function test
#                                is a heuristic on the opening line that falls back
#                                to the nearest brace block)
#       callers  -> callsites   (textual `name(` matches, not a resolved call graph)
#     The old names are still accepted anywhere a scope is configured, so existing
#     env files keep working; only newly written result files use the new names.

#     The scope "toplevel"/"skeleton" keep WHOLE beneath the lines they add.
#
#     Until 09-03 this was hard-wired to "block", which made the tiers non-nested:
#     "module" walks up from the enclosing block to the whole bundler-module wrapper,
#     but "toplevel" kept only the narrow block and then jumped to depth 0. Everything
#     between the two -- which in a bundle is where the onConnectExternal/
#     onMessageExternal registration and its gate checks live -- fell in the gap and
#     was elided, so escalating from "module" to "toplevel" could REMOVE the evidence
#     the model had already been shown. Confirmed on 4 extensions and sized at
#     4-5% of those two scopes' false positives (EXPERIMENTS.md 33.2-33.3, D124/E38).
#
#     "module" (default) makes every tier a strict superset of the one below it:
#     block subset module subset toplevel subset skeleton. Set "block" to reproduce
#     any run before 09-03 byte-identically; "lines" is a deliberately narrower arm
#     for the A/B and should be expected to widen the gap, not close it.
#     Env: HIGH_TIER_CONTEXT_BASE (lines|block|module, default "module")
HIGH_TIER_CONTEXT_BASE = _env_str("HIGH_TIER_CONTEXT_BASE", "module")

# --- (3a) descent: shrink to fit when the STARTING scope is already too big -----
#     Escalation widens an unsure verdict. This is the opposite move, and it fires
#     before any verdict exists: if the prompt at CODE_CONTEXT_MODE already exceeds
#     MAX_PROMPT_TOKENS, walk DOWN the ladder until one fits instead of failing the
#     finding outright. Cost is one render per rung tried and no LLM call.
#
#     Off by default: it changes which scope a finding is judged at, so a run with
#     it on is not directly comparable to one without. In the 08-23 run 490 findings
#     died exactly this way (categorize, at the configured base scope) and the 08-26
#     runs still lose 67-76 each.
#
#     Per-step: this is one flag guarding three independent call sites (categorize,
#     classify, payload -- see pipeline/multi.py and pipeline/common.py's
#     `_apply_shrink`), because "on" originally only reached classify (and,
#     through it, whatever scope payload happened to share). A run that set it
#     `true` still lost the categorize step outright on any candidate whose BASE
#     scope alone was oversized (EXPERIMENTS.md 41) -- module/file *and* block
#     runs both did, since a giant single-block minified bundle makes "block"
#     collapse to nearly the whole file too. true/all/1/yes/on now covers every
#     step; a comma list picks a subset, e.g. CONTEXT_SHRINK_TO_FIT=categorize or
#     CONTEXT_SHRINK_TO_FIT=categorize,payload.
#
#     When it fires, the result records `context_shrunk_from` (the configured scope)
#     alongside `final_context_mode` (the one that fit) for classify, and
#     `category_context_shrunk_from` / `payload_context_shrunk_from` for the other
#     two steps, since each can land at its own narrower scope independently.
#
#     The single-call pipelines' one call (PIPELINE_MODE=single's whole-extension
#     call, or single_vulnerability's per-finding call -- a run is one pipeline at a
#     time, so the two never collide) is NOT a listable step name here -- there is no
#     "single" token, and typing one raises like any other typo. Instead its descent
#     rides whatever this flag already resolves to "everything": true/all/1/yes/on,
#     or an explicit list that happens to spell out every step above
#     (categorize,classify,payload) -- see `_apply_shrink`'s step=="single" case in
#     pipeline/common.py. A genuine subset (e.g. CONTEXT_SHRINK_TO_FIT=categorize)
#     does NOT reach it, only "shrink everything" does. This means the SAME env file
#     needs no per-pipeline edit: `true` (or `all`) turns descent on for whichever
#     pipeline that file's PIPELINE_MODE actually selects.
#     Env: CONTEXT_SHRINK_TO_FIT (default false; false|true|all|<comma list of
#     categorize,classify,payload>)
CONTEXT_SHRINK_TO_FIT_STEPS = frozenset({"categorize", "classify", "payload"})
CONTEXT_SHRINK_TO_FIT = _env_step_set("CONTEXT_SHRINK_TO_FIT", CONTEXT_SHRINK_TO_FIT_STEPS, False)

# --- (3b) symbol request: let the model name what it is missing ----------------
#     Adds `requested_symbols` to the classify schema and enables the "symbols"
#     scope, which resolves those identifiers to their definitions and uses instead
#     of widening the blob. Deterministic: one extra render and one re-ask, no agent
#     loop. Names shorter than 3 characters, or occurring on more than 40 lines, are
#     refused -- compressed extensions rename everything to 1-2 characters and a
#     match on those means nothing.
#
#     Turning this on ALSO changes the classify schema, so it is a prompt-level A/B,
#     not only a context-level one. Put "symbols" on the ladder to use it, e.g.
#     CONTEXT_ESCALATION_ORDER=block,symbols,module,file
#     Env: CONTEXT_SYMBOL_REQUEST (default false)
CONTEXT_SYMBOL_REQUEST = _env_bool("CONTEXT_SYMBOL_REQUEST", False)

# --- (3c) rank and fill: pack a token budget instead of climbing a ladder -------
#     The "packed" scope keeps the enclosing blocks, chunks the rest of the file,
#     ranks chunks by how well they match the finding's report, and fills up to
#     CONTEXT_PACK_BUDGET_TOKENS. Because it stops at the budget it can never build
#     an unsendable prompt, which is the failure the whole of EXPERIMENTS.md 25 is
#     about -- at the cost of handing the model a set of fragments rather than one
#     contiguous region.
#
#     Budget 0 (default) means "derive it": CONTEXT_PACK_BUDGET_FRACTION of
#     MAX_PROMPT_TOKENS, leaving the rest for the report, manifest and instructions.
#     Set an explicit number to pin it.
#     Env: CONTEXT_PACK_BUDGET_TOKENS / CONTEXT_PACK_BUDGET_FRACTION
CONTEXT_PACK_BUDGET_TOKENS = int(_env_str("CONTEXT_PACK_BUDGET_TOKENS", "0"))
CONTEXT_PACK_BUDGET_FRACTION = float(_env_str("CONTEXT_PACK_BUDGET_FRACTION", "0.6"))
#     Headroom left below the cap after the measured overhead, absorbing the
#     difference between the 3-chars-per-token estimate and the real tokenizer.
#     Env: CONTEXT_PACK_RESERVE_TOKENS
CONTEXT_PACK_RESERVE_TOKENS = int(_env_str("CONTEXT_PACK_RESERVE_TOKENS", "512"))


def context_pack_budget():
    """Fallback budget for "packed" when the real prompt overhead is not available.

    The pipeline prefers `pipeline.multi._pack_budget`, which measures what the cap
    leaves after the report, manifest and instructions of THIS finding. This blind
    fraction is only used when there is no cap, or by callers outside that path.
    """
    if CONTEXT_PACK_BUDGET_TOKENS > 0:
        return CONTEXT_PACK_BUDGET_TOKENS
    if MAX_PROMPT_TOKENS:
        return int(MAX_PROMPT_TOKENS * CONTEXT_PACK_BUDGET_FRACTION)
    return 0

# (4) Confidence-based context loopback: measure how sure the model is about the
#     verdict; if it is unsure, re-run the decision with a progressively wider
#     code-context scope (along CONTEXT_ESCALATION_ORDER), and/or downgrade the
#     verdict to NA when it stays unsure.
#
#     CONFIDENCE_LOOPBACK selects HOW "unsure" is decided:
#       none           - feature off: one classify pass, verdict kept as-is.
#       argmax         - (previous default) measure P(chosen verdict) from logprobs
#                        and fail when it is below CONFIDENCE_THRESHOLD_CLASS. On a
#                        2-way {TP,FP} enum this floors at 0.5, so it is really a
#                        margin in disguise; use it for backwards-comparable runs.
#       logprob_margin - measure the FULL per-label distribution and fail when the
#                        gap between the top two verdicts (top1 - top2) is below
#                        CONFIDENCE_THRESHOLD_MARGIN. Symmetric, and it does not hide
#                        a near-boundary flip the way P(argmax) does.
#       vote_margin    - self-consistency: sample the classifier CONFIDENCE_VOTES
#                        times at CONFIDENCE_VOTE_TEMPERATURE, take the plurality
#                        verdict, and fail when the vote margin (share of the winner
#                        minus share of the runner-up) is below
#                        CONFIDENCE_THRESHOLD_MARGIN. Measures trace-to-trace
#                        disagreement, which the single-decode logprob cannot see;
#                        costs CONFIDENCE_VOTES x classify inferences per finding.
#     Env: CONFIDENCE_LOOPBACK (default "argmax"). CONFIDENCE_LOOPBACK_ENABLED is a
#     legacy alias kept so older env files still work: setting it false forces
#     "none".
CONFIDENCE_LOOPBACK = _env_str("CONFIDENCE_LOOPBACK", "argmax")
CONFIDENCE_LOOPBACK_ENABLED = _env_bool(
    "CONFIDENCE_LOOPBACK_ENABLED", str(CONFIDENCE_LOOPBACK).strip().lower() != "none")
# Re-run while confidence < threshold (0..1). Shared default for the two
# per-decision thresholds below. Env: CONFIDENCE_THRESHOLD
CONFIDENCE_THRESHOLD = float(_env_str("CONFIDENCE_THRESHOLD", "0.7"))
# The two measured decisions have their own thresholds, because they are different
# questions with different stakes and different natural confidence levels:
#   _CLASS  - the TP/FP/NA verdict (classify step)
#   _SOURCE - attacker_source, Website vs Extension (payload step)
# Each defaults to CONFIDENCE_THRESHOLD, so setting only that keeps both in step.
# A decision is "unsure" when EITHER measurement is below ITS OWN threshold (not
# when their minimum is) -- so raising one does not silently drag the other along.
# Env: CONFIDENCE_THRESHOLD_CLASS / CONFIDENCE_THRESHOLD_SOURCE
CONFIDENCE_THRESHOLD_CLASS = float(_env_str("CONFIDENCE_THRESHOLD_CLASS",
                                            str(CONFIDENCE_THRESHOLD)))
CONFIDENCE_THRESHOLD_SOURCE = float(_env_str("CONFIDENCE_THRESHOLD_SOURCE",
                                             str(CONFIDENCE_THRESHOLD)))
# The margin threshold for CONFIDENCE_LOOPBACK in ("logprob_margin","vote_margin"):
# a verdict passes when (winner_share - runnerup_share) >= this. On a 2-way enum a
# margin m corresponds to an argmax P(chosen) of (1+m)/2, so 0.20 ~= P>=0.60.
# Env: CONFIDENCE_THRESHOLD_MARGIN
CONFIDENCE_THRESHOLD_MARGIN = float(_env_str("CONFIDENCE_THRESHOLD_MARGIN", "0.20"))
# Maximum number of extra re-runs (escalations) per decision. Env: CONFIDENCE_MAX_LOOPBACKS
CONFIDENCE_MAX_LOOPBACKS = int(_env_str("CONFIDENCE_MAX_LOOPBACKS", "1"))
# What is allowed to trigger an escalation to wider context:
#   both       - low confidence OR the model's explicit needs_more_context (previous)
#   confidence - only low confidence / failing margin
#   request    - only the model's explicit needs_more_context signal. Use this when
#                widening context helps only when the model actually asks for it, not
#                merely because the verdict sits near the boundary (§11: for reasoning
#                models escalation mean-reverts and rarely resolves a genuine tie).
# Env: CONFIDENCE_ESCALATE_TRIGGER (default "both")
CONFIDENCE_ESCALATE_TRIGGER = _env_str("CONFIDENCE_ESCALATE_TRIGGER", "both")
# When the decision is still unsure after the last attempt, stamp result = "NA" even
# if the RESULT_RULES variant's enum is 2-way (TP/FP only). This decouples "NA as a
# pipeline output" from "NA offered to the model": the model can be asked to always
# commit to TP/FP (which keeps the verdict logprobs clean), while the confidence gate
# still abstains on the ones it could not settle. When the enum already includes NA,
# the downgrade happens regardless of this flag. Env: CONFIDENCE_FAIL_CLASSIFY_NA
CONFIDENCE_FAIL_CLASSIFY_NA = _env_bool("CONFIDENCE_FAIL_CLASSIFY_NA", False)
# Self-consistency (CONFIDENCE_LOOPBACK="vote_margin"): number of independent
# classify samples ("votes") per attempt, and the temperature they are drawn at.
# Votes are issued sequentially within a finding, so raising CONFIDENCE_VOTES makes
# each finding ~N x slower but does NOT increase concurrent load -- PARALLEL_WORKERS
# does not need to be lowered. Each vote uses VLLM_SEED+i so a fixed seed still gives
# diverse (not identical) samples; the temperature must be > 0 for any diversity.
# Env: CONFIDENCE_VOTES / CONFIDENCE_VOTE_TEMPERATURE
CONFIDENCE_VOTES = int(_env_str("CONFIDENCE_VOTES", "5"))
CONFIDENCE_VOTE_TEMPERATURE = float(_env_str("CONFIDENCE_VOTE_TEMPERATURE", "0.6"))

# (5) verification_details.specific_domain fallback: when the model leaves the field
#     empty, derive it from manifest.json (externally_connectable.matches /
#     content_scripts.matches) for Website-attacker findings. Small local models
#     reliably skip the field even though the prompt asks for it, which silently
#     drops the domain restriction from the results. Turn this off for a pure-LLM
#     ablation. Env: ANALYZER_FILL_DOMAIN_FROM_MANIFEST (default on)
ANALYZER_FILL_DOMAIN_FROM_MANIFEST = _env_bool("ANALYZER_FILL_DOMAIN_FROM_MANIFEST", True)

# (6) attacker_source correction from the manifest's externally_connectable rules.
#     Chrome's semantics make some source labels provably impossible for an
#     external-message finding (onMessageExternal/onConnectExternal):
#       - block declared WITHOUT `ids`  -> no extension can connect -> "Extension"
#         is impossible; the only attacker is a page in `matches` -> force "Website".
#       - block ABSENT                  -> no web page can connect -> "Website" is
#         impossible; the only attacker is another extension -> force "Extension".
#     A wrong source is not cosmetic: the payload is written for that execution
#     context and the verifier runs that mode, so a mislabel makes a real finding
#     unverifiable. The correction also drives pinned_source_note, which tells the
#     PAYLOAD step the forced source up front so the exploit is written correctly.
#     Modes (env value, string):
#       none          - no correction
#       extweb        - only Extension->Website (the original one-directional
#                       behaviour; DEFAULT, so prior runs reproduce exactly)
#       webext        - only Website->Extension (the reverse, absent-block case)
#       bidirectional - both
#     Legacy values still parse: true/1/on -> extweb, false/0/off -> none.
#     The reverse direction keys on the external-message LISTENER specifically
#     (onMessageExternal/onConnectExternal), not the broader send/connect APIs, so
#     an internal runtime.sendMessage in a content-script finding is never forced.
#     Env: ANALYZER_CORRECT_ATTACKER_SOURCE
def _env_source_mode(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    v = raw.strip().lower()
    legacy = {"true": "extweb", "1": "extweb", "yes": "extweb", "on": "extweb",
              "false": "none", "0": "none", "no": "none", "off": "none"}
    if v in legacy:
        return legacy[v]
    return v if v in ("none", "extweb", "webext", "bidirectional") else default
ANALYZER_CORRECT_ATTACKER_SOURCE = _env_source_mode("ANALYZER_CORRECT_ATTACKER_SOURCE", "extweb")

# (7) Prompt layout tuned for the Ollama (llama.cpp) prefix KV cache. The server
#     re-uses the previous request's attention state only for the LONGEST COMMON
#     PREFIX with the new prompt, so every byte that varies early throws away the
#     cached state of everything behind it. This flag re-orders the prompt from
#     most stable to most volatile; no section is added or removed, so it stays a
#     clean A/B ablation of layout alone:
#       - the system prompt of the multi pipeline's steps collapses to the shared
#         INTRO, identical for every call of the run;
#       - each step's own instructions move to the END of the user message, after
#         the data they refer to;
#       - the user message emits manifest.json + domain hints (stable per
#         extension) before the report snippet (stable per finding) before the
#         code context (the only data block a confidence loopback re-renders).
#     Effect on the multi pipeline: the three calls per finding (categorize ->
#     classify -> payload) run over identical data and now differ only in their
#     trailing instruction block, so steps 2 and 3 prefill just that tail instead
#     of the whole report + code again. The single pipeline keeps its full system
#     prompt (one call per extension, so that block already IS the shared prefix)
#     and only picks up the stable-first user-message order.
#     Worth knowing: the cache lives per Ollama slot, so PARALLEL_WORKERS > 1 has
#     workers evicting each other unless the server's OLLAMA_NUM_PARALLEL is at
#     least as large; PARALLEL_WORKERS=1 gives the highest hit rate.
#     Env: PROMPT_CACHE_OPTIMIZED (default on)
PROMPT_CACHE_OPTIMIZED = _env_bool("PROMPT_CACHE_OPTIMIZED", True)

# (8) Multi pipeline: derive vulnerability_category from the CodeQL rule_id instead
#     of asking the model in the categorize step. CodeQL rule_ids encode the category
#     (chrome/trigger/storage/set -> storage), so a weak local model can't
#     miscategorize (which then poisons the classify step, since it only sees the one
#     category's definition) and one LLM call per finding is saved. Only fires when the
#     rule_id resolves via ANALYZER_RULE_ID_CATEGORY_MAP below; unknown or ambiguous
#     rule_ids (e.g. a network-request trigger that could be 1way or 2way) fall back to
#     the LLM categorize step. Single pipeline is unaffected (it has no discrete
#     categorize step). Env: ANALYZER_CATEGORY_FROM_RULE_ID (default off)
ANALYZER_CATEGORY_FROM_RULE_ID = _env_bool("ANALYZER_CATEGORY_FROM_RULE_ID", False)

# (8b) single_vulnerability only: when ANALYZER_CATEGORY_FROM_RULE_ID pins a
#      candidate's category, ALSO drop the other categories' definitions and
#      per-category payload triggers from that candidate's prompt -- not just the
#      schema enum.
#
#      Multi already gets this for free: build_classify_prompt/build_payload_prompt
#      only ever render the ONE resolved category's section. single_vulnerability's
#      system prompt is meant to be the constant, cacheable prefix every call re-uses
#      (one call per finding, identical instructions every time -- see
#      build_single_vulnerability_system), so this flag only shrinks it for a PINNED
#      candidate; an UNPINNED one is untouched. That asymmetry is deliberate, not an
#      oversight: an unpinned candidate needs the full category text regardless
#      (nothing to save), and that text is currently ahead of `report` in the
#      rendered prompt -- inside whatever prefix an Ollama-style single-slot cache
#      can reuse. `report` differs on every candidate, so anything placed AFTER it
#      (the per-candidate tail this flag uses for a pinned category) can never be
#      served from cache anyway; moving the unpinned case there too would forfeit
#      the cache reuse it already had, for zero token savings. (An earlier version of
#      this flag did exactly that, unconditionally -- fixed 09-04.)
#
#      A pinned candidate has nothing to protect by staying in the system prompt --
#      its category varies with which rule_id resolved, so it was never going to be
#      identical between two differently-pinned candidates regardless of where it
#      lived. Moving JUST the pinned case to the tail is pure upside: fewer tokens
#      sent, and every pinned candidate's system prompt becomes the SAME text
#      regardless of which category got pinned (no category name is embedded there
#      either way), so pinned-to-pinned calls stay just as cacheable on that constant
#      portion as unpinned-to-unpinned calls always were.
#
#      Off by default: the cost of turning it on is the model never seeing a pinned
#      candidate's other categories -- pure upside only if you trust the rule_id map.
#      No effect unless ANALYZER_CATEGORY_FROM_RULE_ID is also on, and no effect at
#      all on multi or single (single_extension), which have no per-candidate
#      pinning to shrink.
#      Env: RULE_INFER_CATEGORY_PROMPT (default off)
RULE_INFER_CATEGORY_PROMPT = _env_bool("RULE_INFER_CATEGORY_PROMPT", False)

# rule_id -> category map for the flag above. Longest matching '/'-separated prefix
# wins, so an entry of "chrome/trigger/storage" also catches
# "chrome/trigger/storage/set". Values MUST be real category names. Leave genuinely
# ambiguous rule_ids out (a missing entry means "ask the model").
#
# Complete as of EXPERIMENTS.md 44: cross-checked against the actual CodeQL query
# pack (55 .ql files, each with an `@id` matching a `query` value below -- see
# queries_1778867646/chrome/**/*.ql, one @id per query) AND against every distinct
# `query` observed across all local datasets (k_datasets/codeql_2026_final,
# _100, _13, _select -- the union is exactly the 51 of 55 queries that have ever
# fired; codeql_2026_final_select alone, 4922 reports/15310 findings, already
# contains that full union). The remaining 4 queries have never fired locally and
# are mapped from their QLDoc @description instead of a sampled `message`; flagged
# below. One rule_id is deliberately left unmapped.
#
# Categories were assigned by reading a sample of each fired rule_id's actual
# `message`/`flow` content, not by guessing from the name -- the naming turned out
# to be a real trap (see the network-request entry below). Two axes recur in the
# names and are otherwise easy to misread:
#   "trigger"      -- SOURCE only: an attacker-controlled entry point reaches the
#                      sensitive API, but the query does not confirm the result leaves
#                      the extension.
#   "exfiltration" -- SOURCE *and* SINK: the query additionally confirms the API's
#                      result reaches an attacker-reachable sink (postMessage,
#                      onMessageExternal, port.postMessage, ...).
# Both variants of a read API (get/getAll/getTree/getRecent/search/...) still map to
# the SAME category -- data_exfiltration is defined by which API was read, not by how
# much of the round trip one specific query happened to confirm; "trigger" is simply
# the lower-confidence sibling of "exfiltration" for the same finding class.
# "reachability" is a third, even-lower-confidence variant with the same property
# (SOURCE only, no taint-verified parameter) and is mapped the same way, per API.
ANALYZER_RULE_ID_CATEGORY_MAP = {
    # -- data_exfiltration: reads a user-sensitive store -------------------- (29 rule_ids, 3110 findings)
    "chrome/trigger/storage/get": "data_exfiltration",                # 203
    "chrome/exfiltration/storage/get": "data_exfiltration",           # 2282
    "chrome/exfiltration/bookmarks/get-tree": "data_exfiltration",    # 17
    "chrome/exfiltration/bookmarks/get": "data_exfiltration",         # 2
    "chrome/exfiltration/bookmarks/get-recent": "data_exfiltration",  # 0 (query pack only, see below)
    "chrome/exfiltration/bookmarks/search": "data_exfiltration",      # 9
    "chrome/exfiltration/cookies/get": "data_exfiltration",           # 129
    "chrome/exfiltration/cookies/get-all": "data_exfiltration",       # 176
    "chrome/exfiltration/history/get-visits": "data_exfiltration",    # 2
    "chrome/exfiltration/history/search": "data_exfiltration",        # 11
    "chrome/exfiltration/management/get-all": "data_exfiltration",    # 11
    "chrome/exfiltration/management/get": "data_exfiltration",        # 5
    "chrome/exfiltration/management/get-self": "data_exfiltration",   # 22
    "chrome/exfiltration/topsites/get": "data_exfiltration",          # 5
    "chrome/reachability/bookmarks/get-tree": "data_exfiltration",    # 21
    "chrome/reachability/management/get-all": "data_exfiltration",    # 16
    "chrome/reachability/management/get-self": "data_exfiltration",   # 15
    "chrome/reachability/history/search": "data_exfiltration",        # 18
    "chrome/reachability/topsites/get": "data_exfiltration",          # 8
    "chrome/trigger/bookmarks/search": "data_exfiltration",           # 5
    "chrome/trigger/bookmarks/get": "data_exfiltration",              # 2
    "chrome/trigger/bookmarks/get-recent": "data_exfiltration",       # 0 (query pack only, see below)
    "chrome/trigger/cookies/get": "data_exfiltration",                # 15
    "chrome/trigger/cookies/get-all": "data_exfiltration",            # 22
    "chrome/trigger/history/get-visits": "data_exfiltration",         # 0 (query pack only, see below)
    "chrome/trigger/history/search": "data_exfiltration",             # 5
    "chrome/trigger/management/get": "data_exfiltration",             # 4
    "browser/exfiltration/storage/get-item": "data_exfiltration",     # 95 (Firefox WebExtension namespace)
    "browser/trigger/storage/get-item": "data_exfiltration",          # 10

    # -- storage: writes/mutates a user-sensitive store ---------------------- (20 rule_ids, 6405 findings)
    "chrome/trigger/storage/set": "storage",                                   # 5038
    "chrome/trigger/storage/remove": "storage",                                # 161
    "chrome/trigger/cookies/set": "storage",                                   # 103
    "chrome/trigger/cookies/remove": "storage",                                # 46
    "chrome/trigger/management/set-enabled": "storage",                        # 33
    "chrome/trigger/management/uninstall": "storage",                          # 2
    "chrome/trigger/declarative-net-request/update-dynamic-rules": "storage",  # 55
    "chrome/reachability/management/uninstall-self": "storage",                # 76
    "chrome/reachability/storage/clear": "storage",                            # 389
    "chrome/reachability/history/delete-all": "storage",                       # 3
    "chrome/trigger/bookmarks/create": "storage",                              # 18
    "chrome/trigger/bookmarks/remove": "storage",                              # 5
    "chrome/trigger/bookmarks/remove-tree": "storage",                         # 2
    "chrome/trigger/history/add-url": "storage",                               # 1
    "chrome/trigger/history/delete-url": "storage",                            # 2
    "chrome/trigger/history/delete-range": "storage",                         # 0 (query pack only, see below)
    "browser/trigger/storage/set-item-key": "storage",                         # 67
    "browser/trigger/storage/set-item-value": "storage",                      # 378
    "browser/trigger/storage/remove-item": "storage",                          # 20
    "browser/reachability/storage/clear": "storage",                           # 6

    # -- code_execution -------------------------------------------------------- (3 rule_ids, 218 findings)
    "chrome/trigger/eval": "code_execution",                        # 80
    "chrome/trigger/tabs/execute-script": "code_execution",         # 103
    "chrome/trigger/set-timeout-set-interval": "code_execution",    # 35

    # -- download ------------------------------------------------------------- (1 rule_id, 116 findings)
    "chrome/trigger/downloads/download": "download",

    # -- 2way_request ----------------------------------------------------- (1 rule_id, 1134 findings)
    # NOT "data_exfiltration": every sampled message for this rule_id is "SINK
    # window.postMessage/onMessageExternal.addListener/port.postMessage & REQUEST
    # Fetch.../XmlHttpRequest" -- a network request whose RESPONSE is confirmed reaching
    # an attacker-controlled sink, which is exactly the definition of 2way_request. It
    # is not a read of bookmarks/cookies/history/storage/topSites/management, so it does
    # not fit data_exfiltration's own definition despite the query's name. A prior
    # version of this map used a blanket "chrome/exfiltration" prefix, which silently
    # mapped these findings to data_exfiltration -- caught by cross-run category
    # agreement analysis (EXPERIMENTS.md 42.1), not by inspection.
    "chrome/exfiltration/network-request": "2way_request",

    # Deliberately ABSENT: "chrome/trigger/network-request" (4327 findings, 28.3% of
    # codeql_2026_final_select -- the single largest rule_id by far). Its message is
    # always "SOURCE ... & REQUEST ..." with no SINK field, so the report never
    # confirms whether the response reaches the attacker -- it may be 1way_request or
    # 2way_request and only the code (or the model reading it) can tell. This is not a
    # context-width problem: even block vs. module (two wide scopes) disagree with each
    # other on this rule_id's category 69% of the time (EXPERIMENTS.md 42.1) -- the
    # ambiguity is inherent to the query, not something more code context resolves.
}
# The 4 rows marked "query pack only" above (chrome/exfiltration/bookmarks/get-recent,
# chrome/trigger/bookmarks/get-recent, chrome/trigger/history/delete-range,
# chrome/trigger/history/get-visits) have 0 findings in every local dataset -- verified
# by reading their .ql source's @description instead of a real report message (bookmarks
# getRecent = another bookmarks read; history deleteRange = another history write;
# history getVisits = another history read -- consistent with their siblings above, no
# surprises). Included for completeness since the query exists and could still fire on
# an extension outside the datasets sampled so far.
#
# Query pack location (for anyone re-verifying this map): a world-readable copy lives at
# /home/gobbi/experiment/RESULTS/codeql/queries_1778867646/chrome/**/*.ql -- each file's
# `@id` QLDoc tag is the rule_id string this map keys on 1:1.

# (8a) Prompt: tell the categorize step that a CodeQL `*/network-request` finding can
#      only be 1way_request or 2way_request. This is the one rule_id the map above
#      deliberately leaves unmapped (genuinely ambiguous from the report alone -- see
#      the comment above `ANALYZER_RULE_ID_CATEGORY_MAP`), and it is the single largest
#      rule_id in the dataset (28.3% of codeql_2026_final_select). A traced miscategorization
#      (EXPERIMENTS.md 45.1) showed the LLM landing on `storage` when the code excerpt
#      happened to make an unrelated storage write more legible than the actual network
#      sink; measured off-menu rate (a category other than 1way/2way_request) was 3.8% at
#      `module` scope but 22-24% at `lines` scope (EXPERIMENTS.md 45.2) -- a schema enum is
#      not restricted per rule_id today, so this is a soft nudge, not a hard guarantee.
#      Zero effect on any other rule_id or on non-CodeQL tools (the hint names CodeQL's
#      report format explicitly, so it reads as inapplicable on a CoCo/DoubleX report).
#      Env: PROMPT_CQL_NETWORK_HINT (default on)
PROMPT_CQL_NETWORK_HINT = _env_bool("PROMPT_CQL_NETWORK_HINT", True)

# (9) Prompt: add a storage/data_exfiltration TP reminder to the TP/FP decision
#     (the multi pipeline's classify step for those two categories, and the single
#     pipeline's whole-task prompt). Counters the two FP mistakes weaker local models
#     make -- demanding exfiltration for a plain storage WRITE, and treating
#     attacker-controlled input as a reason for FP -- and restates that a
#     domain-restricted finding is still a TP. Env: PROMPT_INCLUDE_STORAGE_TP_HINT
#     (default off)
PROMPT_INCLUDE_STORAGE_TP_HINT = _env_bool("PROMPT_INCLUDE_STORAGE_TP_HINT", False)

# (10) Which verdict-rules block the TP/FP decision gets, selected by key from
#      analyzer/prompt_sections.py RESULT_RULES_VARIANTS. Each variant is a complete,
#      self-contained block so you can edit or add one without disturbing the others,
#      keeping A/B comparisons valid:
#        "none" - no verdict guidance at all (ablation)
#        "1"    - original wording, TP/FP only. HISTORICAL BASELINE. Declares wrong
#                 FPs "even worse" than wrong TPs, which biases the model toward TP
#                 (measured ~96% TP, logprob confidence pinned at 1.0).
#        "2"    - original wording + the NA verdict (what earlier NA runs used)
#        "3"    - symmetric, evidence-based: both verdicts carry a burden of proof
#                 (TP must name entry point + path + privilege; FP must name the
#                 specific blocker). No NA.
#        "4"    - variant 3 + NA: when NEITHER burden is met the answer is NA rather
#                 than a guess. The intended corrective for TP inflation.
#        "5"    - exploitability-STRICT, TP/FP only. Treats CodeQL's SOURCE as a claim
#                 to verify; a TP must positively show (a) a genuinely external entry
#                 [rejects internal/library/packaged-file sources], (b) attacker
#                 control with NO sender/origin/validation guard, (c) extension
#                 privilege; cancels the "a write is automatically a vuln" nudge; and
#                 resolves an UNCONFIRMED finding (deciding code not shown) to FP.
#                 Highest TP precision, lower recall -- the Gemini/Prompt_CodeQL.md
#                 high-FP behaviour, aimed at cutting unexploitable TPs (see
#                 PIPELINE_CHANGES §6b).
#        "6"    - variant 5's strictness + NA: an unconfirmed-because-UNSEEN finding
#                 becomes NA (human review) instead of FP; FP stays reserved for an
#                 IDENTIFIED blocker. Recommended for the paper -- honest about "could
#                 not tell" without discarding real vulns as false.
#      Whether the variant describes NA also decides whether "NA" is in the schema
#      enum (prompt_sections.RESULT_RULES_WITH_NA -> schemas.result_values), so the
#      prompt and the allowed outputs can never disagree. NA findings are non-TP
#      downstream: no payload step, and the verifier skips them.
#      Env: RESULT_RULES (default "2" = the behaviour of the runs so far; set "5"/"6"
#      for the exploitability-strict prompt aimed at verification accuracy)
RESULT_RULES = _env_str("RESULT_RULES", "2")

# (11) Thinking-block instructions, selected by key from analyzer/prompt_sections.py
#      REASONING_PROMPT_VARIANTS. Injected LAST into the classify prompt (multi) and
#      the single pipeline's whole-task prompt -- the two whose `result` logprob is
#      measured. The payload step never carries it.
#
#      WHY (EXPERIMENTS.md §21.11 / D48). With a vLLM reasoning parser the trace
#      states its verdict and the JSON field copies it, so the measured token is a
#      transcription, not a decision: 57% of verdict tokens had no runner-up in
#      top_logprobs and 69/156 candidates tied at exactly 1.0 (§20.1). Telling the
#      model to finish the analysis but NOT to announce a verdict inside the thinking
#      moves the decision back to the token that is actually measured. This is the
#      only confidence option on the table that keeps the per-label split
#      (confidence_tp / confidence_fp); every other route in §21 yields a single
#      uncertainty scalar.
#        "none" - no section at all. DEFAULT, and what every run before 08-23 did.
#        "1"    - conclusion suppression only. The clean A/B against "none": exactly
#                 one variable changes. Use this first.
#        "2"    - variant 1 + a two-sided evidence ledger, with an explicit licence
#                 for one side to be empty so the ledger does not invite invented
#                 guards/callers.
#        "3"    - variant 2 + hold both readings open + name the one piece of missing
#                 evidence when the code does not settle it. Strongest anti-lock-in,
#                 highest over-hedging risk on easy findings.
#
#      NO EFFECT without a server-side reasoning parser: guided decoding from token 0
#      leaves no room for a thinking block at all (§20.2), and the section is then
#      just wasted prompt tokens.
#
#      Measuring it needs no hand-labelling. Run 12-26 is the control -- 57% censored,
#      confidence p50 1.0000, median loser 3.0e-04 -- so re-running the same
#      candidates says immediately whether the lock-in weakened. Watch for leakage:
#      the model may still write "so the answer is TP" despite the instruction.
#      Env: REASONING_PROMPT (default "none")
REASONING_PROMPT = _env_str("REASONING_PROMPT", "none")

# (11) Take the confidence driving the context loopback from the MODEL'S TOKEN
#      LOGPROBS instead of the number it writes into the `confidence` field.
#      Self-reported confidence is a stylistic token, not a measurement -- in
#      practice it pins to 1.0/0.95 and the loopback never fires. The logprob of the
#      actual TP/FP/NA token is a real probability from the model.
#      Flow per decision: read p(chosen verdict), normalised over the allowed
#      verdicts; while p < CONFIDENCE_THRESHOLD_CLASS, re-run at the next-wider code
#      context (up to CONFIDENCE_MAX_LOOPBACKS extra tries); if it is still below
#      threshold when the retries run out, record the verdict as "NA" (needs a
#      RESULT_RULES variant that defines NA; otherwise the verdict is kept and only
#      flagged). Requires CONFIDENCE_LOOPBACK_ENABLED and a provider that returns
#      logprobs (vllm/openai). Ollama has no logprobs on /api/chat, so the run falls
#      back to the self-reported number. Multi pipeline only: the single pipeline
#      emits many verdicts per call, so no single token carries "the" decision.
#      Independent of feature 12 below -- turning the source measurement off leaves
#      this one exactly as it is.
#      Env: CONFIDENCE_FROM_LOGPROBS (default on)
CONFIDENCE_FROM_LOGPROBS = _env_bool("CONFIDENCE_FROM_LOGPROBS", True)
# How many alternatives to ask the server for at the verdict token; must be >= the
# number of allowed verdicts so the probability can be normalised over them.
# Env: LOGPROBS_TOP_N
LOGPROBS_TOP_N = int(_env_str("LOGPROBS_TOP_N", "20"))

# (13) Which occurrence of the verdict key to measure in the logprob stream, for a
#      REASONING model. Its <think> trace discusses the JSON before emitting it, so
#      the key (e.g. `"result":`) appears mid-deliberation FIRST and in the final JSON
#      LAST; measuring the first occurrence scores a thinking token, not the decision.
#      Observed on run 2026-08-15_19-11-48 (reasoning model): confidence_class pinned
#      to the 0.333-0.80 band (0.333 = 1/3, uniform over {TP,FP,NA}), got WORSE with
#      more context, AUC 0.449 (no ranking power) -- while confidence_source from the
#      identical code path stayed healthy (median 0.999), because attacker_source
#      rarely appears verbatim in prose.
#        "last"  - measure the LAST occurrence that resolves to a verdict (the emitted
#                  JSON) -> reasoning-safe. For a NON-reasoning model the key appears
#                  once, so last == first and prior (MoE) runs are unchanged.
#        "first" - original behaviour; reproduces the broken extraction for A/B.
#      Complementary server-side option: configure a vLLM reasoning parser so the
#      thinking lands in `reasoning_content` and `content`/logprobs hold only the JSON.
#      Env: LOGPROB_VERDICT_MATCH (default "last")
LOGPROB_VERDICT_MATCH = _env_str("LOGPROB_VERDICT_MATCH", "last")

# (12) Also measure the payload step's attacker_source (Website/Extension) token and
#      let it veto the finding. On top of the classify step's TP/FP/NA measurement,
#      this scores the payload step's one discrete decision -- the execution context
#      the exploit is written for. Rationale: a confidently-TP finding whose
#      attacker_source was a coin flip still produces a payload aimed at the wrong
#      context, which the verifier then writes off (this really happened: the same
#      extension flipped Extension->Website between two runs on identical prompts).
#      A decision counts as unsure when EITHER measurement is under ITS OWN threshold
#      (CONFIDENCE_THRESHOLD_CLASS / _SOURCE), not when their minimum is -- the two
#      questions are judged separately.
#      Both numbers are always written to the result (confidence_class,
#      confidence_source) regardless of this flag; the flag only decides whether the
#      source measurement gets a VOTE in the retry/NA decision. Turning it off does
#      not affect the TP/FP measurement in any way.
#      Cost: an escalation re-runs classify AND payload, since wider code can change
#      either answer. Needs CONFIDENCE_FROM_LOGPROBS + a logprob-capable provider.
#      Env: CONFIDENCE_INCLUDE_SOURCE (default on)
CONFIDENCE_INCLUDE_SOURCE = _env_bool("CONFIDENCE_INCLUDE_SOURCE", True)

# Performance Settings
# Env: MAX_PROMPT_TOKENS (int; "none"/"null" to disable the limit)
MAX_PROMPT_TOKENS = _env_int_or_none("MAX_PROMPT_TOKENS", 500000)  # Skip extensions with prompts exceeding this token count (None = no limit)
# Env: PARALLEL_WORKERS (int; always required downstream, so no "none" option here)
PARALLEL_WORKERS = int(_env_str("PARALLEL_WORKERS", "10"))  # Number of parallel API requests (1 = sequential, 10 = recommended for Gemini)

# How those PARALLEL_WORKERS threads are spent. Env: PARALLEL
#   none / false - fully sequential (one request in flight); PARALLEL_WORKERS ignored.
#   inter        - parallelize ACROSS extensions; each worker runs one extension's
#                  candidate chain sequentially (the original PARALLEL_WORKERS>1
#                  behaviour). Simple, but concurrent requests come from different
#                  extensions, so they share little prompt prefix.
#   intra        - one extension at a time; parallelize ITS candidates across the
#                  workers. Best prompt-cache locality (every in-flight request shares
#                  the same extension's manifest/code prefix), but workers idle when an
#                  extension has fewer candidates than workers.
#   rolling      - a global candidate queue that PRIORITISES the current extension
#                  (intra-style locality) and backfills any spare worker slots with the
#                  next extensions' candidates (inter fallback). Best utilisation while
#                  keeping locality high.
# Candidates within one extension are independent, so intra/rolling parallelise them
# safely; each extension's result file is written once all its candidates finish.
# intra/rolling apply to the MULTI pipeline (which has per-candidate steps); for the
# SINGLE pipeline (one call per extension) intra runs sequentially and rolling behaves
# like inter. Reproducibility note: for a seeded/deterministic run keep this at `none`
# (or PARALLEL_WORKERS=1) -- concurrent batching makes vLLM/Ollama numerics depend on
# batch composition. Env: PARALLEL
PARALLEL = _env_str("PARALLEL", "intra")

# Ollama
OLLAMA_MODEL_PRESET = _env_str("OLLAMA_MODEL_PRESET", "gemma4")  # Env: OLLAMA_MODEL_PRESET
OLLAMA_TIMEOUT = _env_seconds("OLLAMA_TIMEOUT", 300)  # Env: OLLAMA_TIMEOUT (seconds)
OLLAMA_TEMPERATURE = float(_env_str("OLLAMA_TEMPERATURE", "0"))  # deterministic by default
# Context window (num_ctx) sent with each request. Ollama's default is small
# (~4k), which silently truncates large report+code prompts and yields malformed
# JSON; set this to your model's real context length. Env: OLLAMA_NUM_CTX
OLLAMA_NUM_CTX = int(_env_str("OLLAMA_NUM_CTX", "16384"))
# How long the server keeps the model (and with it the prompt/KV cache) loaded
# after a request. Unloading discards the cached prefix, so every gap longer than
# this costs a full prefill on the next call -- keep it comfortably above the
# pauses between requests (report parsing, code extraction, result writing).
# Accepts Ollama's duration syntax ("30m", "1h", "-1" = never unload, "0" =
# unload immediately). Env: OLLAMA_KEEP_ALIVE
OLLAMA_KEEP_ALIVE = _env_str("OLLAMA_KEEP_ALIVE", "30m")
OLLAMA_PRESETS = {
    'llama': 'llama3.3:latest',
    'qwen': 'qwen3-coder:30b',
    'deepseek': 'deepseek-r1:32b',
    'deepseekCoder': 'deepseek-coder-v2:16b',
    'gemma4': 'gemma4:latest'
}
# Env: OLLAMA_MODEL (explicit model name/tag). Unset/empty -> resolved from
# OLLAMA_MODEL_PRESET via OLLAMA_PRESETS (falling back to the preset value itself
# if it isn't a known preset key).
OLLAMA_MODEL = _env_str("OLLAMA_MODEL", OLLAMA_PRESETS.get(OLLAMA_MODEL_PRESET, OLLAMA_MODEL_PRESET))

# Connection mode: by default talk to an Ollama server exposed directly on a
# host:port (the primary use case). Set OLLAMA_USE_SSH_TUNNEL=true to instead
# forward to a remote Ollama over SSH (legacy path).
OLLAMA_USE_SSH_TUNNEL = (os.getenv("OLLAMA_USE_SSH_TUNNEL") or "false").strip().lower() in ("1", "true", "yes", "on")
OLLAMA_HOST = _env_str("OLLAMA_HOST", "127.0.0.1")   # host of the exposed Ollama server
OLLAMA_PORT = int(_env_str("OLLAMA_PORT", "11434"))  # port of the exposed Ollama server

# SSH tunnel settings (only used when OLLAMA_USE_SSH_TUNNEL is true)
OLLAMA_SSH_HOST = os.getenv("OLLAMA_SSH_HOST")
OLLAMA_SSH_PORT = int(os.getenv("OLLAMA_SSH_PORT")) if os.getenv("OLLAMA_SSH_PORT") else 22
OLLAMA_SSH_USER = os.getenv("OLLAMA_SSH_USER")
OLLAMA_SSH_PASSWORD = os.getenv("OLLAMA_SSH_PASSWORD")

# ----------------------------------------------------------------------------
# vLLM (OpenAI-compatible server on host:port)
# ----------------------------------------------------------------------------
# Reached directly over http://HOST:PORT, exactly like the Ollama endpoint. The
# key difference: a vLLM server serves ONE model chosen at launch (`vllm serve
# <model>`), so there is no model preset here -- the served name is auto-detected
# from GET /v1/models and only needs VLLM_MODEL when several are served or you
# want to skip the lookup. Structured output uses vLLM's guided decoding (the
# JSON schema constrains generation, same role as Ollama's `format`).
#
# Caching: vLLM keeps the model resident and does automatic prefix caching
# server-side (enable with --enable-prefix-caching at serve time on older builds;
# on by default on recent ones). So PROMPT_CACHE_OPTIMIZED's stable-prefix layout
# pays off here too, and there is NO per-request keep_alive to set -- that knob is
# Ollama-specific. For reproducible runs set VLLM_SEED (with VLLM_TEMPERATURE=0
# and a fixed served model/version) rather than relying on cache state.
VLLM_HOST = _env_str("VLLM_HOST", "127.0.0.1")   # host of the exposed vLLM server
VLLM_PORT = int(_env_str("VLLM_PORT", "8000"))   # port of the exposed vLLM server
VLLM_TIMEOUT = _env_seconds("VLLM_TIMEOUT", 300)  # Env: VLLM_TIMEOUT (seconds)

# The served model name is required in each request but is fixed at serve time.
# Leave VLLM_MODEL empty to auto-detect it from GET /v1/models; set it to skip the
# lookup or to pick one when several models are served. Env: VLLM_MODEL
VLLM_MODEL = _env_str("VLLM_MODEL", "")

# Optional bearer token -- only needed if the server was started with --api-key.
# Env: VLLM_API_KEY
VLLM_API_KEY = _env_str("VLLM_API_KEY", "")

# -- per-request sampling (all env-overridable) --
VLLM_TEMPERATURE = float(_env_str("VLLM_TEMPERATURE", "0"))  # 0 = greedy/deterministic
VLLM_TOP_P = float(_env_str("VLLM_TOP_P", "1.0"))            # nucleus sampling cutoff
# Penalises a token in proportion to how often it has ALREADY been generated in
# this response (vLLM: logit -= penalty * count, over output tokens only). 0 = off,
# and off is the default: the field is omitted from the request entirely when 0, so
# a run without it is byte-identical to every run before this knob existed.
#
# WHY it exists: at temperature 0 the model can fall into a degenerate repetition
# loop -- observed as ~124k newline characters emitted inside an unterminated
# `fp_explanation` string, which burns the whole VLLM_MAX_TOKENS budget and returns
# either finish_reason='length' (unparseable) or a read timeout. See EXPERIMENTS.md
# 48-52. Any nonzero value breaks the loop; the effect is a tie-break, not a graded
# brake, so magnitude barely matters below ~0.01 (52: identical outcome from 1e-4 to
# 1e-2). It is NOT free -- it perturbs healthy long answers too and can itself turn a
# working candidate unparseable (D207) -- so it is deliberately off by default and
# is best applied only when retrying a candidate that already failed.
#
# RECOMMENDED VALUE when you do enable it: 0.001. Measured on 8 long-FP controls
# (EXPERIMENTS.md 53.1), every value in 1e-4..5e-3 fixes the loop with identical
# disruption (4/8 byte-identical, 1/8 confidence moved, ZERO new parse failures),
# while 0.01 -- the value quoted earlier in 48-52 -- is exactly where a healthy
# candidate starts breaking (1/8), and 0.02 is worse again. Do not raise it above
# 0.005 without re-measuring.
# Env: VLLM_FREQUENCY_PENALTY
VLLM_FREQUENCY_PENALTY = float(_env_str("VLLM_FREQUENCY_PENALTY", "0"))
# Max tokens to GENERATE per request (separate from the prompt). Structured JSON
# answers are small; raise if a schema can yield long output. With a reasoning
# parser this budget covers the <think> trace AND the JSON, so a long trace can
# consume all of it -- see VLLM_THINKING_TOKEN_BUDGET. Env: VLLM_MAX_TOKENS
VLLM_MAX_TOKENS = int(_env_str("VLLM_MAX_TOKENS", "2048"))

# Cap on the REASONING half of that budget, i.e. how many tokens the model may
# spend inside <think> before vLLM force-emits the reasoning_end_str and makes it
# start answering. vLLM's own request field is `thinking_token_budget`; this knob
# maps to it 1:1, like VLLM_MAX_TOKENS -> max_tokens.
#
# WHY it exists: VLLM_MAX_TOKENS is a single budget shared by the trace and the
# JSON, and the trace is drawn first. A model that thinks past the cap never
# closes </think>, so vLLM's parser puts everything in `reasoning_content` and
# returns `content: null` -- the answer is simply missing, and the candidate dies
# with a step error (EXPERIMENTS.md 35). Budgeting the trace leaves guaranteed
# room for the JSON instead of racing it for the same tokens. Rule of thumb: set
# it a few thousand tokens below VLLM_MAX_TOKENS so the schema always fits.
#
# REQUIRES a server-side reasoning parser (`--reasoning-parser qwen3`,
# `deepseek_r1`, ...). Without one, vLLM ignores it (older builds 400 on the
# unknown field), which is why the default leaves it off the request entirely.
# Unset/empty or "none" = no budget = current behaviour, byte-identical requests.
# Env: VLLM_THINKING_TOKEN_BUDGET
VLLM_THINKING_TOKEN_BUDGET = _env_int_or_none("VLLM_THINKING_TOKEN_BUDGET", None)

# Payload-specific override of the above. Today every step (categorize, classify,
# payload) shares the one VLLM_THINKING_TOKEN_BUDGET on every request -- there is no
# per-step distinction. This is the first one: PAYLOAD_THINKING opts payload OUT of
# that shared value and onto its own.
#
# MULTI PIPELINE ONLY. It names a payload *call*, and only PIPELINE_MODE=multi has
# one; single / single_vulnerability decide the payload inside the same request as
# the verdict, so those runs always send VLLM_THINKING_TOKEN_BUDGET (main.py prints a
# NOTE when the flag is set on such a run).
#
# PAYLOAD_THINKING=false (default): no change from today -- payload keeps using
# VLLM_THINKING_TOKEN_BUDGET like every other step.
# PAYLOAD_THINKING=true: payload's request uses PAYLOAD_THINKING_BUDGET instead,
# falling back to VLLM_THINKING_TOKEN_BUDGET (i.e. "the same budget as classify")
# when PAYLOAD_THINKING_BUDGET itself is unset -- so turning this on with no budget
# set is a no-op; set a distinct PAYLOAD_THINKING_BUDGET to actually diverge.
# Unset/empty/"none" for the budget = no cap sent = left out of the request, exactly
# like VLLM_THINKING_TOKEN_BUDGET's own empty state.
# Env: PAYLOAD_THINKING (default false), PAYLOAD_THINKING_BUDGET (default: falls
# back to VLLM_THINKING_TOKEN_BUDGET)
PAYLOAD_THINKING = _env_bool("PAYLOAD_THINKING", False)
PAYLOAD_THINKING_BUDGET = _env_int_or_none("PAYLOAD_THINKING_BUDGET", None)


def payload_thinking_budget():
    """The `thinking_token_budget` to send for a payload-step request, or None.

    None means "send nothing, fall back to whatever _vllm_structured's own default
    resolves to" (VLLM_THINKING_TOKEN_BUDGET) -- returned whenever PAYLOAD_THINKING
    is off, so a run that never touches this setting is byte-identical to before it
    existed.
    """
    if not PAYLOAD_THINKING:
        return None
    return PAYLOAD_THINKING_BUDGET if PAYLOAD_THINKING_BUDGET is not None \
        else VLLM_THINKING_TOKEN_BUDGET


# Sampling seed for run-to-run reproducibility. Set any int for experiment
# determinism (pair with VLLM_TEMPERATURE=0 and a fixed served model/version);
# leave empty/"none" for nondeterministic sampling. Env: VLLM_SEED
VLLM_SEED = _env_int_or_none("VLLM_SEED", None)

# How to ask vLLM for schema-constrained (structured) output:
#   "response_format" - OpenAI-style response_format={"type":"json_schema",...}
#                       (vLLM ~0.6.x and newer). Default.
#   "guided_json"     - vLLM's native `guided_json=<schema>` extra field; use this
#                       if an older server rejects the response_format form.
# Env: VLLM_STRUCTURED_MODE
VLLM_STRUCTURED_MODE = _env_str("VLLM_STRUCTURED_MODE", "response_format")
# Optional guided-decoding backend hint ("xgrammar", "outlines", ...). Empty uses
# the server default. Env: VLLM_GUIDED_BACKEND
VLLM_GUIDED_BACKEND = _env_str("VLLM_GUIDED_BACKEND", "")

# OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-5"
OPENAI_TIMEOUT = 300

# Anthropic
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = "claude-opus-4-5"
ANTHROPIC_TIMEOUT = 300

# Google Gemini (shared settings for regular and batch API)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_TIMEOUT = 300

# Gemini Batch Mode Configuration
# Mode options:
#   'submit'  - Create batch and exit (for long-running jobs)
#   'retrieve' - Download existing batch results (requires GEMINI_BATCH_NAME)
#   'auto'    - Submit batch and wait for completion (blocks until done)
#   'list'    - List recent batch jobs
#   'cancel'  - Cancel a running batch job (requires GEMINI_BATCH_NAME)
#   'delete'  - Delete a batch job (requires GEMINI_BATCH_NAME)
GEMINI_BATCH_MODE = 'submit'
GEMINI_BATCH_NAME = None  # Required for 'retrieve', 'cancel', 'delete' modes
GEMINI_BATCH_CHECK_INTERVAL = 10  # Seconds between status checks when waiting for batch completion
GEMINI_BATCH_LIST_LIMIT = 10  # Maximum number of batch jobs to list in 'list' mode


# ============================================================================
# VERIFIER CONFIGURATION (for verify_extensions.py)
# ============================================================================

# Paths
# All four verifier settings below may be overridden via environment variables of
# the same name (e.g. `docker run --env-file .env.config1`). Unset/empty -> default.
RESULTS_VERIFICATION_DIR = _env_path("RESULTS_VERIFICATION_DIR", BASE_DIR / "results_verification")  # "base results folder" — the verifier will save its run folders here
CHROME_BINARY_PATH = _env_str("CHROME_BINARY_PATH", r"D:\Programme\Chrome Test Versions\chrome\win64-126.0.6478.126\chrome-win64\chrome.exe")  # path to chrome binary for playwright

# Results to verify (directory name within RESULTS_ANALYSIS_DIR)
# Options:
# - "latest": Automatically use the most recent results directory created by the analyzer
# - Custom directory name: e.g., "results_claude-opus-4-5_20250126_123456"
# The verifier will recursively find all *_result.json files in this directory (including subdirectories)
RESULTS_TO_VERIFY = _env_str("RESULTS_TO_VERIFY", "results_gemini_2026-02-18_02-09-50") #"latest"

# Resume an interrupted verification run instead of starting fresh
# Options:
# - None: Start a new run (default)
# - "latest": Resume the most recently created verification results directory
# - Custom directory name: e.g., "results_manual_reference_1"
# Extensions that already have a *_verification.json will be skipped automatically
RESUME_VERIFICATION_RUN = None

# ----------------------------------------------------------------------------
# Timeouts (all values in seconds)
# ----------------------------------------------------------------------------
# Each timeout may be overridden by an environment variable / .env entry of the
# same name. If that variable is unset or empty, the default below is used.

# Wait for payload detection (network/console/download).
# Increase if extensions are slow to process payloads.
PAYLOAD_EXECUTION_TIMEOUT = _env_seconds("PAYLOAD_EXECUTION_TIMEOUT", 3)

# Wait for a page navigation (page.goto) to reach DOMContentLoaded.
PAGE_NAVIGATION_TIMEOUT = _env_seconds("PAGE_NAVIGATION_TIMEOUT", 30)

# Wait when re-navigating to example.com before a detection retry.
RETRY_NAVIGATION_TIMEOUT = _env_seconds("RETRY_NAVIGATION_TIMEOUT", 15)

# Wait for navigation into the extension context (verify_storage.html).
EXTENSION_CONTEXT_NAVIGATION_TIMEOUT = _env_seconds("EXTENSION_CONTEXT_NAVIGATION_TIMEOUT", 2)

# Wait while discovering the runtime extension ID.
EXTENSION_ID_DISCOVERY_TIMEOUT = _env_seconds("EXTENSION_ID_DISCOVERY_TIMEOUT", 5)

# Wait for a browser context to close before giving up and continuing.
BROWSER_CLOSE_TIMEOUT = _env_seconds("BROWSER_CLOSE_TIMEOUT", 10)

# Wait for a single page to close before giving up and continuing.
PAGE_CLOSE_TIMEOUT = _env_seconds("PAGE_CLOSE_TIMEOUT", 5)

# ----------------------------------------------------------------------------
# Extension ID resolution
# ----------------------------------------------------------------------------

# Compute the runtime ID of unpacked extensions from their absolute path instead
# of waiting for a chrome-extension:// URL to appear at runtime.
#
# Chrome derives the ID of an extension loaded via --load-extension (i.e. without
# a 'key' in its manifest) from the extension directory itself:
#   crx_file::id_util::GenerateIdForPath() -> SHA256(absolute path)[:16], with
#   every hex digit mapped onto the alphabet 'a'..'p'.
# See components/crx_file/id_util.cc and ComputeExtensionID() in
# extensions/common/extension.cc ("If there is a path, we generate the ID from
# it. This is useful for development mode, because it keeps the ID stable").
#
# This makes the ID known *before* Chrome starts, which removes the
# EXTENSION_ID_DISCOVERY_TIMEOUT stall, removes the extra discovery browser in
# extension mode, and is the only way to get a correct ID for content-script-only
# extensions (they never expose a chrome-extension:// URL to discover).
#
# Verified against Chrome for Testing 126.0.6478.126 and 147.0.7727.15 on Linux
# (MV3 + MV2, symlinked and trailing-slash paths). Set to false to fall back to
# pure runtime discovery if a future Chrome ever changes the scheme.
DETERMINISTIC_EXTENSION_ID = _env_bool("DETERMINISTIC_EXTENSION_ID", True)

# Recover the extension ID when navigating to verify_storage.html fails.
# On failure the verifier re-reads the live browser context for chrome-extension://
# URLs and retries with those IDs, accepting a candidate only if the page it
# serves carries the verifier's marker. Prevents "Could not navigate to extension
# context" from aborting seeding when the ID in hand is wrong.
EXTENSION_CONTEXT_ID_RECOVERY = _env_bool("EXTENSION_CONTEXT_ID_RECOVERY", True)

# Browser headless mode used when launching Chrome for verification.
# Accepted values (override via HEADLESS in .env):
# - "false": visible browser window (default)
# - "true":  classic headless mode
# - "new":   Chrome's new headless mode
HEADLESS = (os.getenv("HEADLESS") or "false").strip().lower()

# DEBUG_MODE: Enable step-by-step verification with manual confirmation at each step
# When enabled, browser will NOT auto-close after verification for manual inspection
DEBUG_MODE = False

# Limit verification to a single extension (optional)
# Set to an extension ID (e.g., "aahnomepdedgbhmimgchaphhmidicnkb") to verify only that extension
# Set to None to verify all extensions inside RESULTS_TO_VERIFY
DEBUG_SINGLE_EXTENSION = None

# Limit verification to a single result file (optional) - RECOMMENDED FOR DEBUGGING
# Set to a specific result-JSON filename (e.g., "chrome_bookmarks_create_result.json")
# This will load ONLY that file instead of scanning the entire results directory
# Set to None to process all result files
DEBUG_SINGLE_RESULT_FILE = None #'chrome_bookmarks_search_result.json'

# Control extension code extraction behavior
# True: Prefer .crx file (download/extract fresh code, falls back to existing directory if .crx unavailable)
# False: Prefer existing directory (skip re-extraction, falls back to .crx if directory missing)
RESET_EXTENSION_CODE = True

# ----------------------------------------------------------------------------
# Verifier parallelism (storage / data_exfiltration only)
# ----------------------------------------------------------------------------
# Verify several extensions concurrently. Each verification already launches its
# own Chrome with its own temporary profile, so sharing the Chrome binary is not a
# problem -- but the MOCK SERVER is a process-wide singleton on the fixed port 3000
# (that port is baked into the generated payloads, so it cannot be per-worker), and
# every network detection calls reset_and_get_token(), which wipes its global
# counters. Two concurrent network verifications would therefore clear each other's
# in-flight state and mis-attribute requests -- silent false positives/negatives.
#
# So only extensions whose vulnerabilities are ALL detected without the mock server
# run in parallel:
#     parallel-safe : storage            (reads the extension's own chrome.storage)
#                     data_exfiltration  ([EXFIL] on that page's own console)
#     sequential    : 1way_request, 2way_request, code_execution, download
# An extension with any mock-server category -- even mixed with safe ones -- is
# verified sequentially, as is everything when DEBUG_MODE is on (it prompts for
# input at each step). Env: VERIFIER_PARALLEL (default on)
VERIFIER_PARALLEL = _env_bool("VERIFIER_PARALLEL", True)

# How many parallel-safe extensions to verify at once. Each one is a separate
# Chrome instance, so this is bounded by RAM/CPU rather than by the LLM server.
# 1 disables parallelism just like VERIFIER_PARALLEL=false. Env: VERIFIER_PARALLEL_WORKERS
VERIFIER_PARALLEL_WORKERS = int(_env_str("VERIFIER_PARALLEL_WORKERS", "4"))

# ----------------------------------------------------------------------------
# Verification page host (real example.com vs. local dummy server)
# ----------------------------------------------------------------------------
# The verifier navigates the browser to a "victim" page where the target
# extension's content scripts run and where website-mode payloads execute.
#
# Two modes (switch via the USE_LOCAL_VERIFICATION_SERVER env var):
#   - false (default): navigate to the real http://example.com (needs internet)
#   - true:            serve a minimal dummy page from the built-in mock server
#                      on localhost and navigate there instead (fully offline)
#
# In local mode the page is served by the SAME mock server that already acts as
# the exfiltration target, so NO additional port is opened. The mock server only
# binds 127.0.0.1:MOCK_SERVER_PORT, which does not clash with Chrome (Playwright
# drives Chrome over a CDP pipe / its own random debugging port, never 3000).
#
# NOTE: MOCK_SERVER_PORT is also baked into the generated attacker payloads (the
# analyzer prompt hardcodes http://127.0.0.1:3000/api/...), so 3000 is the
# canonical exfiltration port — change it only if you also regenerate payloads.
MOCK_SERVER_HOST = _env_str("MOCK_SERVER_HOST", "127.0.0.1")
MOCK_SERVER_PORT = int(_env_str("MOCK_SERVER_PORT", "3000"))
USE_LOCAL_VERIFICATION_SERVER = (os.getenv("USE_LOCAL_VERIFICATION_SERVER") or "false").strip().lower() in ("1", "true", "yes", "on")

if USE_LOCAL_VERIFICATION_SERVER:
    VERIFICATION_PAGE_URL = f"http://{MOCK_SERVER_HOST}:{MOCK_SERVER_PORT}"
    VERIFICATION_PAGE_DOMAIN = MOCK_SERVER_HOST
    # Chrome match patterns do not allow port numbers, so match the host on any
    # port. Literal IPs (e.g. 127.0.0.1) are accepted by externally_connectable;
    # "localhost" is NOT (it has no second-level domain), so prefer 127.0.0.1.
    EXTERNALLY_CONNECTABLE_MATCH = f"http://{MOCK_SERVER_HOST}/*"
else:
    VERIFICATION_PAGE_URL = "http://example.com"
    VERIFICATION_PAGE_DOMAIN = "example.com"
    EXTERNALLY_CONNECTABLE_MATCH = "*://example.com/*"

# ============================================================================
# VERIFIER FILTERS
# ============================================================================
# Filters are applied before any extension code is downloaded or browser is launched.
# All filters are applied to the TP-verifiable vulnerability list after initial TP filtering.
#
# Each entry may be overridden via the environment variable named in its comment
# (e.g. supplied through `docker run --env-file .env.config1`). For the list-valued
# filters, pass a single value ("data_exfiltration") or a comma-separated list
# ("data_exfiltration, storage"); pass "none" to explicitly disable a filter.
# Unset/empty variables fall back to the defaults below.

VERIFIER_FILTER = {
    # Only verify vulnerabilities of these categories. None = no filter (all categories).
    # Accepts a single string or a list: "code_execution" or ["code_execution", "1way_request"]
    # Options: "code_execution", "1way_request", "2way_request", "download", "data_exfiltration", "storage"
    # Env: VERIFIER_FILTER_VULNERABILITY_CATEGORIES
    "vulnerability_categories": _env_list("VERIFIER_FILTER_VULNERABILITY_CATEGORIES", "data_exfiltration"),

    # Only verify vulnerabilities using these storage APIs. None = no filter (all APIs).
    # Accepts a single string or a list: "chrome.storage.local.set" or ["chrome.storage.local.set", "chrome.cookies.get"]
    # Only relevant when vulnerability_category is "storage" or "data_exfiltration".
    # Env: VERIFIER_FILTER_STORAGE_APIS
    "storage_apis": _env_list("VERIFIER_FILTER_STORAGE_APIS", None),

    # Skip extensions with fewer than this many matching vulnerabilities. None = no minimum.
    # Env: VERIFIER_FILTER_MIN_VULNERABILITIES
    "min_vulnerabilities": _env_int_or_none("VERIFIER_FILTER_MIN_VULNERABILITIES", None),

    # Skip extensions with more than this many matching vulnerabilities. None = no maximum.
    # Env: VERIFIER_FILTER_MAX_VULNERABILITIES
    "max_vulnerabilities": _env_int_or_none("VERIFIER_FILTER_MAX_VULNERABILITIES", 5),
}


# ---------------------------------------------------------------------------
# Candidate prioritisation and per-extension cutoff (EXPERIMENTS.md 56-60)
# ---------------------------------------------------------------------------
# CodeQL emits every finding it can prove; the analyzer need not pay for all of
# them. These select WHICH findings of an extension are worth an LLM call.
#
# Measured on runs that analyzed everything (10 new runs + 2 Beermann-era passes,
# ~20k extension-runs), reporting retained VERIFIED EXTENSIONS at 63% of calls:
#   first_n      89.4%   position carries no signal; baseline only
#   round_robin  95.5%   same cost as first_n, just reordered
#   rule_prior   97.8%   order by the rule's historical verified-rate
#   mmr          98.4%   rule_prior plus a novelty penalty  <- best without screen
#   prior_screen_mmr 98.6% with the screen step on (+~2% cost)
#
# Strategy names: all, first_n, uniq_rule_first, round_robin, n_per_rule,
# n_per_msg, dedup_msg_first_n, dedup_msg_rr, prop_alloc, log_budget,
# greedy_cover, rule_prior, prior_rr, prior_top_rules, prior_best_rule, mmr,
# thompson, screen_top, prior_screen, prior_screen_mmr.
# Default "all" = no cutoff, byte-identical to a run made before this existed.
#   Env: ANALYZER_PRIORITY_STRATEGY
ANALYZER_PRIORITY_STRATEGY = _env_str("ANALYZER_PRIORITY_STRATEGY", "all")

# The budget. A hard per-extension cap for every strategy EXCEPT n_per_rule,
# n_per_msg, prop_alloc and log_budget, where it is per rule / per size and the
# extension total can exceed it (n_per_rule at N=1 tops out at 14 on this corpus,
# N=2 at 23, against 108 uncapped, so no separate total cap is needed).
# 0 disables the cutoff. N=3 is the measured knee.
#   Env: ANALYZER_PRIORITY_N
ANALYZER_PRIORITY_N = _env_int("ANALYZER_PRIORITY_N", 0)

# MMR trade-off: 1.0 is pure yield (novelty off), 0.0 is pure novelty. Measured
# flat across 0.6-0.9 on the two older generations, with a peak at 0.8 that did
# NOT replicate, so anything in that band is defensible and 0.5 is too low.
#   Env: ANALYZER_PRIORITY_MMR_LAM
ANALYZER_PRIORITY_MMR_LAM = _env_float("ANALYZER_PRIORITY_MMR_LAM", 0.7)

# Optional hard cap on findings from one rule under mmr. 0 = off. Measured not to
# help (the soft novelty penalty already does this job); kept for A/B.
#   Env: ANALYZER_PRIORITY_MMR_RULE_CAP
ANALYZER_PRIORITY_MMR_RULE_CAP = _env_int("ANALYZER_PRIORITY_MMR_RULE_CAP", 0)

# How much of the combined score comes from the rule prior vs the screen, for
# prior_screen / prior_screen_mmr. 1.0 = prior only, 0.0 = screen only.
#   Env: ANALYZER_PRIORITY_SCREEN_WEIGHT
ANALYZER_PRIORITY_SCREEN_WEIGHT = _env_float("ANALYZER_PRIORITY_SCREEN_WEIGHT", 0.5)

# Path to the yield prior. Defaults to rule_prior.json beside the pipeline root.
# When absent, prior-based strategies fall back to the base rate (= round_robin).
#   Env: ANALYZER_PRIORITY_PRIOR_FILE
ANALYZER_PRIORITY_PRIOR_FILE = _env_str("ANALYZER_PRIORITY_PRIOR_FILE", "")

# Seed for the thompson strategy only.
#   Env: ANALYZER_PRIORITY_SEED
ANALYZER_PRIORITY_SEED = _env_int("ANALYZER_PRIORITY_SEED", 0)

# Screening step: before classify, run one extra classify call at
# thinking_token_budget=0 purely to harvest the verdict logprob, and rank with it.
# The screen's VERDICT is never used (it agrees with a 6k-think run only 74.7% of
# the time); only its signed confidence, which ranks the expensive run's verified
# findings at AUROC 0.810. Measured cost 2.1% of a full call.
#   Env: ANALYZER_SCREEN_ENABLED
ANALYZER_SCREEN_ENABLED = _env_bool("ANALYZER_SCREEN_ENABLED", False)

# Output cap for the screen call. It emits only {"result": "TP"|"FP"}; a screen
# schema must NOT include fp_explanation (6 of 40 probe calls returned invalid
# JSON when a 600-token cap truncated that string mid-value).
#   Env: ANALYZER_SCREEN_MAX_TOKENS
ANALYZER_SCREEN_MAX_TOKENS = _env_int("ANALYZER_SCREEN_MAX_TOKENS", 40)
