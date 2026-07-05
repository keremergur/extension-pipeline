"""
Configuration file for the Chrome Extension vulnerability report analyzer.
"""

import os
from pathlib import Path
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


# ============================================================================
# GENERAL / SHARED CONFIGURATION
# ============================================================================

# Paths (used by both analyzer and verifier)
# Each may be overridden by an environment variable of the same name (e.g. supplied
# via `docker run --env-file .env.config1`). Unset/empty falls back to the default.
BASE_DIR = Path(__file__).parent # Use this as a variable if all folders are inside the same parent folder
RESULTS_ANALYSIS_DIR = _env_path("RESULTS_ANALYSIS_DIR", BASE_DIR / "results_analysis")  # The Analyzer will save its result-JSONs and the verifier will search for his result-JSONs here
EXTENSION_CODE_DIR = _env_path("EXTENSION_CODE_DIR", BASE_DIR / "extension_code")  # "base source code directory" — Analyzer and Verifier will search for the original extension code here

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
RESUME_RUN = 'results_gemini_2026-02-18_02-09-50'  # e.g., "results_gemini_2026-02-18_10-30-00"

# Paths
DATASETS_DIR = BASE_DIR / "datasets" # The Analyzer will search for CodeQL, CoCo or DoubleX datasets here

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
PROMPT_FILE = BASE_DIR / "prompts" / "Prompt.md" # Prompt template for the analyzer LLM
LLM_PROVIDER = 'gemini'  # Options: 'ollama', 'openai', 'anthropic', 'gemini', 'gemini_batch'

# Performance Settings
MAX_PROMPT_TOKENS = 500000  # Skip extensions with prompts exceeding this token count (None = no limit)
PARALLEL_WORKERS = 10  # Number of parallel API requests (1 = sequential, 10 = recommended for Gemini)

# Ollama
OLLAMA_MODEL_PRESET = 'deepseekCoder'
OLLAMA_TIMEOUT = 300
OLLAMA_PRESETS = {
    'llama': 'llama3.3:latest',
    'qwen': 'qwen3-coder:30b',
    'deepseek': 'deepseek-r1:32b',
    'deepseekCoder': 'deepseek-coder-v2:16b',
}
OLLAMA_MODEL = OLLAMA_PRESETS.get(OLLAMA_MODEL_PRESET, OLLAMA_MODEL_PRESET)
OLLAMA_SSH_HOST = os.getenv("OLLAMA_SSH_HOST")
OLLAMA_SSH_PORT = int(os.getenv("OLLAMA_SSH_PORT")) if os.getenv("OLLAMA_SSH_PORT") else 22
OLLAMA_SSH_USER = os.getenv("OLLAMA_SSH_USER")
OLLAMA_SSH_PASSWORD = os.getenv("OLLAMA_SSH_PASSWORD")

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
