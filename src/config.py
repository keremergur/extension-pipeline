"""
Configuration file for the Chrome Extension vulnerability report analyzer.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()


# ============================================================================
# GENERAL / SHARED CONFIGURATION
# ============================================================================

# Paths (used by both analyzer and verifier)
BASE_DIR = Path(__file__).parent # Use this as a variable if all folders are inside the same parent folder
RESULTS_ANALYSIS_DIR = BASE_DIR / "results_analysis"  # The Analyzer will save its result-JSONs and the verifier will search for his result-JSONs here
EXTENSION_CODE_DIR = BASE_DIR / "extension_code" # "extension_code" # Analyzer and Verifier will search for the original extension code here

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
RESULTS_VERIFICATION_DIR = BASE_DIR / "results_verification" # The verifier will save its results here
CHROME_BINARY_PATH = r"D:\Programme\Chrome Test Versions\chrome\win64-126.0.6478.126\chrome-win64\chrome.exe" # path to chrome binary for playwright

# Results to verify (directory name within RESULTS_ANALYSIS_DIR)
# Options:
# - "latest": Automatically use the most recent results directory created by the analyzer
# - Custom directory name: e.g., "results_claude-opus-4-5_20250126_123456"
# The verifier will recursively find all *_result.json files in this directory (including subdirectories)
RESULTS_TO_VERIFY = "results_gemini_2026-02-18_02-09-50" #"latest"

# Resume an interrupted verification run instead of starting fresh
# Options:
# - None: Start a new run (default)
# - "latest": Resume the most recently created verification results directory
# - Custom directory name: e.g., "results_manual_reference_1"
# Extensions that already have a *_verification.json will be skipped automatically
RESUME_VERIFICATION_RUN = None

# Milliseconds to wait for payload detection (network/console/download)
# Increase if extensions are slow to process payloads
# Note: This includes the 2s sleep before payload execution, so effective wait after payload is timeout - 2000ms
PAYLOAD_EXECUTION_TIMEOUT = 3000

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

# ============================================================================
# VERIFIER FILTERS
# ============================================================================
# Filters are applied before any extension code is downloaded or browser is launched.
# All filters are applied to the TP-verifiable vulnerability list after initial TP filtering.

VERIFIER_FILTER = {
    # Only verify vulnerabilities of these categories. None = no filter (all categories).
    # Accepts a single string or a list: "code_execution" or ["code_execution", "1way_request"]
    # Options: "code_execution", "1way_request", "2way_request", "download", "data_exfiltration", "storage"
    "vulnerability_categories": "data_exfiltration",

    # Only verify vulnerabilities using these storage APIs. None = no filter (all APIs).
    # Accepts a single string or a list: "chrome.storage.local.set" or ["chrome.storage.local.set", "chrome.cookies.get"]
    # Only relevant when vulnerability_category is "storage" or "data_exfiltration".
    "storage_apis": None,

    # Skip extensions with fewer than this many matching vulnerabilities. None = no minimum.
    "min_vulnerabilities": None,

    # Skip extensions with more than this many matching vulnerabilities. None = no maximum.
    "max_vulnerabilities": 5,
}
