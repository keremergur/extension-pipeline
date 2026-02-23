#!/usr/bin/env python3
"""
Chrome Extension Vulnerability Verification Script
====================================================
Verifies vulnerabilities found by analyze_extensions.py by:
1. Downloading and extracting extension code
2. Modifying manifest.json for verification
3. Installing extensions in Chrome
4. Executing verification payloads
5. Documenting verification results
"""

import json
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional
import asyncio
from datetime import datetime
import shutil
import re

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))
import config
from mock_server import get_mock_server

# Import helper functions
from helpers.extension_downloader import download_crx, extract_crx

# Minimal logging - only for critical errors
logging.basicConfig(level=logging.ERROR, format='%(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# API CATEGORY MAPPINGS
# ============================================================================

# API Categories for verification
BOOKMARKS_APIS = {
    'chrome.bookmarks.create', 'chrome.bookmarks.remove', 'chrome.bookmarks.removeTree',
    'chrome.bookmarks.get', 'chrome.bookmarks.getRecent', 'chrome.bookmarks.getTree',
    'chrome.bookmarks.search'
}

COOKIES_APIS = {
    'chrome.cookies.set', 'chrome.cookies.remove',
    'chrome.cookies.get', 'chrome.cookies.getAll'
}

HISTORY_APIS = {
    'chrome.history.addUrl', 'chrome.history.deleteUrl', 'chrome.history.deleteAll',
    'chrome.history.deleteRange', 'chrome.history.getVisits', 'chrome.history.search'
}

MANAGEMENT_APIS = {
    'chrome.management.uninstall', 'chrome.management.uninstallSelf', 'chrome.management.setEnabled',
    'chrome.management.get', 'chrome.management.getAll', 'chrome.management.getSelf'
}

DNR_APIS = {'chrome.declarativeNetRequest.updateDynamicRules'}
TOPSITES_APIS = {'chrome.topSites.get'}
LOCALSTORAGE_APIS = {'localStorage.setItem', 'localStorage.getItem', 'localStorage.removeItem', 'localStorage.clear'}

# APIs that are skipped during verification (not implemented yet)
SKIPPED_APIS = {
    'chrome.history.deleteRange',
    'chrome.history.getVisits',
    'chrome.management.uninstall',
    'chrome.management.uninstallSelf',
    'chrome.management.setEnabled',
    'chrome.management.get',
    'chrome.management.getAll',
    'chrome.management.getSelf',
    'chrome.declarativeNetRequest.updateDynamicRules',
    'chrome.topSites.get'
}
CHROME_STORAGE_APIS = {
    'chrome.storage.local.set', 'chrome.storage.local.get', 'chrome.storage.local.remove', 'chrome.storage.local.clear',
    'chrome.storage.sync.set', 'chrome.storage.sync.get', 'chrome.storage.sync.remove', 'chrome.storage.sync.clear',
    'chrome.storage.session.set', 'chrome.storage.session.get', 'chrome.storage.session.remove', 'chrome.storage.session.clear'
}

# Categories for which a retry after no detection is worthwhile (warm-up / timing issues)
RETRY_CATEGORIES: set = set()  # Disabled: retries cost time without reliable benefit

# ============================================================================
# COLOR CODES
# ============================================================================
class Color:
    """Terminal color and formatting codes."""
    BOLD = '\033[1m'
    END = '\033[0m'


# ============================================================================
# LOGGING HELPERS
# ============================================================================
def log_step(step_num: int, title: str):
    """Log a numbered step."""
    print(f"\n  [{step_num}] {title}")


def log_success(msg: str):
    """Log success message."""
    print(f"      ✓ {msg}")


def log_error(msg: str):
    """Log error message."""
    print(f"      ✗ {msg}")


def log_info(msg: str):
    """Log info message."""
    print(f"      • {msg}")


def ask_continue(msg: str = "Continue?") -> bool:
    """Ask user to continue (y/Enter to continue, anything else to abort)."""
    response = input(f"\n  → {msg} (y/n): ").strip().lower()
    return response in ['y', 'yes', '']


def log_mock_server_ready(mock_server_url: str):
    """Log that mock server is ready with endpoints."""
    print(f"      • Mock server ready: {mock_server_url}")


# ============================================================================
# UTILITIES
# ============================================================================


def has_background_context(extension_dir: Path) -> bool:
    """Check if extension has a background page or service worker.

    Extensions without a background context (content-script-only) have no discoverable
    chrome-extension:// URLs, so runtime extension ID discovery always times out for them.
    """
    try:
        with open(extension_dir / "manifest.json", 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        bg = manifest.get('background', {})
        if isinstance(bg, dict):
            return bool(bg.get('service_worker') or bg.get('page') or bg.get('scripts'))
        return False
    except Exception:
        return False


def get_analysis_results_dir() -> Optional[Path]:
    """
    Get the analysis results directory based on config.RESULTS_TO_VERIFY.

    If RESULTS_TO_VERIFY is "latest", find the most recent results_analysis directory.
    Otherwise, use the specified directory name.
    """
    if not config.RESULTS_ANALYSIS_DIR.exists():
        log_error(f"Results directory not found: {config.RESULTS_ANALYSIS_DIR}")
        return None

    if config.RESULTS_TO_VERIFY == "latest":
        # Find most recent directory
        results_dirs = [d for d in config.RESULTS_ANALYSIS_DIR.iterdir()
                       if d.is_dir() and d.name.startswith('results_')]

        if not results_dirs:
            log_error("No results directories found")
            return None

        latest = max(results_dirs, key=lambda p: p.stat().st_mtime)
        return latest
    else:
        # Use specified directory
        specified_dir = config.RESULTS_ANALYSIS_DIR / config.RESULTS_TO_VERIFY
        if not specified_dir.exists():
            log_error(f"Specified results directory not found: {specified_dir}")
            return None
        return specified_dir


def load_json_results(results_dir: Path) -> List[tuple]:
    """
    Load all JSON result files from a results directory.
    Recursively searches all subdirectories for *_result.json files.

    Returns:
        List of tuples: (extension_id, data, json_file, relative_subdir)
        - relative_subdir: Path relative to results_dir (e.g., "codeql_2026_1")
    """
    if not results_dir.exists():
        log_error(f"Results directory not found: {results_dir}")
        return []

    # Check for DEBUG_SINGLE_RESULT_FILE mode
    if config.DEBUG_SINGLE_RESULT_FILE:
        # Load only the specified file
        json_file = list(results_dir.rglob(config.DEBUG_SINGLE_RESULT_FILE))
        if not json_file:
            log_error(f"Debug file not found: {config.DEBUG_SINGLE_RESULT_FILE}")
            return []
        json_files = [json_file[0]]
        log_info(f"DEBUG: Loading single result file: {config.DEBUG_SINGLE_RESULT_FILE}")
    else:
        # Load all *_result.json files
        json_files = list(results_dir.rglob("*_result.json"))

    results = []

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                # Handle markdown code blocks
                if content.startswith('```'):
                    content = content[content.find('\n')+1:content.rfind('```')]
                data = json.loads(content)
                extension_id = data.get('extension_id')

                # Get relative path from results_dir to the json file's parent directory
                relative_subdir = json_file.parent.relative_to(results_dir)

                results.append((extension_id, data, json_file, relative_subdir))
        except Exception as e:
            log_error(f"Load {json_file.name}: {e}")

    return results


def create_verification_output_dir(results_dir_name: str) -> Path:
    """
    Create verification output directory with auto-incrementing suffix if it already exists.

    Args:
        results_dir_name: Name of the results directory (e.g., "results_claude-opus-4-5_20250126_123456")

    Returns:
        Path to the created verification output directory
    """
    base_path = config.RESULTS_VERIFICATION_DIR / results_dir_name

    # If base path doesn't exist, use it
    if not base_path.exists():
        base_path.mkdir(parents=True, exist_ok=True)
        return base_path

    # Otherwise, find next available suffix
    counter = 1
    while True:
        candidate = config.RESULTS_VERIFICATION_DIR / f"{results_dir_name}_{counter}"
        if not candidate.exists():
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        counter += 1


def get_or_create_verification_output_dir(results_dir_name: str) -> Path:
    """
    Return existing verification directory (resume mode) or create a new one.

    Controlled by config.RESUME_VERIFICATION_RUN:
    - None: Create new directory (default)
    - "latest": Resume most recently created matching verification directory
    - Custom name: Resume that specific directory
    """
    resume = getattr(config, 'RESUME_VERIFICATION_RUN', None)
    if not resume:
        return create_verification_output_dir(results_dir_name)

    if resume == "latest":
        # Find most recent directory whose name starts with results_dir_name
        candidates = sorted(config.RESULTS_VERIFICATION_DIR.glob(f"{results_dir_name}*"))
        if not candidates:
            log_info("RESUME_VERIFICATION_RUN='latest' but no matching directory found — creating new one")
            return create_verification_output_dir(results_dir_name)
        verification_dir = candidates[-1]
    else:
        verification_dir = config.RESULTS_VERIFICATION_DIR / resume
        if not verification_dir.exists():
            raise ValueError(f"RESUME_VERIFICATION_RUN directory not found: {verification_dir}")

    log_info(f"RESUMING verification: {verification_dir.name}")
    return verification_dir


def filter_tp_verifiable_results(results: List[tuple]) -> List[tuple]:
    """
    Filter results to TP (True Positive) + verifiable vulnerabilities (Website or Extension).

    Returns:
        List of tuples: (extension_id, vulnerabilities, file_path, relative_subdir)
    """
    filtered = []

    for extension_id, data, file_path, relative_subdir in results:
        vulnerabilities = data.get('vulnerabilities', [])
        tp_verifiable_vulns = [
            v for v in vulnerabilities
            if v.get('result') == 'TP' and v.get('attacker_source') in ['Website', 'Extension']
        ]

        if tp_verifiable_vulns:
            filtered.append((extension_id, tp_verifiable_vulns, file_path, relative_subdir))

    return filtered


def apply_verifier_filters(tp_verifiable: List[tuple]) -> List[tuple]:
    """
    Apply VERIFIER_FILTER settings from config to the TP-verifiable vulnerability list.

    Filters applied (in order):
    1. vulnerability_categories: keep only vulns matching the specified category/categories
    2. storage_apis: keep only vulns matching the specified storage_api/apis
    3. min_vulnerabilities / max_vulnerabilities: skip extensions outside the count range

    Both category and api filters accept a single string or a list of strings.
    All filters operate on the already-TP-filtered list returned by filter_tp_verifiable_results.
    """
    vf = getattr(config, 'VERIFIER_FILTER', {}) or {}

    # Normalize category filter to a set (or None)
    cat_raw = vf.get('vulnerability_categories')
    if isinstance(cat_raw, str):
        cat_filter = {cat_raw}
    elif cat_raw:
        cat_filter = set(cat_raw)
    else:
        cat_filter = None

    # Normalize storage_api filter to a set (or None)
    api_raw = vf.get('storage_apis')
    if isinstance(api_raw, str):
        api_filter = {api_raw}
    elif api_raw:
        api_filter = set(api_raw)
    else:
        api_filter = None

    min_count = vf.get('min_vulnerabilities')
    max_count = vf.get('max_vulnerabilities')

    has_cat_or_api_filter = bool(cat_filter or api_filter)
    has_count_filter = min_count is not None or max_count is not None

    if not has_cat_or_api_filter and not has_count_filter:
        return tp_verifiable  # Nothing to do

    # Log active filters
    if cat_filter:
        log_info(f"Category filter: {sorted(cat_filter)}")
    if api_filter:
        log_info(f"Storage API filter: {sorted(api_filter)}")
    if min_count is not None or max_count is not None:
        log_info(f"Vulnerability count range: [{min_count}, {max_count}]")

    result = []
    skipped_filter = 0
    skipped_count = 0

    for extension_id, vulnerabilities, file_path, relative_subdir in tp_verifiable:
        # Step 1: Apply category + storage_api filters
        if has_cat_or_api_filter:
            matching = []
            for v in vulnerabilities:
                if cat_filter and v.get('vulnerability_category') not in cat_filter:
                    continue
                if api_filter:
                    storage_api = (v.get('verification_details') or {}).get('storage_api')
                    if storage_api not in api_filter:
                        continue
                matching.append(v)
            if not matching:
                skipped_filter += 1
                continue
        else:
            matching = vulnerabilities

        # Step 2: Apply min/max count filter
        if has_count_filter:
            count = len(matching)
            if min_count is not None and count < min_count:
                skipped_count += 1
                continue
            if max_count is not None and count > max_count:
                skipped_count += 1
                continue

        result.append((extension_id, matching, file_path, relative_subdir))

    if skipped_filter:
        log_info(f"Skipped {skipped_filter} extension(s): no vulnerabilities match category/API filter")
    if skipped_count:
        log_info(f"Skipped {skipped_count} extension(s): vulnerability count outside [{min_count}, {max_count}]")

    return result


def get_extension_code_dir(extension_id: str) -> Optional[Path]:
    """Download and extract extension .crx file."""
    extension_dir = config.EXTENSION_CODE_DIR / extension_id
    crx_file = config.EXTENSION_CODE_DIR / f"{extension_id}.crx"

    # Logger wrapper for helper functions
    def logger(msg: str, level: str = "INFO"):
        if level == "ERROR":
            log_error(msg)
        else:
            log_info(msg)

    if config.RESET_EXTENSION_CODE:
        # Force fresh extraction from .crx file
        # Priority: .crx file (local or download) -> extract
        # Fallback: If .crx unavailable but directory exists -> use directory with warning

        if crx_file.exists():
            # Local .crx exists -> extract
            if not extract_crx(crx_file, extension_dir, logger):
                return None
        else:
            # Local .crx doesn't exist -> try download
            if download_crx(extension_id, crx_file, config, logger):
                # Download successful -> extract
                if not extract_crx(crx_file, extension_dir, logger):
                    return None
            else:
                # Download failed -> check if directory exists as fallback
                if extension_dir.exists() and (extension_dir / "manifest.json").exists():
                    log_info(f"WARNING: No .crx file available, using existing extracted directory")
                    log_info(f"Directory: {extension_dir}")
                    return extension_dir
                return None

        # Validate extraction
        if (extension_dir / "manifest.json").exists():
            return extension_dir
        return None

    else:
        # Prefer existing directory (skip re-extraction to preserve manual changes)
        # Priority: Existing directory
        # Fallback: .crx file (local or download) -> extract

        if extension_dir.exists() and (extension_dir / "manifest.json").exists():
            log_info(f"Using existing extension code (RESET_EXTENSION_CODE=False)")
            return extension_dir

        # Directory doesn't exist -> get .crx and extract
        if crx_file.exists():
            # Local .crx exists -> extract
            if not extract_crx(crx_file, extension_dir, logger):
                return None
        else:
            # Local .crx doesn't exist -> try download
            if download_crx(extension_id, crx_file, config, logger):
                # Download successful -> extract
                if not extract_crx(crx_file, extension_dir, logger):
                    return None
            else:
                # Download failed -> check if directory exists as fallback
                if extension_dir.exists() and (extension_dir / "manifest.json").exists():
                    log_info(f"WARNING: No .crx file available, using existing extracted directory")
                    log_info(f"Directory: {extension_dir}")
                    return extension_dir
                return None

        # Validate extraction
        if (extension_dir / "manifest.json").exists():
            return extension_dir
        return None


def validate_extension_structure(extension_dir: Path) -> bool:
    """Validate extension structure (manifest.json exists and is valid)."""
    manifest = extension_dir / "manifest.json"
    if not manifest.exists():
        log_error("No manifest.json found")
        return False

    try:
        with open(manifest, 'r', encoding='utf-8') as f:
            json.load(f)
        return True
    except Exception as e:
        log_error(f"Invalid manifest.json: {e}")
        return False


def modify_manifest_for_verification(extension_dir: Path) -> tuple:
    """Modify manifest.json to allow verification on example.com.
    Always replaces all matches unconditionally:
      - content_scripts / web_accessible_resources: <all_urls>
      - externally_connectable: *://example.com/* (Chrome rejects <all_urls> here)
    """
    manifest_path = extension_dir / "manifest.json"
    modifications = {
        "manifest_modified": False,
        "content_scripts_modified": 0,
        "web_accessible_resources_modified": 0,
        "externally_connectable_modified": 0,
    }

    if not manifest_path.exists():
        return False, modifications

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        # content_scripts: set all matches to <all_urls>
        if "content_scripts" in manifest:
            for script in manifest["content_scripts"]:
                if isinstance(script, dict) and "matches" in script:
                    if script["matches"] != ["<all_urls>"]:
                        script["matches"] = ["<all_urls>"]
                        modifications["content_scripts_modified"] += 1

        # web_accessible_resources: set all matches to <all_urls>
        if "web_accessible_resources" in manifest:
            for resource in manifest["web_accessible_resources"]:
                if isinstance(resource, dict) and "matches" in resource:
                    if resource["matches"] != ["<all_urls>"]:
                        resource["matches"] = ["<all_urls>"]
                        modifications["web_accessible_resources_modified"] += 1

        # externally_connectable: set matches to *://example.com/*
        # Chrome does NOT support <all_urls> for externally_connectable
        if "externally_connectable" in manifest:
            if isinstance(manifest["externally_connectable"], dict) and "matches" in manifest["externally_connectable"]:
                if manifest["externally_connectable"]["matches"] != ["*://example.com/*"]:
                    manifest["externally_connectable"]["matches"] = ["*://example.com/*"]
                    modifications["externally_connectable_modified"] = 1

        # Only write if something actually changed
        if modifications["content_scripts_modified"] or modifications["web_accessible_resources_modified"] or modifications["externally_connectable_modified"]:
            modifications["manifest_modified"] = True
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)

        return True, modifications

    except Exception as e:
        log_error(f"Manifest modification: {e}")
        return False, modifications


# ============================================================================
# VERIFIER EXTENSION UTILITIES
# ============================================================================
def prepare_verifier_extension(extension_id: str, payload: str) -> Optional[Path]:
    """Copy verifier extension template and inject payload."""
    try:
        verifier_template = Path(__file__).parent / "verifier_extensions" / "_original"
        if not verifier_template.exists():
            log_error(f"Verifier extension template not found: {verifier_template}")
            return None

        # Create directory for this specific verification
        verifier_dir = Path(__file__).parent / "verifier_extensions" / f"{extension_id}_verifier"

        # Remove old version if exists
        if verifier_dir.exists():
            shutil.rmtree(verifier_dir)

        verifier_dir.mkdir(parents=True, exist_ok=True)

        # Copy manifest.json
        manifest_src = verifier_template / "manifest.json"
        manifest_dst = verifier_dir / "manifest.json"
        shutil.copy(manifest_src, manifest_dst)

        # Read content_script template
        content_script_template = verifier_template / "content_script.js"
        with open(content_script_template, 'r', encoding='utf-8') as f:
            content = f.read()

        # Inject payload
        content = content.replace(
            "// ===== PAYLOAD_PLACEHOLDER_START =====\n      // The actual payload will be inserted here by the verifier\n      // ===== PAYLOAD_PLACEHOLDER_END =====",
            payload
        )

        # Write modified content_script.js
        content_script_dst = verifier_dir / "content_script.js"
        with open(content_script_dst, 'w', encoding='utf-8') as f:
            f.write(content)

        log_success(f"Verifier extension prepared for {extension_id}")
        return verifier_dir

    except Exception as e:
        log_error(f"Failed to prepare verifier extension: {e}")
        return None


# ============================================================================
# EXTENSION ID DISCOVERY AND PAYLOAD REPLACEMENT
# ============================================================================

def has_fixed_extension_id(extension_dir: Path) -> bool:
    """
    Check if extension has a fixed ID (via 'key' in manifest.json).

    Extensions with 'key' field have deterministic IDs that match the .crx filename.
    Extensions without 'key' get random IDs when loaded unpacked.

    Args:
        extension_dir: Path to unpacked extension directory

    Returns:
        True if manifest.json contains 'key' field, False otherwise
    """
    try:
        manifest_path = extension_dir / "manifest.json"
        if not manifest_path.exists():
            return False

        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        return 'key' in manifest
    except Exception as e:
        log_error(f"Failed to read manifest for key check: {e}")
        return False


def payload_mentions_extension_id(payload: str, extension_id: str) -> bool:
    """Return True if the payload references the given extension ID (as a standalone token or in a chrome-extension:// URL)."""
    if not payload or not extension_id:
        return False
    if extension_id not in payload:
        return False
    try:
        boundary = re.compile(rf"(?<![0-9a-z]){re.escape(extension_id)}(?![0-9a-z])")
        return bool(boundary.search(payload))
    except Exception:
        return True


def _is_valid_extension_id(candidate: str) -> bool:
    return (
        isinstance(candidate, str)
        and len(candidate) == 32
        and all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in candidate)
    )


def _extract_extension_id_from_url(url: str) -> Optional[str]:
    if not isinstance(url, str):
        return None
    if not url.startswith("chrome-extension://"):
        return None
    candidate = url.replace("chrome-extension://", "").split("/", 1)[0]
    return candidate if _is_valid_extension_id(candidate) else None


def _iter_context_urls(context) -> List[str]:
    urls: List[str] = []
    for attr in ("pages", "background_pages", "service_workers"):
        for item in getattr(context, attr, []) or []:
            try:
                urls.append(item.url)
            except Exception:
                continue
    return urls


async def discover_runtime_extension_id_from_context(
    context,
    timeout_ms: int = 5000,
    debug: bool = False,
) -> Optional[str]:
    """
    Discover the runtime extension ID from a Playwright context.

    Prefers MV3 service worker URLs, falls back to MV2 background pages and regular pages.
    """
    try:
        start_time = asyncio.get_event_loop().time()
        logged_details = False

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout_ms / 1000:
                if debug and not logged_details:
                    log_error(f"Extension discovery timeout ({timeout_ms}ms)")
                    urls = _iter_context_urls(context)
                    if urls:
                        log_info(f"Found {len(urls)} context URL(s):")
                        for url in urls:
                            log_info(f"   {url}")
                    logged_details = True
                return None

            for url in _iter_context_urls(context):
                extension_id = _extract_extension_id_from_url(url)
                if extension_id:
                    return extension_id

            await asyncio.sleep(0.1)

    except Exception as e:
        if debug:
            log_error(f"Extension discovery error: {e}")
        return None


def replace_extension_id_in_payload(payload: str, old_id: str, new_id: str) -> str:
    """
    Replace the old (incorrect) extension ID with the new (correct) extension ID in the payload.

    Args:
        payload: The JavaScript payload string
        old_id: The extension ID used at analysis time (from result JSON)
        new_id: The actual extension ID at runtime

    Returns:
        Modified payload with old_id replaced by new_id
    """
    if not old_id or not new_id or old_id == new_id:
        return payload

    # Replace in various contexts where extension ID might appear
    # chrome.runtime.sendMessage("old_id", ...)
    # chrome.runtime.connect("old_id", ...)
    # etc.
    modified = payload

    # Replace inside chrome-extension://<id>/... URLs
    try:
        modified = re.sub(
            rf"(chrome-extension://){re.escape(old_id)}(?=/)",
            rf"\\1{new_id}",
            modified,
        )
    except Exception:
        pass

    # Replace standalone occurrences (quoted or unquoted)
    try:
        modified = re.sub(
            rf"(?<![0-9a-z]){re.escape(old_id)}(?![0-9a-z])",
            new_id,
            modified,
        )
    except Exception:
        pass

    # Extra: quoted exact matches
    modified = modified.replace(f'"{old_id}"', f'"{new_id}"')
    modified = modified.replace(f"'{old_id}'", f"'{new_id}'")
    modified = modified.replace(f"`{old_id}`", f"`{new_id}`")

    if modified != payload:
        log_success(f"Replaced extension ID: {old_id} → {new_id}")
    else:
        log_info(f"Extension ID {old_id} not found in payload (might not be needed)")

    return modified


# ============================================================================
# CHROME BROWSER SETUP
# ============================================================================
async def launch_browser_with_extension(extension_dir: Path, p, verifier_dir: Optional[Path] = None, user_data_dir: Optional[Path] = None):
    """
    Launch Chrome with extension(s) loaded.

    Args:
        extension_dir: Path to the extension to load
        p: Playwright instance
        verifier_dir: Optional path to attacker/verifier extension
        user_data_dir: Optional custom user data directory. If None, creates a unique temporary directory.

    Returns:
        Tuple of (context, user_data_dir) where user_data_dir is the path that should be cleaned up after use
    """
    chrome_path = Path(config.CHROME_BINARY_PATH)

    if not chrome_path.exists():
        log_error(f"Chrome not found: {chrome_path}")
        return None, None

    extension_dir_abs = extension_dir.resolve()

    # Create a unique temporary user data directory for Chrome profile if not provided
    import tempfile
    import uuid
    if user_data_dir is None:
        # Use UUID to ensure each browser instance gets a completely fresh profile
        unique_id = uuid.uuid4().hex[:8]
        user_data_dir = Path(tempfile.gettempdir()) / f"chrome_extension_test_{unique_id}"

    user_data_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Build extension args
        load_extensions = [str(extension_dir_abs)]
        disable_extensions = [str(extension_dir_abs)]

        # Add verifier extension if provided
        if verifier_dir:
            verifier_dir_abs = verifier_dir.resolve()
            load_extensions.append(str(verifier_dir_abs))
            disable_extensions.append(str(verifier_dir_abs))
            log_info(f"Verifier extension path: {verifier_dir_abs}")

        log_info(f"Target extension path: {extension_dir_abs}")
        log_info(f"Chrome user data: {user_data_dir}")

        # Build args list
        args = [
            f"--load-extension={','.join(load_extensions)}",
            f"--disable-extensions-except={','.join(disable_extensions)}",
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
        ]

        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(user_data_dir),
            executable_path=str(chrome_path),
            args=args,
            headless=False
        )
        log_success("Browser launched successfully")
        return context, user_data_dir
    except Exception as e:
        log_error(f"Browser launch: {e}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
        return None, None


# ============================================================================
# VERIFICATION
# ============================================================================
async def verify_extension_mode_vulnerability(extension_id: str, extension_dir: Path, vuln: dict, p, debug_mode: bool = False) -> Dict:
    """Verify a single extension-mode vulnerability using verifier extension.

    Two-browser approach:
    1. Browser 1: Only target extension → discover real extension ID
    2. Browser 2: Target + Verifier (with correct payload) → execute and detect
    """
    vuln_record = {
        **vuln,
        "detection": None,
        "verification_status": None,
        "error": None
    }

    payload = vuln.get('attacker_payload')
    rule_id = vuln.get('rule_id')

    if not payload:
        vuln_record["verification_status"] = "missing_payload"
        log_info("No payload provided")
        return vuln_record

    try:
        # Manifest was already modified once in verify_extension() before this call

        # Only discover the runtime extension ID if we actually need to replace it in the payload.
        needs_id_replacement = payload_mentions_extension_id(payload, extension_id)

        if debug_mode and needs_id_replacement and not ask_continue("Proceed to extension ID discovery?"):
            vuln_record["verification_status"] = "skipped"
            return vuln_record

        # Step 1: Determine target extension ID
        target_extension_id = None

        # Check if extension has a fixed ID (via 'key' in manifest.json)
        if has_fixed_extension_id(extension_dir):
            # Extension has 'key' → ID is deterministic and matches the .crx filename
            target_extension_id = extension_id
            if debug_mode:
                log_step(2, "Extension ID determination")
                log_success(f"Extension has fixed ID (manifest 'key' present): {target_extension_id}")
        else:
            # Extension has no 'key' → ID is random, need to discover it
            if not needs_id_replacement:
                target_extension_id = extension_id
                if debug_mode:
                    log_step(2, "Extension ID determination")
                    log_info("Payload contains no target extension ID; skipping ID discovery")
            elif not has_background_context(extension_dir):
                # Content-script-only extension: no background page/SW → discovery always times out
                target_extension_id = extension_id
                if debug_mode:
                    log_step(2, "Extension ID determination")
                    log_info("No background context (no SW/background page) – skipping ID discovery, using original ID")
            else:
                if debug_mode:
                    log_step(2, "Launching browser with target extension only (for ID discovery)")

                context, discovery_user_data_dir = await launch_browser_with_extension(extension_dir, p, verifier_dir=None)

                if not context:
                    vuln_record["verification_status"] = "browser_launch_failed"
                    vuln_record["error"] = "Failed to launch Chrome"
                    log_error("Failed to launch Chrome")
                    return vuln_record

                log_success("Browser launched with target extension")

                # Discover target extension ID
                if debug_mode:
                    log_step(3, "Discovering target extension ID")

                temp_page = await context.new_page()
                try:
                    # Use HTTP to avoid mixed content issues
                    await temp_page.goto("http://example.com", timeout=30000, wait_until="domcontentloaded")
                except Exception:
                    pass  # Extension may initialize without a successful navigation

                await asyncio.sleep(0.5)
                target_extension_id = await discover_runtime_extension_id_from_context(
                    context, timeout_ms=5000, debug=debug_mode
                )
                await temp_page.close()

                if not target_extension_id:
                    await context.close()
                    vuln_record["verification_status"] = "extension_id_discovery_failed"
                    log_error("Failed to discover target extension ID")
                    return vuln_record

                log_success(f"Target extension ID: {target_extension_id}")

                # Close browser after ID discovery
                try:
                    await asyncio.wait_for(context.close(), timeout=10.0)
                except asyncio.TimeoutError:
                    log_info("Browser close timed out after 10s — continuing anyway")

                # Cleanup user data directory
                if discovery_user_data_dir and discovery_user_data_dir.exists():
                    shutil.rmtree(discovery_user_data_dir, ignore_errors=True)

        if not target_extension_id:
            vuln_record["verification_status"] = "extension_id_determination_failed"
            log_error("Failed to determine target extension ID")
            return vuln_record

        if debug_mode and not ask_continue("Proceed to verifier extension preparation?"):
            vuln_record["verification_status"] = "skipped"
            return vuln_record

        # Step 2: Prepare verifier extension with correct extension ID in payload
        if debug_mode:
            log_step(3, "Preparing verifier extension")

        original_extension_id = extension_id
        modified_payload = payload

        if needs_id_replacement and original_extension_id and target_extension_id and original_extension_id != target_extension_id:
            log_info(f"Original extension ID: {original_extension_id}")
            log_info(f"Actual extension ID:   {target_extension_id}")

            modified_payload = replace_extension_id_in_payload(payload, original_extension_id, target_extension_id)

            if modified_payload != payload:
                log_success("Extension ID replaced in payload")
            else:
                log_info("Extension ID not found in payload")
        else:
            if needs_id_replacement:
                log_info("Extension ID matches - no replacement needed")
            elif debug_mode:
                log_info("No extension ID replacement needed")

        verifier_dir = prepare_verifier_extension(extension_id, modified_payload)
        if not verifier_dir:
            vuln_record["verification_status"] = "verifier_prep_failed"
            vuln_record["error"] = "Failed to prepare verifier extension"
            log_error("Failed to prepare verifier extension")
            return vuln_record

        log_success("Verifier extension prepared with correct payload")

        if debug_mode and not ask_continue("Proceed to launch browser with both extensions?"):
            vuln_record["verification_status"] = "skipped"
            return vuln_record

        # Step 3: Launch browser with BOTH extensions
        if debug_mode:
            log_step(4, "Launching browser with target + verifier extensions")

        context, extension_mode_user_data_dir = await launch_browser_with_extension(extension_dir, p, verifier_dir)

        if not context:
            vuln_record["verification_status"] = "browser_launch_failed"
            vuln_record["error"] = "Failed to launch Chrome"
            log_error("Failed to launch Chrome")
            return vuln_record

        log_success("Browser launched with both extensions")

        try:
            if debug_mode and not ask_continue("Proceed to testing?"):
                await context.close()
                vuln_record["verification_status"] = "skipped"
                return vuln_record

            vulnerability_category = vuln.get('vulnerability_category')
            verification_details = vuln.get('verification_details')

            # Reset mock server before test and get verification token
            mock_server = get_mock_server()
            verification_token = mock_server.reset_and_get_token()

            # Check if API should be skipped before doing any further work
            storage_api_check = verification_details.get('storage_api') if verification_details else None
            if storage_api_check and storage_api_check in SKIPPED_APIS:
                log_info(f"API {storage_api_check} is in skip list - skipping verification")
                vuln_record["verification_status"] = "skipped"
                await context.close()
                return vuln_record

            # Seed test data BEFORE payload execution (verifier extension runs at DOMContentLoaded)
            # data_exfiltration needs data to read; storage delete/remove/clear needs data to delete
            seed_page = await context.new_page()
            seed_success = await seed_test_data(
                seed_page,
                vulnerability_category,
                verification_details,
                target_extension_id,
                str(extension_dir)
            )
            await seed_page.close()
            if not seed_success:
                log_error("Failed to seed test data - ABORTING to prevent false positives")
                vuln_record["verification_status"] = "seeding_failed"
                vuln_record["error"] = "Failed to seed test data"
                await context.close()
                return vuln_record

            # Create page for testing
            page = await context.new_page()

            # Start detection listeners BEFORE loading page (payload executes on DOMContentLoaded)
            if debug_mode:
                log_step(5, f"Testing: {rule_id}")

            detection_task = asyncio.create_task(
                wait_for_detection(
                    page,
                    vulnerability_category=vulnerability_category,
                    verification_details=verification_details,
                    timeout_ms=config.PAYLOAD_EXECUTION_TIMEOUT,
                    mock_server=mock_server,
                    verification_token=verification_token,
                    extension_id=extension_id,
                    extension_path=str(extension_dir)
                )
            )

            # Load page - this triggers DOMContentLoaded and executes payload with active listeners
            try:
                # Use HTTP (not HTTPS) to avoid mixed content blocking
                await page.goto("http://example.com", timeout=30000, wait_until="domcontentloaded")
            except Exception as nav_error:
                log_error(f"Page load failed: {nav_error}")
                detection_task.cancel()
                try:
                    await detection_task
                except asyncio.CancelledError:
                    pass
                vuln_record["verification_status"] = "page_load_failed"
                vuln_record["error"] = str(nav_error)
                await page.close()
                return vuln_record

            # Wait for detection result
            detection = await detection_task

            # For storage vulnerabilities, also check if the key was modified
            if vulnerability_category == "storage" and not detection:
                storage_api = verification_details.get('storage_api') if verification_details else None
                storage_key = verification_details.get('storage_key') if verification_details else None
                storage_domain = verification_details.get('storage_domain') if verification_details else None

                if storage_api:
                    storage_modified = await check_storage_modified(page, storage_api, storage_key, extension_id=target_extension_id, storage_domain=storage_domain, extension_path=str(extension_dir))
                    if storage_modified:
                        detection = "storage"

            vuln_record["detection"] = detection

            if detection:
                vuln_record["verification_status"] = "verified"
                log_success(f"Detection: {detection}")
            else:
                vuln_record["verification_status"] = "no_detection"
                log_info("Payload executed, no detection")

            if debug_mode:
                log_info("Payload executed - inspect the page/console now")
                log_info("Browser will remain open for manual inspection")
                if ask_continue("Close browser?"):
                    await page.close()
                    await context.close()
                else:
                    input("Press Enter to close browser...")
                    await page.close()
                    await context.close()
            else:
                await page.close()
                await context.close()

        except Exception as e:
            vuln_record["verification_status"] = "execution_error"
            vuln_record["error"] = str(e)
            log_error(f"Payload execution: {e}")
            try:
                await context.close()
                # Cleanup user data directory
                if extension_mode_user_data_dir and extension_mode_user_data_dir.exists():
                    shutil.rmtree(extension_mode_user_data_dir, ignore_errors=True)
            except:
                pass
        finally:
            # Final cleanup attempt
            if extension_mode_user_data_dir and extension_mode_user_data_dir.exists():
                try:
                    shutil.rmtree(extension_mode_user_data_dir, ignore_errors=True)
                except:
                    pass

    except Exception as e:
        vuln_record["verification_status"] = "error"
        vuln_record["error"] = str(e)
        log_error(f"Extension-mode verification error: {e}")

    return vuln_record


# ============================================================================
# EXTENSION CONTEXT NAVIGATION UTILITIES
# ============================================================================
async def navigate_to_extension_context(page, extension_id: str) -> bool:
    """Navigate to verify_storage.html in the extension context to access Chrome APIs.

    The file is guaranteed to exist because prepare_extension_storage_verification()
    always writes it before the browser is launched.

    Returns:
        True if navigation succeeded, False otherwise.
    """
    url = f'chrome-extension://{extension_id}/verify_storage.html'
    try:
        await page.goto(url, wait_until='domcontentloaded', timeout=2000)
        await asyncio.sleep(0.3)
        return True
    except Exception:
        log_error(f"Could not navigate to extension context: {url}")
        return False




def prepare_extension_storage_verification(extension_dir: Path, vulnerabilities: List[dict]):
    """Write verify_storage.html into the extension directory before browser launch.

    This minimal page is navigated to by the verifier whenever Chrome APIs need to be
    called from extension context (storage checks, seeding, data verification).
    Registered in web_accessible_resources so Chrome permits navigation to it.
    """
    (extension_dir / 'verify_storage.html').write_text(
        '<!DOCTYPE html><html><body></body></html>', encoding='utf-8'
    )

    # Register verify_storage.html as web_accessible_resource so Chrome allows navigation.
    manifest_path = extension_dir / 'manifest.json'
    if not manifest_path.exists():
        return
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        manifest_version = manifest.get('manifest_version', 2)

        if manifest_version >= 3:
            # MV3: web_accessible_resources is an array of objects
            entry = {"resources": ["verify_storage.html"], "matches": ["<all_urls>"]}
            if "web_accessible_resources" not in manifest:
                manifest["web_accessible_resources"] = [entry]
            else:
                already_listed = any(
                    isinstance(r, dict) and "verify_storage.html" in r.get("resources", [])
                    for r in manifest["web_accessible_resources"]
                )
                if not already_listed:
                    manifest["web_accessible_resources"].append(entry)
        else:
            # MV2: web_accessible_resources is a flat array of strings
            if "web_accessible_resources" not in manifest:
                manifest["web_accessible_resources"] = ["verify_storage.html"]
            elif "verify_storage.html" not in manifest["web_accessible_resources"]:
                manifest["web_accessible_resources"].append("verify_storage.html")

        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
    except Exception as e:
        log_error(f"Failed to register verify_storage.html in manifest: {e}")


async def check_storage_modified(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str] = None, storage_domain: Optional[str] = None, extension_path: Optional[str] = None) -> bool:
    """
    Check if storage was modified by verifying the exploit marker or API-specific changes.

    Routes to appropriate handler based on storage_api.

    Args:
        page: Playwright page
        storage_api: The API used (e.g., "chrome.storage.local.set", "chrome.bookmarks.create")
        storage_key: Key/identifier to check (can be None for some APIs)
        extension_id: Extension ID (required for extension context APIs)
        storage_domain: Domain for cookies/localStorage (e.g., "example.com")
        extension_path: Path to extension directory

    Returns:
        True if storage was modified as expected, False otherwise
    """
    if not storage_api:
        log_error("storage_api is required")
        return False

    # Route to appropriate handler based on API
    if storage_api in CHROME_STORAGE_APIS:
        return await check_chrome_storage(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in LOCALSTORAGE_APIS:
        return await check_web_storage(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in BOOKMARKS_APIS:
        return await check_bookmarks(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in COOKIES_APIS:
        return await check_cookies(page, storage_api, storage_key, storage_domain, extension_id, extension_path)
    elif storage_api in HISTORY_APIS:
        return await check_history(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in MANAGEMENT_APIS:
        return await check_management(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in DNR_APIS:
        return await check_dnr(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in TOPSITES_APIS:
        return await check_topsites(page, storage_api, storage_key, extension_id, extension_path)
    else:
        log_error(f"Unknown storage_api: {storage_api}")
        return False


# ============================================================================
# API-SPECIFIC VERIFICATION FUNCTIONS
# ============================================================================
async def check_chrome_storage(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.storage.* operations (existing implementation).

    Supported APIs:
    - chrome.storage.local.set/get/remove/clear
    - chrome.storage.sync.set/get/remove/clear
    - chrome.storage.session.set/get/remove/clear

    This is the existing 90% working implementation - preserved as-is.
    """
    if not extension_id:
        log_error(f"Extension ID required for chrome.storage API")
        return False

    # For .clear() APIs, storage_key can be None (they clear all keys)
    is_clear_api = storage_api.endswith('.clear')
    is_remove_api = '.remove' in storage_api
    if not storage_key and not is_clear_api:
        log_error(f"Storage key required for chrome.storage API (except .clear)")
        return False

    # Determine storage area from API name
    if 'local' in storage_api:
        storage_area = 'local'
    elif 'sync' in storage_api:
        storage_area = 'sync'
    elif 'session' in storage_api:
        storage_area = 'session'
    else:
        log_error(f"Cannot determine storage area from API: {storage_api}")
        return False

    # Prefer service worker (MV3) - avoids web_accessible_resources navigation issues.
    # Fall back to a regular extension page (MV2 background page / popup / options).
    # Note: service_workers is a property (list), not a method - no parentheses.
    # We match any chrome-extension:// worker because the runtime ID may differ from
    # the original extension_id when loaded unpacked without a 'key' in the manifest.
    sw = next(
        (w for w in page.context.service_workers if w.url.startswith("chrome-extension://")),
        None
    )

    async def _eval_storage(ctx):
        """Run the appropriate storage read in the given execution context."""
        if is_clear_api:
            return await ctx.evaluate(f"""
                () => new Promise((resolve) => {{
                    chrome.storage.{storage_area}.get(null, (items) => {{
                        resolve(Object.keys(items).length === 0);
                    }});
                }})
            """)
        elif is_remove_api:
            return await ctx.evaluate(f"""
                () => new Promise((resolve) => {{
                    chrome.storage.{storage_area}.get('{storage_key}', (result) => {{
                        resolve(result['{storage_key}'] === undefined);
                    }});
                }})
            """)
        else:
            value = await ctx.evaluate(f"""
                () => new Promise((resolve) => {{
                    chrome.storage.{storage_area}.get('{storage_key}', (result) => {{
                        resolve(result['{storage_key}'] !== undefined ? String(result['{storage_key}']) : null);
                    }});
                }})
            """)
            return value in ("exploit", "123456789")

    if sw:
        try:
            return await _eval_storage(sw)
        except Exception as e:
            log_error(f"Chrome storage read (service worker) failed: {e}")
            return False

    # MV2 fallback: try background page before navigating (avoids wrong-ID navigation)
    bg = next(
        (p for p in page.context.background_pages if p.url.startswith("chrome-extension://")),
        None
    )
    if bg:
        try:
            return await _eval_storage(bg)
        except Exception as e:
            log_error(f"Chrome storage read (background page) failed: {e}")
            return False

    # Last resort: navigate to an extension page (requires correct extension_id)
    extension_page = await page.context.new_page()
    try:
        if not await navigate_to_extension_context(extension_page, extension_id):
            log_error("Could not navigate to any extension context for storage read")
            return False
        return await _eval_storage(extension_page)
    except Exception as e:
        log_error(f"Chrome storage read failed: {e}")
        return False
    finally:
        await extension_page.close()


async def check_web_storage(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify localStorage/sessionStorage operations in extension context.

    Supported APIs:
    - localStorage.setItem/removeItem/clear
    - sessionStorage.setItem/removeItem/clear
    """
    is_clear_api = storage_api.endswith('.clear')
    is_remove_api = 'removeItem' in storage_api
    if not storage_key and not is_clear_api:
        log_error(f"Storage key required for web storage API (except .clear)")
        return False

    storage_type = "localStorage" if "localStorage" in storage_api else "sessionStorage"

    if not extension_id:
        log_error(f"Extension ID required for extension {storage_type}")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        log_error(f"Could not navigate to extension context for {storage_type} check")
        await extension_page.close()
        return False

    try:
        if is_clear_api:
            result = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        return {storage_type}.length === 0;
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
        elif is_remove_api:
            result = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        return {storage_type}.getItem('{storage_key}') === null;
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
        else:
            result = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        const value = {storage_type}.getItem('{storage_key}');
                        return value === 'exploit' || value === '123456789';
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
        return result
    except Exception as e:
        log_error(f"Extension {storage_type} check failed: {e}")
        return False
    finally:
        await extension_page.close()




async def check_bookmarks(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.bookmarks operations.

    Storage APIs:
    - chrome.bookmarks.create: Check bookmark exists with title = storage_key
    - chrome.bookmarks.remove: Check bookmark with title = storage_key was removed (uses .search())
    - chrome.bookmarks.removeTree: Check bookmark folder with title = storage_key was removed (uses .search())

    Data Exfiltration APIs:
    - chrome.bookmarks.get/getRecent/getTree/search: Handled by seed_test_data + console detection

    Note: storage_key is bookmark title, not ID (per Prompt line 135)
    """
    if not extension_id or not extension_path:
        log_error("Extension ID and path required for bookmarks API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        if 'create' in storage_api:
            # Search for bookmark with title = storage_key
            if not storage_key:
                log_error("Storage key (bookmark title) required for bookmarks.create")
                await extension_page.close()
                return False

            result = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.bookmarks.search({{title: '{storage_key}'}}, results => {{
                        resolve(results && results.length > 0);
                    }});
                }})
            """)
        elif 'remove' in storage_api or 'removeTree' in storage_api:
            # Check if bookmark with title = storage_key was removed
            # (storage_key is bookmark title, not ID - see Prompt line 135)
            if not storage_key:
                log_error("Storage key (bookmark title) required for bookmarks.remove")
                await extension_page.close()
                return False

            result = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.bookmarks.search({{title: '{storage_key}'}}, results => {{
                        // If no results, bookmark was removed
                        resolve(results && results.length === 0);
                    }});
                }})
            """)
        else:
            # Data exfiltration APIs - no storage verification needed
            result = False

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"Bookmark check failed: {e}")
        await extension_page.close()
        return False


async def check_cookies(page, storage_api: str, storage_key: Optional[str], storage_domain: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.cookies operations.

    Storage APIs:
    - chrome.cookies.set: Check cookie exists
    - chrome.cookies.remove: Check cookie was removed

    Data Exfiltration APIs:
    - chrome.cookies.get/getAll: Handled by seed_test_data + console detection
    """
    if not storage_key:
        log_error("Storage key (cookie name) required for cookies API")
        return False

    if storage_domain:
        # Get cookies for specific domain
        cookies = await page.context.cookies([f'https://{storage_domain}'])

        if 'remove' in storage_api:
            # Check if cookie was removed (should NOT exist)
            for cookie in cookies:
                if cookie.get('name') == storage_key:
                    return False
            return True
        else:
            # Check if cookie exists with exploit marker
            for cookie in cookies:
                if cookie.get('name') == storage_key and cookie.get('value') in ('exploit', '123456789'):
                    log_info(f"Found cookie '{storage_key}={cookie.get('value')}' for domain {storage_domain}")
                    return True
            return False
    else:
        # Fallback: Search all cookies in browser
        all_cookies = await page.context.cookies()

        if 'remove' in storage_api:
            # Check if cookie was removed (should NOT exist)
            for cookie in all_cookies:
                if cookie.get('name') == storage_key:
                    return False
            return True
        else:
            # Check if cookie exists with exploit marker
            for cookie in all_cookies:
                if cookie.get('name') == storage_key and cookie.get('value') in ('exploit', '123456789'):
                    log_info(f"Found cookie '{storage_key}={cookie.get('value')}' for domain {cookie.get('domain')}")
                    return True
            return False


async def check_history(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.history operations.

    Storage APIs:
    - chrome.history.addUrl: Check URL exists in history
    - chrome.history.deleteUrl: Check URL was deleted
    - chrome.history.deleteAll: Check all history was deleted
    - chrome.history.deleteRange: Check history in range was deleted

    Data Exfiltration APIs:
    - chrome.history.getVisits/search: Handled by seed_test_data + console detection
    """
    if not extension_id or not extension_path:
        log_error("Extension ID and path required for history API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        if 'addUrl' in storage_api:
            # Check if URL exists in history
            if not storage_key:
                log_error("Storage key (URL) required for history.addUrl")
                await extension_page.close()
                return False

            result = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.history.search({{text: '{storage_key}'}}, results => {{
                        const found = results && results.some(r => r.url === '{storage_key}');
                        resolve(found);
                    }});
                }})
            """)
        elif 'delete' in storage_api:
            # Check if URL/history was deleted (should NOT exist)
            if 'deleteAll' in storage_api:
                # Check if history is mostly empty (< 3 entries)
                # Note: Extension pages themselves might still be in history,
                # so we can't expect it to be completely empty
                result = await extension_page.evaluate("""
                    () => new Promise(resolve => {
                        chrome.history.search({text: '', maxResults: 10}, results => {
                            // Consider successful if very few entries remain
                            resolve(results && results.length < 3);
                        });
                    })
                """)
            elif 'deleteRange' in storage_api:
                # deleteRange deletes by time range, not URL
                # For verification, we just check if history is empty or reduced
                # (Since we can't know the exact time range, we check if ANY history was deleted)
                result = await extension_page.evaluate("""
                    () => new Promise(resolve => {
                        chrome.history.search({text: ''}, results => {
                            // Consider it successful if history is empty or very small
                            resolve(results && results.length < 10);
                        });
                    })
                """)
            elif storage_key:
                # Check if specific URL is gone (deleteUrl)
                result = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.history.search({{text: '{storage_key}'}}, results => {{
                            const found = results && results.some(r => r.url === '{storage_key}');
                            resolve(!found);
                        }});
                    }})
                """)
            else:
                log_error("Storage key required for history.deleteUrl")
                result = False
        else:
            # Data exfiltration APIs - no storage verification needed
            result = False

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"History check failed: {e}")
        await extension_page.close()
        return False


async def check_management(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.management operations.

    Storage APIs:
    - chrome.management.uninstall: Check extension with ID = storage_key was uninstalled
    - chrome.management.uninstallSelf: Check current extension was uninstalled
    - chrome.management.setEnabled: SKIPPED (too complex)

    Data Exfiltration APIs:
    - chrome.management.get/getAll/getSelf: Handled by seed_test_data + console detection
    """
    if 'setEnabled' in storage_api:
        # Skipped per user requirement
        log_info("chrome.management.setEnabled verification skipped")
        return False

    if not extension_id or not extension_path:
        log_error("Extension ID and path required for management API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        if 'uninstall' in storage_api:
            if 'uninstallSelf' in storage_api:
                # uninstallSelf: Extension uninstalls itself
                # We can't verify this in real-time because the extension would be gone
                # Check if the extension ID still exists (it should be gone after uninstall)
                result = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.management.getSelf(info => {{
                            // If extension still exists, uninstall failed
                            resolve(chrome.runtime.lastError !== undefined || !info);
                        }});
                    }})
                """)
            else:
                # Check if extension (storage_key = extension ID) still exists
                if not storage_key:
                    log_error("Storage key (extension ID) required for management.uninstall")
                    await extension_page.close()
                    return False

                result = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.management.get('{storage_key}', info => {{
                            // If error, extension doesn't exist (was uninstalled)
                            resolve(chrome.runtime.lastError !== undefined);
                        }});
                    }})
                """)
        else:
            # Data exfiltration APIs - no storage verification needed
            result = False

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"Management check failed: {e}")
        await extension_page.close()
        return False


async def check_dnr(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.declarativeNetRequest operations.

    Storage APIs:
    - chrome.declarativeNetRequest.updateDynamicRules: Check rule with ID = storage_key exists
    """
    if not extension_id or not extension_path:
        log_error("Extension ID and path required for declarativeNetRequest API")
        return False

    if not storage_key:
        log_error("Storage key (rule ID) required for declarativeNetRequest API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        # Check if rule with ID = storage_key exists
        result = await extension_page.evaluate(f"""
            () => new Promise(resolve => {{
                chrome.declarativeNetRequest.getDynamicRules(rules => {{
                    const found = rules && rules.some(r => String(r.id) === '{storage_key}');
                    resolve(found);
                }});
            }})
        """)

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"DNR check failed: {e}")
        await extension_page.close()
        return False


async def check_topsites(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.topSites operations.

    Data Exfiltration APIs:
    - chrome.topSites.get: Data exfiltration only, no storage verification

    Note: topSites is read-only, so there's no storage modification to verify.
    Verification happens via console/network detection of exfiltrated data.
    """
    log_info("topSites.get is data_exfiltration only, no storage verification")
    return False


# ============================================================================
# LEGACY STORAGE CHECK (OLD IMPLEMENTATION - REMOVED)
# ============================================================================
# The old check_storage_modified implementation has been refactored into
# the API-specific functions above. The function signature is preserved
# but now routes to the appropriate handler.


async def seed_test_data(page, vulnerability_category: str, verification_details: Optional[Dict], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Seed test data for verification.

    Creates known data in browser storage/APIs that can be:
    - Exfiltrated by the payload (data_exfiltration category)
    - Deleted/removed by the payload (storage category with remove/delete/clear operations)

    Args:
        page: Playwright page
        vulnerability_category: "data_exfiltration" or "storage"
        verification_details: Dict with storage_api, storage_key, storage_domain
        extension_id: Extension ID
        extension_path: Path to extension directory

    Returns:
        True if seeding successful, False otherwise
    """
    # Only seed for data_exfiltration OR storage operations that need data to delete
    if vulnerability_category == "data_exfiltration":
        # All data_exfiltration needs seeding (reading data)
        pass
    elif vulnerability_category == "storage":
        # Only delete/remove/clear operations need seeding
        storage_api = verification_details.get('storage_api', '') if verification_details else ''
        needs_seed_keywords = ['remove', 'delete', 'clear']
        if not any(keyword in storage_api.lower() for keyword in needs_seed_keywords):
            return True  # No seeding needed for .set/.create/.add operations
    else:
        return True  # Unknown category, no seeding

    if not verification_details:
        return True

    storage_api = verification_details.get('storage_api')
    storage_key = verification_details.get('storage_key')

    if not storage_api:
        return True

    if not extension_id or not extension_path:
        log_error("Extension ID and path required for seeding test data")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        # For chrome.storage APIs, fall back to the extension's service worker (MV3).
        # The runtime ID may differ from extension_id when loaded unpacked, so we match
        # any chrome-extension:// service worker rather than filtering by ID.
        if storage_api in CHROME_STORAGE_APIS:
            # Try MV3 service worker first
            sw = next(
                (w for w in page.context.service_workers if w.url.startswith("chrome-extension://")),
                None
            )
            # Try MV2 background page as fallback
            bg = next(
                (p for p in page.context.background_pages if p.url.startswith("chrome-extension://")),
                None
            ) if not sw else None
            ext_ctx = sw or bg
            if ext_ctx:
                await extension_page.close()
                storage_key_local = storage_key or "testKey"
                storage_area = "local"
                if "sync" in storage_api:
                    storage_area = "sync"
                elif "session" in storage_api:
                    storage_area = "session"
                ctx_label = "service worker" if sw else "background page"
                try:
                    seeded = await ext_ctx.evaluate(f"""
                        () => new Promise(resolve => {{
                            chrome.storage.{storage_area}.set({{'{storage_key_local}': 'exploit'}}, () => {{
                                resolve(!chrome.runtime.lastError);
                            }});
                        }})
                    """)
                    if seeded:
                        log_success(f"Seeded test chrome.storage.{storage_area} key: {storage_key_local} (via {ctx_label})")
                    return seeded
                except Exception as e:
                    log_error(f"Extension context seeding failed ({ctx_label}): {e}")
                    return False
        await extension_page.close()
        return False

    success = False
    try:
        if storage_api in BOOKMARKS_APIS:
            # Create test bookmark
            if not storage_key:
                storage_key = "TestBookmark"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.bookmarks.create({{
                        title: '{storage_key}',
                        url: 'http://exploit.test/'
                    }}, result => resolve(!!result));
                }})
            """)
            if success:
                log_success(f"Seeded test bookmark: {storage_key}")

        elif storage_api in COOKIES_APIS:
            # Create test cookie
            storage_domain = verification_details.get('storage_domain', 'example.com')
            if not storage_key:
                storage_key = "testCookie"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.cookies.set({{
                        url: 'http://{storage_domain}',
                        name: '{storage_key}',
                        value: 'exploit'
                    }}, cookie => resolve(!!cookie));
                }})
            """)
            if success:
                log_success(f"Seeded test cookie: {storage_key}={storage_domain}")

        elif storage_api in HISTORY_APIS:
            # Add test URL to history
            if not storage_key:
                storage_key = "http://exploit-test.example.com/"

            # For history.search, storage_key might be just a search term (e.g., "exploit")
            # We need to create a valid URL that contains the search term
            seed_url = storage_key
            if not storage_key.startswith('http'):
                seed_url = f"http://{storage_key}.test/"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.history.addUrl({{url: '{seed_url}'}}, () => {{
                        resolve(!chrome.runtime.lastError);
                    }});
                }})
            """)
            if success:
                log_success(f"Seeded test history URL: {seed_url}")

        elif storage_api in MANAGEMENT_APIS or storage_api in TOPSITES_APIS:
            # No seeding needed - these return existing data
            success = True
            log_info(f"No seeding needed for {storage_api} (returns existing data)")

        elif storage_api in CHROME_STORAGE_APIS:
            # Seed chrome.storage
            if not storage_key:
                storage_key = "testKey"

            storage_area = "local"
            if "sync" in storage_api:
                storage_area = "sync"
            elif "session" in storage_api:
                storage_area = "session"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.storage.{storage_area}.set({{'{storage_key}': 'exploit'}}, () => {{
                        resolve(!chrome.runtime.lastError);
                    }});
                }})
            """)
            if success:
                log_success(f"Seeded test chrome.storage.{storage_area} key: {storage_key}")

        elif storage_api in LOCALSTORAGE_APIS:
            # Seed localStorage/sessionStorage in extension context
            storage_type = "localStorage" if "localStorage" in storage_api else "sessionStorage"
            if not storage_key:
                storage_key = "testKey"

            success = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        {storage_type}.setItem('{storage_key}', 'exploit');
                        return true;
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
            if success:
                log_success(f"Seeded {storage_type} key '{storage_key}' in extension context")

        else:
            # Unknown API - skip seeding
            success = True

        await extension_page.close()
        return success
    except Exception as e:
        log_error(f"Seeding failed for {storage_api}: {e}")
        await extension_page.close()
        return False


async def verify_exfiltrated_data(
    page,
    storage_api: Optional[str],
    exfiltrated_data: str,
    extension_id: str,
    extension_path: str,
    verification_details: Optional[Dict]
) -> bool:
    """
    Verify that exfiltrated data actually exists in the browser.

    Prevents false positives when seeding fails or payload exfiltrates undefined/null.
    For each API group, retrieves actual browser data and checks if exfiltrated data appears in it.

    Returns:
        True if exfiltrated data is valid and found in browser, False otherwise
    """
    if not storage_api:
        log_info("No storage_api specified - skipping data verification")
        return True  # Cannot verify without knowing which API

    try:
        extension_page = await page.context.new_page()
        if not await navigate_to_extension_context(extension_page, extension_id):
            log_error("Cannot navigate to extension context for data verification")
            await extension_page.close()
            return False  # Cannot verify - safer to reject

        actual_data = None

        # Get actual data based on API group
        if storage_api in CHROME_STORAGE_APIS:
            # Get all storage for the area
            storage_area = "local"
            if "sync" in storage_api:
                storage_area = "sync"
            elif "session" in storage_api:
                storage_area = "session"

            actual_data = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.storage.{storage_area}.get(null, (items) => {{
                        resolve(JSON.stringify(items));
                    }});
                }})
            """)

        elif storage_api in BOOKMARKS_APIS:
            # Get all bookmarks
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.bookmarks.getTree(tree => {
                        resolve(JSON.stringify(tree));
                    });
                })
            """)

        elif storage_api in COOKIES_APIS:
            # Get all cookies
            storage_domain = verification_details.get('storage_domain') if verification_details else None
            if storage_domain:
                actual_data = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.cookies.getAll({{domain: '{storage_domain}'}}, cookies => {{
                            resolve(JSON.stringify(cookies));
                        }});
                    }})
                """)
            else:
                actual_data = await extension_page.evaluate("""
                    () => new Promise(resolve => {
                        chrome.cookies.getAll({}, cookies => {
                            resolve(JSON.stringify(cookies));
                        });
                    })
                """)

        elif storage_api in HISTORY_APIS:
            # Get recent history
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.history.search({text: '', maxResults: 100}, results => {
                        resolve(JSON.stringify(results));
                    });
                })
            """)

        elif storage_api in MANAGEMENT_APIS:
            # Get all extensions
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.management.getAll(extensions => {
                        resolve(JSON.stringify(extensions));
                    });
                })
            """)

        elif storage_api in TOPSITES_APIS:
            # Get top sites
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.topSites.get(sites => {
                        resolve(JSON.stringify(sites));
                    });
                })
            """)

        elif storage_api in LOCALSTORAGE_APIS:
            # Read localStorage/sessionStorage from extension context
            storage_type = "localStorage" if "localStorage" in storage_api else "sessionStorage"
            actual_data = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        const items = {{}};
                        for (let i = 0; i < {storage_type}.length; i++) {{
                            const key = {storage_type}.key(i);
                            items[key] = {storage_type}.getItem(key);
                        }}
                        return JSON.stringify(items);
                    }} catch(e) {{
                        return null;
                    }}
                }}
            """)

        await extension_page.close()

        # Verify exfiltrated data appears in actual data
        if actual_data:
            # Convert exfiltrated_data to string for comparison (if it's an object/array)
            if isinstance(exfiltrated_data, (dict, list)):
                exfil_str = json.dumps(exfiltrated_data)
            else:
                exfil_str = str(exfiltrated_data)

            # Normalize both for comparison (lowercase, strip whitespace)
            actual_normalized = actual_data.lower().strip()
            exfil_normalized = exfil_str.lower().strip()

            # Check if seeded markers appear in BOTH exfiltrated and actual data
            # This works for simple values AND complex objects (if marker is in object property)
            seeded_markers = ["exploit", "123456789"]
            marker_in_exfil = any(marker in exfil_normalized for marker in seeded_markers)
            marker_in_actual = any(marker in actual_normalized for marker in seeded_markers)

            if marker_in_exfil and marker_in_actual:
                log_info(f"✓ Seeded data found in both exfiltrated and actual browser data")
                return True

            # Fallback: Direct substring match (for non-seeded data like topSites, management)
            data_match = (
                exfil_normalized in actual_normalized or
                actual_normalized in exfil_normalized
            )

            if data_match:
                log_info(f"✓ Exfiltrated data matches actual browser data")
                return True
            else:
                log_error(f"✗ Exfiltrated data NOT in browser data")
                log_error(f"  Exfiltrated: {exfiltrated_data[:100]}...")
                log_error(f"  Actual: {actual_data[:100] if actual_data else 'None'}...")
                return False
        else:
            log_error("No actual data retrieved from browser")
            return False

    except Exception as e:
        log_error(f"Data verification failed: {e}")
        return False  # Safer to reject on error


# ============================================================================
# DETECTION AND EXECUTION
# ============================================================================
async def wait_for_detection(
    page,
    vulnerability_category: Optional[str] = None,
    verification_details: Optional[Dict] = None,
    timeout_ms: Optional[int] = None,
    mock_server=None,
    verification_token: Optional[str] = None,
    extension_id: Optional[str] = None,
    extension_path: Optional[str] = None
) -> Optional[str]:
    """
    Wait for detection events with category-aware detection.

    Uses multiple detection methods:
    - Console logs (for code_execution, 2way_request with unique token)
    - Mock server request counts (for 1way_request, downloads)
    - Downloads (for download vulnerabilities)
    - Storage checks (handled separately)

    Args:
        verification_token: Unique token for 2way_request verification (from mock server)

    Returns:
        The detected vulnerability category matching the analysis categories,
        or None if no detection occurred:
        "code_execution", "1way_request", "2way_request", "download", "storage"
    """
    if timeout_ms is None:
        timeout_ms = config.PAYLOAD_EXECUTION_TIMEOUT

    if verification_details is None:
        verification_details = {}

    detection = None
    console_logs = []
    console_messages = []  # Store full msg objects for later parsing
    token_in_console = False
    extension_request_confirmed = False

    def on_console(msg):
        nonlocal detection, token_in_console
        console_text = msg.text
        console_logs.append(msg.text)
        console_messages.append(msg)  # Store full msg for arg extraction later

        # 2way_request: [2WAY] prefix + token in console is one half of the proof (also needs extension origin)
        if vulnerability_category == "2way_request" and "[2WAY]" in console_text and verification_token and verification_token in console_text:
            token_in_console = True
            if extension_request_confirmed:
                detection = "2way_request"
        # data_exfiltration: Check for exfiltration marker in console
        elif vulnerability_category == "data_exfiltration" and "[EXFIL]" in console_text:
            detection = "data_exfiltration"

    async def on_download(download):
        nonlocal detection
        filename = download.suggested_filename.lower()

        if filename == "exploit.txt":
            detection = "download"

    page.on("console", on_console)
    page.context.on("download", on_download)

    try:
        start_time = asyncio.get_event_loop().time()
        last_check = start_time
        while detection is None:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout_ms / 1000:
                break

            # Check mock server periodically (not every 50ms!)
            current_time = asyncio.get_event_loop().time()
            if current_time - last_check >= 0.5 or current_time - start_time < 0.1:  # Check soon and every 500ms
                # Check mock server for network requests (works for Service Worker requests too)
                # IMPORTANT: Only count as verified if request came from extension context
                if mock_server and vulnerability_category in ["1way_request", "2way_request", "code_execution"]:
                    requests_info = mock_server.get_requests()
                    if requests_info:
                        has_extension_context = requests_info.get('has_extension_context', False)
                        total_requests = requests_info.get('total_requests', 0)

                        if total_requests > 0 and has_extension_context:
                            # Request came from extension context - real vulnerability
                            if vulnerability_category == "1way_request":
                                detection = "1way_request"
                            elif vulnerability_category == "2way_request":
                                # Extension made the request; also need token in console
                                extension_request_confirmed = True
                                if token_in_console:
                                    detection = "2way_request"
                            elif vulnerability_category == "code_execution":
                                # Extension executed attacker-controlled code and made the fetch
                                # ext param != 'web' (enforced by has_extension_context) confirms extension context
                                detection = "code_execution"
                        # If total_requests > 0 but NOT from extension context,
                        # code ran on website only - not a real vulnerability, don't set detection

                # Check mock server for file downloads
                if mock_server and vulnerability_category == "download":
                    requests_info = mock_server.get_requests()
                    if requests_info:
                        # For downloads, check if request to /api/file came from extension context
                        file_requests = [r for r in requests_info.get('requests', []) if r.get('path') == '/api/file']
                        extension_file_requests = [
                            r for r in file_requests
                            if (r.get('extension_id') and r['extension_id'] != 'web')
                            or (r.get('origin') or '').startswith('chrome-extension://')
                        ]
                        if extension_file_requests:
                            detection = "download"

                last_check = current_time

            await asyncio.sleep(0.1)

    except Exception as e:
        log_error(f"Detection waiting error: {e}")

    finally:
        page.remove_listener("console", on_console)
        page.context.remove_listener("download", on_download)

    # 2way_request fallback: extension made the request but token didn't reach the website
    # → still a verified vulnerability, but only 1way
    if detection is None and vulnerability_category == "2way_request" and extension_request_confirmed:
        detection = "1way_request"

    # If no detection, check if requests came but not from extension context (helpful for debugging)
    if detection is None and mock_server:
        requests_info = mock_server.get_requests()
        if requests_info and requests_info.get('total_requests', 0) > 0:
            if not requests_info.get('has_extension_context', False):
                log_info(f"Request received but NOT from extension context (ext='web') - not a vulnerability")

    # CRITICAL: For data_exfiltration, verify that exfiltrated data matches actual browser data
    # This prevents false positives when seeding fails or data is undefined/null
    if detection == "data_exfiltration" and extension_id and extension_path:
        log_info("Verifying exfiltrated data matches actual browser data...")

        # Parse exfiltrated data from console messages (extract actual JS values, not just text!)
        exfiltrated_data = None
        for msg in console_messages:
            if "[EXFIL]" in msg.text:
                try:
                    args = msg.args
                    if len(args) > 1:  # [0] = "[EXFIL]", [1] = actual data
                        # Extract the actual JavaScript value (not just string representation!)
                        exfil_value = await args[1].json_value()

                        # Skip if undefined, null, or empty
                        if exfil_value is not None and exfil_value not in ["", [], {}]:
                            exfiltrated_data = exfil_value
                            break
                except Exception as e:
                    log_error(f"Failed to extract exfiltrated value from console: {e}")
                    continue

        if not exfiltrated_data:
            log_error("No valid data found after [EXFIL] marker - only undefined/null")
            detection = None
        else:
            # Get actual browser data to compare
            storage_api = verification_details.get('storage_api') if verification_details else None
            actual_data_valid = await verify_exfiltrated_data(
                page, storage_api, exfiltrated_data, extension_id, extension_path, verification_details
            )

            if not actual_data_valid:
                log_error("Exfiltrated data does NOT match actual browser data - false positive!")
                detection = None
            else:
                log_success("Exfiltrated data verified against actual browser data")

    return detection


async def execute_payload_and_detect(
    page,
    payload: str,
    vulnerability_category: Optional[str] = None,
    verification_details: Optional[Dict] = None,
    timeout_ms: Optional[int] = None,
    mock_server=None,
    verification_token: Optional[str] = None,
    extension_id: Optional[str] = None,
    extension_path: Optional[str] = None,
    skip_seeding: bool = False
) -> Optional[str]:
    """Execute JavaScript payload and detect based on vulnerability category."""
    if timeout_ms is None:
        timeout_ms = config.PAYLOAD_EXECUTION_TIMEOUT

    if verification_details is None:
        verification_details = {}

    # Check if this API should be skipped
    storage_api = verification_details.get('storage_api')
    if storage_api and storage_api in SKIPPED_APIS:
        log_info(f"API {storage_api} is in skip list - skipping verification")
        return "skipped"  # Special return value to indicate skip

    detection = None

    try:
        # Seed test data BEFORE payload execution (for data_exfiltration and storage delete operations)
        # (unless skip_seeding=True, which means it was already done by the caller)
        if not skip_seeding:
            log_info(f"Checking if seeding needed for {vulnerability_category}...")
            seed_success = await seed_test_data(page, vulnerability_category, verification_details, extension_id, extension_path)
            if not seed_success:
                log_error("Failed to seed test data - ABORTING verification to prevent false positives")
                return None  # CRITICAL: Don't continue without seeded data!

        # For non-storage vulnerabilities, start detection listeners BEFORE payload
        if vulnerability_category != "storage":
            # Start detection task before executing payload
            detection_task = asyncio.create_task(
                wait_for_detection(
                    page,
                    vulnerability_category=vulnerability_category,
                    verification_details=verification_details,
                    timeout_ms=timeout_ms,
                    mock_server=mock_server,
                    verification_token=verification_token,
                    extension_id=extension_id,
                    extension_path=extension_path
                )
            )

        # Give extension time to load and register event listeners
        await asyncio.sleep(1.0)

        # Execute in main world (not isolated world) to allow postMessage communication with extension
        await page.add_script_tag(content=payload)

        # For storage vulnerabilities, check if the key was modified
        if vulnerability_category == "storage":
            storage_api = verification_details.get('storage_api')
            storage_key = verification_details.get('storage_key')
            storage_domain = verification_details.get('storage_domain')

            if not storage_api:
                log_error(f"Storage vulnerability missing required field: storage_api")
                detection = None
            else:
                # Give storage operation time to complete
                await asyncio.sleep(0.5)

                log_info(f"Checking storage: key='{storage_key}' using {storage_api}" + (f" for domain {storage_domain}" if storage_domain else ""))
                storage_modified = await check_storage_modified(page, storage_api, storage_key, extension_id=extension_id, storage_domain=storage_domain, extension_path=extension_path)
                if storage_modified:
                    detection = "storage"
                else:
                    detection = None
        else:
            # Wait for detection task to complete
            detection = await detection_task

    except Exception as e:
        log_error(f"Payload execution: {e}")
        detection = None

    return detection


async def verify_extension(extension_id: str, vulnerabilities: List[dict], debug_mode: bool = False) -> Dict:
    """Verify a single extension's vulnerabilities."""
    verification_result = {
        "extension_id": extension_id,
        "timestamp": datetime.now().isoformat(),
        "status": "failed",  # Will be updated based on verification results
        "vulnerabilities_verified": [],
        "errors": []
    }

    try:
        # Step 1: Get extension code
        if debug_mode:
            log_step(1, "Downloading and extracting extension code")

        extension_dir = get_extension_code_dir(extension_id)
        if not extension_dir:
            verification_result["status"] = "failed"
            verification_result["errors"].append("Extension code not found")
            log_error("Extension code not found")
            return verification_result

        log_success("Extension code extracted")

        if debug_mode and not ask_continue("Proceed to manifest validation?"):
            return verification_result

        # Step 2: Validate extension structure
        if debug_mode:
            log_step(2, "Validating extension structure")

        if not validate_extension_structure(extension_dir):
            verification_result["status"] = "failed"
            verification_result["errors"].append("Invalid extension structure")
            log_error("Invalid extension structure")
            return verification_result

        log_success("Extension structure valid")

        # Separate vulnerabilities by attacker source
        extension_mode_vulns = [v for v in vulnerabilities if v.get('attacker_source') == 'Extension']
        website_mode_vulns = [v for v in vulnerabilities if v.get('attacker_source') == 'Website']

        # Prepare storage verification page if any vulnerability uses ext_* storage
        prepare_extension_storage_verification(extension_dir, vulnerabilities)

        # Modify manifest ONCE for all vulnerabilities (sets all matches to <all_urls>)
        # specific_domain per vulnerability only affects which URL is loaded, not the manifest
        if debug_mode:
            log_step(2, "Modifying manifest.json")
        success, modifications = modify_manifest_for_verification(extension_dir)
        if not success:
            verification_result["status"] = "failed"
            verification_result["errors"].append("Failed to modify manifest")
            log_error("Failed to modify manifest")
            return verification_result
        if modifications["manifest_modified"]:
            mod_parts = []
            if modifications['content_scripts_modified'] > 0:
                mod_parts.append(f"{modifications['content_scripts_modified']} content scripts")
            if modifications['web_accessible_resources_modified'] > 0:
                mod_parts.append(f"{modifications['web_accessible_resources_modified']} web resources")
            if modifications['externally_connectable_modified'] > 0:
                mod_parts.append(f"{modifications['externally_connectable_modified']} externally_connectable")
            log_success(f"Manifest modified ({', '.join(mod_parts)})")
        else:
            log_info("No manifest modifications needed")

        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            vulnerabilities_with_detection = []

            # Step 3a: Handle Extension-Mode vulnerabilities
            if extension_mode_vulns:
                if debug_mode:
                    print(f"\n{Color.BOLD}EXTENSION-MODE VULNERABILITIES{Color.END} ({len(extension_mode_vulns)})")

                for idx, vuln in enumerate(extension_mode_vulns, 1):
                    if debug_mode:
                        print(f"\n{Color.BOLD}[{idx}/{len(extension_mode_vulns)}] Verifying: {vuln.get('rule_id')}{Color.END}")

                    result = await verify_extension_mode_vulnerability(
                        extension_id, extension_dir, vuln, p, debug_mode=debug_mode
                    )
                    vulnerabilities_with_detection.append(result)

            # Step 3b: Handle Website-Mode vulnerabilities
            # IMPORTANT: Each vulnerability gets a fresh browser to avoid data contamination
            if website_mode_vulns:
                if debug_mode:
                    print(f"\n{Color.BOLD}WEBSITE-MODE VULNERABILITIES{Color.END} ({len(website_mode_vulns)})")

                if debug_mode and not ask_continue("Proceed to vulnerability testing?"):
                    return verification_result

                # Step 4 & 5: Launch fresh browser for EACH vulnerability to avoid data contamination
                for idx, vuln in enumerate(website_mode_vulns, 1):
                    if debug_mode:
                        print(f"\n{Color.BOLD}[{idx}/{len(website_mode_vulns)}] Testing: {vuln.get('rule_id')}{Color.END}")
                        log_step(4, f"Launching FRESH browser (avoiding data contamination)")

                    payload = vuln.get('attacker_payload')
                    rule_id = vuln.get('rule_id')

                    # Early skip check for SKIPPED_APIS (before browser launch to avoid wasted work)
                    verification_details_early = vuln.get('verification_details')
                    storage_api_early = verification_details_early.get('storage_api') if verification_details_early else None
                    if storage_api_early and storage_api_early in SKIPPED_APIS:
                        log_info(f"API {storage_api_early} is in skip list - skipping verification")
                        vulnerabilities_with_detection.append({
                            **vuln,
                            "manifest_modifications": modifications,
                            "detection": None,
                            "verification_status": "skipped",
                            "error": None
                        })
                        continue

                    # Start fresh browser for this vulnerability
                    context, user_data_dir = await launch_browser_with_extension(extension_dir, p)

                    if not context:
                        vuln_record = {
                            **vuln,
                            "manifest_modifications": modifications,
                            "detection": None,
                            "verification_status": "browser_launch_failed",
                            "error": "Failed to launch Chrome"
                        }
                        vulnerabilities_with_detection.append(vuln_record)
                        log_error("Failed to launch Chrome")
                        continue

                    log_success("Fresh browser launched")

                    # Discover actual extension ID for this fresh browser instance
                    # Skip discovery for content-script-only extensions (no background context → always times out)
                    payload_cur = vuln.get('attacker_payload', '')
                    needs_id = payload_mentions_extension_id(payload_cur, extension_id)
                    # storage/data_exfiltration need runtime ID for verify_storage.html navigation,
                    # even when the payload doesn't explicitly mention the extension ID
                    vulnerability_category_cur = vuln.get('vulnerability_category', '')
                    needs_storage_context = vulnerability_category_cur in ('storage', 'data_exfiltration')
                    if (not needs_id and not needs_storage_context) or not has_background_context(extension_dir):
                        actual_extension_id = extension_id
                        if needs_id or needs_storage_context:
                            log_info("No background context – skipping ID discovery, using original ID")
                    else:
                        temp_page = await context.new_page()
                        try:
                            await temp_page.goto("http://example.com", timeout=30000, wait_until="domcontentloaded")
                        except Exception:
                            pass
                        await asyncio.sleep(0.5)

                        actual_extension_id = await discover_runtime_extension_id_from_context(
                            context, timeout_ms=5000, debug=debug_mode
                        )
                        await temp_page.close()

                        if not actual_extension_id:
                            log_info("Warning: Could not discover actual extension ID, using original ID")
                            actual_extension_id = extension_id
                        else:
                            log_info(f"Discovered actual extension ID: {actual_extension_id}")

                    vuln_record = {
                        **vuln,
                        "manifest_modifications": modifications,
                        "detection": None,
                        "verification_status": None,
                        "error": None
                    }

                    if debug_mode:
                        log_step(5 + idx - 1, f"Executing payload for {rule_id}")

                    if payload:
                        # Replace extension ID in payload if needed
                        modified_payload = payload
                        if payload_mentions_extension_id(payload, extension_id) and actual_extension_id and actual_extension_id != extension_id:
                            modified_payload = replace_extension_id_in_payload(payload, extension_id, actual_extension_id)

                        try:
                            page = await context.new_page()

                            if debug_mode:
                                log_info("Navigating to example.com...")

                            try:
                                # Use HTTP (not HTTPS) to avoid mixed content blocking HTTP requests to mock server
                                await page.goto("http://example.com", timeout=30000, wait_until="domcontentloaded")
                                # Ensure this page/tab is active (bring to front)
                                await page.bring_to_front()
                                log_success("Page loaded successfully")
                            except Exception as nav_error:
                                log_error(f"Navigation failed: {nav_error}")
                                # Try to get more info about what happened
                                try:
                                    content = await page.content()
                                    if "ERR_" in content or len(content) < 100:
                                        log_error("Page content appears to be an error")
                                except:
                                    pass
                                vuln_record["verification_status"] = "page_load_failed"
                                vuln_record["error"] = str(nav_error)
                                await page.close()
                                await context.close()
                                if user_data_dir and user_data_dir.exists():
                                    shutil.rmtree(user_data_dir, ignore_errors=True)
                                vulnerabilities_with_detection.append(vuln_record)
                                continue

                            if debug_mode:
                                log_info("Page loaded, opening console")
                                await page.keyboard.press('Control+Shift+J')
                                await asyncio.sleep(0.5)

                                if not ask_continue("Execute payload?"):
                                    vuln_record["verification_status"] = "skipped"
                                    await page.close()
                                    await context.close()
                                    if user_data_dir and user_data_dir.exists():
                                        shutil.rmtree(user_data_dir, ignore_errors=True)
                                    vulnerabilities_with_detection.append(vuln_record)
                                    continue

                            # Get mock server for detection and verification token
                            mock_server = get_mock_server()
                            verification_token = mock_server.reset_and_get_token()

                            # Seed test data ONCE (for data_exfiltration and storage delete operations)
                            vulnerability_category = vuln.get('vulnerability_category')
                            log_info(f"Checking if seeding needed for {vulnerability_category}...")
                            seed_success = await seed_test_data(
                                page,
                                vulnerability_category,
                                vuln.get('verification_details'),
                                actual_extension_id,
                                str(extension_dir)
                            )
                            if not seed_success:
                                log_error("Failed to seed test data - ABORTING to prevent false positives")
                                vuln_record["verification_status"] = "seeding_failed"
                                vuln_record["error"] = "Failed to seed test data"
                                await page.close()
                                await context.close()
                                if user_data_dir and user_data_dir.exists():
                                    shutil.rmtree(user_data_dir, ignore_errors=True)
                                vulnerabilities_with_detection.append(vuln_record)
                                continue  # Skip this vulnerability

                            detection = await execute_payload_and_detect(
                                page,
                                modified_payload,
                                vulnerability_category=vulnerability_category,
                                verification_details=vuln.get('verification_details'),
                                mock_server=mock_server,
                                verification_token=verification_token,
                                extension_id=actual_extension_id,
                                extension_path=str(extension_dir),
                                skip_seeding=True  # Already seeded above
                            )

                            # Retry once if no detection (extension warm-up issue)
                            # Only retry for network/code_execution categories where timing is the likely cause
                            if not detection and vulnerability_category in RETRY_CATEGORIES:
                                try:
                                    if page.is_closed():
                                        raise RuntimeError("Page was closed before retry")
                                    # Navigate back to example.com (page may be on wrong domain after storage check)
                                    await page.goto("http://example.com", wait_until="domcontentloaded", timeout=15000)
                                    await asyncio.sleep(1.0)
                                    verification_token = mock_server.reset_and_get_token()
                                    detection = await execute_payload_and_detect(
                                        page,
                                        modified_payload,
                                        vulnerability_category=vulnerability_category,
                                        verification_details=vuln.get('verification_details'),
                                        mock_server=mock_server,
                                        verification_token=verification_token,
                                        extension_id=actual_extension_id,
                                        extension_path=str(extension_dir),
                                        skip_seeding=True  # Don't seed again on retry!
                                    )
                                except Exception as retry_err:
                                    log_error(f"Retry failed: {retry_err}")
                                    detection = None

                            vuln_record["detection"] = detection

                            if detection:
                                vuln_record["verification_status"] = "verified"
                                log_success(f"Detection: {detection}")
                            else:
                                vuln_record["verification_status"] = "no_detection"
                                log_info("Payload executed, no detection")

                            if debug_mode:
                                log_info("Payload executed - inspect the page/console now")
                                if not ask_continue("Close browser and continue?"):
                                    vuln_record["verification_status"] = "skipped"
                                    await page.close()
                                    await context.close()
                                    # Cleanup user data directory
                                    if user_data_dir and user_data_dir.exists():
                                        shutil.rmtree(user_data_dir, ignore_errors=True)
                                    vulnerabilities_with_detection.append(vuln_record)
                                    continue

                            try:
                                await asyncio.wait_for(page.close(), timeout=5.0)
                            except (asyncio.TimeoutError, Exception):
                                pass
                        except Exception as e:
                            vuln_record["verification_status"] = "execution_error"
                            vuln_record["error"] = str(e)
                            log_error(f"Payload execution: {e}")
                    else:
                        vuln_record["verification_status"] = "missing_payload"
                        log_info("No payload provided")

                    vulnerabilities_with_detection.append(vuln_record)

                    # Close browser after THIS vulnerability (fresh browser for next one)
                    if debug_mode:
                        log_info("Closing browser to ensure clean state for next vulnerability")
                        if not ask_continue("Close browser?"):
                            input("Press Enter to close browser...")

                    try:
                        await asyncio.wait_for(context.close(), timeout=10.0)
                    except asyncio.TimeoutError:
                        log_info("Browser close timed out (10s) — continuing")
                    except Exception:
                        pass

                    # Cleanup user data directory to free disk space
                    if user_data_dir and user_data_dir.exists():
                        try:
                            shutil.rmtree(user_data_dir, ignore_errors=True)
                            log_info(f"Cleaned up user data directory")
                        except Exception as cleanup_error:
                            log_error(f"Cleanup warning: {cleanup_error}")

            # Set final verification status
            verification_result["vulnerabilities_verified"] = vulnerabilities_with_detection

            # Determine overall status based on vulnerability results
            detections = [v.get('detection') for v in vulnerabilities_with_detection if v.get('detection')]

            # Count different vulnerability statuses
            vuln_statuses = [v.get('verification_status') for v in vulnerabilities_with_detection]
            has_errors = any(s in ['execution_error', 'page_load_failed', 'browser_launch_failed',
                                   'manifest_mod_failed', 'verifier_prep_failed',
                                   'extension_id_discovery_failed', 'extension_id_determination_failed',
                                   'seeding_failed', 'error'] for s in vuln_statuses)
            has_skipped = any(s == 'skipped' for s in vuln_statuses)

            if detections:
                verification_result["status"] = "verified"
            elif has_errors:
                verification_result["status"] = "error"
            elif has_skipped:
                verification_result["status"] = "skipped"
            else:
                # No detections and no errors = failed verification
                verification_result["status"] = "failed"

            log_success(f"Extension verification complete: {verification_result['status']}")

    except Exception as e:
        log_error(f"Verification error: {e}")
        verification_result["status"] = "error"
        verification_result["errors"].append(str(e))

    return verification_result


# ============================================================================
# MAIN
# ============================================================================
async def main():
    """Main verification workflow."""
    print("\n" + "=" * 70)
    print("EXTENSION VERIFICATION")
    print("=" * 70)

    # Start mock server
    mock_server = get_mock_server()
    if not mock_server.start():
        log_error("Failed to start mock server")
        return

    mock_server_url = mock_server.get_url()
    log_mock_server_ready(mock_server_url)

    # Get analysis results directory (based on config.RESULTS_TO_VERIFY)
    results_dir = get_analysis_results_dir()
    if not results_dir:
        log_error("Cannot find results directory")
        return

    log_info(f"Using results: {results_dir.name}")

    # Load and filter results (recursively searches all subdirectories)
    all_results = load_json_results(results_dir)
    if not all_results:
        log_error("No results found")
        return

    tp_verifiable = filter_tp_verifiable_results(all_results)
    if not tp_verifiable:
        log_error("No TP+verifiable vulnerabilities found")
        return

    # Apply VERIFIER_FILTER settings (category, storage_api, min/max vulnerability count)
    tp_verifiable = apply_verifier_filters(tp_verifiable)
    if not tp_verifiable:
        log_error("No extensions remain after applying VERIFIER_FILTER")
        return

    # Filter for single extension if specified (only if DEBUG_SINGLE_RESULT_FILE not used)
    single_extension_mode = config.DEBUG_SINGLE_EXTENSION is not None and config.DEBUG_SINGLE_EXTENSION != ""
    single_file_mode = config.DEBUG_SINGLE_RESULT_FILE is not None and config.DEBUG_SINGLE_RESULT_FILE != ""

    if single_extension_mode and not single_file_mode:
        tp_verifiable = [
            (ext_id, vulns, path, subdir) for ext_id, vulns, path, subdir in tp_verifiable
            if ext_id == config.DEBUG_SINGLE_EXTENSION
        ]
        if not tp_verifiable:
            log_error(f"Extension not found: {config.DEBUG_SINGLE_EXTENSION}")
            return

    # Create (or resume) verification output directory (mirrors structure from results_analysis)
    verification_output_dir = get_or_create_verification_output_dir(results_dir.name)
    log_info(f"Output directory: {verification_output_dir.relative_to(config.RESULTS_VERIFICATION_DIR)}")

    # Use debug mode from config
    debug_mode = config.DEBUG_MODE

    if debug_mode:
        print(f"\n{Color.BOLD}DEBUG MODE ENABLED{Color.END}")
        if single_file_mode:
            print(f"  Single file mode: {config.DEBUG_SINGLE_RESULT_FILE}")
        elif single_extension_mode:
            print(f"  Single extension mode: {config.DEBUG_SINGLE_EXTENSION}")
        log_step(0, "Mock server initialization")
        log_success("Mock server running")
        log_info(f"Endpoints: {mock_server_url}/api/data, {mock_server_url}/api/file")
        log_info("Step-by-step verification with manual confirmation at each step")
        print()
    else:
        log_info(f"Extensions to verify: {len(tp_verifiable)}")
        log_info(f"Mock server: {mock_server_url}")
        print()

    # Verify each extension
    all_verifications = []
    resume_mode = bool(getattr(config, 'RESUME_VERIFICATION_RUN', None))
    for idx, (extension_id, vulnerabilities, _, relative_subdir) in enumerate(tp_verifiable, 1):
        # Pre-compute output paths so we can check for existing results
        output_subdir = verification_output_dir / relative_subdir
        verification_file = output_subdir / f"{extension_id}_verification.json"

        # Skip already-verified extensions when resuming
        if resume_mode and verification_file.exists():
            with open(verification_file, 'r', encoding='utf-8') as f:
                existing = json.load(f)
            all_verifications.append(existing)
            if not debug_mode:
                print(f"[{idx}/{len(tp_verifiable)}] {extension_id}... skipped (already verified)")
            continue

        if debug_mode:
            print(f"\n{Color.BOLD}Verifying: {extension_id}{Color.END}")
        else:
            print(f"[{idx}/{len(tp_verifiable)}] {extension_id}...", end=" ", flush=True)

        verification = await verify_extension(extension_id, vulnerabilities, debug_mode=debug_mode)
        all_verifications.append(verification)

        # Save individual verification result (preserve subdirectory structure)
        output_subdir.mkdir(parents=True, exist_ok=True)
        with open(verification_file, 'w', encoding='utf-8') as f:
            json.dump(verification, f, indent=2, default=str)

        if not debug_mode:
            status = verification.get('status', 'unknown')
            detections = len([v for v in verification.get('vulnerabilities_verified', []) if v.get('detection')])
            print(f"{status} ({detections} detected)" if detections else f"{status}")

    # Save summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "source_results_dir": results_dir.name,
        "total_extensions": len(tp_verifiable),
        "debug_mode": debug_mode,
        "verifications": all_verifications,
        "summary_stats": {
            "verified": sum(1 for v in all_verifications if v.get('status') == 'verified'),
            "failed": sum(1 for v in all_verifications if v.get('status') == 'failed'),
            "error": sum(1 for v in all_verifications if v.get('status') == 'error'),
            "skipped": sum(1 for v in all_verifications if v.get('status') == 'skipped'),
        }
    }

    summary_file = verification_output_dir / "verification_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, default=str)

    # Stop mock server
    mock_server.stop()

    # Summary
    print("\n" + "=" * 70)
    stats = summary['summary_stats']
    print(f"Results:")
    print(f"  Verified: {stats['verified']}")
    print(f"  Failed:   {stats['failed']}")
    print(f"  Error:    {stats['error']}")
    print(f"  Skipped:  {stats['skipped']}")
    print(f"Saved: {verification_output_dir}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
