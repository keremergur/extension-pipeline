import json
import os
import shutil
from pathlib import Path
from typing import List, Optional
import config
from .logging_utils import log_error, log_info


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


def _fmt_env_value(value) -> str:
    """Render a resolved config value back into the env-file string form.

    None -> "none" (the disable sentinel), lists/tuples -> comma-separated,
    everything else -> str(value). Used so the snapshot round-trips through the
    same _env_list / _env_int_or_none parsing in config.py.
    """
    if value is None:
        return "none"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def write_env_snapshot(verification_output_dir: Path) -> Path:
    """Record the configuration used for this run inside the run folder.

    With `docker run --env-file <file>` the variables are injected into the
    environment but the original file path is not visible to the process. So:
    - If the optional `ENV_FILE` variable points to a readable file, copy that
      exact file into the run folder (keeps its original name, e.g. .env.config1).
    - Otherwise, write a reconstructed snapshot of the resolved verifier settings
      so every run still carries a record of how it was configured.

    Returns the path of the file written.
    """
    env_file = os.getenv("ENV_FILE")
    if env_file and Path(env_file).is_file():
        dest = verification_output_dir / Path(env_file).name
        shutil.copy2(env_file, dest)
        log_info(f"Copied env file into run folder: {dest.name}")
        return dest

    lines = [
        "# Snapshot of the verifier configuration for this run.",
        "# Reconstructed from resolved settings (ENV_FILE not set, so the original",
        "# env file path is unknown when using `docker --env-file`).",
        f"EXTENSION_CODE_DIR={config.EXTENSION_CODE_DIR}",
        f"RESULTS_ANALYSIS_DIR={config.RESULTS_ANALYSIS_DIR}",
        f"RESULTS_VERIFICATION_DIR={config.RESULTS_VERIFICATION_DIR}",
        f"CHROME_BINARY_PATH={config.CHROME_BINARY_PATH}",
        f"RESULTS_TO_VERIFY={config.RESULTS_TO_VERIFY}",
        f"HEADLESS={config.HEADLESS}",
        f"USE_LOCAL_VERIFICATION_SERVER={config.USE_LOCAL_VERIFICATION_SERVER}",
        f"VERIFICATION_PAGE_URL={config.VERIFICATION_PAGE_URL}",
        f"MOCK_SERVER_HOST={config.MOCK_SERVER_HOST}",
        f"MOCK_SERVER_PORT={config.MOCK_SERVER_PORT}",
        f"PAYLOAD_EXECUTION_TIMEOUT={config.PAYLOAD_EXECUTION_TIMEOUT}",
        f"PAGE_NAVIGATION_TIMEOUT={config.PAGE_NAVIGATION_TIMEOUT}",
        f"RETRY_NAVIGATION_TIMEOUT={config.RETRY_NAVIGATION_TIMEOUT}",
        f"EXTENSION_CONTEXT_NAVIGATION_TIMEOUT={config.EXTENSION_CONTEXT_NAVIGATION_TIMEOUT}",
        f"EXTENSION_ID_DISCOVERY_TIMEOUT={config.EXTENSION_ID_DISCOVERY_TIMEOUT}",
        f"BROWSER_CLOSE_TIMEOUT={config.BROWSER_CLOSE_TIMEOUT}",
        f"PAGE_CLOSE_TIMEOUT={config.PAGE_CLOSE_TIMEOUT}",
        f"DETERMINISTIC_EXTENSION_ID={config.DETERMINISTIC_EXTENSION_ID}",
        f"EXTENSION_CONTEXT_ID_RECOVERY={config.EXTENSION_CONTEXT_ID_RECOVERY}",
        f"VERIFIER_FILTER_VULNERABILITY_CATEGORIES={_fmt_env_value(config.VERIFIER_FILTER.get('vulnerability_categories'))}",
        f"VERIFIER_FILTER_STORAGE_APIS={_fmt_env_value(config.VERIFIER_FILTER.get('storage_apis'))}",
        f"VERIFIER_FILTER_MIN_VULNERABILITIES={_fmt_env_value(config.VERIFIER_FILTER.get('min_vulnerabilities'))}",
        f"VERIFIER_FILTER_MAX_VULNERABILITIES={_fmt_env_value(config.VERIFIER_FILTER.get('max_vulnerabilities'))}",
    ]
    dest = verification_output_dir / "env_used.env"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log_info(f"Wrote env snapshot into run folder: {dest.name}")
    return dest
