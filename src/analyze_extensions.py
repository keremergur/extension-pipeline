"""
Main script for analyzing Chrome Extension vulnerability datasets using LLMs.
"""

from pathlib import Path
from typing import List, Optional, Tuple, Dict
import re
import requests
import json
import time
import random
import hashlib
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from sshtunnel import SSHTunnelForwarder
import jsbeautifier
import config

# Global lock for thread-safe file logging
_log_file_lock = threading.Lock()
# Thread-local storage for per-worker context (e.g. extension ID prefix)
_thread_local = threading.local()


class TokenBucket:
    """Sliding-window token counter to proactively stay under Google's TPM limit.

    Tracks how many input tokens have been submitted in the last `window` seconds.
    Workers check this before submitting and sleep until there is headroom.
    """
    def __init__(self, limit: int = 800_000, window: int = 60):
        self._limit = limit
        self._window = window
        self._entries: list = []  # [(submit_time, token_count), ...]
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        """Remove entries older than window seconds. Must be called with lock held."""
        cutoff = now - self._window
        self._entries = [(t, n) for t, n in self._entries if t > cutoff]

    def current(self) -> int:
        with self._lock:
            self._evict(time.time())
            return sum(n for _, n in self._entries)

    def add(self, tokens: int) -> None:
        """Record a successful submission."""
        with self._lock:
            self._evict(time.time())
            self._entries.append((time.time(), tokens))

    def remove(self, tokens: int) -> None:
        """Undo an optimistic add when a submission was rejected (rate limit)."""
        with self._lock:
            for i in range(len(self._entries) - 1, -1, -1):
                if self._entries[i][1] == tokens:
                    self._entries.pop(i)
                    return

    def wait_and_add(self, tokens: int) -> None:
        """Atomically wait until tokens fit, then add them in one lock acquisition.

        Check and add happen inside the same lock, so no two workers can both
        see 'room available' and slip through simultaneously.
        """
        while True:
            with self._lock:
                self._evict(time.time())
                total = sum(n for _, n in self._entries)
                if total + tokens <= self._limit:
                    self._entries.append((time.time(), tokens))
                    return
            print(f"  🪣  Token bucket full ({total:,}/{self._limit:,}) - waiting 10s...")
            time.sleep(10)

    def replace_and_wait(self, tokens: int) -> None:
        """Atomically refresh an existing slot: find the most recent entry of
        `tokens`, swap it for a fresh one (updated timestamp), all within one
        lock acquisition.

        Used on retry so there is NO gap between releasing the old slot and
        claiming the new one.  Other workers cannot slip in during the swap.

        If the old entry has already aged out (evicted), behaves like
        wait_and_add(): blocks until there is room, then adds a fresh entry.
        """
        while True:
            with self._lock:
                self._evict(time.time())
                total = sum(n for _, n in self._entries)

                # Locate the most recent matching entry (our previous slot)
                old_idx = None
                for i in range(len(self._entries) - 1, -1, -1):
                    if self._entries[i][1] == tokens:
                        old_idx = i
                        break

                # Total without our old slot
                total_without_old = total - tokens if old_idx is not None else total

                if total_without_old + tokens <= self._limit:
                    # Fits: remove old entry (if still present) and add fresh one
                    if old_idx is not None:
                        self._entries.pop(old_idx)
                    self._entries.append((time.time(), tokens))
                    return
                # Bucket is full even excluding our own slot → hold it and wait

            print(f"  🪣  Token bucket full ({total_without_old:,}/{self._limit:,}) - waiting 10s...")
            time.sleep(10)


_token_bucket = TokenBucket()

# Import helper functions
from helpers.extension_downloader import download_crx, extract_crx

# Import API clients based on configuration
if config.LLM_PROVIDER == 'openai':
    from openai import OpenAI
elif config.LLM_PROVIDER == 'anthropic':
    import anthropic
elif config.LLM_PROVIDER in ['gemini', 'gemini_batch']:
    from google import genai
    from google.genai import types as genai_types


# ============================================================================
# GLOBALS
# ============================================================================
CURRENT_RESULTS_DIR = None


# ============================================================================
# INITIALIZATION
# ============================================================================
def create_results_directory() -> Path:
    """Create timestamped results directory."""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    model_id = get_model_identifier()
    dir_name = f"results_{model_id}_{timestamp}"
    results_dir = config.RESULTS_ANALYSIS_DIR / dir_name
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def get_or_create_results_directory() -> Path:
    """Return existing directory (resume) or create a new one."""
    resume = getattr(config, 'RESUME_RUN', None)
    if not resume:
        return create_results_directory()

    if resume == "latest":
        candidates = sorted(config.RESULTS_ANALYSIS_DIR.glob("results_*"))
        if not candidates:
            raise ValueError("RESUME_RUN='latest' but no results directories found")
        results_dir = candidates[-1]
    else:
        results_dir = config.RESULTS_ANALYSIS_DIR / resume
        if not results_dir.exists():
            raise ValueError(f"RESUME_RUN directory not found: {results_dir}")

    print(f"RESUMING run: {results_dir.name}")
    return results_dir


def get_model_identifier() -> str:
    """Get model identifier for folder naming."""
    if config.LLM_PROVIDER == 'ollama':
        return config.OLLAMA_MODEL_PRESET
    return config.LLM_PROVIDER


def get_current_model_name() -> str:
    """Get full model name for display."""
    providers = {
        'ollama': config.OLLAMA_MODEL,
        'openai': config.OPENAI_MODEL,
        'anthropic': config.ANTHROPIC_MODEL,
        'gemini': config.GEMINI_MODEL,
        'gemini_batch': config.GEMINI_MODEL
    }
    return providers.get(config.LLM_PROVIDER, "unknown")


def setup_llm_client():
    """Initialize LLM client based on provider."""
    if config.LLM_PROVIDER == 'ollama':
        tunnel = setup_ssh_tunnel()
        print(f"SSH tunnel: localhost:{tunnel.local_bind_port}")
        return tunnel, tunnel.local_bind_port

    if config.LLM_PROVIDER == 'openai':
        client = OpenAI(api_key=config.OPENAI_API_KEY)
        print("OpenAI initialized")
        return None, client

    if config.LLM_PROVIDER == 'anthropic':
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        print("Anthropic initialized")
        return None, client

    if config.LLM_PROVIDER in ['gemini', 'gemini_batch']:
        # Create client using new google-genai package
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        print(f"Google Gemini initialized ({config.GEMINI_MODEL})")
        if config.LLM_PROVIDER == 'gemini_batch':
            print(f"  Batch mode: {config.GEMINI_BATCH_MODE}")
        return None, client

    raise ValueError(f"Unknown provider: {config.LLM_PROVIDER}")


def setup_ssh_tunnel() -> SSHTunnelForwarder:
    """Set up SSH tunnel to Ollama API."""
    tunnel = SSHTunnelForwarder(
        (config.OLLAMA_SSH_HOST, config.OLLAMA_SSH_PORT),
        ssh_username=config.OLLAMA_SSH_USER,
        ssh_password=config.OLLAMA_SSH_PASSWORD,
        remote_bind_address=('127.0.0.1', 11434),
        local_bind_address=('127.0.0.1', 0),
        allow_agent=False,
        host_pkey_directories=[]
    )
    tunnel.start()
    return tunnel


# ============================================================================
# LOGGING
# ============================================================================
# Global variable to track current dataset for logging
CURRENT_DATASET_NAME = None

def log_message(dataset_name: str, message_type: str, message: str):
    """Log message to dataset log file (thread-safe)."""
    log_file = CURRENT_RESULTS_DIR / dataset_name / "log.txt"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with _log_file_lock:  # Thread-safe file writing
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message_type}: {message}\n")


def log(message: str, level: str = "INFO"):
    """Console logging with consistent format.

    Also writes to log file if CURRENT_DATASET_NAME is set.
    """
    # Per-worker prefix for readable parallel output
    ext_id = getattr(_thread_local, 'extension_id', None)
    prefix = f"[{ext_id[:12]}] " if ext_id else ""

    # Console output
    if level == "INFO":
        print(f"  {prefix}{message}")
    elif level == "ERROR":
        print(f"  {prefix}ERROR: {message}")
    elif level == "HEADER":
        print(f"\n{'='*80}")
        print(f"{prefix}{message}")
        print('='*80)

    # Also write to file if dataset is set (thread-safe)
    if CURRENT_DATASET_NAME and CURRENT_RESULTS_DIR:
        try:
            log_file = CURRENT_RESULTS_DIR / CURRENT_DATASET_NAME / "log.txt"
            if log_file.exists() or log_file.parent.exists():
                log_file.parent.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with _log_file_lock:  # Thread-safe file writing
                    with open(log_file, 'a', encoding='utf-8') as f:
                        if level == "HEADER":
                            f.write(f"\n[{timestamp}] {'='*60}\n{message}\n{'='*60}\n")
                        else:
                            f.write(f"[{timestamp}] {level}: {message}\n")
        except:
            pass  # Don't crash if file logging fails


# ============================================================================
# DATASET HANDLING
# ============================================================================
def get_extensions_for_dataset(dataset_config: dict) -> List[Path]:
    """Get extension directories for a dataset."""
    dataset_name = dataset_config["name"]
    tool_type = dataset_config["tool"]
    reports_dir = config.DATASETS_DIR / dataset_name

    if not reports_dir.exists():
        log(f"Directory not found: {reports_dir}", "ERROR")
        return []

    # Collect all extensions
    all_extensions = _collect_extensions(reports_dir, tool_type)

    # Apply filtering
    extensions = _filter_extensions(all_extensions, dataset_config)

    # Validate extensions
    valid_extensions = _validate_extensions(extensions, dataset_config)

    return valid_extensions


def _collect_extensions(reports_dir: Path, tool_type: str) -> List[Path]:
    """Collect all extension directories or report files."""
    if tool_type == "doublex":
        extensions_dir = reports_dir / "extensions"
        if not extensions_dir.exists():
            return []
        return [d for d in extensions_dir.iterdir() if d.is_dir()]

    if tool_type == "codeql":
        # For CodeQL, return JSON report files instead of directories
        return sorted([f for f in reports_dir.iterdir() if f.is_file() and f.suffix == '.json'])

    return [d for d in reports_dir.iterdir() if d.is_dir()]


def _filter_extensions(extensions: List[Path], dataset_config: dict) -> List[Path]:
    """Apply limit and specific filters."""
    specific = dataset_config.get("specific")
    limit = dataset_config.get("limit")

    # Filter to specific extensions
    if specific:
        extensions = [e for e in extensions if e.name in specific]
        log(f"Filtered to {len(extensions)} specific extensions")
        return extensions

    # Apply limit
    extensions = sorted(extensions)
    if limit and limit > 0:
        extensions = extensions[:limit]
        log(f"Limited to {limit} extensions")

    return extensions


def _validate_extensions(extensions: List[Path], dataset_config: dict) -> List[Path]:
    """Validate that extensions have required datasets."""
    dataset_name = dataset_config["name"]
    tool_type = dataset_config["tool"]
    valid = []
    invalid_count = 0

    for ext_dir in extensions:
        report_path = _get_report_path(ext_dir, dataset_name, tool_type)
        if report_path and report_path.exists():
            valid.append(ext_dir)
        else:
            invalid_count += 1
            log_message(dataset_name, "INVALID", f"{ext_dir.name} - Missing report")

    if invalid_count > 0:
        log(f"Skipped {invalid_count} extensions without datasets")

    return valid


def _get_report_path(ext_path: Path, dataset_name: str, tool_type: str) -> Optional[Path]:
    """Get report file path for an extension."""
    if tool_type == "coco":
        return ext_path / "opgen_generated_files" / "used_time.txt"

    if tool_type == "doublex":
        return config.DATASETS_DIR / dataset_name / f"{ext_path.name}-analysis.json"

    if tool_type == "codeql":
        # For CodeQL, ext_path is already the JSON file
        return ext_path if ext_path.is_file() and ext_path.suffix == '.json' else None

    return None


# ============================================================================
# REPORT PROCESSING
# ============================================================================
def clean_coco_report(report_content: str) -> str:
    """Remove code snippets from CoCo report, keeping only metadata."""
    if not report_content:
        return ""

    lines = report_content.split('\n')
    cleaned_lines = []
    in_code_block = False

    for line in lines:
        if line.strip().startswith('Line '):
            in_code_block = True
            continue

        if in_code_block:
            # Exit code block on metadata line
            if (line.startswith('$FilePath$') or line.startswith('~~~') or
                line.startswith('===') or line.startswith('([') or
                line.strip().startswith('Line ') or not line.strip()):
                in_code_block = False
            else:
                continue

        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


def extract_line_numbers_from_coco(report_content: str) -> dict:
    """Extract file paths and line ranges from CoCo report.

    Returns:
        dict: {filename: [(start, end), ...]}
    """
    line_refs = {}
    current_file = None

    for line in report_content.split('\n'):
        if line.startswith('$FilePath$'):
            file_path = line.replace('$FilePath$', '').strip()
            if '/opgen_generated_files/' in file_path:
                file_path = file_path.split('/opgen_generated_files/')[-1]
            current_file = file_path
            if current_file not in line_refs:
                line_refs[current_file] = []

        elif line.strip().startswith('Line ') and current_file:
            try:
                line_num = int(line.strip().split()[1])
                # Store as single-line range
                line_refs[current_file].append((line_num, line_num))
            except (ValueError, IndexError):
                pass

    return line_refs


def extract_line_numbers_from_doublex(report_content: str) -> dict:
    """Extract file paths and line ranges from DoubleX JSON report.

    Returns:
        dict: {filename: [(start, end), ...]}
    """
    line_refs = {}

    try:
        data = json.loads(report_content)
    except json.JSONDecodeError:
        return line_refs

    for section in ['cs', 'bp']:
        if section not in data:
            continue

        for danger_type in ['direct_dangers', 'indirect_dangers', 'exfiltration_dangers']:
            dangers = data[section].get(danger_type, {})

            for danger_info in dangers.values():
                filename = danger_info.get('filename', '')
                if '/' in filename:
                    filename = filename.split('/')[-1]

                if filename not in line_refs:
                    line_refs[filename] = []

                line_range = str(danger_info.get('line', ''))
                if ' - ' in line_range:
                    try:
                        start, end = line_range.split(' - ')
                        # Store as range
                        line_refs[filename].append((int(start), int(end)))
                    except ValueError:
                        pass
                else:
                    try:
                        line_num = int(line_range)
                        # Store as single-line range
                        line_refs[filename].append((line_num, line_num))
                    except ValueError:
                        pass

    return line_refs


def extract_line_numbers_from_codeql(report_content: str) -> dict:
    """Extract file paths and line ranges from CodeQL report (both old SARIF and new compact format).

    Returns:
        dict: {filename: [(start, end), ...]}
    """
    line_refs = {}

    try:
        data = json.loads(report_content)
    except json.JSONDecodeError:
        return line_refs

    # Handle both old SARIF format (runs[0].results) and new compact format (results)
    if 'results' in data:
        results = data.get('results', [])
    else:
        results = data.get('runs', [{}])[0].get('results', [])

    for result in results:
        # Extract from main locations
        for loc in result.get('locations', []):
            artifact = loc.get('artifactLocation', {})
            region = loc.get('region', {})

            filename = artifact.get('file', '')
            start_line = region.get('startLine', 0)
            end_line = region.get('endLine', start_line)

            if filename and start_line > 0:
                if filename not in line_refs:
                    line_refs[filename] = []

                # Store as range directly
                line_refs[filename].append((start_line, end_line))

        # Extract from code flows (data flow paths)
        for flow in result.get('codeFlows', []):
            for thread_flow in flow.get('threadFlows', []):
                for flow_loc in thread_flow.get('locations', []):
                    location = flow_loc.get('location', {})
                    artifact = location.get('artifactLocation', {})
                    region = location.get('region', {})

                    filename = artifact.get('file', '')
                    start_line = region.get('startLine', 0)
                    end_line = region.get('endLine', start_line)

                    if filename and start_line > 0:
                        if filename not in line_refs:
                            line_refs[filename] = []

                        # Store as range directly
                        line_refs[filename].append((start_line, end_line))

    return line_refs


def filter_codeql_sarif_report(report_content: str) -> str:
    """Process CodeQL report - handles both old SARIF and new compact format.

    New format (already filtered server-side):
    {
        "artifacts": [...],
        "results": [...]
    }

    Old format (needs filtering):
    {
        "runs": [{
            "results": [...]
        }]
    }
    """
    try:
        data = json.loads(report_content)
    except json.JSONDecodeError:
        return report_content

    # Check if new compact format (already filtered)
    if 'artifacts' in data and 'results' in data:
        # New format - already filtered, return as-is
        return report_content

    # Old SARIF format - extract and filter results
    results = []
    if 'runs' in data and len(data['runs']) > 0:
        run = data['runs'][0]
        if 'results' in run:
            # Filter out chrome/manifest-version results
            results = [r for r in run['results'] if r.get('ruleId') != 'chrome/manifest-version']

    # Return filtered results as JSON
    filtered_report = {
        "results": results
    }

    return json.dumps(filtered_report, indent=2)


def beautify_js(content: str) -> str:
    """Beautify minified JavaScript code with caching.

    Cache is based on content hash to avoid re-beautifying the same code.
    This significantly speeds up repeated analysis of the same extensions.
    """
    # Create cache directory
    cache_dir = config.BASE_DIR / ".beautify_cache"
    cache_dir.mkdir(exist_ok=True)

    # Generate hash of content
    content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
    cache_file = cache_dir / f"{content_hash}.js"

    # Check cache
    if cache_file.exists():
        try:
            return cache_file.read_text(encoding='utf-8')
        except:
            pass  # If cache read fails, re-beautify

    # Beautify
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        beautified = jsbeautifier.beautify(content, opts)

        # Save to cache
        try:
            cache_file.write_text(beautified, encoding='utf-8')
        except:
            pass  # If cache write fails, no problem - just slower next time

        return beautified
    except Exception as e:
        # If beautification fails, return original
        return content


def extract_code_context(ext_dir: Path, line_refs: dict, context_lines: int = 10) -> str:
    """Extract code lines with context from extension files.

    Automatically beautifies all JavaScript files for better readability.

    Args:
        ext_dir: Directory containing extension code
        line_refs: Dict mapping filename to list of (start_line, end_line) tuples
        context_lines: Number of lines to add before/after each range

    Returns:
        Formatted string with code context
    """
    if not line_refs:
        return ""

    output = ["# ORIGINAL EXTENSION CODE\n"]

    for filename, line_ranges in sorted(line_refs.items()):
        if not line_ranges:
            continue

        # Find file
        file_path = ext_dir / "opgen_generated_files" / filename
        if not file_path.exists():
            file_path = ext_dir / filename
        if not file_path.exists():
            continue

        # Read file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_lines = f.readlines()
        except Exception:
            continue

        # Always beautify JavaScript files
        if filename.endswith('.js'):
            content = ''.join(file_lines)
            beautified = beautify_js(content)
            file_lines = beautified.splitlines(keepends=True)
            output.append(f"\n## {filename} (beautified)\n")
        else:
            output.append(f"\n## {filename}\n")

        # Expand ranges with context
        expanded_ranges = []
        for start, end in line_ranges:
            expanded_start = max(1, start - context_lines)
            expanded_end = min(len(file_lines), end + context_lines)
            expanded_ranges.append((expanded_start, expanded_end))

        # Merge overlapping ranges
        merged = []
        for start, end in sorted(expanded_ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))

        # Output code
        for idx, (start, end) in enumerate(merged):
            for i in range(start - 1, end):
                if i < len(file_lines):
                    output.append(f"{i+1:4d} | {file_lines[i].rstrip()}\n")
            if idx < len(merged) - 1:
                output.append("\n")

    return "".join(output)


def read_file_safe(file_path: Path) -> Optional[str]:
    """Safely read a file."""
    try:
        if file_path.exists():
            return file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        pass
    return None


# ============================================================================
# PROMPT BUILDING
# ============================================================================
def build_prompt(extension_id: str, tool_name: str, report_content: str,
                 manifest_content: str, prompt_template: str,
                 code_context: str = None) -> Tuple[str, str]:
    """Build unified prompt for LLM analysis.

    Returns:
        Tuple of (system_prompt, user_message) where system_prompt is the template
        and user_message contains the report and code contents.
    """
    system_prompt = prompt_template

    user_parts = [
        "# REPORT CONTENTS\n\n",
        f"- Extension ID: {extension_id}\n",
        f"- Analysis Tool: {tool_name.upper()}\n\n",
    ]

    # Add report
    if tool_name in ["doublex", "codeql"]:
        report_filename = "analysis.json"
    else:
        report_filename = "analysis.txt"
    user_parts.append(f"{report_filename}\n\n{report_content}\n\n")

    # Add manifest
    if manifest_content:
        user_parts.append(f"manifest.json\n\n{manifest_content}\n\n")

    # Add code context
    if code_context:
        user_parts.append("---\n\n")
        user_parts.append(code_context)

    user_message = "".join(user_parts)

    return system_prompt, user_message


def estimate_token_count(text: str) -> int:
    """Estimate token count (~3 chars per token for code-heavy prompts)."""
    return len(text) // 3


# ============================================================================
# BATCH PROCESSING (GEMINI)
# ============================================================================
def save_batch_info(dataset_name: str, batch_name: str, num_requests: int,
                   total_files: int = 0, total_line_ranges: int = 0) -> None:
    """Save batch information to file for later retrieval.

    Args:
        dataset_name: Name of the dataset
        batch_name: Gemini batch job name
        num_requests: Number of requests in batch
        total_files: Total files with extracted context (for logging only)
        total_line_ranges: Total line ranges extracted (for logging only)
    """
    batch_info = {
        "batch_name": batch_name,
        "dataset_name": dataset_name,
        "num_requests": num_requests,
        "total_files": total_files,
        "total_line_ranges": total_line_ranges,
        "submitted_at": datetime.now().isoformat(),
        "status": "submitted"
    }

    info_file = CURRENT_RESULTS_DIR / dataset_name / "batch_info.json"
    info_file.parent.mkdir(parents=True, exist_ok=True)

    with open(info_file, 'w', encoding='utf-8') as f:
        json.dump(batch_info, f, indent=2)

    log(f"Batch info saved to: {info_file}")
    log(f"Batch name: {batch_name}")
    log(f"To retrieve results later, set GEMINI_BATCH_MODE='retrieve' and GEMINI_BATCH_NAME='{batch_name}'")


def load_batch_info(dataset_name: str) -> dict:
    """Load batch information from file for retrieve mode.

    Returns:
        Dict with: batch_name, dataset_name, num_requests, submitted_at, status
        Returns None if file doesn't exist
    """
    info_file = CURRENT_RESULTS_DIR / dataset_name / "batch_info.json"

    if not info_file.exists():
        return None

    with open(info_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_batch_request_line(file_handle, prompt_data: dict) -> None:
    """Write a single batch request line to JSONL file.

    Args:
        file_handle: Open file handle for writing
        prompt_data: Dict with keys: extension_id, system_prompt, user_message

    Format (from docs): {"key": "request-1", "request": {"contents": [...]}}
    """
    # Combine system prompt and user message into one prompt
    full_prompt = ""
    if prompt_data.get('system_prompt'):
        full_prompt = f"{prompt_data['system_prompt']}\n\n{prompt_data['user_message']}"
    else:
        full_prompt = prompt_data['user_message']

    # Simple format as shown in docs
    batch_request = {
        "key": prompt_data['extension_id'],
        "request": {
            "contents": [{
                "parts": [{"text": full_prompt}]
            }],
            "generation_config": {
                "temperature": 1.0,
                "max_output_tokens": 8192
            }
        }
    }

    file_handle.write(json.dumps(batch_request) + '\n')


def submit_gemini_batch(requests_file: Path) -> str:
    """Submit batch job to Gemini and return batch name (file-based).

    Returns:
        Batch job name (used to check status and get results)
    """
    # Create client with new google-genai SDK
    client = genai.Client(api_key=config.GEMINI_API_KEY)

    # Upload JSONL file
    print(f"Uploading batch file: {requests_file}")
    uploaded_file = client.files.upload(
        file=str(requests_file),
        config=genai_types.UploadFileConfig(
            display_name=f'batch-requests-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
            mime_type='jsonl'
        )
    )
    print(f"File uploaded: {uploaded_file.name}")

    # Create batch job with file reference
    print("Creating batch job...")
    batch_job = client.batches.create(
        model=config.GEMINI_MODEL,
        src=uploaded_file.name,  # File reference, not inline list
        config={
            'display_name': f'batch-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
        }
    )

    print(f"Batch job created: {batch_job.name}")
    print(f"Status: {batch_job.state}")
    return batch_job.name


def cancel_gemini_batch(batch_name: str) -> bool:
    """Cancel an ongoing batch job.

    WARNING: Partial results from cancelled jobs are lost!

    Args:
        batch_name: The batch job name to cancel

    Returns:
        True if cancellation successful, False otherwise
    """
    try:
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        client.batches.cancel(name=batch_name)
        print(f"✓ Batch job cancelled: {batch_name}")
        print("  Warning: Partial results are lost!")
        return True
    except Exception as e:
        print(f"✗ Failed to cancel batch: {e}")
        return False


def delete_gemini_batch(batch_name: str) -> bool:
    """Delete a batch job (stops processing and removes from list).

    Args:
        batch_name: The batch job name to delete

    Returns:
        True if deletion successful, False otherwise
    """
    try:
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        client.batches.delete(name=batch_name)
        print(f"✓ Batch job deleted: {batch_name}")
        return True
    except Exception as e:
        print(f"✗ Failed to delete batch: {e}")
        return False


def list_gemini_batches(limit: int = 10) -> list:
    """List recent batch jobs.

    Args:
        limit: Maximum number of batch jobs to return

    Returns:
        List of batch job objects
    """
    try:
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        batches = client.batches.list(config={'page_size': limit})

        print(f"\n{'='*80}")
        print(f"RECENT BATCH JOBS (limit: {limit})")
        print(f"{'='*80}\n")

        # Build index of local batch_info.json files for statistics lookup
        local_batch_info = {}
        if CURRENT_RESULTS_DIR.exists():
            for dataset_dir in CURRENT_RESULTS_DIR.iterdir():
                if dataset_dir.is_dir():
                    info_file = dataset_dir / "batch_info.json"
                    if info_file.exists():
                        try:
                            with open(info_file, 'r', encoding='utf-8') as f:
                                info = json.load(f)
                                batch_name = info.get('batch_name')
                                if batch_name:
                                    local_batch_info[batch_name] = info
                        except:
                            pass

        batch_list = []
        for batch in batches:
            batch_list.append(batch)

            # Extract state
            state = batch.state.name if hasattr(batch.state, 'name') else str(batch.state)

            # Extract timestamps if available
            create_time = getattr(batch, 'create_time', 'N/A')

            # Print batch info
            print(f"Name: {batch.name}")
            print(f"  Model: {getattr(batch, 'model', 'N/A')}")
            print(f"  State: {state}")
            print(f"  Created: {create_time}")
            print(f"  Display Name: {getattr(batch, 'display_name', 'N/A')}")

            # Add local statistics if available
            if batch.name in local_batch_info:
                info = local_batch_info[batch.name]
                print(f"  Requests: {info.get('num_requests', 'N/A')}")
                print(f"  Files: {info.get('total_files', 'N/A')}")
                print(f"  Line Ranges: {info.get('total_line_ranges', 'N/A')}")

            print()

        if not batch_list:
            print("No batch jobs found.")

        print(f"{'='*80}\n")
        return batch_list

    except Exception as e:
        print(f"✗ Failed to list batches: {e}")
        return []


def wait_for_batch_completion(batch_name: str) -> bool:
    """Wait for batch job to complete.

    Returns:
        True if successful, False if failed
    """
    print(f"Waiting for batch completion: {batch_name}")
    start_time = time.time()

    client = genai.Client(api_key=config.GEMINI_API_KEY)

    while True:
        # Get batch status
        batch_job = client.batches.get(name=batch_name)
        state = batch_job.state.name if hasattr(batch_job.state, 'name') else str(batch_job.state)

        elapsed = int(time.time() - start_time)
        print(f"  Status: {state} (elapsed: {elapsed}s)")

        if state == 'JOB_STATE_SUCCEEDED':
            print("Batch completed successfully!")
            return True
        elif state in ['JOB_STATE_FAILED', 'JOB_STATE_CANCELLED']:
            print(f"Batch failed with state: {state}")
            return False
        elif state in ['JOB_STATE_PROCESSING', 'JOB_STATE_PENDING', 'JOB_STATE_QUEUED']:
            time.sleep(config.GEMINI_BATCH_CHECK_INTERVAL)
        else:
            print(f"Unknown state: {state}")
            time.sleep(config.GEMINI_BATCH_CHECK_INTERVAL)


def download_batch_results(batch_name: str, output_file: Path) -> None:
    """Download batch results to file (file-based format).

    Args:
        batch_name: The batch job name
        output_file: Where to save results JSONL
    """
    print(f"Downloading results to: {output_file}")

    client = genai.Client(api_key=config.GEMINI_API_KEY)

    # Get batch job to find output file
    batch_job = client.batches.get(name=batch_name)

    if not batch_job.dest or not batch_job.dest.file_name:
        raise ValueError("No output file found in batch results")

    print(f"Output file: {batch_job.dest.file_name}")

    # Download the result file
    file_content = client.files.download(file=batch_job.dest.file_name)

    # Write to output file
    with open(output_file, 'wb') as f:
        f.write(file_content)

    print("Results downloaded successfully")


def parse_batch_results(results_file: Path) -> dict:
    """Parse batch results JSONL file (file-based format).

    Returns:
        Dict mapping key (extension_id) -> response_text
    """
    results = {}

    with open(results_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue

            result = json.loads(line)
            key = result.get('key')  # Extension ID from request

            if not key:
                continue

            # Extract response text
            response = result.get('response', {})
            candidates = response.get('candidates', [])
            if candidates and len(candidates) > 0:
                content = candidates[0].get('content', {})
                parts = content.get('parts', [])
                if parts and len(parts) > 0:
                    response_text = parts[0].get('text', '')
                    results[key] = response_text
            else:
                # Handle errors
                error = result.get('error', {})
                results[key] = json.dumps({"error": f"Batch processing error: {error}"})

    return results


# ============================================================================
# LLM INTERACTION
# ============================================================================
def query_llm(prompt: str, client, system_prompt: str = None) -> str:
    """Send request to configured LLM provider.

    Args:
        prompt: The user message content
        client: The LLM client
        system_prompt: System prompt (only used for Anthropic)
    """
    try:
        if config.LLM_PROVIDER == 'ollama':
            local_port = client
            response = requests.post(
                f"http://127.0.0.1:{local_port}/api/generate",
                json={
                    "model": config.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=config.OLLAMA_TIMEOUT
            )
            response.raise_for_status()
            result = response.json()
            return result.get('response', '').strip()

        if config.LLM_PROVIDER == 'openai':
            response = client.chat.completions.create(
                model=config.OPENAI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                timeout=config.OPENAI_TIMEOUT
            )
            return response.choices[0].message.content.strip()

        if config.LLM_PROVIDER == 'anthropic':
            # For backward compatibility, if system_prompt is not provided,
            # treat entire prompt as user message
            if system_prompt is None:
                system_prompt = ""
                user_message = prompt
            else:
                user_message = prompt

            response = client.messages.create(
                model=config.ANTHROPIC_MODEL,
                max_tokens=4096,
                temperature=1,
                system=system_prompt,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": user_message
                            }
                        ]
                    }
                ],
                timeout=config.ANTHROPIC_TIMEOUT
            )
            return response.content[0].text.strip()

        if config.LLM_PROVIDER == 'gemini':
            # Gemini regular API with new google-genai SDK
            # Retry with exponential backoff for rate limits
            contents = [{
                'role': 'user',
                'parts': [{'text': prompt}]
            }]

            config_dict = {
                'temperature': 1.0,
                # No max_output_tokens limit - let Gemini use its maximum
            }

            # Add system instruction if provided
            if system_prompt:
                config_dict['system_instruction'] = {
                    'parts': [{'text': system_prompt}]
                }

            # Estimate prompt tokens for token bucket tracking
            prompt_tokens = estimate_token_count(prompt + (system_prompt or ""))

            # Retry loop for rate limit handling
            max_retries = 50
            for retry in range(max_retries):
                # Atomically wait until there is room in the sliding-window budget,
                # then record the tokens. Check + add happen in one lock acquisition
                # so no two workers can both see headroom and both slip through.
                _token_bucket.wait_and_add(prompt_tokens)

                try:
                    response = client.models.generate_content(
                        model=config.GEMINI_MODEL,
                        contents=contents,
                        config=config_dict
                    )

                    # Check finish reason for warnings (but don't retry)
                    if hasattr(response, 'candidates') and len(response.candidates) > 0:
                        candidate = response.candidates[0]
                        finish_reason = getattr(candidate, 'finish_reason', None)

                        if finish_reason:
                            finish_reason_name = finish_reason.name if hasattr(finish_reason, 'name') else str(finish_reason)

                            # Warn about unusual finish reasons
                            if finish_reason_name == 'SAFETY':
                                print(f"  ⚠️  Response truncated: SAFETY filter triggered")
                            elif finish_reason_name == 'RECITATION':
                                print(f"  ⚠️  Response truncated: RECITATION detected")
                            elif finish_reason_name not in ['STOP', 'stop', None, '', 'MAX_TOKENS']:
                                print(f"  ⚠️  Unusual finish reason: {finish_reason_name}")

                    return response.text.strip()

                except Exception as e:
                    error_str = str(e)

                    # Check if this is a rate limit error
                    is_rate_limit = (
                        "429" in error_str or
                        "rate_limit" in error_str.lower() or
                        "quota" in error_str.lower() or
                        "RESOURCE_EXHAUSTED" in error_str
                    )

                    if is_rate_limit:
                        # Request was rejected - undo the optimistic bucket entry
                        _token_bucket.remove(prompt_tokens)
                        if retry == 0:
                            print(f"  ⚠️  Rate limit error (full): {error_str[:300]}")

                    if is_rate_limit and retry < max_retries - 1:
                        # Exponential backoff with ±10% jitter
                        base = min(120, 5 * (2 ** retry))
                        wait_time = base * random.uniform(0.9, 1.1)
                        print(f"  ⚠️  Rate limit - Waiting {wait_time:.0f}s - retry {retry+2}/{max_retries}...")
                        time.sleep(wait_time)
                        continue  # Retry
                    else:
                        # Not a rate limit error, or last retry failed
                        print(f"  ⚠️  Final error (full): {error_str[:300]}")
                        raise  # Re-raise the exception

        if config.LLM_PROVIDER == 'gemini_batch':
            # Gemini Batch API - not supported in direct query mode
            # Batch mode should be handled at a higher level
            return json.dumps({"error": "Gemini Batch API requires batch processing mode. Use regular 'gemini' for single requests."})

        return json.dumps({"error": f"Unknown provider: {config.LLM_PROVIDER}"})

    except requests.exceptions.Timeout:
        return json.dumps({"error": "Request timed out"})
    except Exception as e:
        error_str = str(e)

        return json.dumps({"error": f"LLM query failed: {str(e)}"})


# ============================================================================
# ANALYSIS
# ============================================================================
def prepare_batch_prompt(ext_path: Path, prompt_template: str,
                        dataset_config: dict, current: int, total: int) -> dict:
    """Prepare prompt data for batch processing (doesn't call LLM).

    Returns:
        Dict with keys: extension_id, system_prompt, user_message, metadata
        Returns None if extension should be skipped
    """
    start_time = time.time()
    dataset_name = dataset_config["name"]
    tool_type = dataset_config["tool"]
    code_context_lines = dataset_config.get("code_context_lines", 10)

    # Get extension info (same logic as analyze_extension)
    if tool_type == "codeql":
        extension_id = ext_path.stem
        report_path = ext_path
        crx_file = config.EXTENSION_CODE_DIR / f"{extension_id}.crx"
        extension_code_dir = config.EXTENSION_CODE_DIR / extension_id

        # Use file filter if enabled (faster extraction)
        file_filter = config.EXTRACT_FILE_EXTENSIONS if config.EXTRACT_ONLY_CODE_FILES else None

        if download_crx(extension_id, crx_file, config, log):
            extract_crx(crx_file, extension_code_dir, log, file_filter)

        manifest_content = read_file_safe(extension_code_dir / "manifest.json")
    else:
        extension_id = ext_path.name
        report_path = _get_report_path(ext_path, dataset_name, tool_type)
        manifest_content = read_file_safe(ext_path / "manifest.json")

    log(f"Preparing [{current}/{total}]: {extension_id}", "HEADER")

    # Read report
    if not report_path or not report_path.exists():
        log("Report not found - skipping", "ERROR")
        return None

    report_content = read_file_safe(report_path)
    if not report_content:
        log("Empty report - skipping", "ERROR")
        return None

    # Process report based on tool type
    if tool_type == "coco":
        cleaned_report = clean_coco_report(report_content)
        line_refs = extract_line_numbers_from_coco(report_content)
        final_report = cleaned_report
        code_context = extract_code_context(ext_path, line_refs, code_context_lines)
    elif tool_type == "doublex":
        line_refs = extract_line_numbers_from_doublex(report_content)
        final_report = report_content
        code_context = extract_code_context(ext_path, line_refs, code_context_lines)
    elif tool_type == "codeql":
        final_report = filter_codeql_sarif_report(report_content)
        line_refs = extract_line_numbers_from_codeql(report_content)
        total_ranges = sum(len(ranges) for ranges in line_refs.values())
        log(f"Extracted {len(line_refs)} files, {total_ranges} line ranges")
        code_context = extract_code_context(extension_code_dir, line_refs, code_context_lines)
    else:
        log(f"Tool type '{tool_type}' not implemented - skipping", "ERROR")
        return None

    # Track stats for batch summary
    num_files = len(line_refs) if line_refs else 0
    num_line_ranges = sum(len(ranges) for ranges in line_refs.values()) if line_refs else 0

    # Build prompt
    code_section = code_context if code_context else None
    system_prompt, user_message = build_prompt(
        extension_id=extension_id,
        tool_name=tool_type,
        report_content=final_report,
        manifest_content=manifest_content,
        prompt_template=prompt_template,
        code_context=code_section
    )

    # Token counting
    full_prompt = system_prompt + "\n" + user_message
    tokens = estimate_token_count(full_prompt)
    log(f"Prompt: {len(full_prompt)} chars, ~{tokens} tokens")

    # Save prompt if inspection mode
    if config.INSPECTION_MODE:
        prompt_file = CURRENT_RESULTS_DIR / dataset_name / f"{extension_id}_prompt.txt"
        prompt_file.parent.mkdir(parents=True, exist_ok=True)
        prompt_file.write_text(full_prompt, encoding='utf-8')

    return {
        'extension_id': extension_id,
        'system_prompt': system_prompt,
        'user_message': user_message,
        'tokens': tokens,
        'dataset_name': dataset_name,
        'num_files': num_files,
        'num_line_ranges': num_line_ranges
    }


def analyze_extension(ext_path: Path, llm_client, prompt_template: str,
                     dataset_config: dict, current: int, total: int) -> None:
    """Analyze a single extension or report (unified for all tool types)."""
    dataset_name = dataset_config["name"]
    tool_type = dataset_config["tool"]
    code_context_lines = dataset_config.get("code_context_lines", 10)
    start_time = time.time()

    # Determine extension_id early so we can check for existing results
    extension_id = ext_path.stem if tool_type == "codeql" else ext_path.name
    _thread_local.extension_id = extension_id  # For prefixed log output in parallel runs

    # Skip if already processed (resume mode)
    output_file = CURRENT_RESULTS_DIR / dataset_name / f"{extension_id}_result.json"
    if output_file.exists():
        log(f"[{current}/{total}] {extension_id}: already processed, skipping")
        return

    # Stagger parallel workers to avoid simultaneous first submissions to the LLM
    if config.PARALLEL_WORKERS > 1:
        time.sleep(random.uniform(0, config.PARALLEL_WORKERS * 0.5))

    # Get report_path (extension_id already determined above)
    if tool_type == "codeql":
        # For CodeQL, ext_path is the JSON file itself
        report_path = ext_path

        # Download and extract .crx file from remote server
        crx_file = config.EXTENSION_CODE_DIR / f"{extension_id}.crx"
        extension_code_dir = config.EXTENSION_CODE_DIR / extension_id

        # Use file filter if enabled (faster extraction)
        file_filter = config.EXTRACT_FILE_EXTENSIONS if config.EXTRACT_ONLY_CODE_FILES else None

        if download_crx(extension_id, crx_file, config, log):
            extract_crx(crx_file, extension_code_dir, log, file_filter)

        # Read manifest from extracted extension
        manifest_content = read_file_safe(extension_code_dir / "manifest.json")
    else:
        # For COCO and DoubLeX, ext_path is a directory
        report_path = _get_report_path(ext_path, dataset_name, tool_type)
        manifest_content = read_file_safe(ext_path / "manifest.json")

    log(f"Extension [{current}/{total}]: {extension_id}", "HEADER")

    # Read report
    if not report_path or not report_path.exists():
        log("Report not found", "ERROR")
        log_message(dataset_name, "ERROR", f"{extension_id} - Report not found")
        return

    report_content = read_file_safe(report_path)
    if not report_content:
        log("Report content is empty", "ERROR")
        log_message(dataset_name, "ERROR", f"{extension_id} - Empty report")
        return

    # Process report based on tool type
    if tool_type == "coco":
        cleaned_report = clean_coco_report(report_content)
        line_refs = extract_line_numbers_from_coco(report_content)
        final_report = cleaned_report
        code_context = extract_code_context(ext_path, line_refs, code_context_lines)
    elif tool_type == "doublex":
        line_refs = extract_line_numbers_from_doublex(report_content)
        final_report = report_content
        code_context = extract_code_context(ext_path, line_refs, code_context_lines)
    elif tool_type == "codeql":
        final_report = filter_codeql_sarif_report(report_content)
        line_refs = extract_line_numbers_from_codeql(report_content)

        # Log extracted locations
        total_ranges = sum(len(ranges) for ranges in line_refs.values())
        log(f"Extracted {len(line_refs)} files, {total_ranges} line ranges from CodeQL report")

        code_context = extract_code_context(extension_code_dir, line_refs, code_context_lines)
    else:
        log(f"Tool type '{tool_type}' not yet implemented", "ERROR")
        return

    # Build code section (always use code_context, never full source)
    code_section = code_context if code_context else None

    # Build prompt
    system_prompt, user_message = build_prompt(
        extension_id=extension_id,
        tool_name=tool_type,
        report_content=final_report,
        manifest_content=manifest_content,
        prompt_template=prompt_template,
        code_context=code_section
    )

    # For token counting and logging, use full prompt
    full_prompt = system_prompt + "\n" + user_message
    tokens = estimate_token_count(full_prompt)
    log(f"Prompt: {len(full_prompt)} chars, ~{tokens} tokens")

    # Check token limit
    if config.MAX_PROMPT_TOKENS and tokens > config.MAX_PROMPT_TOKENS:
        log(f"SKIPPED: Prompt exceeds token limit ({tokens} > {config.MAX_PROMPT_TOKENS})", "ERROR")
        log_message(dataset_name, "SKIPPED", f"{extension_id} - Tokens: {tokens} (limit: {config.MAX_PROMPT_TOKENS})")
        return  # Skip this extension

    # Save prompt if inspection mode
    if config.INSPECTION_MODE:
        prompt_file = CURRENT_RESULTS_DIR / dataset_name / f"{extension_id}_prompt.txt"
        prompt_file.parent.mkdir(parents=True, exist_ok=True)
        prompt_file.write_text(full_prompt, encoding='utf-8')

    # Query LLM (or skip in dry-run mode)
    if config.DRY_RUN_MODE:
        log(f"DRY RUN - Skipping LLM call (saving costs)")
        query_start = time.time()
        # Create minimal sample response
        result = json.dumps({
            "note": "DRY_RUN_MODE - LLM call skipped",
            "extension_id": extension_id,
            "prompt_size_chars": len(full_prompt),
            "estimated_tokens": tokens
        }, indent=2)
        query_time = time.time() - query_start
    else:
        log(f"Querying {get_current_model_name()}...")
        query_start = time.time()
        result = query_llm(user_message, llm_client, system_prompt)
        query_time = time.time() - query_start

    # Save result
    output_file = CURRENT_RESULTS_DIR / dataset_name / f"{extension_id}_result.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(result, encoding='utf-8')

    total_time = time.time() - start_time

    # Log timing
    log_message(dataset_name, "TIMING",
                f"{extension_id} - Query: {query_time:.2f}s, Total: {total_time:.2f}s, Tokens: ~{tokens}")

    log(f"Query: {query_time:.2f}s | Total: {total_time:.2f}s")
    preview = result.replace('\n', ' ')[:100]
    log(f"Preview: {preview}...")


def process_dataset_batch(extensions: list, dataset_config: dict,
                         prompt_template: str) -> int:
    """Process a dataset using Gemini Batch API.

    Supports six modes (configured via config.GEMINI_BATCH_MODE):
    - 'submit': Create batch, save info, exit (for long-running batches)
    - 'retrieve': Download existing batch results (use config.GEMINI_BATCH_NAME)
    - 'auto': Submit and wait for completion (blocks until done)
    - 'list': List recent batch jobs
    - 'cancel': Cancel a running batch job (use config.GEMINI_BATCH_NAME)
    - 'delete': Delete a batch job (use config.GEMINI_BATCH_NAME)

    Returns:
        Number of extensions processed
    """
    dataset_name = dataset_config["name"]
    batch_mode = config.GEMINI_BATCH_MODE

    # ========== LIST MODE ==========
    if batch_mode == 'list':
        log(f"BATCH MODE: LIST - Listing recent batch jobs", "HEADER")
        list_gemini_batches(limit=config.GEMINI_BATCH_LIST_LIMIT)
        return 0

    # ========== CANCEL MODE ==========
    if batch_mode == 'cancel':
        log(f"BATCH MODE: CANCEL - Cancelling batch job", "HEADER")

        batch_name = config.GEMINI_BATCH_NAME
        if not batch_name:
            batch_info = load_batch_info(dataset_name)
            if batch_info:
                batch_name = batch_info['batch_name']
                log(f"Loaded batch name from saved info: {batch_name}")
            else:
                log("ERROR: No batch name provided and no saved batch info found", "ERROR")
                log("Set config.GEMINI_BATCH_NAME to the batch you want to cancel", "ERROR")
                return 0

        log(f"Cancelling batch: {batch_name}")
        if cancel_gemini_batch(batch_name):
            log("Batch cancelled successfully", "HEADER")
        else:
            log("Failed to cancel batch", "ERROR")
        return 0

    # ========== DELETE MODE ==========
    if batch_mode == 'delete':
        log(f"BATCH MODE: DELETE - Deleting batch job", "HEADER")

        batch_name = config.GEMINI_BATCH_NAME
        if not batch_name:
            batch_info = load_batch_info(dataset_name)
            if batch_info:
                batch_name = batch_info['batch_name']
                log(f"Loaded batch name from saved info: {batch_name}")
            else:
                log("ERROR: No batch name provided and no saved batch info found", "ERROR")
                log("Set config.GEMINI_BATCH_NAME to the batch you want to delete", "ERROR")
                return 0

        log(f"Deleting batch: {batch_name}")
        if delete_gemini_batch(batch_name):
            log("Batch deleted successfully", "HEADER")
        else:
            log("Failed to delete batch", "ERROR")
        return 0

    # ========== RETRIEVE MODE ==========
    if batch_mode == 'retrieve':
        log(f"BATCH MODE: RETRIEVE - Downloading existing batch results", "HEADER")

        # DRY_RUN_MODE doesn't make sense in retrieve mode
        if config.DRY_RUN_MODE:
            log("WARNING: DRY_RUN_MODE is enabled but has no effect in 'retrieve' mode", "HEADER")

        # Get batch name from config or from saved file
        batch_name = config.GEMINI_BATCH_NAME
        if not batch_name:
            batch_info = load_batch_info(dataset_name)
            if batch_info:
                batch_name = batch_info['batch_name']
                log(f"Loaded batch name from saved info: {batch_name}")
            else:
                log("ERROR: No batch name provided and no saved batch info found", "ERROR")
                log("Set config.GEMINI_BATCH_NAME or ensure batch_info.json exists", "ERROR")
                return 0

        # Check batch status
        log(f"Checking batch status: {batch_name}")
        try:
            client = genai.Client(api_key=config.GEMINI_API_KEY)
            batch_job = client.batches.get(name=batch_name)
            state = batch_job.state.name if hasattr(batch_job.state, 'name') else str(batch_job.state)
            log(f"Batch status: {state}")

            if state != 'JOB_STATE_SUCCEEDED':
                log(f"Batch not ready yet (status: {state})", "ERROR")
                log("Wait until status is JOB_STATE_SUCCEEDED, then try again", "ERROR")
                return 0

        except Exception as e:
            log(f"Failed to get batch status: {e}", "ERROR")
            return 0

        # Download results
        batch_results_file = CURRENT_RESULTS_DIR / dataset_name / "batch_results.jsonl"
        try:
            download_batch_results(batch_name, batch_results_file)
            log(f"Results downloaded: {batch_results_file.name}")
        except Exception as e:
            log(f"Failed to download results: {e}", "ERROR")
            return 0

        # Parse and save results
        log("Parsing batch results...")
        results_map = parse_batch_results(batch_results_file)

        saved_count = 0
        for ext_id, result_text in results_map.items():
            output_file = CURRENT_RESULTS_DIR / dataset_name / f"{ext_id}_result.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(result_text, encoding='utf-8')
            saved_count += 1
            log(f"Saved result for {ext_id}")

        log(f"Batch retrieve complete: {saved_count} results saved", "HEADER")
        return saved_count

    # ========== SUBMIT MODE or AUTO MODE ==========
    log(f"BATCH MODE: {batch_mode.upper()} - Preparing {len(extensions)} prompts", "HEADER")

    # Step 1 & 2: Stream prompts directly to file (memory efficient!)
    batch_requests_file = CURRENT_RESULTS_DIR / dataset_name / "batch_requests.jsonl"
    batch_requests_file.parent.mkdir(parents=True, exist_ok=True)

    num_requests = 0
    total_files = 0
    total_line_ranges = 0

    with open(batch_requests_file, 'w', encoding='utf-8') as f:
        for idx, ext_dir in enumerate(extensions, 1):
            prompt_data = prepare_batch_prompt(ext_dir, prompt_template,
                                               dataset_config, idx, len(extensions))
            if prompt_data:
                # Write immediately to file instead of collecting in memory
                write_batch_request_line(f, prompt_data)
                num_requests += 1
                total_files += prompt_data.get('num_files', 0)
                total_line_ranges += prompt_data.get('num_line_ranges', 0)

    if num_requests == 0:
        log("No valid prompts to process", "ERROR")
        return 0

    log(f"Prepared {num_requests} valid prompts for batch processing")
    log(f"Statistics: {total_files} files with context, {total_line_ranges} line ranges extracted")
    log(f"Created batch request file: {batch_requests_file.name}")

    # DRY RUN MODE: Stop here, don't submit
    if config.DRY_RUN_MODE:
        log("="*80, "HEADER")
        log("DRY RUN MODE - Batch NOT submitted", "HEADER")
        log(f"Prepared {num_requests} prompts", "HEADER")
        log(f"Batch request file: {batch_requests_file.name}", "HEADER")
        log("To actually submit, set DRY_RUN_MODE = False", "HEADER")
        log("="*80, "HEADER")
        return 0

    # Step 3: Submit batch job
    try:
        batch_name = submit_gemini_batch(batch_requests_file)
        log(f"Batch submitted: {batch_name}")
        save_batch_info(dataset_name, batch_name, num_requests,
                       total_files, total_line_ranges)
    except Exception as e:
        log(f"Failed to submit batch: {e}", "ERROR")
        return 0

    # If submit mode, exit here
    if batch_mode == 'submit':
        log("="*80, "HEADER")
        log(f"BATCH SUBMITTED - Exiting (mode: submit)", "HEADER")
        log(f"Batch name: {batch_name}", "HEADER")
        log(f"Batch info saved to: batch_info.json", "HEADER")
        log("", "HEADER")
        log("To check status and download results later:", "HEADER")
        log("  1. Set GEMINI_BATCH_MODE = 'retrieve'", "HEADER")
        log(f"  2. Set GEMINI_BATCH_NAME = '{batch_name}'", "HEADER")
        log("  3. Run analyzer again", "HEADER")
        log("="*80, "HEADER")
        return 0  # Return 0 because results not downloaded yet

    # ========== AUTO MODE - Wait for completion ==========
    log("Waiting for batch to complete (this may take hours)...")
    if not wait_for_batch_completion(batch_name):
        log("Batch processing failed", "ERROR")
        return 0

    # Download results
    batch_results_file = CURRENT_RESULTS_DIR / dataset_name / "batch_results.jsonl"
    try:
        download_batch_results(batch_name, batch_results_file)
        log(f"Results downloaded: {batch_results_file.name}")
    except Exception as e:
        log(f"Failed to download results: {e}", "ERROR")
        return 0

    # Parse and save results
    log("Parsing batch results...")
    results_map = parse_batch_results(batch_results_file)

    if len(results_map) != len(prompts_data):
        log(f"WARNING: Result count ({len(results_map)}) != Request count ({len(prompts_data)})", "ERROR")

    saved_count = 0
    for ext_id, result_text in results_map.items():
        output_file = CURRENT_RESULTS_DIR / dataset_name / f"{ext_id}_result.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(result_text, encoding='utf-8')
        saved_count += 1
        log(f"Saved result for {ext_id}")

    log(f"Batch complete: {saved_count}/{len(prompts_data)} results saved", "HEADER")
    return saved_count


# ============================================================================
# MAIN
# ============================================================================
def main():
    """Main function to process all configured analysis tools."""
    global CURRENT_RESULTS_DIR

    print("="*80)
    print("CHROME EXTENSION VULNERABILITY ANALYZER")
    print("="*80)
    print(f"Provider: {config.LLM_PROVIDER.upper()}")
    print(f"Model: {get_current_model_name()}")
    if config.DRY_RUN_MODE:
        print("WARNING: DRY RUN MODE - LLM calls will be skipped (no costs)")
    print("="*80)

    # Create or resume results directory
    CURRENT_RESULTS_DIR = get_or_create_results_directory()
    print(f"Results: {CURRENT_RESULTS_DIR.relative_to(config.BASE_DIR)}\n")

    # Download all extensions as tar if enabled (MUCH faster for large datasets)
    if config.USE_TAR_DOWNLOAD:
        from helpers.extension_downloader import download_extensions_tar
        print("Downloading extensions tar file...")
        if download_extensions_tar(config.EXTENSION_CODE_DIR, config, print):
            print("✓ Extensions tar downloaded and extracted\n")
        else:
            print("⚠ Tar download failed, falling back to individual downloads\n")

    # Check configuration
    if not config.DATASETS:
        print("ERROR: No datasets configured")
        return

    if not config.PROMPT_FILE or not config.PROMPT_FILE.exists():
        print("ERROR: Prompt file not found")
        return

    # Show enabled datasets
    enabled = [d for d in config.DATASETS if d.get('enabled', True)]
    print(f"\nDatasets: {', '.join(d['name'] for d in enabled)}")

    tunnel = None
    total_processed = 0

    try:
        # Setup LLM
        tunnel, llm_client = setup_llm_client()

        # Process each dataset
        for dataset_config in config.DATASETS:
            if not dataset_config.get('enabled', True):
                continue

            dataset_name = dataset_config["name"]
            tool_type = dataset_config["tool"]

            # Set global dataset name for logging
            global CURRENT_DATASET_NAME
            CURRENT_DATASET_NAME = dataset_name

            log(f"Processing: {dataset_name.upper()}", "HEADER")

            # Load appropriate prompt template
            if tool_type == "codeql":
                prompt_file = config.BASE_DIR / "prompts" / "Prompt_CodeQL.md"
            else:
                prompt_file = config.PROMPT_FILE

            if not prompt_file.exists():
                log(f"Prompt file not found: {prompt_file}", "ERROR")
                continue

            dataset_prompt_template = prompt_file.read_text(encoding='utf-8')

            # Initialize log file (append when resuming, overwrite on fresh run)
            log_file = CURRENT_RESULTS_DIR / dataset_name / "log.txt"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            if getattr(config, 'RESUME_RUN', None) and log_file.exists():
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n# RESUMED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            else:
                log_file.write_text(
                    f"# Analysis Log - {dataset_name}\n"
                    f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n",
                    encoding='utf-8'
                )

            # Get extensions
            extensions = get_extensions_for_dataset(dataset_config)
            if not extensions:
                log("No valid extensions found")
                continue

            log(f"Found {len(extensions)} valid extensions")

            # Process based on provider mode
            if config.LLM_PROVIDER == 'gemini_batch':
                # Use batch processing for Gemini Batch API
                processed = process_dataset_batch(extensions, dataset_config,
                                                  dataset_prompt_template)
                total_processed += processed
            else:
                # Process extensions (parallel or sequential based on config)
                if config.PARALLEL_WORKERS > 1:
                    log(f"Processing with {config.PARALLEL_WORKERS} parallel workers")

                    # Parallel processing with thread pool
                    with ThreadPoolExecutor(max_workers=config.PARALLEL_WORKERS) as executor:
                        # Submit all extensions to thread pool
                        futures = {}
                        for idx, ext_dir in enumerate(extensions, 1):
                            future = executor.submit(
                                analyze_extension,
                                ext_dir, llm_client, dataset_prompt_template,
                                dataset_config, idx, len(extensions)
                            )
                            futures[future] = (idx, ext_dir)

                        # Wait for completion and handle errors
                        for future in as_completed(futures):
                            idx, ext_dir = futures[future]
                            try:
                                future.result()  # Get result to catch exceptions
                                total_processed += 1
                            except Exception as e:
                                log(f"Error processing extension {idx}/{len(extensions)} ({ext_dir.name}): {e}", "ERROR")
                                import traceback
                                traceback.print_exc()
                else:
                    log("Processing sequentially (PARALLEL_WORKERS=1)")

                    # Sequential processing (original behavior)
                    for idx, ext_dir in enumerate(extensions, 1):
                        analyze_extension(ext_dir, llm_client, dataset_prompt_template,
                                        dataset_config, idx, len(extensions))
                        total_processed += 1

        print("\n" + "="*80)
        print(f"COMPLETE: Processed {total_processed} extensions")
        print(f"Results: {CURRENT_RESULTS_DIR}")
        print("="*80)

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if tunnel and tunnel.is_active:
            tunnel.stop()
            print("\nSSH tunnel closed")


if __name__ == "__main__":
    main()
