"""Thread-safe console + per-dataset file logging for the analyzer.

Extracted verbatim (behaviour-preserving) from the original
analyze_extensions.py so parallel worker output stays readable and each dataset
keeps its own log.txt.
"""

import threading
from datetime import datetime

from . import state

# Global lock for thread-safe file logging.
_log_file_lock = threading.Lock()
# Thread-local storage for per-worker context (e.g. extension ID prefix).
_thread_local = threading.local()


def set_worker_extension(extension_id):
    """Tag the current worker thread with the extension it is processing.

    Used only to prefix parallel log lines so interleaved output stays readable.
    """
    _thread_local.extension_id = extension_id


def log_message(dataset_name: str, message_type: str, message: str):
    """Append a structured line to the dataset's log.txt (thread-safe)."""
    log_file = state.CURRENT_RESULTS_DIR / dataset_name / "log.txt"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with _log_file_lock:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message_type}: {message}\n")


def log(message: str, level: str = "INFO"):
    """Console logging with consistent format.

    Also mirrors to the current dataset's log file when state.CURRENT_DATASET_NAME
    is set.
    """
    ext_id = getattr(_thread_local, 'extension_id', None)
    prefix = f"[{ext_id[:12]}] " if ext_id else ""

    if level == "INFO":
        print(f"  {prefix}{message}")
    elif level == "ERROR":
        print(f"  {prefix}ERROR: {message}")
    elif level == "HEADER":
        print(f"\n{'='*80}")
        print(f"{prefix}{message}")
        print('='*80)

    if state.CURRENT_DATASET_NAME and state.CURRENT_RESULTS_DIR:
        try:
            log_file = state.CURRENT_RESULTS_DIR / state.CURRENT_DATASET_NAME / "log.txt"
            if log_file.exists() or log_file.parent.exists():
                log_file.parent.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with _log_file_lock:
                    with open(log_file, 'a', encoding='utf-8') as f:
                        if level == "HEADER":
                            f.write(f"\n[{timestamp}] {'='*60}\n{message}\n{'='*60}\n")
                        else:
                            f.write(f"[{timestamp}] {level}: {message}\n")
        except Exception:
            pass  # Never let file logging crash the run.
