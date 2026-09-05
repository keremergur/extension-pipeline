import contextvars
import logging
logging.basicConfig(level=logging.ERROR, format='%(message)s')
logger = logging.getLogger(__name__)

# Extension currently being verified, used to prefix log lines so the interleaved
# output of concurrent verifications stays attributable. A ContextVar (not a
# thread-local) because the verifier is asyncio: concurrent verifications are tasks
# on ONE thread, and each task gets its own copy of the context automatically.
_current_extension = contextvars.ContextVar("verifier_extension_id", default=None)


def set_worker_extension(extension_id):
    """Tag the current asyncio task with the extension it is verifying."""
    _current_extension.set(extension_id)


def _prefix() -> str:
    ext_id = _current_extension.get()
    return f"[{ext_id[:12]}] " if ext_id else ""


def log_step(step_num: int, title: str):
    """Log a numbered step."""
    print(f"\n  {_prefix()}[{step_num}] {title}")


def log_success(msg: str):
    """Log success message."""
    print(f"      {_prefix()}✓ {msg}")


def log_error(msg: str):
    """Log error message."""
    print(f"      {_prefix()}✗ {msg}")


def log_step_failed(step: str, reason: str = ""):
    """Log that verification failed at a specific step, for easier debugging."""
    suffix = f": {reason}" if reason else ""
    print(f"      {_prefix()}✗ FAILED at step '{step}'{suffix}")


def log_info(msg: str):
    """Log info message."""
    print(f"      {_prefix()}• {msg}")


def ask_continue(msg: str = "Continue?") -> bool:
    """Ask user to continue (y/Enter to continue, anything else to abort)."""
    response = input(f"\n  → {msg} (y/n): ").strip().lower()
    return response in ['y', 'yes', '']


def log_mock_server_ready(mock_server_url: str):
    """Log that mock server is ready with endpoints."""
    print(f"      • Mock server ready: {mock_server_url}")
