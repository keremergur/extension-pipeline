import logging
logging.basicConfig(level=logging.ERROR, format='%(message)s')
logger = logging.getLogger(__name__)


def log_step(step_num: int, title: str):
    """Log a numbered step."""
    print(f"\n  [{step_num}] {title}")


def log_success(msg: str):
    """Log success message."""
    print(f"      ✓ {msg}")


def log_error(msg: str):
    """Log error message."""
    print(f"      ✗ {msg}")


def log_step_failed(step: str, reason: str = ""):
    """Log that verification failed at a specific step, for easier debugging."""
    suffix = f": {reason}" if reason else ""
    print(f"      ✗ FAILED at step '{step}'{suffix}")


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
