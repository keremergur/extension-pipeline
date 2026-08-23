import tempfile
import uuid
from pathlib import Path
from typing import Optional
import config
from .logging_utils import log_error, log_success, log_info


def _resolve_headless_mode(headless_setting: str):
    """Translate the config.HEADLESS string into Playwright launch parameters.

    Returns a tuple of (headless, extra_args):
    - "true": classic headless mode      -> (True, [])
    - "new":  Chrome's new headless mode -> (False, ["--headless=new"])
    - anything else (incl. "false"):     -> (False, [])  visible window
    """
    setting = (headless_setting or "").strip().lower()
    if setting == "true":
        return True, []
    if setting == "new":
        return False, ["--headless=new"]
    return False, []


async def launch_browser_with_extension(extension_dir: Path, p, verifier_dir: Optional[Path] = None, user_data_dir: Optional[Path] = None, extra_args: Optional[list] = None):
    """
    Launch Chrome with extension(s) loaded.

    Args:
        extension_dir: Path to the extension to load
        p: Playwright instance
        verifier_dir: Optional path to attacker/verifier extension
        user_data_dir: Optional custom user data directory. If None, creates a unique temporary directory.
        extra_args: Optional extra Chrome launch args (e.g. domain-spoofing host-resolver rules).

    Returns:
        Tuple of (context, user_data_dir) where user_data_dir is the path that should be cleaned up after use
    """
    chrome_path = Path(config.CHROME_BINARY_PATH)

    if not chrome_path.exists():
        log_error(f"Chrome not found: {chrome_path}")
        return None, None

    extension_dir_abs = extension_dir.resolve()

    # Create a unique temporary user data directory for Chrome profile if not provided
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

        # Resolve the headless mode from config (true / false / new).
        headless, headless_args = _resolve_headless_mode(config.HEADLESS)
        log_info(f"Headless mode: {config.HEADLESS}")

        # Build args list
        args = [
            f"--load-extension={','.join(load_extensions)}",
            f"--disable-extensions-except={','.join(disable_extensions)}",
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
        ] + headless_args

        # Caller-supplied launch args (e.g. domain-spoofing host-resolver rules; see domain_spoofing.py).
        if extra_args:
            args.extend(extra_args)

        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(user_data_dir),
            executable_path=str(chrome_path),
            args=args,
            headless=headless
        )
        log_success("Browser launched successfully")
        return context, user_data_dir
    except Exception as e:
        log_error(f"Browser launch: {e}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
        return None, None
