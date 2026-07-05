import asyncio
import config
from .logging_utils import log_error
from .timing import timer


async def navigate_to_extension_context(page, extension_id: str) -> bool:
    """Navigate to verify_storage.html in the extension context to access Chrome APIs.

    The file is guaranteed to exist because prepare_extension_storage_verification()
    always writes it before the browser is launched.

    Returns:
        True if navigation succeeded, False otherwise.
    """
    url = f'chrome-extension://{extension_id}/verify_storage.html'
    try:
        # Playwright expects the navigation timeout in milliseconds.
        async with timer.step("extension_context_navigation", "EXTENSION_CONTEXT_NAVIGATION_TIMEOUT"):
            await page.goto(url, wait_until='domcontentloaded', timeout=int(config.EXTENSION_CONTEXT_NAVIGATION_TIMEOUT * 1000))
        await asyncio.sleep(0.3)
        return True
    except Exception:
        log_error(f"Could not navigate to extension context: {url}")
        return False
