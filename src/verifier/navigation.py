import asyncio
from typing import Optional
import config
from .constants import STORAGE_PAGE_FILENAME, STORAGE_PAGE_MARKER
from .extension_id import peek_runtime_extension_ids
from .logging_utils import log_error, log_info
from .timing import timer


async def _page_has_marker(page) -> Optional[bool]:
    """Whether the loaded page is the storage page the verifier wrote.

    Returns True/False, or None if the marker could not be read at all (page gone,
    evaluation blocked) — callers decide how strict to be about that.
    """
    try:
        content = await page.evaluate(
            "() => document.querySelector('meta[name=\"verifier-storage-page\"]')?.content || null"
        )
        return content == STORAGE_PAGE_MARKER
    except Exception:
        return None


async def _try_navigate(page, extension_id: str, require_marker: bool) -> bool:
    """Attempt one navigation into `extension_id`'s context."""
    url = f'chrome-extension://{extension_id}/{STORAGE_PAGE_FILENAME}'
    try:
        # Playwright expects the navigation timeout in milliseconds.
        async with timer.step("extension_context_navigation", "EXTENSION_CONTEXT_NAVIGATION_TIMEOUT"):
            await page.goto(url, wait_until='domcontentloaded', timeout=int(config.EXTENSION_CONTEXT_NAVIGATION_TIMEOUT * 1000))
        await asyncio.sleep(0.3)
    except Exception:
        return False

    has_marker = await _page_has_marker(page)

    if not require_marker:
        # The ID was derived from the target extension itself, so a page that loads
        # at all is the target's. Only log when the marker is provably absent.
        if has_marker is False:
            log_info(f"Extension context {extension_id} served a page without the verifier marker")
        return True

    # Recovery candidates are IDs harvested from the browser, which may belong to
    # the verifier extension or a Chrome component extension - demand the marker.
    return has_marker is True


async def navigate_to_extension_context(page, extension_id: str) -> bool:
    """Navigate to the verifier's storage page in the extension context to access Chrome APIs.

    The file is guaranteed to exist because prepare_extension_storage_verification()
    always writes it before the browser is launched.

    If the navigation fails and config.EXTENSION_CONTEXT_ID_RECOVERY is enabled, the
    extension ID in hand was wrong (unpacked extensions get a random ID unless their
    manifest pins one). The live browser context is then re-read for chrome-extension://
    origins and each is retried, accepting only a page carrying the verifier marker.

    Returns:
        True if navigation succeeded, False otherwise.
    """
    if await _try_navigate(page, extension_id, require_marker=False):
        return True

    url = f'chrome-extension://{extension_id}/{STORAGE_PAGE_FILENAME}'

    if not config.EXTENSION_CONTEXT_ID_RECOVERY:
        log_error(f"Could not navigate to extension context: {url}")
        return False

    try:
        candidates = [c for c in peek_runtime_extension_ids(page.context) if c != extension_id]
    except Exception:
        candidates = []

    for candidate in candidates:
        if await _try_navigate(page, candidate, require_marker=True):
            log_info(f"Recovered extension context: {extension_id} -> {candidate}")
            return True

    log_error(f"Could not navigate to extension context: {url}")
    if candidates:
        log_error(f"  ID recovery tried {len(candidates)} live context(s): {', '.join(candidates)}")
    return False
