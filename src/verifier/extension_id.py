import re
import asyncio
from typing import List, Optional
from .logging_utils import log_error, log_info, log_success


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
    timeout_s: float = 5,
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
            if elapsed > timeout_s:
                if debug and not logged_details:
                    log_error(f"Extension discovery timeout ({timeout_s}s)")
                    urls = _iter_context_urls(context)
                    if urls:
                        log_info(f"Found {len(urls)} context URL(s):")
                        for url in urls:
                            log_info(f"   {url}")
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
