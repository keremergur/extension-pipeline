import re
import os
import asyncio
import hashlib
from pathlib import Path
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


def peek_runtime_extension_ids(context) -> List[str]:
    """Return the extension IDs currently visible in a context, without waiting.

    Unlike discover_runtime_extension_id_from_context() this never polls: it is a
    snapshot of what already exists, used to cross-check a computed ID and to feed
    ID recovery after a failed extension-context navigation.
    """
    ids: List[str] = []
    for url in _iter_context_urls(context):
        extension_id = _extract_extension_id_from_url(url)
        if extension_id and extension_id not in ids:
            ids.append(extension_id)
    return ids


def compute_unpacked_extension_id(extension_dir) -> Optional[str]:
    """Compute the ID Chrome assigns to an unpacked extension loaded from `extension_dir`.

    Reimplements crx_file::id_util::GenerateIdForPath():
      SHA256(<absolute path bytes>) -> first 16 bytes -> hex -> each hex digit
      mapped to 'a' + value (so '0'->'a' ... 'f'->'p'), giving a 32-char ID.

    Chrome hashes the path *after* base::MakeAbsoluteFilePath(), which on POSIX is
    realpath(): symlinks resolved, '..' collapsed, trailing separators stripped —
    hence os.path.realpath() here. Path bytes are the platform's native encoding
    for base::FilePath::CharType (UTF-8 on POSIX, UTF-16LE on Windows, where the
    drive letter is also upper-cased by MaybeNormalizePath).

    Only valid for extensions WITHOUT a 'key' in manifest.json — with a key the ID
    is derived from that key instead (see has_fixed_extension_id()).

    Returns None if the path cannot be resolved.
    """
    try:
        real_path = os.path.realpath(str(Path(extension_dir)))
        if os.name == "nt":
            # MaybeNormalizePath(): upper-case the drive letter so the hash matches
            # regardless of how the path was spelled on the command line.
            if len(real_path) >= 2 and real_path[1] == ":":
                real_path = real_path[0].upper() + real_path[1:]
            path_bytes = real_path.encode("utf-16-le")
        else:
            path_bytes = real_path.encode("utf-8")

        digest = hashlib.sha256(path_bytes).digest()[:16]
        extension_id = "".join(
            chr(ord("a") + nibble)
            for byte in digest
            for nibble in (byte >> 4, byte & 0x0F)
        )
        return extension_id if _is_valid_extension_id(extension_id) else None
    except Exception as e:
        log_error(f"Failed to compute unpacked extension ID for {extension_dir}: {e}")
        return None


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
