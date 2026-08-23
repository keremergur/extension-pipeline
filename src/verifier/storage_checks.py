import json
import os
from typing import Dict, Optional
from .logging_utils import log_error, log_info
from .navigation import navigate_to_extension_context
from .constants import (
    BOOKMARKS_APIS, COOKIES_APIS, HISTORY_APIS, MANAGEMENT_APIS,
    DNR_APIS, TOPSITES_APIS, LOCALSTORAGE_APIS, CHROME_STORAGE_APIS,
    EXPLOIT_MARKERS,
)

#: Relax the storage-write match from exact-equality to marker-as-substring. Measured on the real
#: dataset: of storage writes the extension provably performed, ~22% were rejected only because the
#: exploit marker was wrapped (JSON-quoted, suffixed like ``exploit_access_token``, or nested inside an
#: object that ``String()`` flattened to ``[object Object]``). With this on, the value is read as
#: ``JSON.stringify`` (so object contents are visible) and any marker appearing as a substring counts.
#: Precision is guarded by the no-op negative control: a do-nothing payload writes nothing, so the key
#: stays absent and cannot match — any pre-existing coincidental value would also verify under the
#: control and be caught. Set STORAGE_VALUE_SUBSTRING_MATCH=false for the strict exact-match behaviour.
_STORAGE_SUBSTRING_MATCH = (os.getenv("STORAGE_VALUE_SUBSTRING_MATCH") or "true").strip().lower() \
    in ("1", "true", "yes", "on")


def _value_matches_marker(value: Optional[str]) -> bool:
    """Whether a read-back storage value evidences the attack.

    Always matches an exact marker; when substring matching is enabled also matches a marker embedded
    in a larger (JSON-stringified) value, which is how attacker writes most commonly appear.
    """
    if value is None:
        return False
    if value in EXPLOIT_MARKERS:
        return True
    if _STORAGE_SUBSTRING_MATCH:
        low = str(value).lower()
        return any(marker.lower() in low for marker in EXPLOIT_MARKERS)
    return False


async def check_storage_modified(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str] = None, storage_domain: Optional[str] = None, extension_path: Optional[str] = None, diagnostics: Optional[Dict] = None) -> bool:
    """
    Check if storage was modified by verifying the exploit marker or API-specific changes.

    Routes to appropriate handler based on storage_api.

    Args:
        page: Playwright page
        storage_api: The API used (e.g., "chrome.storage.local.set", "chrome.bookmarks.create")
        storage_key: Key/identifier to check (can be None for some APIs)
        extension_id: Extension ID (required for extension context APIs)
        storage_domain: Domain for cookies/localStorage (e.g., "example.com")
        extension_path: Path to extension directory

    Returns:
        True if storage was modified as expected, False otherwise
    """
    if not storage_api:
        log_error("storage_api is required")
        return False

    # Route to appropriate handler based on API
    if storage_api in CHROME_STORAGE_APIS:
        return await check_chrome_storage(page, storage_api, storage_key, extension_id, extension_path, diagnostics)
    elif storage_api in LOCALSTORAGE_APIS:
        return await check_web_storage(page, storage_api, storage_key, extension_id, extension_path, diagnostics)
    elif storage_api in BOOKMARKS_APIS:
        return await check_bookmarks(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in COOKIES_APIS:
        return await check_cookies(page, storage_api, storage_key, storage_domain, extension_id, extension_path)
    elif storage_api in HISTORY_APIS:
        return await check_history(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in MANAGEMENT_APIS:
        return await check_management(page, storage_api, storage_key, extension_id, extension_path)
    elif storage_api in DNR_APIS:
        return await check_dnr(page, storage_api, storage_key, extension_id, extension_path, diagnostics)
    elif storage_api in TOPSITES_APIS:
        return await check_topsites(page, storage_api, storage_key, extension_id, extension_path)
    else:
        log_error(f"Unknown storage_api: {storage_api}")
        return False


async def check_chrome_storage(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str], diagnostics: Optional[Dict] = None) -> bool:
    """
    Verify chrome.storage.* operations (existing implementation).

    Supported APIs:
    - chrome.storage.local.set/get/remove/clear
    - chrome.storage.sync.set/get/remove/clear
    - chrome.storage.session.set/get/remove/clear

    This is the existing 90% working implementation - preserved as-is.
    """
    if not extension_id:
        log_error(f"Extension ID required for chrome.storage API")
        return False

    # For .clear() APIs, storage_key can be None (they clear all keys)
    is_clear_api = storage_api.endswith('.clear')
    is_remove_api = '.remove' in storage_api
    if not storage_key and not is_clear_api:
        log_error(f"Storage key required for chrome.storage API (except .clear)")
        return False

    # Determine storage area from API name
    if 'local' in storage_api:
        storage_area = 'local'
    elif 'sync' in storage_api:
        storage_area = 'sync'
    elif 'session' in storage_api:
        storage_area = 'session'
    else:
        log_error(f"Cannot determine storage area from API: {storage_api}")
        return False

    # Prefer service worker (MV3) - avoids web_accessible_resources navigation issues.
    # Fall back to a regular extension page (MV2 background page / popup / options).
    # Note: service_workers is a property (list), not a method - no parentheses.
    # We match any chrome-extension:// worker because the runtime ID may differ from
    # the original extension_id when loaded unpacked without a 'key' in the manifest.
    sw = next(
        (w for w in page.context.service_workers if w.url.startswith("chrome-extension://")),
        None
    )

    async def _eval_storage(ctx):
        """Run the appropriate storage read in the given execution context."""
        # Reaching here means an extension context was obtained (the read below runs in it).
        if diagnostics is not None:
            diagnostics["storage_context_reached"] = True
        if is_clear_api:
            return await ctx.evaluate(f"""
                () => new Promise((resolve) => {{
                    chrome.storage.{storage_area}.get(null, (items) => {{
                        resolve(Object.keys(items).length === 0);
                    }});
                }})
            """)
        elif is_remove_api:
            return await ctx.evaluate(f"""
                () => new Promise((resolve) => {{
                    chrome.storage.{storage_area}.get('{storage_key}', (result) => {{
                        resolve(result['{storage_key}'] === undefined);
                    }});
                }})
            """)
        else:
            # JSON-stringify (not String()) so an object's contents stay visible instead of
            # collapsing to "[object Object]" and hiding an embedded marker.
            value = await ctx.evaluate(f"""
                () => new Promise((resolve) => {{
                    chrome.storage.{storage_area}.get('{storage_key}', (result) => {{
                        const v = result['{storage_key}'];
                        if (v === undefined) return resolve(null);
                        resolve(typeof v === 'string' ? v : JSON.stringify(v));
                    }});
                }})
            """)
            # Split "key never written" from "key written but value isn't our marker": the former is a
            # non-fire (payload/channel), the latter means the check is too strict for this write.
            if diagnostics is not None:
                diagnostics["storage_key_present"] = value is not None
                if value is not None:
                    diagnostics["storage_observed_value"] = str(value)[:80]
            return _value_matches_marker(value)

    if sw:
        try:
            return await _eval_storage(sw)
        except Exception as e:
            log_error(f"Chrome storage read (service worker) failed: {e}")
            return False

    # MV2 fallback: try background page before navigating (avoids wrong-ID navigation)
    bg = next(
        (p for p in page.context.background_pages if p.url.startswith("chrome-extension://")),
        None
    )
    if bg:
        try:
            return await _eval_storage(bg)
        except Exception as e:
            log_error(f"Chrome storage read (background page) failed: {e}")
            return False

    # Last resort: navigate to an extension page (requires correct extension_id)
    extension_page = await page.context.new_page()
    try:
        if not await navigate_to_extension_context(extension_page, extension_id):
            log_error("Could not navigate to any extension context for storage read")
            if diagnostics is not None:
                diagnostics["storage_context_reached"] = False
            return False
        return await _eval_storage(extension_page)
    except Exception as e:
        log_error(f"Chrome storage read failed: {e}")
        return False
    finally:
        await extension_page.close()


async def check_web_storage(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str], diagnostics: Optional[Dict] = None) -> bool:
    """
    Verify localStorage/sessionStorage operations in extension context.

    Supported APIs:
    - localStorage.setItem/removeItem/clear
    - sessionStorage.setItem/removeItem/clear
    """
    is_clear_api = storage_api.endswith('.clear')
    is_remove_api = 'removeItem' in storage_api
    if not storage_key and not is_clear_api:
        log_error(f"Storage key required for web storage API (except .clear)")
        return False

    storage_type = "localStorage" if "localStorage" in storage_api else "sessionStorage"

    if not extension_id:
        log_error(f"Extension ID required for extension {storage_type}")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        log_error(f"Could not navigate to extension context for {storage_type} check")
        if diagnostics is not None:
            diagnostics["storage_context_reached"] = False
        await extension_page.close()
        return False
    if diagnostics is not None:
        diagnostics["storage_context_reached"] = True

    try:
        if is_clear_api:
            result = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        return {storage_type}.length === 0;
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
        elif is_remove_api:
            result = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        return {storage_type}.getItem('{storage_key}') === null;
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
        else:
            value = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        return {storage_type}.getItem('{storage_key}');
                    }} catch(e) {{
                        return null;
                    }}
                }}
            """)
            # Same split as chrome.storage: key-absent (non-fire) vs value-not-marker (check too strict).
            if diagnostics is not None:
                diagnostics["storage_key_present"] = value is not None
                if value is not None:
                    diagnostics["storage_observed_value"] = str(value)[:80]
            result = _value_matches_marker(value)
        return result
    except Exception as e:
        log_error(f"Extension {storage_type} check failed: {e}")
        return False
    finally:
        await extension_page.close()


async def check_bookmarks(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.bookmarks operations.

    Storage APIs:
    - chrome.bookmarks.create: Check bookmark exists with title = storage_key
    - chrome.bookmarks.remove: Check bookmark with title = storage_key was removed (uses .search())
    - chrome.bookmarks.removeTree: Check bookmark folder with title = storage_key was removed (uses .search())

    Data Exfiltration APIs:
    - chrome.bookmarks.get/getRecent/getTree/search: Handled by seed_test_data + console detection

    Note: storage_key is bookmark title, not ID (per Prompt line 135)
    """
    if not extension_id or not extension_path:
        log_error("Extension ID and path required for bookmarks API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        if 'create' in storage_api:
            # Search for bookmark with title = storage_key
            if not storage_key:
                log_error("Storage key (bookmark title) required for bookmarks.create")
                await extension_page.close()
                return False

            result = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.bookmarks.search({{title: '{storage_key}'}}, results => {{
                        resolve(results && results.length > 0);
                    }});
                }})
            """)
        elif 'remove' in storage_api or 'removeTree' in storage_api:
            # Check if bookmark with title = storage_key was removed
            # (storage_key is bookmark title, not ID - see Prompt line 135)
            if not storage_key:
                log_error("Storage key (bookmark title) required for bookmarks.remove")
                await extension_page.close()
                return False

            result = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.bookmarks.search({{title: '{storage_key}'}}, results => {{
                        // If no results, bookmark was removed
                        resolve(results && results.length === 0);
                    }});
                }})
            """)
        else:
            # Data exfiltration APIs - no storage verification needed
            result = False

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"Bookmark check failed: {e}")
        await extension_page.close()
        return False


async def check_cookies(page, storage_api: str, storage_key: Optional[str], storage_domain: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.cookies operations.

    Storage APIs:
    - chrome.cookies.set: Check cookie exists
    - chrome.cookies.remove: Check cookie was removed

    Data Exfiltration APIs:
    - chrome.cookies.get/getAll: Handled by seed_test_data + console detection
    """
    if not storage_key:
        log_error("Storage key (cookie name) required for cookies API")
        return False

    # Scope the lookup to the specific domain when known, otherwise search all cookies.
    if storage_domain:
        cookies = await page.context.cookies([f'https://{storage_domain}'])
    else:
        cookies = await page.context.cookies()

    if 'remove' in storage_api:
        # Removal succeeded only if the cookie no longer exists.
        for cookie in cookies:
            if cookie.get('name') == storage_key:
                return False
        return True

    # Otherwise the cookie must exist and carry an exploit marker.
    for cookie in cookies:
        if cookie.get('name') == storage_key and cookie.get('value') in EXPLOIT_MARKERS:
            domain_label = storage_domain or cookie.get('domain')
            log_info(f"Found cookie '{storage_key}={cookie.get('value')}' for domain {domain_label}")
            return True
    return False


async def check_history(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.history operations.

    Storage APIs:
    - chrome.history.addUrl: Check URL exists in history
    - chrome.history.deleteUrl: Check URL was deleted
    - chrome.history.deleteAll: Check all history was deleted
    - chrome.history.deleteRange: Check history in range was deleted

    Data Exfiltration APIs:
    - chrome.history.getVisits/search: Handled by seed_test_data + console detection
    """
    if not extension_id or not extension_path:
        log_error("Extension ID and path required for history API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        if 'addUrl' in storage_api:
            # Check if URL exists in history
            if not storage_key:
                log_error("Storage key (URL) required for history.addUrl")
                await extension_page.close()
                return False

            result = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.history.search({{text: '{storage_key}'}}, results => {{
                        const found = results && results.some(r => r.url === '{storage_key}');
                        resolve(found);
                    }});
                }})
            """)
        elif 'delete' in storage_api:
            # Check if URL/history was deleted (should NOT exist)
            if 'deleteAll' in storage_api:
                # Check if history is mostly empty (< 3 entries)
                # Note: Extension pages themselves might still be in history,
                # so we can't expect it to be completely empty
                result = await extension_page.evaluate("""
                    () => new Promise(resolve => {
                        chrome.history.search({text: '', maxResults: 10}, results => {
                            // Consider successful if very few entries remain
                            resolve(results && results.length < 3);
                        });
                    })
                """)
            elif 'deleteRange' in storage_api:
                # deleteRange deletes by time range, not URL
                # For verification, we just check if history is empty or reduced
                # (Since we can't know the exact time range, we check if ANY history was deleted)
                result = await extension_page.evaluate("""
                    () => new Promise(resolve => {
                        chrome.history.search({text: ''}, results => {
                            // Consider it successful if history is empty or very small
                            resolve(results && results.length < 10);
                        });
                    })
                """)
            elif storage_key:
                # Check if specific URL is gone (deleteUrl)
                result = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.history.search({{text: '{storage_key}'}}, results => {{
                            const found = results && results.some(r => r.url === '{storage_key}');
                            resolve(!found);
                        }});
                    }})
                """)
            else:
                log_error("Storage key required for history.deleteUrl")
                result = False
        else:
            # Data exfiltration APIs - no storage verification needed
            result = False

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"History check failed: {e}")
        await extension_page.close()
        return False


async def check_management(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.management operations.

    Storage APIs:
    - chrome.management.uninstall: Check extension with ID = storage_key was uninstalled
    - chrome.management.uninstallSelf: Check current extension was uninstalled
    - chrome.management.setEnabled: SKIPPED (too complex)

    Data Exfiltration APIs:
    - chrome.management.get/getAll/getSelf: Handled by seed_test_data + console detection
    """
    if 'setEnabled' in storage_api:
        # Skipped per user requirement
        log_info("chrome.management.setEnabled verification skipped")
        return False

    if not extension_id or not extension_path:
        log_error("Extension ID and path required for management API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        await extension_page.close()
        return False

    try:
        if 'uninstall' in storage_api:
            if 'uninstallSelf' in storage_api:
                # uninstallSelf: Extension uninstalls itself
                # We can't verify this in real-time because the extension would be gone
                # Check if the extension ID still exists (it should be gone after uninstall)
                result = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.management.getSelf(info => {{
                            // If extension still exists, uninstall failed
                            resolve(chrome.runtime.lastError !== undefined || !info);
                        }});
                    }})
                """)
            else:
                # Check if extension (storage_key = extension ID) still exists
                if not storage_key:
                    log_error("Storage key (extension ID) required for management.uninstall")
                    await extension_page.close()
                    return False

                result = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.management.get('{storage_key}', info => {{
                            // If error, extension doesn't exist (was uninstalled)
                            resolve(chrome.runtime.lastError !== undefined);
                        }});
                    }})
                """)
        else:
            # Data exfiltration APIs - no storage verification needed
            result = False

        await extension_page.close()
        return result
    except Exception as e:
        log_error(f"Management check failed: {e}")
        await extension_page.close()
        return False


async def check_dnr(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str], diagnostics: Optional[Dict] = None) -> bool:
    """
    Verify chrome.declarativeNetRequest operations.

    Storage APIs:
    - chrome.declarativeNetRequest.updateDynamicRules: Check rule with ID = storage_key exists

    Instrumented so we can tell a non-fire (no dynamic rules were added at all) from an
    ID mismatch (a rule was added but under a different id than the expected storage_key).
    """
    if not extension_id or not extension_path:
        log_error("Extension ID and path required for declarativeNetRequest API")
        return False

    if not storage_key:
        log_error("Storage key (rule ID) required for declarativeNetRequest API")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        if diagnostics is not None:
            diagnostics["storage_context_reached"] = False
        await extension_page.close()
        return False
    if diagnostics is not None:
        diagnostics["storage_context_reached"] = True

    try:
        # Read the full dynamic rule set (serialized) so we can match the attacker target, not just id.
        rules_json = await extension_page.evaluate(
            """() => new Promise(resolve => {
                try {
                    chrome.declarativeNetRequest.getDynamicRules(rules => {
                        resolve(JSON.stringify(rules || []));
                    });
                } catch (e) { resolve('__ERR__:' + e); }
            })"""
        )
        key = str(storage_key)
        matched = False
        if isinstance(rules_json, str) and not rules_json.startswith('__ERR__'):
            try:
                rules = json.loads(rules_json)
            except Exception:
                rules = []
            ids = [str(r.get('id')) for r in rules if isinstance(r, dict)]
            if diagnostics is not None:
                diagnostics["dnr_rule_ids"] = ids
                diagnostics["dnr_expected_id"] = key
            # A redirect/block DNR exploit adds a rule *targeting* the attacker value (domain/URL),
            # which the analyzer records in storage_key; the integer rule id is auto-assigned. Count it
            # verified if a rule carries that exact id, or — for a non-numeric key — if the attacker
            # value appears anywhere in the rule set (its urlFilter/redirect). Precision is guarded by
            # the no-op negative control: a do-nothing payload adds no rule, so nothing can match.
            if key in ids:
                matched = True
            elif key and not key.isdigit():
                matched = key.lower() in rules_json.lower()
        elif diagnostics is not None:
            diagnostics["dnr_rule_ids"] = rules_json
            diagnostics["dnr_expected_id"] = key
        await extension_page.close()
        return matched
    except Exception as e:
        log_error(f"DNR check failed: {e}")
        await extension_page.close()
        return False


async def check_topsites(page, storage_api: str, storage_key: Optional[str], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Verify chrome.topSites operations.

    Data Exfiltration APIs:
    - chrome.topSites.get: Data exfiltration only, no storage verification

    Note: topSites is read-only, so there's no storage modification to verify.
    Verification happens via console/network detection of exfiltrated data.
    """
    log_info("topSites.get is data_exfiltration only, no storage verification")
    return False
