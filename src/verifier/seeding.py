import json
from typing import Dict, Optional
import config
from .logging_utils import log_error, log_info, log_success
from .navigation import navigate_to_extension_context
from .constants import (
    BOOKMARKS_APIS, COOKIES_APIS, HISTORY_APIS, MANAGEMENT_APIS,
    TOPSITES_APIS, CHROME_STORAGE_APIS, LOCALSTORAGE_APIS,
    EXPLOIT_MARKERS,
)


def _preview(value, limit: int = 100) -> str:
    """Truncated, always-sliceable rendering of a value for log output.

    Exfiltrated values come from JSHandle.json_value(), so they can be dicts or
    lists, not just strings. Slicing those directly raises (on Python 3.12 a dict
    lookup with a slice key), which previously turned a normal "data did not match"
    log line into a "Data verification failed" exception and hid the mismatch.
    """
    if value is None:
        return "None"
    if not isinstance(value, str):
        try:
            value = json.dumps(value)
        except Exception:
            value = str(value)
    return value[:limit] + "..." if len(value) > limit else value


async def seed_test_data(page, vulnerability_category: str, verification_details: Optional[Dict], extension_id: Optional[str], extension_path: Optional[str]) -> bool:
    """
    Seed test data for verification.

    Creates known data in browser storage/APIs that can be:
    - Exfiltrated by the payload (data_exfiltration category)
    - Deleted/removed by the payload (storage category with remove/delete/clear operations)

    Args:
        page: Playwright page
        vulnerability_category: "data_exfiltration" or "storage"
        verification_details: Dict with storage_api, storage_key, storage_domain
        extension_id: Extension ID
        extension_path: Path to extension directory

    Returns:
        True if seeding successful, False otherwise
    """
    # Only seed for data_exfiltration OR storage operations that need data to delete
    if vulnerability_category == "data_exfiltration":
        # All data_exfiltration needs seeding (reading data)
        pass
    elif vulnerability_category == "storage":
        # Only delete/remove/clear operations need seeding
        storage_api = verification_details.get('storage_api', '') if verification_details else ''
        needs_seed_keywords = ['remove', 'delete', 'clear']
        if not any(keyword in storage_api.lower() for keyword in needs_seed_keywords):
            return True  # No seeding needed for .set/.create/.add operations
    else:
        return True  # Unknown category, no seeding

    if not verification_details:
        return True

    storage_api = verification_details.get('storage_api')
    storage_key = verification_details.get('storage_key')

    if not storage_api:
        return True

    if not extension_id or not extension_path:
        log_error("Extension ID and path required for seeding test data")
        return False

    extension_page = await page.context.new_page()
    if not await navigate_to_extension_context(extension_page, extension_id):
        # For chrome.storage APIs, fall back to the extension's service worker (MV3).
        # The runtime ID may differ from extension_id when loaded unpacked, so we match
        # any chrome-extension:// service worker rather than filtering by ID.
        if storage_api in CHROME_STORAGE_APIS:
            # Try MV3 service worker first
            sw = next(
                (w for w in page.context.service_workers if w.url.startswith("chrome-extension://")),
                None
            )
            # Try MV2 background page as fallback
            bg = next(
                (p for p in page.context.background_pages if p.url.startswith("chrome-extension://")),
                None
            ) if not sw else None
            ext_ctx = sw or bg
            if ext_ctx:
                await extension_page.close()
                storage_key_local = storage_key or "testKey"
                storage_area = "local"
                if "sync" in storage_api:
                    storage_area = "sync"
                elif "session" in storage_api:
                    storage_area = "session"
                ctx_label = "service worker" if sw else "background page"
                try:
                    seeded = await ext_ctx.evaluate(f"""
                        () => new Promise(resolve => {{
                            chrome.storage.{storage_area}.set({{'{storage_key_local}': 'exploit'}}, () => {{
                                resolve(!chrome.runtime.lastError);
                            }});
                        }})
                    """)
                    if seeded:
                        log_success(f"Seeded test chrome.storage.{storage_area} key: {storage_key_local} (via {ctx_label})")
                    return seeded
                except Exception as e:
                    log_error(f"Extension context seeding failed ({ctx_label}): {e}")
                    return False
        await extension_page.close()
        return False

    success = False
    try:
        if storage_api in BOOKMARKS_APIS:
            # Create test bookmark
            if not storage_key:
                storage_key = "TestBookmark"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.bookmarks.create({{
                        title: '{storage_key}',
                        url: 'http://exploit.test/'
                    }}, result => resolve(!!result));
                }})
            """)
            if success:
                log_success(f"Seeded test bookmark: {storage_key}")

        elif storage_api in COOKIES_APIS:
            # Create test cookie
            storage_domain = verification_details.get('storage_domain') or config.VERIFICATION_PAGE_DOMAIN
            if not storage_key:
                storage_key = "testCookie"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.cookies.set({{
                        url: 'http://{storage_domain}',
                        name: '{storage_key}',
                        value: 'exploit'
                    }}, cookie => resolve(!!cookie));
                }})
            """)
            if success:
                log_success(f"Seeded test cookie: {storage_key}={storage_domain}")

        elif storage_api in HISTORY_APIS:
            # Add test URL to history
            if not storage_key:
                storage_key = "http://exploit-test.example.com/"

            # For history.search, storage_key might be just a search term (e.g., "exploit")
            # We need to create a valid URL that contains the search term
            seed_url = storage_key
            if not storage_key.startswith('http'):
                seed_url = f"http://{storage_key}.test/"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.history.addUrl({{url: '{seed_url}'}}, () => {{
                        resolve(!chrome.runtime.lastError);
                    }});
                }})
            """)
            if success:
                log_success(f"Seeded test history URL: {seed_url}")

        elif storage_api in MANAGEMENT_APIS or storage_api in TOPSITES_APIS:
            # No seeding needed - these return existing data
            success = True
            log_info(f"No seeding needed for {storage_api} (returns existing data)")

        elif storage_api in CHROME_STORAGE_APIS:
            # Seed chrome.storage
            if not storage_key:
                storage_key = "testKey"

            storage_area = "local"
            if "sync" in storage_api:
                storage_area = "sync"
            elif "session" in storage_api:
                storage_area = "session"

            success = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.storage.{storage_area}.set({{'{storage_key}': 'exploit'}}, () => {{
                        resolve(!chrome.runtime.lastError);
                    }});
                }})
            """)
            if success:
                log_success(f"Seeded test chrome.storage.{storage_area} key: {storage_key}")

        elif storage_api in LOCALSTORAGE_APIS:
            # Seed localStorage/sessionStorage in extension context
            storage_type = "localStorage" if "localStorage" in storage_api else "sessionStorage"
            if not storage_key:
                storage_key = "testKey"

            success = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        {storage_type}.setItem('{storage_key}', 'exploit');
                        return true;
                    }} catch(e) {{
                        return false;
                    }}
                }}
            """)
            if success:
                log_success(f"Seeded {storage_type} key '{storage_key}' in extension context")

        else:
            # Unknown API - skip seeding
            success = True

        await extension_page.close()
        return success
    except Exception as e:
        log_error(f"Seeding failed for {storage_api}: {e}")
        await extension_page.close()
        return False


async def verify_exfiltrated_data(
    page,
    storage_api: Optional[str],
    exfiltrated_data: str,
    extension_id: str,
    extension_path: str,
    verification_details: Optional[Dict]
) -> bool:
    """
    Verify that exfiltrated data actually exists in the browser.

    Prevents false positives when seeding fails or payload exfiltrates undefined/null.
    For each API group, retrieves actual browser data and checks if exfiltrated data appears in it.

    Returns:
        True if exfiltrated data is valid and found in browser, False otherwise
    """
    if not storage_api:
        log_info("No storage_api specified - skipping data verification")
        return True  # Cannot verify without knowing which API

    try:
        extension_page = await page.context.new_page()
        if not await navigate_to_extension_context(extension_page, extension_id):
            log_error("Cannot navigate to extension context for data verification")
            await extension_page.close()
            return False  # Cannot verify - safer to reject

        actual_data = None

        # Get actual data based on API group
        if storage_api in CHROME_STORAGE_APIS:
            # Get all storage for the area
            storage_area = "local"
            if "sync" in storage_api:
                storage_area = "sync"
            elif "session" in storage_api:
                storage_area = "session"

            actual_data = await extension_page.evaluate(f"""
                () => new Promise(resolve => {{
                    chrome.storage.{storage_area}.get(null, (items) => {{
                        resolve(JSON.stringify(items));
                    }});
                }})
            """)

        elif storage_api in BOOKMARKS_APIS:
            # Get all bookmarks
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.bookmarks.getTree(tree => {
                        resolve(JSON.stringify(tree));
                    });
                })
            """)

        elif storage_api in COOKIES_APIS:
            # Get all cookies
            storage_domain = verification_details.get('storage_domain') if verification_details else None
            if storage_domain:
                actual_data = await extension_page.evaluate(f"""
                    () => new Promise(resolve => {{
                        chrome.cookies.getAll({{domain: '{storage_domain}'}}, cookies => {{
                            resolve(JSON.stringify(cookies));
                        }});
                    }})
                """)
            else:
                actual_data = await extension_page.evaluate("""
                    () => new Promise(resolve => {
                        chrome.cookies.getAll({}, cookies => {
                            resolve(JSON.stringify(cookies));
                        });
                    })
                """)

        elif storage_api in HISTORY_APIS:
            # Get recent history
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.history.search({text: '', maxResults: 100}, results => {
                        resolve(JSON.stringify(results));
                    });
                })
            """)

        elif storage_api in MANAGEMENT_APIS:
            # Get all extensions
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.management.getAll(extensions => {
                        resolve(JSON.stringify(extensions));
                    });
                })
            """)

        elif storage_api in TOPSITES_APIS:
            # Get top sites
            actual_data = await extension_page.evaluate("""
                () => new Promise(resolve => {
                    chrome.topSites.get(sites => {
                        resolve(JSON.stringify(sites));
                    });
                })
            """)

        elif storage_api in LOCALSTORAGE_APIS:
            # Read localStorage/sessionStorage from extension context
            storage_type = "localStorage" if "localStorage" in storage_api else "sessionStorage"
            actual_data = await extension_page.evaluate(f"""
                () => {{
                    try {{
                        const items = {{}};
                        for (let i = 0; i < {storage_type}.length; i++) {{
                            const key = {storage_type}.key(i);
                            items[key] = {storage_type}.getItem(key);
                        }}
                        return JSON.stringify(items);
                    }} catch(e) {{
                        return null;
                    }}
                }}
            """)

        await extension_page.close()

        # Verify exfiltrated data appears in actual data
        if actual_data:
            # Convert exfiltrated_data to string for comparison (if it's an object/array)
            if isinstance(exfiltrated_data, (dict, list)):
                exfil_str = json.dumps(exfiltrated_data)
            else:
                exfil_str = str(exfiltrated_data)

            # Normalize both for comparison (lowercase, strip whitespace)
            actual_normalized = actual_data.lower().strip()
            exfil_normalized = exfil_str.lower().strip()

            # Check if seeded markers appear in BOTH exfiltrated and actual data
            # This works for simple values AND complex objects (if marker is in object property)
            marker_in_exfil = any(marker in exfil_normalized for marker in EXPLOIT_MARKERS)
            marker_in_actual = any(marker in actual_normalized for marker in EXPLOIT_MARKERS)

            if marker_in_exfil and marker_in_actual:
                log_info(f"✓ Seeded data found in both exfiltrated and actual browser data")
                return True

            # Fallback: Direct substring match (for non-seeded data like topSites, management)
            data_match = (
                exfil_normalized in actual_normalized or
                actual_normalized in exfil_normalized
            )

            if data_match:
                log_info(f"✓ Exfiltrated data matches actual browser data")
                return True
            else:
                log_error(f"✗ Exfiltrated data NOT in browser data")
                log_error(f"  Exfiltrated: {_preview(exfiltrated_data)}")
                log_error(f"  Actual: {_preview(actual_data)}")
                return False
        else:
            log_error("No actual data retrieved from browser")
            return False

    except Exception as e:
        log_error(f"Data verification failed: {e}")
        return False  # Safer to reject on error
