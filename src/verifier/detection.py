import asyncio
from typing import Dict, Optional
import config
from .logging_utils import log_error, log_info, log_success
from .constants import SKIPPED_APIS
from .seeding import seed_test_data, verify_exfiltrated_data
from .storage_checks import check_storage_modified


def derive_failure_reason(vulnerability_category: Optional[str], detection: Optional[str],
                          diagnostics: Optional[Dict]) -> Optional[str]:
    """Turn a non-detection into a concrete, machine-readable reason (see Phase 1).

    Returns None when detection succeeded. Otherwise returns a short slug explaining the most
    likely cause, inferred from the diagnostics collected during ``wait_for_detection``.
    """
    if detection:
        return None
    d = diagnostics or {}

    if vulnerability_category in ("1way_request", "2way_request", "code_execution", "download"):
        total = d.get("requests_total", 0)
        ext_ctx = d.get("requests_from_extension_context", 0)
        if total == 0:
            return "no_request_reached_mock_server"
        if ext_ctx == 0:
            # A request arrived but from the page, not the privileged extension context —
            # per the threat model this is NOT a vulnerability (common false-signal case).
            return "request_ran_on_page_not_extension_context"
        if vulnerability_category == "2way_request" and not d.get("token_in_console"):
            return "request_ok_but_response_token_not_returned"
        return "request_seen_but_not_confirmed"

    if vulnerability_category == "data_exfiltration":
        if not d.get("exfil_marker_seen"):
            return "no_exfil_marker_in_console"
        if d.get("exfil_value_valid") is False:
            return "exfil_value_mismatch_or_empty"
        return "exfil_marker_seen_but_unconfirmed"

    if vulnerability_category == "storage":
        # Split the formerly opaque miss (only populated for chrome.storage / web-storage writes):
        #  - context never reached  -> extension-context read failed (infra)
        #  - key present, wrong value -> extension DID write, but not our marker (check too strict)
        #  - key absent               -> the write never happened (payload/channel non-fire)
        if d.get("storage_context_reached") is False:
            return "storage_context_unreachable"
        if d.get("storage_key_present") is True:
            return "storage_value_not_marker"
        if d.get("storage_key_present") is False:
            return "storage_key_absent"
        return "storage_key_not_modified"

    if d.get("timed_out"):
        return "timed_out"
    return "payload_injected_no_signal"


async def wait_for_detection(
    page,
    vulnerability_category: Optional[str] = None,
    verification_details: Optional[Dict] = None,
    timeout_s: Optional[float] = None,
    mock_server=None,
    verification_token: Optional[str] = None,
    extension_id: Optional[str] = None,
    extension_path: Optional[str] = None,
    diagnostics: Optional[Dict] = None
) -> Optional[str]:
    """
    Wait for detection events with category-aware detection.

    Uses multiple detection methods:
    - Console logs (for code_execution, 2way_request with unique token)
    - Mock server request counts (for 1way_request, downloads)
    - Downloads (for download vulnerabilities)
    - Storage checks (handled separately)

    Args:
        verification_token: Unique token for 2way_request verification (from mock server)

    Returns:
        The detected vulnerability category matching the analysis categories,
        or None if no detection occurred:
        "code_execution", "1way_request", "2way_request", "download", "storage"
    """
    if timeout_s is None:
        timeout_s = config.PAYLOAD_EXECUTION_TIMEOUT

    if verification_details is None:
        verification_details = {}

    detection = None
    console_logs = []
    console_messages = []  # Store full msg objects for later parsing
    token_in_console = False
    extension_request_confirmed = False

    if diagnostics is None:
        diagnostics = {}
    diagnostics.setdefault("requests_total", 0)
    diagnostics.setdefault("requests_from_extension_context", 0)
    diagnostics.setdefault("token_in_console", False)
    diagnostics.setdefault("exfil_marker_seen", False)
    diagnostics.setdefault("exfil_value_valid", None)
    diagnostics.setdefault("timed_out", False)

    def on_console(msg):
        nonlocal detection, token_in_console
        console_text = msg.text
        console_logs.append(msg.text)
        console_messages.append(msg)  # Store full msg for arg extraction later

        # 2way_request: [2WAY] prefix + token in console is one half of the proof (also needs extension origin)
        if vulnerability_category == "2way_request" and "[2WAY]" in console_text and verification_token and verification_token in console_text:
            token_in_console = True
            diagnostics["token_in_console"] = True
            if extension_request_confirmed:
                detection = "2way_request"
        # data_exfiltration: Check for exfiltration marker in console
        elif vulnerability_category == "data_exfiltration" and "[EXFIL]" in console_text:
            diagnostics["exfil_marker_seen"] = True
            detection = "data_exfiltration"

    async def on_download(download):
        nonlocal detection
        filename = download.suggested_filename.lower()

        if filename == "exploit.txt":
            detection = "download"

    page.on("console", on_console)
    page.context.on("download", on_download)

    try:
        start_time = asyncio.get_event_loop().time()
        last_check = start_time
        while detection is None:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout_s:
                diagnostics["timed_out"] = True
                break

            # Check mock server periodically (not every 50ms!)
            current_time = asyncio.get_event_loop().time()
            if current_time - last_check >= 0.5 or current_time - start_time < 0.1:  # Check soon and every 500ms
                # Check mock server for network requests (works for Service Worker requests too)
                # IMPORTANT: Only count as verified if request came from extension context
                if mock_server and vulnerability_category in ["1way_request", "2way_request", "code_execution"]:
                    requests_info = mock_server.get_requests()
                    if requests_info:
                        has_extension_context = requests_info.get('has_extension_context', False)
                        total_requests = requests_info.get('total_requests', 0)
                        diagnostics["requests_total"] = total_requests
                        diagnostics["requests_from_extension_context"] = requests_info.get('extension_context_requests', 0)
                        # Keep the fingerprints of the requests that DID arrive. When attribution
                        # rejects them (request_ran_on_page_not_extension_context) this is the only
                        # evidence available offline for judging whether that rejection was right.
                        # Which evidence carried the attribution (ext_param / extension_origin /
                        # uninitiated). A verified result must always say what it rests on.
                        attr = requests_info.get('attribution_counts') or {}
                        if attr:
                            diagnostics["attribution_counts"] = attr
                        observed = requests_info.get('requests') or []
                        if observed:
                            diagnostics["observed_requests"] = [
                                {k: r.get(k) for k in
                                 ("path", "extension_id", "origin", "referer",
                                  "sec_fetch_site", "sec_fetch_mode", "sec_fetch_dest", "method")}
                                for r in observed[:10]
                            ]

                        if total_requests > 0 and has_extension_context:
                            # Request came from extension context - real vulnerability
                            if vulnerability_category == "1way_request":
                                detection = "1way_request"
                            elif vulnerability_category == "2way_request":
                                # Extension made the request; also need token in console
                                extension_request_confirmed = True
                                if token_in_console:
                                    detection = "2way_request"
                            elif vulnerability_category == "code_execution":
                                # Extension executed attacker-controlled code and made the fetch
                                # ext param != 'web' (enforced by has_extension_context) confirms extension context
                                detection = "code_execution"
                        # If total_requests > 0 but NOT from extension context,
                        # code ran on website only - not a real vulnerability, don't set detection

                # Check mock server for file downloads
                if mock_server and vulnerability_category == "download":
                    requests_info = mock_server.get_requests()
                    if requests_info:
                        # For downloads, check if request to /api/file came from extension context
                        file_requests = [r for r in requests_info.get('requests', []) if r.get('path') == '/api/file']
                        extension_file_requests = [
                            r for r in file_requests
                            if (r.get('extension_id') and r['extension_id'] != 'web')
                            or (r.get('origin') or '').startswith('chrome-extension://')
                        ]
                        if extension_file_requests:
                            detection = "download"

                last_check = current_time

            await asyncio.sleep(0.1)

    except Exception as e:
        log_error(f"Detection waiting error: {e}")

    finally:
        page.remove_listener("console", on_console)
        page.context.remove_listener("download", on_download)

    # 2way_request fallback: extension made the request but token didn't reach the website
    # → still a verified vulnerability, but only 1way
    if detection is None and vulnerability_category == "2way_request" and extension_request_confirmed:
        detection = "1way_request"

    # If no detection, check if requests came but not from extension context (helpful for debugging)
    if detection is None and mock_server:
        requests_info = mock_server.get_requests()
        if requests_info and requests_info.get('total_requests', 0) > 0:
            if not requests_info.get('has_extension_context', False):
                log_info(f"Request received but NOT from extension context (ext='web') - not a vulnerability")

    # CRITICAL: For data_exfiltration, verify that exfiltrated data matches actual browser data
    # This prevents false positives when seeding fails or data is undefined/null
    if detection == "data_exfiltration" and extension_id and extension_path:
        log_info("Verifying exfiltrated data matches actual browser data...")

        # Parse exfiltrated data from console messages (extract actual JS values, not just text!)
        exfiltrated_data = None
        for msg in console_messages:
            if "[EXFIL]" in msg.text:
                try:
                    args = msg.args
                    if len(args) > 1:  # [0] = "[EXFIL]", [1] = actual data
                        # Extract the actual JavaScript value (not just string representation!)
                        exfil_value = await args[1].json_value()

                        # Skip if undefined, null, or empty
                        if exfil_value is not None and exfil_value not in ["", [], {}]:
                            exfiltrated_data = exfil_value
                            break
                except Exception as e:
                    log_error(f"Failed to extract exfiltrated value from console: {e}")
                    continue

        if not exfiltrated_data:
            log_error("No valid data found after [EXFIL] marker - only undefined/null")
            diagnostics["exfil_value_valid"] = False
            detection = None
        else:
            # Get actual browser data to compare
            storage_api = verification_details.get('storage_api') if verification_details else None
            actual_data_valid = await verify_exfiltrated_data(
                page, storage_api, exfiltrated_data, extension_id, extension_path, verification_details
            )

            if not actual_data_valid:
                log_error("Exfiltrated data does NOT match actual browser data - false positive!")
                diagnostics["exfil_value_valid"] = False
                detection = None
            else:
                log_success("Exfiltrated data verified against actual browser data")
                diagnostics["exfil_value_valid"] = True

    # Capture a capped console tail for offline debugging of failures.
    if getattr(config, "CAPTURE_CONSOLE_LOGS", False):
        max_lines = getattr(config, "MAX_CAPTURED_CONSOLE_LINES", 40) or 40
        diagnostics["console_tail"] = console_logs[-max_lines:]

    return detection


async def simulate_user_interactions(page) -> None:
    """Best-effort user-gesture simulation for interaction-gated vulnerabilities.

    Some vulnerable handlers only run after a click or form submit. After the payload has installed its
    listeners, synthetically activate the page's controls so those handlers fire. Purely additive and
    precision-safe (a no-op payload installs no handler, so nothing can be triggered) and guarded so it
    can never raise or break a run.
    """
    try:
        await page.evaluate(
            """() => {
                const clickable = document.querySelectorAll(
                    'button, a[href], input[type=submit], input[type=button], [role=button], [onclick]');
                clickable.forEach(el => {
                    try { el.click(); } catch (e) {}
                    try { el.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true})); } catch (e) {}
                });
                document.querySelectorAll('form').forEach(f => {
                    try { f.requestSubmit ? f.requestSubmit() : f.submit(); } catch (e) {}
                });
            }"""
        )
    except Exception:
        pass


async def execute_payload_and_detect(
    page,
    payload: str,
    vulnerability_category: Optional[str] = None,
    verification_details: Optional[Dict] = None,
    timeout_s: Optional[float] = None,
    mock_server=None,
    verification_token: Optional[str] = None,
    extension_id: Optional[str] = None,
    extension_path: Optional[str] = None,
    skip_seeding: bool = False,
    diagnostics: Optional[Dict] = None
) -> Optional[str]:
    """Execute JavaScript payload and detect based on vulnerability category.

    If a mutable ``diagnostics`` dict is passed it is forwarded to ``wait_for_detection`` and
    populated with observations explaining the outcome (see Phase 1).
    """
    if timeout_s is None:
        timeout_s = config.PAYLOAD_EXECUTION_TIMEOUT

    if verification_details is None:
        verification_details = {}

    # Check if this API should be skipped
    storage_api = verification_details.get('storage_api')
    if storage_api and storage_api in SKIPPED_APIS:
        log_info(f"API {storage_api} is in skip list - skipping verification")
        return "skipped"  # Special return value to indicate skip

    detection = None

    try:
        # Seed test data BEFORE payload execution (for data_exfiltration and storage delete operations)
        # (unless skip_seeding=True, which means it was already done by the caller)
        if not skip_seeding:
            log_info(f"Checking if seeding needed for {vulnerability_category}...")
            seed_success = await seed_test_data(page, vulnerability_category, verification_details, extension_id, extension_path)
            if not seed_success:
                log_error("Failed to seed test data - ABORTING verification to prevent false positives")
                return None  # CRITICAL: Don't continue without seeded data!

        # For non-storage vulnerabilities, start detection listeners BEFORE payload
        if vulnerability_category != "storage":
            # Start detection task before executing payload
            detection_task = asyncio.create_task(
                wait_for_detection(
                    page,
                    vulnerability_category=vulnerability_category,
                    verification_details=verification_details,
                    timeout_s=timeout_s,
                    mock_server=mock_server,
                    verification_token=verification_token,
                    extension_id=extension_id,
                    extension_path=extension_path,
                    diagnostics=diagnostics
                )
            )

        # Give extension time to load and register event listeners (configurable — see
        # PAYLOAD_PRE_INJECT_SETTLE; the single payload injection below is lost if the listener
        # isn't ready yet).
        await asyncio.sleep(getattr(config, "PAYLOAD_PRE_INJECT_SETTLE", 1.0))

        # Readiness snapshot at payload-fire time. Records whether the extension's execution context
        # (MV3 service worker / MV2 background page) is up when we send the message. Correlating this
        # with run-to-run verified↔missed flips is the definitive test for the timing hypothesis: if
        # the misses cluster on "context cold at fire", the wobble is a startup race; if not, it isn't.
        if diagnostics is not None:
            try:
                _ctx = page.context
                diagnostics["ext_sw_at_fire"] = sum(
                    1 for w in _ctx.service_workers if w.url.startswith("chrome-extension://"))
                diagnostics["ext_bg_at_fire"] = sum(
                    1 for p in _ctx.background_pages if p.url.startswith("chrome-extension://"))
            except Exception:
                pass

        # Execute in main world (not isolated world) to allow postMessage communication with extension
        await page.add_script_tag(content=payload)

        # Interaction-gated vulnerabilities (~1/3 of unverified per the thesis) only fire after a click
        # or form submit. Now that the payload's listeners are installed, synthetically activate page
        # controls so those handlers run. Flag-gated; precision-safe — a no-op payload installs no
        # handler, so this can never manufacture a detection.
        if getattr(config, "SIMULATE_USER_INTERACTION", False):
            await simulate_user_interactions(page)

        # For storage vulnerabilities, check if the key was modified
        if vulnerability_category == "storage":
            storage_api = verification_details.get('storage_api')
            storage_key = verification_details.get('storage_key')
            storage_domain = verification_details.get('storage_domain')

            if not storage_api:
                log_error(f"Storage vulnerability missing required field: storage_api")
                detection = None
            else:
                # Give storage operation time to complete
                await asyncio.sleep(0.5)

                log_info(f"Checking storage: key='{storage_key}' using {storage_api}" + (f" for domain {storage_domain}" if storage_domain else ""))
                storage_modified = await check_storage_modified(page, storage_api, storage_key, extension_id=extension_id, storage_domain=storage_domain, extension_path=extension_path, diagnostics=diagnostics)
                if storage_modified:
                    detection = "storage"
                else:
                    detection = None
        else:
            # Wait for detection task to complete
            detection = await detection_task

    except Exception as e:
        log_error(f"Payload execution: {e}")
        detection = None

    return detection
