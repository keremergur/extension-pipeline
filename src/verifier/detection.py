import asyncio
from typing import Dict, Optional
import config
from .logging_utils import log_error, log_info, log_success
from .constants import SKIPPED_APIS
from .seeding import seed_test_data, verify_exfiltrated_data
from .storage_checks import check_storage_modified


async def wait_for_detection(
    page,
    vulnerability_category: Optional[str] = None,
    verification_details: Optional[Dict] = None,
    timeout_s: Optional[float] = None,
    mock_server=None,
    verification_token: Optional[str] = None,
    extension_id: Optional[str] = None,
    extension_path: Optional[str] = None
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

    def on_console(msg):
        nonlocal detection, token_in_console
        console_text = msg.text
        console_logs.append(msg.text)
        console_messages.append(msg)  # Store full msg for arg extraction later

        # 2way_request: [2WAY] prefix + token in console is one half of the proof (also needs extension origin)
        if vulnerability_category == "2way_request" and "[2WAY]" in console_text and verification_token and verification_token in console_text:
            token_in_console = True
            if extension_request_confirmed:
                detection = "2way_request"
        # data_exfiltration: Check for exfiltration marker in console
        elif vulnerability_category == "data_exfiltration" and "[EXFIL]" in console_text:
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
            detection = None
        else:
            # Get actual browser data to compare
            storage_api = verification_details.get('storage_api') if verification_details else None
            actual_data_valid = await verify_exfiltrated_data(
                page, storage_api, exfiltrated_data, extension_id, extension_path, verification_details
            )

            if not actual_data_valid:
                log_error("Exfiltrated data does NOT match actual browser data - false positive!")
                detection = None
            else:
                log_success("Exfiltrated data verified against actual browser data")

    return detection


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
    skip_seeding: bool = False
) -> Optional[str]:
    """Execute JavaScript payload and detect based on vulnerability category."""
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
                    extension_path=extension_path
                )
            )

        # Give extension time to load and register event listeners
        await asyncio.sleep(1.0)

        # Execute in main world (not isolated world) to allow postMessage communication with extension
        await page.add_script_tag(content=payload)

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
                storage_modified = await check_storage_modified(page, storage_api, storage_key, extension_id=extension_id, storage_domain=storage_domain, extension_path=extension_path)
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
