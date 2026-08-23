import asyncio
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from playwright.async_api import async_playwright
import config
from mock_server import get_mock_server
from .logging_utils import log_step, log_success, log_error, log_info, ask_continue, log_step_failed
from .constants import Color, SKIPPED_APIS, RETRY_CATEGORIES
from .browser import launch_browser_with_extension
from .extension_code import get_extension_code_dir, validate_extension_structure
from .manifest import (
    has_background_context, has_fixed_extension_id,
    modify_manifest_for_verification, prepare_extension_storage_verification,
    pin_extension_id,
)
from .extension_id import (
    payload_mentions_extension_id,
    discover_runtime_extension_id_from_context,
    replace_extension_id_in_payload,
)
from .verifier_extension import prepare_verifier_extension
from .seeding import seed_test_data
from .detection import wait_for_detection, execute_payload_and_detect, derive_failure_reason
from .storage_checks import check_storage_modified
from .timing import timer
from .debugging import capture_failure_artifacts
from domain_spoofing import spoof_target


async def verify_extension_mode_vulnerability(extension_id: str, extension_dir: Path, vuln: dict, p, debug_mode: bool = False, pinned_extension_id: str = None) -> Dict:
    """Verify a single extension-mode vulnerability using verifier extension.

    Two-browser approach:
    1. Browser 1: Only target extension → discover real extension ID
    2. Browser 2: Target + Verifier (with correct payload) → execute and detect
    """
    vuln_record = {
        **vuln,
        "detection": None,
        "verification_status": None,
        "error": None
    }

    payload = vuln.get('attacker_payload')
    rule_id = vuln.get('rule_id')

    # Resolve navigation target + domain-spoofing launch args (no-op unless spoofing is enabled).
    nav_url, spoof_args = spoof_target(vuln, config)
    # Always record the resolved target so every result JSON is self-explanatory offline.
    vuln_record["nav_url"] = nav_url
    vuln_record["spoofing_applied"] = bool(spoof_args)

    if not payload:
        vuln_record["verification_status"] = "missing_payload"
        log_info("No payload provided")
        return vuln_record

    try:
        # Manifest was already modified once in verify_extension() before this call

        # Only discover the runtime extension ID if we actually need to replace it in the payload.
        needs_id_replacement = payload_mentions_extension_id(payload, extension_id)

        if debug_mode and needs_id_replacement and not ask_continue("Proceed to extension ID discovery?"):
            vuln_record["verification_status"] = "skipped"
            return vuln_record

        # Step 1: Determine target extension ID
        target_extension_id = None

        # Content-script-only extension whose ID we pinned: use the known ID directly (discovery is
        # impossible for it, and the pinned manifest 'key' makes the runtime ID deterministic).
        if pinned_extension_id:
            target_extension_id = pinned_extension_id
            if debug_mode:
                log_step(2, "Extension ID determination")
                log_success(f"Using pinned content-script-only extension ID: {target_extension_id}")
        # Check if extension has a fixed ID (via 'key' in manifest.json)
        elif has_fixed_extension_id(extension_dir):
            # Extension has 'key' → ID is deterministic and matches the .crx filename
            target_extension_id = extension_id
            if debug_mode:
                log_step(2, "Extension ID determination")
                log_success(f"Extension has fixed ID (manifest 'key' present): {target_extension_id}")
        else:
            # Extension has no 'key' → ID is random, need to discover it
            if not needs_id_replacement:
                target_extension_id = extension_id
                if debug_mode:
                    log_step(2, "Extension ID determination")
                    log_info("Payload contains no target extension ID; skipping ID discovery")
            elif not has_background_context(extension_dir):
                # Content-script-only extension: no background page/SW → discovery always times out
                target_extension_id = extension_id
                if debug_mode:
                    log_step(2, "Extension ID determination")
                    log_info("No background context (no SW/background page) – skipping ID discovery, using original ID")
            else:
                if debug_mode:
                    log_step(2, "Launching browser with target extension only (for ID discovery)")

                context, discovery_user_data_dir = await launch_browser_with_extension(extension_dir, p, verifier_dir=None)

                if not context:
                    vuln_record["verification_status"] = "browser_launch_failed"
                    vuln_record["error"] = "Failed to launch Chrome"
                    log_step_failed("launch browser", "Failed to launch Chrome")
                    return vuln_record

                log_success("Browser launched with target extension")

                # Discover target extension ID
                if debug_mode:
                    log_step(3, "Discovering target extension ID")

                temp_page = await context.new_page()
                try:
                    # Use HTTP to avoid mixed content issues
                    async with timer.step("id_discovery_navigation", "PAGE_NAVIGATION_TIMEOUT"):
                        await temp_page.goto(config.VERIFICATION_PAGE_URL, timeout=int(config.PAGE_NAVIGATION_TIMEOUT * 1000), wait_until="domcontentloaded")
                except Exception:
                    pass  # Extension may initialize without a successful navigation

                await asyncio.sleep(0.5)
                async with timer.step("extension_id_discovery", "EXTENSION_ID_DISCOVERY_TIMEOUT"):
                    target_extension_id = await discover_runtime_extension_id_from_context(
                        context, timeout_s=config.EXTENSION_ID_DISCOVERY_TIMEOUT, debug=debug_mode
                    )
                await temp_page.close()

                if not target_extension_id:
                    await context.close()
                    vuln_record["verification_status"] = "extension_id_discovery_failed"
                    log_step_failed("discover extension ID", "Failed to discover target extension ID")
                    return vuln_record

                log_success(f"Target extension ID: {target_extension_id}")

                # Close browser after ID discovery
                try:
                    async with timer.step("browser_close", "BROWSER_CLOSE_TIMEOUT"):
                        await asyncio.wait_for(context.close(), timeout=config.BROWSER_CLOSE_TIMEOUT)
                except asyncio.TimeoutError:
                    log_info(f"Browser close timed out after {config.BROWSER_CLOSE_TIMEOUT}s — continuing anyway")

                # Cleanup user data directory
                if discovery_user_data_dir and discovery_user_data_dir.exists():
                    shutil.rmtree(discovery_user_data_dir, ignore_errors=True)

        if not target_extension_id:
            vuln_record["verification_status"] = "extension_id_determination_failed"
            log_step_failed("determine extension ID", "Failed to determine target extension ID")
            return vuln_record

        if debug_mode and not ask_continue("Proceed to verifier extension preparation?"):
            vuln_record["verification_status"] = "skipped"
            return vuln_record

        # Step 2: Prepare verifier extension with correct extension ID in payload
        if debug_mode:
            log_step(3, "Preparing verifier extension")

        original_extension_id = extension_id
        modified_payload = payload

        if needs_id_replacement and original_extension_id and target_extension_id and original_extension_id != target_extension_id:
            log_info(f"Original extension ID: {original_extension_id}")
            log_info(f"Actual extension ID:   {target_extension_id}")

            modified_payload = replace_extension_id_in_payload(payload, original_extension_id, target_extension_id)

            if modified_payload != payload:
                log_success("Extension ID replaced in payload")
            else:
                log_info("Extension ID not found in payload")
        else:
            if needs_id_replacement:
                log_info("Extension ID matches - no replacement needed")
            elif debug_mode:
                log_info("No extension ID replacement needed")

        verifier_dir = prepare_verifier_extension(extension_id, modified_payload)
        if not verifier_dir:
            vuln_record["verification_status"] = "verifier_prep_failed"
            vuln_record["error"] = "Failed to prepare verifier extension"
            log_step_failed("prepare verifier extension", "Failed to prepare verifier extension")
            return vuln_record

        log_success("Verifier extension prepared with correct payload")

        if debug_mode and not ask_continue("Proceed to launch browser with both extensions?"):
            vuln_record["verification_status"] = "skipped"
            return vuln_record

        # Step 3: Launch browser with BOTH extensions
        if debug_mode:
            log_step(4, "Launching browser with target + verifier extensions")

        context, extension_mode_user_data_dir = await launch_browser_with_extension(extension_dir, p, verifier_dir, extra_args=spoof_args)

        if not context:
            vuln_record["verification_status"] = "browser_launch_failed"
            vuln_record["error"] = "Failed to launch Chrome"
            log_step_failed("launch browser", "Failed to launch Chrome")
            return vuln_record

        log_success("Browser launched with both extensions")

        try:
            if debug_mode and not ask_continue("Proceed to testing?"):
                await context.close()
                vuln_record["verification_status"] = "skipped"
                return vuln_record

            vulnerability_category = vuln.get('vulnerability_category')
            verification_details = vuln.get('verification_details')

            # Reset mock server before test and get verification token
            mock_server = get_mock_server()
            verification_token = mock_server.reset_and_get_token()

            # Check if API should be skipped before doing any further work
            storage_api_check = verification_details.get('storage_api') if verification_details else None
            if storage_api_check and storage_api_check in SKIPPED_APIS:
                log_info(f"API {storage_api_check} is in skip list - skipping verification")
                vuln_record["verification_status"] = "skipped"
                await context.close()
                return vuln_record

            # Seed test data BEFORE payload execution (verifier extension runs at DOMContentLoaded)
            # data_exfiltration needs data to read; storage delete/remove/clear needs data to delete
            seed_page = await context.new_page()
            async with timer.step("seeding"):
                seed_success = await seed_test_data(
                    seed_page,
                    vulnerability_category,
                    verification_details,
                    target_extension_id,
                    str(extension_dir)
                )
            await seed_page.close()
            if not seed_success:
                log_step_failed("seed test data", "ABORTING to prevent false positives")
                vuln_record["verification_status"] = "seeding_failed"
                vuln_record["error"] = "Failed to seed test data"
                await context.close()
                return vuln_record

            # Create page for testing
            page = await context.new_page()

            # Start detection listeners BEFORE loading page (payload executes on DOMContentLoaded)
            if debug_mode:
                log_step(5, f"Testing: {rule_id}")

            diagnostics = {}
            detection_task = asyncio.create_task(
                wait_for_detection(
                    page,
                    vulnerability_category=vulnerability_category,
                    verification_details=verification_details,
                    timeout_s=config.PAYLOAD_EXECUTION_TIMEOUT,
                    mock_server=mock_server,
                    verification_token=verification_token,
                    extension_id=target_extension_id,
                    extension_path=str(extension_dir),
                    diagnostics=diagnostics
                )
            )

            # Load page - this triggers DOMContentLoaded and executes payload with active listeners
            try:
                # Default nav is the configured verification page; with domain spoofing on, nav_url is
                # the real restricted origin over HTTPS.
                async with timer.step("page_navigation", "PAGE_NAVIGATION_TIMEOUT"):
                    await page.goto(nav_url, timeout=int(config.PAGE_NAVIGATION_TIMEOUT * 1000), wait_until="domcontentloaded")
            except Exception as nav_error:
                log_step_failed("load page", str(nav_error))
                detection_task.cancel()
                try:
                    await detection_task
                except asyncio.CancelledError:
                    pass
                vuln_record["verification_status"] = "page_load_failed"
                vuln_record["error"] = str(nav_error)
                await page.close()
                return vuln_record

            # Wait for detection result
            async with timer.step("payload_detection", "PAYLOAD_EXECUTION_TIMEOUT"):
                detection = await detection_task

            # For storage vulnerabilities, also check if the key was modified
            if vulnerability_category == "storage" and not detection:
                storage_api = verification_details.get('storage_api') if verification_details else None
                storage_key = verification_details.get('storage_key') if verification_details else None
                storage_domain = verification_details.get('storage_domain') if verification_details else None

                if storage_api:
                    storage_modified = await check_storage_modified(page, storage_api, storage_key, extension_id=target_extension_id, storage_domain=storage_domain, extension_path=str(extension_dir), diagnostics=diagnostics)
                    if storage_modified:
                        detection = "storage"

            vuln_record["detection"] = detection
            vuln_record["diagnostics"] = diagnostics
            vuln_record["target_extension_id"] = target_extension_id

            if detection:
                vuln_record["verification_status"] = "verified"
                log_success(f"Detection: {detection}")
            else:
                vuln_record["verification_status"] = "no_detection"
                vuln_record["failure_reason"] = derive_failure_reason(
                    vulnerability_category, detection, diagnostics)
                log_info(f"Payload executed, no detection ({vuln_record['failure_reason']})")

            # Debuggability: dump screenshot/DOM/payload/debug.json while the page is still open.
            await capture_failure_artifacts(
                page, extension_id=extension_id, rule_id=rule_id,
                vulnerability_category=vulnerability_category, nav_url=nav_url,
                executed_payload=modified_payload, target_extension_id=target_extension_id,
                spoofing_applied=bool(spoof_args), diagnostics=diagnostics,
                failure_reason=vuln_record.get("failure_reason"),
                verification_status=vuln_record.get("verification_status"),
                on_success=bool(detection),
            )

            if debug_mode:
                log_info("Payload executed - inspect the page/console now")
                log_info("Browser will remain open for manual inspection")
                if ask_continue("Close browser?"):
                    await page.close()
                    await context.close()
                else:
                    input("Press Enter to close browser...")
                    await page.close()
                    await context.close()
            else:
                await page.close()
                await context.close()

        except Exception as e:
            vuln_record["verification_status"] = "execution_error"
            vuln_record["error"] = str(e)
            log_error(f"Payload execution: {e}")
            try:
                await context.close()
                # Cleanup user data directory
                if extension_mode_user_data_dir and extension_mode_user_data_dir.exists():
                    shutil.rmtree(extension_mode_user_data_dir, ignore_errors=True)
            except:
                pass
        finally:
            # Final cleanup attempt
            if extension_mode_user_data_dir and extension_mode_user_data_dir.exists():
                try:
                    shutil.rmtree(extension_mode_user_data_dir, ignore_errors=True)
                except:
                    pass

    except Exception as e:
        vuln_record["verification_status"] = "error"
        vuln_record["error"] = str(e)
        log_error(f"Extension-mode verification error: {e}")

    return vuln_record


async def verify_extension(extension_id: str, vulnerabilities: List[dict], debug_mode: bool = False) -> Dict:
    """Verify a single extension's vulnerabilities."""
    verification_result = {
        "extension_id": extension_id,
        "timestamp": datetime.now().isoformat(),
        "status": "failed",  # Will be updated based on verification results
        "vulnerabilities_verified": [],
        "errors": []
    }

    timer.start_extension(extension_id)

    try:
        # Step 1: Get extension code
        if debug_mode:
            log_step(1, "Downloading and extracting extension code")

        extension_dir = get_extension_code_dir(extension_id)
        if not extension_dir:
            verification_result["status"] = "failed"
            verification_result["errors"].append("Extension code not found")
            log_step_failed("get extension code", "Extension code not found")
            return verification_result

        log_success("Extension code extracted")

        if debug_mode and not ask_continue("Proceed to manifest validation?"):
            return verification_result

        # Step 2: Validate extension structure
        if debug_mode:
            log_step(2, "Validating extension structure")

        if not validate_extension_structure(extension_dir):
            verification_result["status"] = "failed"
            verification_result["errors"].append("Invalid extension structure")
            log_step_failed("validate extension structure", "Invalid extension structure")
            return verification_result

        log_success("Extension structure valid")

        # Separate vulnerabilities by attacker source
        extension_mode_vulns = [v for v in vulnerabilities if v.get('attacker_source') == 'Extension']
        website_mode_vulns = [v for v in vulnerabilities if v.get('attacker_source') == 'Website']

        # Prepare storage verification page if any vulnerability uses ext_* storage
        prepare_extension_storage_verification(extension_dir, vulnerabilities)

        # Modify manifest ONCE for all vulnerabilities (sets all matches to <all_urls>)
        # specific_domain per vulnerability only affects which URL is loaded, not the manifest
        if debug_mode:
            log_step(2, "Modifying manifest.json")
        success, modifications = modify_manifest_for_verification(extension_dir)
        if not success:
            verification_result["status"] = "failed"
            verification_result["errors"].append("Failed to modify manifest")
            log_step_failed("modify manifest", "Failed to modify manifest")
            return verification_result
        if modifications["manifest_modified"]:
            mod_parts = []
            if modifications['content_scripts_modified'] > 0:
                mod_parts.append(f"{modifications['content_scripts_modified']} content scripts")
            if modifications['web_accessible_resources_modified'] > 0:
                mod_parts.append(f"{modifications['web_accessible_resources_modified']} web resources")
            if modifications['externally_connectable_modified'] > 0:
                mod_parts.append(f"{modifications['externally_connectable_modified']} externally_connectable")
            log_success(f"Manifest modified ({', '.join(mod_parts)})")
        else:
            log_info("No manifest modifications needed")

        # Pin the ID of every extension that doesn't ship its own 'key'. An unpacked extension loads
        # under a non-original, path-derived ID regardless, so pinning to a *known* ID is strictly more
        # reliable than runtime discovery — it removes the lazy-MV3-service-worker discovery timeout
        # that otherwise makes ID discovery fall back to the wrong (original) ID, breaking every
        # extension-context navigation (seeding + storage verification). Extensions with their own
        # 'key' keep their packed identity (pin_extension_id returns None for them), and discovery
        # below stays as a fallback for the rare case pinning could not write the manifest.
        # Pinning can be disabled with DETERMINISTIC_EXTENSION_ID=false to reproduce the old
        # runtime-ID-discovery behaviour (used for old-vs-new baseline comparisons). Default on.
        _pin_enabled = (os.getenv("DETERMINISTIC_EXTENSION_ID", "true").strip().lower()
                        not in ("0", "false", "no", "off"))
        pinned_extension_id = None
        if _pin_enabled and not has_fixed_extension_id(extension_dir):
            pinned_extension_id = pin_extension_id(extension_dir)
            if pinned_extension_id:
                log_success(f"Pinned extension ID: {pinned_extension_id}")

        async with async_playwright() as p:
            vulnerabilities_with_detection = []

            # Step 3a: Handle Extension-Mode vulnerabilities
            if extension_mode_vulns:
                if debug_mode:
                    print(f"\n{Color.BOLD}EXTENSION-MODE VULNERABILITIES{Color.END} ({len(extension_mode_vulns)})")

                for idx, vuln in enumerate(extension_mode_vulns, 1):
                    if debug_mode:
                        print(f"\n{Color.BOLD}[{idx}/{len(extension_mode_vulns)}] Verifying: {vuln.get('rule_id')}{Color.END}")

                    timer.start_vuln(vuln.get('rule_id'), vuln.get('attacker_source'))
                    result = await verify_extension_mode_vulnerability(
                        extension_id, extension_dir, vuln, p, debug_mode=debug_mode,
                        pinned_extension_id=pinned_extension_id,
                    )
                    vulnerabilities_with_detection.append(result)

            # Step 3b: Handle Website-Mode vulnerabilities
            # IMPORTANT: Each vulnerability gets a fresh browser to avoid data contamination
            if website_mode_vulns:
                if debug_mode:
                    print(f"\n{Color.BOLD}WEBSITE-MODE VULNERABILITIES{Color.END} ({len(website_mode_vulns)})")

                if debug_mode and not ask_continue("Proceed to vulnerability testing?"):
                    return verification_result

                # Step 4 & 5: Launch fresh browser for EACH vulnerability to avoid data contamination
                for idx, vuln in enumerate(website_mode_vulns, 1):
                    if debug_mode:
                        print(f"\n{Color.BOLD}[{idx}/{len(website_mode_vulns)}] Testing: {vuln.get('rule_id')}{Color.END}")
                        log_step(4, f"Launching FRESH browser (avoiding data contamination)")

                    timer.start_vuln(vuln.get('rule_id'), vuln.get('attacker_source'))
                    payload = vuln.get('attacker_payload')
                    rule_id = vuln.get('rule_id')

                    # Resolve navigation target + domain-spoofing launch args for this vulnerability.
                    # No-op (configured page, no args) unless spoofing is enabled and a specific_domain is set.
                    nav_url, spoof_args = spoof_target(vuln, config)

                    # Early skip check for SKIPPED_APIS (before browser launch to avoid wasted work)
                    verification_details_early = vuln.get('verification_details')
                    storage_api_early = verification_details_early.get('storage_api') if verification_details_early else None
                    if storage_api_early and storage_api_early in SKIPPED_APIS:
                        log_info(f"API {storage_api_early} is in skip list - skipping verification")
                        vulnerabilities_with_detection.append({
                            **vuln,
                            "manifest_modifications": modifications,
                            "detection": None,
                            "verification_status": "skipped",
                            "error": None
                        })
                        continue

                    # Start fresh browser for this vulnerability
                    context, user_data_dir = await launch_browser_with_extension(extension_dir, p, extra_args=spoof_args)

                    if not context:
                        vuln_record = {
                            **vuln,
                            "manifest_modifications": modifications,
                            "detection": None,
                            "verification_status": "browser_launch_failed",
                            "error": "Failed to launch Chrome"
                        }
                        vulnerabilities_with_detection.append(vuln_record)
                        log_step_failed("launch browser", "Failed to launch Chrome")
                        continue

                    log_success("Fresh browser launched")

                    # Discover actual extension ID for this fresh browser instance
                    # Skip discovery for content-script-only extensions (no background context → always times out)
                    payload_cur = vuln.get('attacker_payload', '')
                    needs_id = payload_mentions_extension_id(payload_cur, extension_id)
                    # storage/data_exfiltration need runtime ID for verify_storage.html navigation,
                    # even when the payload doesn't explicitly mention the extension ID
                    vulnerability_category_cur = vuln.get('vulnerability_category', '')
                    needs_storage_context = vulnerability_category_cur in ('storage', 'data_exfiltration')
                    if pinned_extension_id:
                        # Content-script-only extension with a pinned manifest key → ID is known.
                        actual_extension_id = pinned_extension_id
                    elif (not needs_id and not needs_storage_context) or not has_background_context(extension_dir):
                        actual_extension_id = extension_id
                        if needs_id or needs_storage_context:
                            log_info("No background context – skipping ID discovery, using original ID")
                    else:
                        temp_page = await context.new_page()
                        try:
                            async with timer.step("id_discovery_navigation", "PAGE_NAVIGATION_TIMEOUT"):
                                await temp_page.goto(config.VERIFICATION_PAGE_URL, timeout=int(config.PAGE_NAVIGATION_TIMEOUT * 1000), wait_until="domcontentloaded")
                        except Exception:
                            pass
                        await asyncio.sleep(0.5)

                        async with timer.step("extension_id_discovery", "EXTENSION_ID_DISCOVERY_TIMEOUT"):
                            actual_extension_id = await discover_runtime_extension_id_from_context(
                                context, timeout_s=config.EXTENSION_ID_DISCOVERY_TIMEOUT, debug=debug_mode
                            )
                        await temp_page.close()

                        if not actual_extension_id:
                            log_info("Warning: Could not discover actual extension ID, using original ID")
                            actual_extension_id = extension_id
                        else:
                            log_info(f"Discovered actual extension ID: {actual_extension_id}")

                    vuln_record = {
                        **vuln,
                        "manifest_modifications": modifications,
                        "detection": None,
                        "verification_status": None,
                        "error": None,
                        "nav_url": nav_url,
                        "spoofing_applied": bool(spoof_args),
                        "target_extension_id": actual_extension_id,
                    }

                    if debug_mode:
                        log_step(5 + idx - 1, f"Executing payload for {rule_id}")

                    if payload:
                        # Replace extension ID in payload if needed
                        modified_payload = payload
                        if payload_mentions_extension_id(payload, extension_id) and actual_extension_id and actual_extension_id != extension_id:
                            modified_payload = replace_extension_id_in_payload(payload, extension_id, actual_extension_id)

                        try:
                            page = await context.new_page()

                            if debug_mode:
                                log_info(f"Navigating to {config.VERIFICATION_PAGE_URL}...")

                            try:
                                # Default nav is the configured verification page; with domain spoofing
                                # on, nav_url is the real restricted origin over HTTPS.
                                async with timer.step("page_navigation", "PAGE_NAVIGATION_TIMEOUT"):
                                    await page.goto(nav_url, timeout=int(config.PAGE_NAVIGATION_TIMEOUT * 1000), wait_until="domcontentloaded")
                                # Ensure this page/tab is active (bring to front)
                                await page.bring_to_front()
                                log_success("Page loaded successfully")
                            except Exception as nav_error:
                                log_step_failed("load page", str(nav_error))
                                # Try to get more info about what happened
                                try:
                                    content = await page.content()
                                    if "ERR_" in content or len(content) < 100:
                                        log_error("Page content appears to be an error")
                                except:
                                    pass
                                vuln_record["verification_status"] = "page_load_failed"
                                vuln_record["error"] = str(nav_error)
                                await page.close()
                                await context.close()
                                if user_data_dir and user_data_dir.exists():
                                    shutil.rmtree(user_data_dir, ignore_errors=True)
                                vulnerabilities_with_detection.append(vuln_record)
                                continue

                            if debug_mode:
                                log_info("Page loaded, opening console")
                                await page.keyboard.press('Control+Shift+J')
                                await asyncio.sleep(0.5)

                                if not ask_continue("Execute payload?"):
                                    vuln_record["verification_status"] = "skipped"
                                    await page.close()
                                    await context.close()
                                    if user_data_dir and user_data_dir.exists():
                                        shutil.rmtree(user_data_dir, ignore_errors=True)
                                    vulnerabilities_with_detection.append(vuln_record)
                                    continue

                            # Get mock server for detection and verification token
                            mock_server = get_mock_server()
                            verification_token = mock_server.reset_and_get_token()

                            # Seed test data ONCE (for data_exfiltration and storage delete operations)
                            vulnerability_category = vuln.get('vulnerability_category')
                            log_info(f"Checking if seeding needed for {vulnerability_category}...")
                            async with timer.step("seeding"):
                                seed_success = await seed_test_data(
                                    page,
                                    vulnerability_category,
                                    vuln.get('verification_details'),
                                    actual_extension_id,
                                    str(extension_dir)
                                )
                            if not seed_success:
                                log_step_failed("seed test data", "ABORTING to prevent false positives")
                                vuln_record["verification_status"] = "seeding_failed"
                                vuln_record["error"] = "Failed to seed test data"
                                await page.close()
                                await context.close()
                                if user_data_dir and user_data_dir.exists():
                                    shutil.rmtree(user_data_dir, ignore_errors=True)
                                vulnerabilities_with_detection.append(vuln_record)
                                continue  # Skip this vulnerability

                            diagnostics = {}
                            async with timer.step("payload_detection", "PAYLOAD_EXECUTION_TIMEOUT"):
                                detection = await execute_payload_and_detect(
                                    page,
                                    modified_payload,
                                    vulnerability_category=vulnerability_category,
                                    verification_details=vuln.get('verification_details'),
                                    mock_server=mock_server,
                                    verification_token=verification_token,
                                    extension_id=actual_extension_id,
                                    extension_path=str(extension_dir),
                                    skip_seeding=True,  # Already seeded above
                                    diagnostics=diagnostics
                                )

                            # Retry once if no detection (extension warm-up issue)
                            # Only retry for network/code_execution categories where timing is the likely cause
                            if not detection and vulnerability_category in RETRY_CATEGORIES:
                                try:
                                    if page.is_closed():
                                        raise RuntimeError("Page was closed before retry")
                                    # Navigate back to the attacker origin (page may be on a different domain after storage check)
                                    async with timer.step("retry_navigation", "RETRY_NAVIGATION_TIMEOUT"):
                                        await page.goto(nav_url, wait_until="domcontentloaded", timeout=int(config.RETRY_NAVIGATION_TIMEOUT * 1000))
                                    await asyncio.sleep(1.0)
                                    verification_token = mock_server.reset_and_get_token()
                                    diagnostics = {}
                                    async with timer.step("retry_payload_detection", "PAYLOAD_EXECUTION_TIMEOUT"):
                                        detection = await execute_payload_and_detect(
                                            page,
                                            modified_payload,
                                            vulnerability_category=vulnerability_category,
                                            verification_details=vuln.get('verification_details'),
                                            mock_server=mock_server,
                                            verification_token=verification_token,
                                            extension_id=actual_extension_id,
                                            extension_path=str(extension_dir),
                                            skip_seeding=True,  # Don't seed again on retry!
                                            diagnostics=diagnostics
                                        )
                                except Exception as retry_err:
                                    log_error(f"Retry failed: {retry_err}")
                                    detection = None

                            vuln_record["detection"] = detection
                            vuln_record["diagnostics"] = diagnostics

                            if detection:
                                vuln_record["verification_status"] = "verified"
                                log_success(f"Detection: {detection}")
                            else:
                                vuln_record["verification_status"] = "no_detection"
                                vuln_record["failure_reason"] = derive_failure_reason(
                                    vulnerability_category, detection, diagnostics)
                                log_info(f"Payload executed, no detection ({vuln_record['failure_reason']})")

                            # Debuggability: dump screenshot/DOM/payload/debug.json (page still open).
                            await capture_failure_artifacts(
                                page, extension_id=extension_id, rule_id=rule_id,
                                vulnerability_category=vulnerability_category, nav_url=nav_url,
                                executed_payload=modified_payload, target_extension_id=actual_extension_id,
                                spoofing_applied=bool(spoof_args), diagnostics=diagnostics,
                                failure_reason=vuln_record.get("failure_reason"),
                                verification_status=vuln_record.get("verification_status"),
                                on_success=bool(detection),
                            )

                            if debug_mode:
                                log_info("Payload executed - inspect the page/console now")
                                if not ask_continue("Close browser and continue?"):
                                    vuln_record["verification_status"] = "skipped"
                                    await page.close()
                                    await context.close()
                                    # Cleanup user data directory
                                    if user_data_dir and user_data_dir.exists():
                                        shutil.rmtree(user_data_dir, ignore_errors=True)
                                    vulnerabilities_with_detection.append(vuln_record)
                                    continue

                            try:
                                async with timer.step("page_close", "PAGE_CLOSE_TIMEOUT"):
                                    await asyncio.wait_for(page.close(), timeout=config.PAGE_CLOSE_TIMEOUT)
                            except (asyncio.TimeoutError, Exception):
                                pass
                        except Exception as e:
                            vuln_record["verification_status"] = "execution_error"
                            vuln_record["error"] = str(e)
                            log_error(f"Payload execution: {e}")
                    else:
                        vuln_record["verification_status"] = "missing_payload"
                        log_info("No payload provided")

                    vulnerabilities_with_detection.append(vuln_record)

                    # Close browser after THIS vulnerability (fresh browser for next one)
                    if debug_mode:
                        log_info("Closing browser to ensure clean state for next vulnerability")
                        if not ask_continue("Close browser?"):
                            input("Press Enter to close browser...")

                    try:
                        async with timer.step("browser_close", "BROWSER_CLOSE_TIMEOUT"):
                            await asyncio.wait_for(context.close(), timeout=config.BROWSER_CLOSE_TIMEOUT)
                    except asyncio.TimeoutError:
                        log_info(f"Browser close timed out ({config.BROWSER_CLOSE_TIMEOUT}s) — continuing")
                    except Exception:
                        pass

                    # Cleanup user data directory to free disk space
                    if user_data_dir and user_data_dir.exists():
                        try:
                            shutil.rmtree(user_data_dir, ignore_errors=True)
                            log_info(f"Cleaned up user data directory")
                        except Exception as cleanup_error:
                            log_error(f"Cleanup warning: {cleanup_error}")

            # Set final verification status
            verification_result["vulnerabilities_verified"] = vulnerabilities_with_detection

            # Determine overall status based on vulnerability results
            detections = [v.get('detection') for v in vulnerabilities_with_detection if v.get('detection')]

            # Count different vulnerability statuses
            vuln_statuses = [v.get('verification_status') for v in vulnerabilities_with_detection]
            has_errors = any(s in ['execution_error', 'page_load_failed', 'browser_launch_failed',
                                   'manifest_mod_failed', 'verifier_prep_failed',
                                   'extension_id_discovery_failed', 'extension_id_determination_failed',
                                   'seeding_failed', 'error'] for s in vuln_statuses)
            has_skipped = any(s == 'skipped' for s in vuln_statuses)

            if detections:
                verification_result["status"] = "verified"
            elif has_errors:
                verification_result["status"] = "error"
            elif has_skipped:
                verification_result["status"] = "skipped"
            else:
                # No detections and no errors = failed verification
                verification_result["status"] = "failed"

            log_success(f"Extension verification complete: {verification_result['status']}")

    except Exception as e:
        log_error(f"Verification error: {e}")
        verification_result["status"] = "error"
        verification_result["errors"].append(str(e))
    finally:
        # Finalize timings; attach each vuln's verification_status (same order)
        timer.end_extension(verification_result.get("vulnerabilities_verified"))

    return verification_result
