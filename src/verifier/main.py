import asyncio
import json
from datetime import datetime
import config
from mock_server import get_mock_server
from domain_spoofing import get_spoof_server
from .logging_utils import log_error, log_info, log_mock_server_ready, log_step, log_success
from .constants import Color
from .results import (
    get_analysis_results_dir, load_json_results,
    filter_tp_verifiable_results, apply_verifier_filters,
    get_or_create_verification_output_dir,
    write_env_snapshot,
)
from .orchestrator import verify_extension
from .timing import timer
from .console_logging import ConsoleTee
from .debugging import set_artifact_root


def _preflight() -> bool:
    """Fail fast & loud on misconfiguration before any real work (prevents whole-run waste).

    Checks the things that otherwise produce a silent all-failed run: the Chrome binary must exist,
    and if domain spoofing is enabled the TLS cert dependency must be importable.
    """
    from pathlib import Path as _Path
    ok = True

    chrome = _Path(config.CHROME_BINARY_PATH)
    if chrome.exists():
        log_success(f"Preflight: Chrome binary OK ({chrome})")
    else:
        log_error(f"Preflight: Chrome binary NOT found at {chrome}")
        log_error("  -> Set CHROME_BINARY_PATH (env/.env) to the Chrome-for-Testing binary on this host.")
        ok = False

    if getattr(config, "ENABLE_DOMAIN_SPOOFING", False):
        try:
            from cryptography import x509  # noqa: F401
            log_success("Preflight: domain spoofing enabled; cryptography available")
        except Exception as e:
            log_error(f"Preflight: ENABLE_DOMAIN_SPOOFING is on but 'cryptography' is missing: {e}")
            log_error("  -> pip install cryptography, or disable ENABLE_DOMAIN_SPOOFING.")
            ok = False

    return ok


async def main():
    """Main verification workflow."""
    # Tee all console output to <run dir>/console.txt (set once the run dir
    # exists below). Buffers until then so nothing is lost.
    console_tee = ConsoleTee()
    console_tee.start_capture()
    try:
        await _run(console_tee)
    finally:
        console_tee.stop()


async def _run(console_tee):
    print("\n" + "=" * 70)
    print("EXTENSION VERIFICATION")
    print("=" * 70)

    # Startup preflight — bail out loudly on misconfiguration rather than producing an all-failed run.
    if not _preflight():
        log_error("Preflight failed — aborting before launching any browser. Fix the above and re-run.")
        return

    # Start mock server
    mock_server = get_mock_server()
    if not mock_server.start():
        log_error("Failed to start mock server")
        return

    mock_server_url = mock_server.get_url()
    log_mock_server_ready(mock_server_url)

    # Start the domain-spoofing HTTPS origin server if enabled (Phase 2).
    if getattr(config, "ENABLE_DOMAIN_SPOOFING", False):
        spoof_server = get_spoof_server(https_port=getattr(config, "DOMAIN_SPOOF_HTTPS_PORT", 3443))
        if not spoof_server.start():
            log_error("Failed to start domain-spoof server — continuing without spoofing")

    # Log which verification page host is in use (real example.com vs. local server)
    page_mode = "local dummy server" if config.USE_LOCAL_VERIFICATION_SERVER else "example.com"
    log_info(f"Verification page: {config.VERIFICATION_PAGE_URL} ({page_mode})")

    # Get analysis results directory (based on config.RESULTS_TO_VERIFY)
    results_dir = get_analysis_results_dir()
    if not results_dir:
        log_error("Cannot find results directory")
        return

    log_info(f"Using results: {results_dir.name}")

    # Load and filter results (recursively searches all subdirectories)
    all_results = load_json_results(results_dir)
    if not all_results:
        log_error("No results found")
        return

    tp_verifiable = filter_tp_verifiable_results(all_results)
    if not tp_verifiable:
        log_error("No TP+verifiable vulnerabilities found")
        return

    # Apply VERIFIER_FILTER settings (category, storage_api, min/max vulnerability count)
    tp_verifiable = apply_verifier_filters(tp_verifiable)
    if not tp_verifiable:
        log_error("No extensions remain after applying VERIFIER_FILTER")
        return

    # Filter for single extension if specified (only if DEBUG_SINGLE_RESULT_FILE not used)
    single_extension_mode = config.DEBUG_SINGLE_EXTENSION is not None and config.DEBUG_SINGLE_EXTENSION != ""
    single_file_mode = config.DEBUG_SINGLE_RESULT_FILE is not None and config.DEBUG_SINGLE_RESULT_FILE != ""

    if single_extension_mode and not single_file_mode:
        tp_verifiable = [
            (ext_id, vulns, path, subdir) for ext_id, vulns, path, subdir in tp_verifiable
            if ext_id == config.DEBUG_SINGLE_EXTENSION
        ]
        if not tp_verifiable:
            log_error(f"Extension not found: {config.DEBUG_SINGLE_EXTENSION}")
            return

    # Create (or resume) verification output directory (mirrors structure from results_analysis)
    verification_output_dir = get_or_create_verification_output_dir(results_dir.name)
    log_info(f"Output directory: {verification_output_dir.relative_to(config.RESULTS_VERIFICATION_DIR)}")

    # Mirror all console output to <run dir>/console.txt from here on (and flush
    # the output buffered before the run dir existed).
    console_tee.set_file(verification_output_dir / "console.txt")

    # Point failure-artifact capture (screenshots/DOM/payload/debug.json) at this run directory.
    set_artifact_root(verification_output_dir / "_debug_artifacts")

    # Record the configuration used for this run (copied env file, or a
    # reconstructed snapshot when the original env file path is unknown).
    write_env_snapshot(verification_output_dir)

    # Start collecting per-step / per-vuln / per-extension timings (-> time.json)
    timer.start_run()

    # Use debug mode from config
    debug_mode = config.DEBUG_MODE

    if debug_mode:
        print(f"\n{Color.BOLD}DEBUG MODE ENABLED{Color.END}")
        if single_file_mode:
            print(f"  Single file mode: {config.DEBUG_SINGLE_RESULT_FILE}")
        elif single_extension_mode:
            print(f"  Single extension mode: {config.DEBUG_SINGLE_EXTENSION}")
        log_step(0, "Mock server initialization")
        log_success("Mock server running")
        log_info(f"Endpoints: {mock_server_url}/api/data, {mock_server_url}/api/file")
        log_info("Step-by-step verification with manual confirmation at each step")
        print()
    else:
        log_info(f"Extensions to verify: {len(tp_verifiable)}")
        log_info(f"Mock server: {mock_server_url}")
        print()

    # Verify each extension
    all_verifications = []
    resume_mode = bool(getattr(config, 'RESUME_VERIFICATION_RUN', None))
    for idx, (extension_id, vulnerabilities, _, relative_subdir) in enumerate(tp_verifiable, 1):
        # Pre-compute output paths so we can check for existing results.
        # The verifier writes its own per-extension result JSON under <run>/results/,
        # preserving the analyzer subdirectory structure; also used for resume.
        output_subdir = verification_output_dir / "results" / relative_subdir
        verification_file = output_subdir / f"{extension_id}_result.json"

        # Skip already-verified extensions when resuming
        if resume_mode and verification_file.exists():
            with open(verification_file, 'r', encoding='utf-8') as f:
                existing = json.load(f)
            all_verifications.append(existing)
            if not debug_mode:
                print(f"[{idx}/{len(tp_verifiable)}] {extension_id}... skipped (already verified)")
            continue

        if debug_mode:
            print(f"\n{Color.BOLD}Verifying: {extension_id}{Color.END}")
        else:
            print(f"[{idx}/{len(tp_verifiable)}] {extension_id}...", end=" ", flush=True)

        # Hard per-extension timeout — safety net against the silent-hang bug (see Phase 1).
        # Disabled in debug mode, which is legitimately long-running due to interactive prompts.
        per_ext_timeout = getattr(config, 'PER_EXTENSION_TIMEOUT', None)
        try:
            if per_ext_timeout and not debug_mode:
                verification = await asyncio.wait_for(
                    verify_extension(extension_id, vulnerabilities, debug_mode=debug_mode),
                    timeout=per_ext_timeout
                )
            else:
                verification = await verify_extension(extension_id, vulnerabilities, debug_mode=debug_mode)
        except asyncio.TimeoutError:
            log_error(f"Extension {extension_id} timed out after {per_ext_timeout}s — recording as error")
            verification = {
                "extension_id": extension_id,
                "timestamp": datetime.now().isoformat(),
                "status": "error",
                "vulnerabilities_verified": [],
                "errors": [f"Per-extension timeout ({per_ext_timeout}s) exceeded"],
                "failure_reason": "timed_out",
            }
        all_verifications.append(verification)

        # Save individual verification result (preserve subdirectory structure)
        output_subdir.mkdir(parents=True, exist_ok=True)
        with open(verification_file, 'w', encoding='utf-8') as f:
            json.dump(verification, f, indent=2, default=str)

        if not debug_mode:
            status = verification.get('status', 'unknown')
            detections = len([v for v in verification.get('vulnerabilities_verified', []) if v.get('detection')])
            print(f"{status} ({detections} detected)" if detections else f"{status}")

    # Save summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "source_results_dir": results_dir.name,
        "total_extensions": len(tp_verifiable),
        "debug_mode": debug_mode,
        "use_local_verification_server": config.USE_LOCAL_VERIFICATION_SERVER,
        "verification_page_url": config.VERIFICATION_PAGE_URL,
        "verifications": all_verifications,
        "summary_stats": {
            "verified": sum(1 for v in all_verifications if v.get('status') == 'verified'),
            "failed": sum(1 for v in all_verifications if v.get('status') == 'failed'),
            "error": sum(1 for v in all_verifications if v.get('status') == 'error'),
            "skipped": sum(1 for v in all_verifications if v.get('status') == 'skipped'),
        }
    }

    # Aggregate failure reasons across all vulnerabilities (Phase 1 diagnostics) for quick triage.
    failure_hist = {}
    for v in all_verifications:
        for vv in v.get('vulnerabilities_verified', []):
            reason = vv.get('failure_reason')
            if reason:
                failure_hist[reason] = failure_hist.get(reason, 0) + 1
    summary["failure_reasons"] = dict(sorted(failure_hist.items(), key=lambda x: -x[1]))

    summary_file = verification_output_dir / "verification_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, default=str)

    # Save timing breakdown (per-step / per-vuln / per-extension durations)
    timer.end_run()
    time_file = verification_output_dir / "time.json"
    with open(time_file, 'w', encoding='utf-8') as f:
        json.dump(timer.as_dict(), f, indent=2, default=str)

    # Stop mock server
    mock_server.stop()

    # Summary
    print("\n" + "=" * 70)
    stats = summary['summary_stats']
    print(f"Results:")
    print(f"  Verified: {stats['verified']}")
    print(f"  Failed:   {stats['failed']}")
    print(f"  Error:    {stats['error']}")
    print(f"  Skipped:  {stats['skipped']}")
    print(f"Saved: {verification_output_dir}")
    print("=" * 70 + "\n")
