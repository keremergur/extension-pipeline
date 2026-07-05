import json
from datetime import datetime
import config
from mock_server import get_mock_server
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

    # Start mock server
    mock_server = get_mock_server()
    if not mock_server.start():
        log_error("Failed to start mock server")
        return

    mock_server_url = mock_server.get_url()
    log_mock_server_ready(mock_server_url)

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

        verification = await verify_extension(extension_id, vulnerabilities, debug_mode=debug_mode)
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
