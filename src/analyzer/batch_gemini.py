"""Gemini Batch API support (single-prompt mode only).

Ported from the original script. Batch mode issues one request per extension, so
it maps onto the single pipeline's whole-extension prompt; the multi-step
pipeline is not batched. Structured output is requested via response_schema so
batch results are constrained JSON just like the interactive path.
"""

import json
import time
from datetime import datetime
from pathlib import Path

import config
from google import genai
from google.genai import types as genai_types

from . import prompt_builder, state
from .logging_utils import log
from .results_store import save_prompt
from .schemas import final_result_schema
from .tools import get_adapter


# ---- batch info persistence --------------------------------------------

def save_batch_info(dataset_name, batch_name, num_requests, total_files=0, total_line_ranges=0):
    batch_info = {
        "batch_name": batch_name, "dataset_name": dataset_name,
        "num_requests": num_requests, "total_files": total_files,
        "total_line_ranges": total_line_ranges,
        "submitted_at": datetime.now().isoformat(), "status": "submitted",
    }
    info_file = state.CURRENT_RESULTS_DIR / dataset_name / "batch_info.json"
    info_file.parent.mkdir(parents=True, exist_ok=True)
    with open(info_file, 'w', encoding='utf-8') as f:
        json.dump(batch_info, f, indent=2)
    log(f"Batch info saved to: {info_file}")
    log(f"To retrieve later: GEMINI_BATCH_MODE='retrieve', GEMINI_BATCH_NAME='{batch_name}'")


def load_batch_info(dataset_name):
    info_file = state.CURRENT_RESULTS_DIR / dataset_name / "batch_info.json"
    if not info_file.exists():
        return None
    with open(info_file, 'r', encoding='utf-8') as f:
        return json.load(f)


# ---- request preparation -----------------------------------------------

def prepare_batch_prompt(unit, dataset_config, current, total):
    """Build one batch request's prompt data (no LLM call)."""
    dataset_name = dataset_config["name"]
    tool_type = dataset_config["tool"]
    code_context_lines = dataset_config.get("code_context_lines", 10)
    adapter = get_adapter(tool_type)

    extension_id = adapter.extension_id_for(unit)
    log(f"Preparing [{current}/{total}]: {extension_id}", "HEADER")

    prepared = adapter.prepare(unit, dataset_name, code_context_lines, logger=log)
    if prepared is None:
        log("Report not found/empty - skipping", "ERROR")
        return None

    categories = prompt_builder.get_enabled_categories()
    system_prompt = prompt_builder.build_single_system(categories)
    user_message = prompt_builder.build_user_message(
        extension_id, tool_type, prepared.processed_report,
        prepared.manifest_content, prepared.code_context or None,
    )
    save_prompt(dataset_name, extension_id, "single_batch", system_prompt, user_message)

    return {
        "extension_id": extension_id,
        "system_prompt": system_prompt,
        "user_message": user_message,
        "num_files": len(prepared.line_refs),
        "num_line_ranges": sum(len(r) for r in prepared.line_refs.values()),
    }


def write_batch_request_line(file_handle, prompt_data, categories):
    full_prompt = prompt_data["user_message"]
    if prompt_data.get("system_prompt"):
        full_prompt = f"{prompt_data['system_prompt']}\n\n{prompt_data['user_message']}"

    batch_request = {
        "key": prompt_data["extension_id"],
        "request": {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generation_config": {
                "temperature": 1.0,
                "response_mime_type": "application/json",
                "response_schema": final_result_schema(categories),
            },
        },
    }
    file_handle.write(json.dumps(batch_request) + '\n')


# ---- batch lifecycle ----------------------------------------------------

def submit_gemini_batch(requests_file: Path) -> str:
    client = genai.Client(api_key=config.GEMINI_API_KEY)
    print(f"Uploading batch file: {requests_file}")
    uploaded_file = client.files.upload(
        file=str(requests_file),
        config=genai_types.UploadFileConfig(
            display_name=f'batch-requests-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
            mime_type='jsonl',
        ),
    )
    print(f"File uploaded: {uploaded_file.name}")
    batch_job = client.batches.create(
        model=config.GEMINI_MODEL, src=uploaded_file.name,
        config={'display_name': f'batch-{datetime.now().strftime("%Y%m%d-%H%M%S")}'},
    )
    print(f"Batch job created: {batch_job.name} (state: {batch_job.state})")
    return batch_job.name


def cancel_gemini_batch(batch_name: str) -> bool:
    try:
        genai.Client(api_key=config.GEMINI_API_KEY).batches.cancel(name=batch_name)
        print(f"✓ Batch job cancelled: {batch_name} (partial results are lost)")
        return True
    except Exception as e:
        print(f"✗ Failed to cancel batch: {e}")
        return False


def delete_gemini_batch(batch_name: str) -> bool:
    try:
        genai.Client(api_key=config.GEMINI_API_KEY).batches.delete(name=batch_name)
        print(f"✓ Batch job deleted: {batch_name}")
        return True
    except Exception as e:
        print(f"✗ Failed to delete batch: {e}")
        return False


def list_gemini_batches(limit: int = 10) -> list:
    try:
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        batches = client.batches.list(config={'page_size': limit})
        print(f"\n{'='*80}\nRECENT BATCH JOBS (limit: {limit})\n{'='*80}\n")
        batch_list = []
        for batch in batches:
            batch_list.append(batch)
            state_name = batch.state.name if hasattr(batch.state, 'name') else str(batch.state)
            print(f"Name: {batch.name}")
            print(f"  Model: {getattr(batch, 'model', 'N/A')}")
            print(f"  State: {state_name}")
            print(f"  Created: {getattr(batch, 'create_time', 'N/A')}")
            print(f"  Display Name: {getattr(batch, 'display_name', 'N/A')}\n")
        if not batch_list:
            print("No batch jobs found.")
        print(f"{'='*80}\n")
        return batch_list
    except Exception as e:
        print(f"✗ Failed to list batches: {e}")
        return []


def wait_for_batch_completion(batch_name: str) -> bool:
    print(f"Waiting for batch completion: {batch_name}")
    start_time = time.time()
    client = genai.Client(api_key=config.GEMINI_API_KEY)
    while True:
        batch_job = client.batches.get(name=batch_name)
        state_name = batch_job.state.name if hasattr(batch_job.state, 'name') else str(batch_job.state)
        print(f"  Status: {state_name} (elapsed: {int(time.time() - start_time)}s)")
        if state_name == 'JOB_STATE_SUCCEEDED':
            print("Batch completed successfully!")
            return True
        if state_name in ('JOB_STATE_FAILED', 'JOB_STATE_CANCELLED'):
            print(f"Batch failed with state: {state_name}")
            return False
        time.sleep(config.GEMINI_BATCH_CHECK_INTERVAL)


def download_batch_results(batch_name: str, output_file: Path) -> None:
    print(f"Downloading results to: {output_file}")
    client = genai.Client(api_key=config.GEMINI_API_KEY)
    batch_job = client.batches.get(name=batch_name)
    if not batch_job.dest or not batch_job.dest.file_name:
        raise ValueError("No output file found in batch results")
    file_content = client.files.download(file=batch_job.dest.file_name)
    with open(output_file, 'wb') as f:
        f.write(file_content)
    print("Results downloaded successfully")


def parse_batch_results(results_file: Path) -> dict:
    results = {}
    with open(results_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            result = json.loads(line)
            key = result.get('key')
            if not key:
                continue
            candidates = result.get('response', {}).get('candidates', [])
            if candidates:
                parts = candidates[0].get('content', {}).get('parts', [])
                if parts:
                    results[key] = parts[0].get('text', '')
            else:
                results[key] = json.dumps({"error": f"Batch error: {result.get('error', {})}"})
    return results


# ---- orchestration ------------------------------------------------------

def process_dataset_batch(units, dataset_config) -> int:
    """Drive the Gemini Batch API for one dataset (single-prompt requests)."""
    dataset_name = dataset_config["name"]
    batch_mode = config.GEMINI_BATCH_MODE

    if batch_mode == 'list':
        log("BATCH MODE: LIST", "HEADER")
        list_gemini_batches(limit=config.GEMINI_BATCH_LIST_LIMIT)
        return 0

    if batch_mode in ('cancel', 'delete'):
        log(f"BATCH MODE: {batch_mode.upper()}", "HEADER")
        batch_name = _resolve_batch_name(dataset_name)
        if not batch_name:
            return 0
        ok = cancel_gemini_batch(batch_name) if batch_mode == 'cancel' else delete_gemini_batch(batch_name)
        log(f"Batch {batch_mode} {'succeeded' if ok else 'failed'}", "HEADER")
        return 0

    if batch_mode == 'retrieve':
        return _retrieve(dataset_name)

    # ---- submit / auto -------------------------------------------------
    log(f"BATCH MODE: {batch_mode.upper()} - Preparing {len(units)} prompts", "HEADER")
    categories = prompt_builder.get_enabled_categories()
    batch_requests_file = state.CURRENT_RESULTS_DIR / dataset_name / "batch_requests.jsonl"
    batch_requests_file.parent.mkdir(parents=True, exist_ok=True)

    num_requests = total_files = total_line_ranges = 0
    with open(batch_requests_file, 'w', encoding='utf-8') as f:
        for idx, unit in enumerate(units, 1):
            data = prepare_batch_prompt(unit, dataset_config, idx, len(units))
            if data:
                write_batch_request_line(f, data, categories)
                num_requests += 1
                total_files += data.get('num_files', 0)
                total_line_ranges += data.get('num_line_ranges', 0)

    if num_requests == 0:
        log("No valid prompts to process", "ERROR")
        return 0

    log(f"Prepared {num_requests} prompts ({total_files} files, {total_line_ranges} line ranges)")

    if config.DRY_RUN_MODE:
        log("DRY RUN MODE - Batch NOT submitted", "HEADER")
        return 0

    try:
        batch_name = submit_gemini_batch(batch_requests_file)
        log(f"Batch submitted: {batch_name}")
        save_batch_info(dataset_name, batch_name, num_requests, total_files, total_line_ranges)
    except Exception as e:
        log(f"Failed to submit batch: {e}", "ERROR")
        return 0

    if batch_mode == 'submit':
        log(f"BATCH SUBMITTED - set GEMINI_BATCH_MODE='retrieve' and "
            f"GEMINI_BATCH_NAME='{batch_name}' to fetch results later", "HEADER")
        return 0

    # auto mode
    log("Waiting for batch to complete (this may take hours)...")
    if not wait_for_batch_completion(batch_name):
        log("Batch processing failed", "ERROR")
        return 0
    return _download_and_save(dataset_name, batch_name)


def _resolve_batch_name(dataset_name):
    batch_name = config.GEMINI_BATCH_NAME
    if not batch_name:
        info = load_batch_info(dataset_name)
        if info:
            batch_name = info['batch_name']
            log(f"Loaded batch name from saved info: {batch_name}")
        else:
            log("ERROR: No batch name provided and no saved batch info found", "ERROR")
    return batch_name


def _retrieve(dataset_name):
    log("BATCH MODE: RETRIEVE", "HEADER")
    batch_name = _resolve_batch_name(dataset_name)
    if not batch_name:
        return 0
    client = genai.Client(api_key=config.GEMINI_API_KEY)
    try:
        batch_job = client.batches.get(name=batch_name)
        state_name = batch_job.state.name if hasattr(batch_job.state, 'name') else str(batch_job.state)
        log(f"Batch status: {state_name}")
        if state_name != 'JOB_STATE_SUCCEEDED':
            log(f"Batch not ready (status: {state_name})", "ERROR")
            return 0
    except Exception as e:
        log(f"Failed to get batch status: {e}", "ERROR")
        return 0
    return _download_and_save(dataset_name, batch_name)


def _download_and_save(dataset_name, batch_name):
    results_file = state.CURRENT_RESULTS_DIR / dataset_name / "batch_results.jsonl"
    try:
        download_batch_results(batch_name, results_file)
    except Exception as e:
        log(f"Failed to download results: {e}", "ERROR")
        return 0

    log("Parsing batch results...")
    results_map = parse_batch_results(results_file)
    saved = 0
    for ext_id, result_text in results_map.items():
        out = state.CURRENT_RESULTS_DIR / dataset_name / f"{ext_id}_result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result_text, encoding='utf-8')
        saved += 1
    log(f"Batch complete: {saved} results saved", "HEADER")
    return saved
