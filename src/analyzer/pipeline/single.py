"""Single-prompt pipeline: one structured call per extension.

Kept "on the side" per the requirement -- this reproduces the original
one-big-prompt behaviour, but now uses structured output (no JSON boilerplate in
the prompt) and the composable, category-filterable sections.
"""

import time

import config

from .. import domains, prompt_builder
from ..extension_io import CONTEXTUAL_MODES, extract_code_context
from ..llm_client import LLMError
from ..logging_utils import log, log_message
from ..results_store import get_current_model_name, save_prompt
from ..schemas import final_result_schema
from ..tools import get_adapter
from . import common
from .multi import _pack_budget


def analyze_extension_single(unit, client, dataset_config, current, total) -> None:
    dataset_name = dataset_config["name"]
    tool_type = dataset_config["tool"]
    code_context_lines = dataset_config.get("code_context_lines", 10)
    code_context_mode = dataset_config.get("code_context_mode") \
        or getattr(config, "CODE_CONTEXT_MODE", "lines")
    adapter = get_adapter(tool_type)

    extension_id = adapter.extension_id_for(unit)
    common.begin(extension_id)

    if common.already_processed(dataset_name, extension_id):
        log(f"[{current}/{total}] {extension_id}: already processed, skipping")
        return

    common.stagger_start()
    log(f"Extension [{current}/{total}]: {extension_id}", "HEADER")

    prepared = adapter.prepare(unit, dataset_name, code_context_lines, logger=log,
                               code_context_mode=code_context_mode)
    if prepared is None:
        log("Report not found or empty", "ERROR")
        log_message(dataset_name, "ERROR", f"{extension_id} - Report missing/empty")
        return

    categories = prompt_builder.get_enabled_categories()
    loopback = getattr(config, "CONFIDENCE_LOOPBACK_ENABLED", False)
    schema = final_result_schema(categories, include_confidence=loopback)
    system_prompt = prompt_builder.build_single_system(categories)

    def build(mode, hints=None):
        def message(ctx):
            return prompt_builder.build_user_message(
                extension_id, tool_type, prepared.processed_report,
                prepared.manifest_content, ctx or None,
            )

        # Attempt 0 reuses the context already rendered by prepare(); wider retries
        # (loopback) re-render at the requested scope. A scope that depends on the
        # model's own request ("symbols") is never served from that cache.
        if (mode == code_context_mode and prepared.code_context is not None
                and mode not in CONTEXTUAL_MODES):
            ctx = prepared.code_context
        else:
            budget = (_pack_budget(system_prompt, message) if mode == "packed"
                      else config.context_pack_budget())
            ctx = extract_code_context(prepared.code_dir, prepared.line_refs,
                                       code_context_lines, mode=mode,
                                       all_line_refs=prepared.line_refs,
                                       requested_symbols=(hints or {}).get("requested_symbols"),
                                       query=prepared.processed_report,
                                       pack_budget=budget)
        return system_prompt, message(ctx)

    start_time = time.time()
    if config.DRY_RUN_MODE:
        sys_p, user_p = build(code_context_mode)
        save_prompt(dataset_name, extension_id, "single", sys_p, user_p)
        if not common.check_token_limit(sys_p + "\n" + user_p, dataset_name, extension_id):
            return
        log("DRY RUN - skipping LLM call")
        result = {"note": "DRY_RUN_MODE - LLM call skipped", "extension_id": extension_id}
    else:
        log(f"Querying {get_current_model_name()}...")
        try:
            result, _ = common.query_with_loopback(
                build, schema, client, base_mode=code_context_mode,
                dataset_name=dataset_name, extension_id=extension_id, label="single",
            )
            result.setdefault("extension_id", extension_id)
            for vuln in result.get("vulnerabilities") or []:
                for field, change in domains.apply_to_vulnerability(
                        vuln, prepared.manifest_content).items():
                    log(f"[{vuln.get('rule_id')}] {field} corrected from manifest: {change}")
        except common.PromptTooLarge:
            return  # skip (no result file) so it can be retried later, as before
        except (LLMError, Exception) as e:
            log(f"Query failed: {e}", "ERROR")
            result = {"error": str(e), "extension_id": extension_id}

    common.write_result(dataset_name, extension_id, result)
    elapsed = time.time() - start_time
    log_message(dataset_name, "TIMING", f"{extension_id} - Total: {elapsed:.2f}s")
    log(f"Total: {elapsed:.2f}s")
