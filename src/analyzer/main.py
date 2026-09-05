"""Analyzer entry point / orchestration.

Drives the configured datasets through the selected pipeline (single or multi),
or through the Gemini Batch API when LLM_PROVIDER == 'gemini_batch'.
"""

import traceback
from datetime import datetime

import config

from . import state
from .datasets import get_extensions_for_dataset
from .llm_client import setup_llm_client
from .logging_utils import log
from .pipeline import canonical_pipeline_mode, scheduler
from .prompt_builder import get_enabled_categories
from .results_store import get_current_model_name, get_or_create_results_directory


def _display_path(path, base):
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def main():
    # Normalised (and validated) once here, so the whole run -- header, scheduler and
    # dispatch -- uses the canonical name and a typo'd mode fails loudly instead of
    # silently running a different pipeline.
    raw_pipeline_mode = getattr(config, 'PIPELINE_MODE', 'single')
    pipeline_mode = canonical_pipeline_mode(raw_pipeline_mode)
    categories = get_enabled_categories()

    print("=" * 80)
    print("CHROME EXTENSION VULNERABILITY ANALYZER")
    print("=" * 80)
    print(f"Provider: {config.LLM_PROVIDER.upper()}")
    print(f"Model:    {get_current_model_name()}")
    print(f"Pipeline: {pipeline_mode}"
          + (f" (configured as '{raw_pipeline_mode}')"
             if str(raw_pipeline_mode).strip().lower() != pipeline_mode else ""))
    print(f"Parallel: {scheduler.parallel_mode()} (workers={config.PARALLEL_WORKERS})")
    print(f"Categories: {', '.join(categories) if categories else 'all'}")
    print(f"Code context: {getattr(config, 'CODE_CONTEXT_MODE', 'lines')}")
    # Which scope toplevel/skeleton keep whole is the difference between the D124
    # elision defect and its fix, so a run whose start scope or ladder can reach one
    # of them records the base in its own header.
    from .extension_io import HIGH_TIER_MODES, canonical_mode, high_tier_base
    from .pipeline.common import escalation_order
    _start = canonical_mode(getattr(config, 'CODE_CONTEXT_MODE', 'lines'))
    if _start in HIGH_TIER_MODES or (
            getattr(config, 'CONFIDENCE_LOOPBACK_ENABLED', False)
            and any(m in HIGH_TIER_MODES for m in escalation_order())):
        print(f"  high-tier base: '{high_tier_base()}' kept whole beneath "
              f"toplevel/skeleton (HIGH_TIER_CONTEXT_BASE)")
    cache_layout = getattr(config, 'PROMPT_CACHE_OPTIMIZED', False)
    _shrink_steps = getattr(config, 'CONTEXT_SHRINK_TO_FIT', frozenset())
    _shrink_label = ("context_shrink_to_fit" if _shrink_steps
                     == getattr(config, 'CONTEXT_SHRINK_TO_FIT_STEPS', object())
                     else f"context_shrink_to_fit[{','.join(sorted(_shrink_steps))}]")
    _opts = [name for name, on in (
        ("externally_connectable", getattr(config, 'PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE', False)),
        ("result_examples", getattr(config, 'PROMPT_INCLUDE_RESULT_EXAMPLES', False)),
        ("storage_tp_hint", getattr(config, 'PROMPT_INCLUDE_STORAGE_TP_HINT', False)),
        ("category_from_rule_id", getattr(config, 'ANALYZER_CATEGORY_FROM_RULE_ID', False)),
        ("confidence_loopback", getattr(config, 'CONFIDENCE_LOOPBACK_ENABLED', False)),
        (_shrink_label, bool(_shrink_steps)),
        ("context_symbol_request", getattr(config, 'CONTEXT_SYMBOL_REQUEST', False)),
        ("logprob_confidence", getattr(config, 'CONFIDENCE_FROM_LOGPROBS', False)),
        ("source_confidence_vote", getattr(config, 'CONFIDENCE_INCLUDE_SOURCE', False)),
        ("prompt_cache_layout", cache_layout),
    ) if on]
    print(f"Optional features: {', '.join(_opts) if _opts else 'none'}")
    from .schemas import result_rules_variant, result_values
    _rr_raw = str(getattr(config, 'RESULT_RULES', 'none') or 'none').strip().lower()
    _rr = result_rules_variant()
    print(f"Result rules: variant {_rr} (verdicts: {'/'.join(result_values())})")
    if _rr != _rr_raw:
        # A typo would otherwise silently strip ALL verdict guidance from the prompt.
        from .prompt_sections import RESULT_RULES_VARIANTS
        print(f"  WARNING: RESULT_RULES={_rr_raw!r} is not a known variant "
              f"({', '.join(sorted(RESULT_RULES_VARIANTS))}, or 'none') -- "
              f"running with NO verdict rules.")
    from .prompt_builder import reasoning_prompt_variant
    _rp_raw = str(getattr(config, 'REASONING_PROMPT', 'none') or 'none').strip().lower()
    _rp = reasoning_prompt_variant()
    print(f"Reasoning prompt: variant {_rp}")
    if _rp != _rp_raw:
        from .prompt_sections import REASONING_PROMPT_VARIANTS
        print(f"  WARNING: REASONING_PROMPT={_rp_raw!r} is not a known variant "
              f"({', '.join(sorted(REASONING_PROMPT_VARIANTS))}, or 'none') -- "
              f"running with NO reasoning instructions.")
    elif _rp != "none":
        # Dead prompt weight without a parser: guided decoding from token 0 leaves
        # no room for a thinking block (EXPERIMENTS.md §20.2).
        print("  NOTE: has an effect only if the server runs a reasoning parser "
              "(--reasoning-parser); without one there is no thinking block to shape.")
    if getattr(config, 'CONFIDENCE_LOOPBACK_ENABLED', False):
        print(f"  loopback: threshold class={config.CONFIDENCE_THRESHOLD_CLASS}, "
              f"source={config.CONFIDENCE_THRESHOLD_SOURCE}, "
              f"max_loopbacks={config.CONFIDENCE_MAX_LOOPBACKS}")
        # Print the ladder as it will actually be walked, from the configured start
        # scope -- a typo'd CONTEXT_ESCALATION_ORDER entry is dropped silently
        # otherwise, and the run would quietly escalate somewhere else.
        from .pipeline.common import narrower_modes, _next_context_mode
        base = _start
        walk, m = [], base
        for _ in range(config.CONFIDENCE_MAX_LOOPBACKS):
            m = _next_context_mode(m)
            if m is None:
                break
            walk.append(m)
        print(f"  context ladder: {' -> '.join(escalation_order())}")
        print(f"  reachable from '{base}' in {config.CONFIDENCE_MAX_LOOPBACKS} "
              f"loopback(s): {' -> '.join([base] + walk)}"
              + ("  (already at the widest reachable scope)" if not walk else ""))
        if getattr(config, 'CONTEXT_SHRINK_TO_FIT', False):
            print(f"  descent on: an oversized '{base}' falls back through "
                  f"{' -> '.join(narrower_modes(base)) or '(nothing narrower)'}")
        if 'packed' in escalation_order() or base == 'packed':
            print(f"  packed budget: {config.context_pack_budget()} tokens")
        if 'symbols' in escalation_order() and not getattr(
                config, 'CONTEXT_SYMBOL_REQUEST', False):
            print("  WARNING: 'symbols' is on the ladder but CONTEXT_SYMBOL_REQUEST is "
                  "off -- the model is never asked for symbols, so that rung will "
                  "render as plain 'block'.")
        if getattr(config, 'CONFIDENCE_FROM_LOGPROBS', False):
            from .llm_client import supports_logprobs
            if not supports_logprobs():
                print(f"  NOTE: CONFIDENCE_FROM_LOGPROBS is on but "
                      f"{config.LLM_PROVIDER} returns no logprobs -- falling back to "
                      f"the model's self-reported confidence.")
            elif pipeline_mode == 'single':
                print("  NOTE: logprob confidence needs one decisive verdict token per "
                      "call; the single (single_extension) pipeline emits many verdicts "
                      "per call, so it falls back to self-reported confidence. "
                      "PIPELINE_MODE=single_vulnerability is the per-finding version "
                      "that can be measured.")
    if cache_layout and config.LLM_PROVIDER == 'ollama':
        print(f"  prompt cache: keep_alive={config.OLLAMA_KEEP_ALIVE}")
        if config.PARALLEL_WORKERS > 1:
            # Each Ollama slot holds its own cached prefix, so more workers than
            # slots means they keep evicting one another.
            print(f"  WARNING: PARALLEL_WORKERS={config.PARALLEL_WORKERS} -- workers share the "
                  f"server's slots and evict each other's cached prefix. Use "
                  f"PARALLEL_WORKERS=1, or raise OLLAMA_NUM_PARALLEL on the server to match.")
    if cache_layout and config.LLM_PROVIDER == 'vllm':
        print("  prompt cache: served by vLLM automatic prefix caching (serve-time setting)")
    if config.LLM_PROVIDER == 'vllm':
        _seed = getattr(config, 'VLLM_SEED', None)
        print(f"  vLLM sampling: temperature={config.VLLM_TEMPERATURE}, "
              f"seed={_seed if _seed is not None else 'unset (nondeterministic)'}")
        if getattr(config, 'PAYLOAD_THINKING', False) and pipeline_mode != 'multi':
            # There is no payload STEP outside the multi pipeline, so the knob has
            # nothing to attach to. Say so rather than let a run be configured for a
            # budget it never sends.
            print(f"  NOTE: PAYLOAD_THINKING is on but the {pipeline_mode} pipeline has "
                  f"no separate payload call -- every request uses "
                  f"VLLM_THINKING_TOKEN_BUDGET={config.VLLM_THINKING_TOKEN_BUDGET}.")
    if config.DRY_RUN_MODE:
        print("WARNING: DRY RUN MODE - LLM calls will be skipped (no costs)")
    print("=" * 80)

    state.CURRENT_RESULTS_DIR = get_or_create_results_directory()
    print(f"Results: {_display_path(state.CURRENT_RESULTS_DIR, config.BASE_DIR)}\n")

    if config.USE_TAR_DOWNLOAD:
        from helpers.extension_downloader import download_extensions_tar
        print("Downloading extensions tar file...")
        if download_extensions_tar(config.EXTENSION_CODE_DIR, config, print):
            print("✓ Extensions tar downloaded and extracted\n")
        else:
            print("⚠ Tar download failed, falling back to individual downloads\n")

    if not config.DATASETS:
        print("ERROR: No datasets configured")
        return

    enabled = [d for d in config.DATASETS if d.get('enabled', True)]
    print(f"Datasets: {', '.join(d['name'] for d in enabled)}\n")

    tunnel = None
    total_processed = 0
    try:
        tunnel, client = setup_llm_client()

        for dataset_config in config.DATASETS:
            if not dataset_config.get('enabled', True):
                continue

            dataset_name = dataset_config["name"]
            state.CURRENT_DATASET_NAME = dataset_name
            log(f"Processing: {dataset_name.upper()}", "HEADER")

            _init_log_file(dataset_name)

            units = get_extensions_for_dataset(dataset_config)
            if not units:
                log("No valid extensions found")
                continue
            log(f"Found {len(units)} valid extensions")

            if config.LLM_PROVIDER == 'gemini_batch':
                # Imported lazily so non-Gemini runs don't require the Gemini SDK.
                from .batch_gemini import process_dataset_batch
                total_processed += process_dataset_batch(units, dataset_config)
            else:
                total_processed += scheduler.process_dataset(
                    units, client, dataset_config, pipeline_mode)

        print("\n" + "=" * 80)
        print(f"COMPLETE: Processed {total_processed} extensions")
        print(f"Results: {state.CURRENT_RESULTS_DIR}")
        print("=" * 80)

    except Exception as e:
        print(f"\nERROR: {e}")
        traceback.print_exc()
    finally:
        if tunnel and getattr(tunnel, 'is_active', False):
            tunnel.stop()
            print("\nSSH tunnel closed")


def _init_log_file(dataset_name: str) -> None:
    log_file = state.CURRENT_RESULTS_DIR / dataset_name / "log.txt"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    if getattr(config, 'RESUME_RUN', None) and log_file.exists():
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n# RESUMED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    else:
        log_file.write_text(
            f"# Analysis Log - {dataset_name}\n"
            f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n",
            encoding='utf-8',
        )


if __name__ == "__main__":
    main()
