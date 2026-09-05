"""Multi-step pipeline.

Per candidate finding, run a short chain of small prompts:

    1. categorize  -> vulnerability_category
    2. classify    -> TP/FP (+ fp_explanation)
    3. payload     -> attacker payload + verification details   (only if TP)

Each step's prompt contains only the sections relevant to that step (and, from
step 2 on, only the one category's section), so the context stays small enough
for a local model. The per-candidate objects are assembled deterministically
into the same final result shape as the single pipeline.

The three steps of one candidate are fired back to back over identical data, so
with config.PROMPT_CACHE_OPTIMIZED the step instructions ride at the END of the
user message (the `task` argument) instead of in the system prompt, letting steps
2 and 3 re-use the prefix Ollama already has cached from step 1.

Candidates of one extension are independent, so the module is split into three
reusable pieces the scheduler (pipeline.scheduler) drives at whatever granularity
config.PARALLEL asks for:

    prepare_multi(...)         -> MultiJob   (report parse + candidate split; no LLM)
    analyze_one_candidate(...) -> vuln       (the 3-step chain for ONE candidate)
    finalize_multi(job)                      (assemble + write the result file)

analyze_extension_multi() below simply runs all three in order for one extension
(the sequential / inter path); intra and rolling call the pieces themselves.
"""

import re
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Dict, List, Optional

import config

from .. import domains, priority, prompt_builder, state
from ..extension_io import CONTEXTUAL_MODES, extract_code_context
from ..llm_client import LLMError, estimate_token_count, query_structured
from ..logging_utils import log, log_message, set_worker_extension
from ..results_store import get_current_model_name, save_prompt
from ..schemas import categorize_schema, classify_schema, payload_schema
from ..tools import get_adapter
from . import common

_NULL_DETAILS = {
    "specific_domain": None, "domain_restriction_source": None,
    "storage_api": None, "storage_key": None, "storage_domain": None,
}


def _safe(identifier: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', identifier)[:80]


@dataclass
class MultiJob:
    """One extension's worth of multi-pipeline work, shared across candidate tasks.

    `record`/`ordered_vulns` are thread-safe so candidates may complete out of
    order (intra/rolling) yet the written result keeps candidate order. `pending`
    is the rolling scheduler's countdown of not-yet-finished candidates.
    """
    extension_id: str
    dataset_name: str
    candidates: List[Any]
    categories: Optional[List[str]]
    code_context_lines: int
    base_mode: str
    current: int
    total: int
    start_time: float
    pending: int = 0
    # Candidate prioritisation bookkeeping (analyzer.priority). `skipped` holds
    # the findings a cutoff dropped, so the result file records what was NOT
    # analyzed rather than silently shrinking.
    total_candidates: int = 0
    priority_strategy: str = "all"
    priority_n: int = 0
    skipped: List[dict] = field(default_factory=list)
    _vulns: Dict[int, dict] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record(self, idx: int, vuln: dict) -> None:
        with self._lock:
            self._vulns[idx] = vuln

    def ordered_vulns(self) -> List[dict]:
        with self._lock:
            return [self._vulns[i] for i in sorted(self._vulns)]


def prepare_multi(unit, dataset_config, current, total) -> Optional[MultiJob]:
    """Parse the report and split it into candidates (no LLM calls).

    Returns None -- with the appropriate log -- when the extension is already
    processed or its report is missing/empty.
    """
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
        return None

    log(f"Extension [{current}/{total}]: {extension_id}", "HEADER")

    prepared = adapter.prepare(unit, dataset_name, code_context_lines, logger=log,
                               code_context_mode=code_context_mode)
    if prepared is None:
        log("Report not found or empty", "ERROR")
        log_message(dataset_name, "ERROR", f"{extension_id} - Report missing/empty")
        return None

    candidates = adapter.split_candidates(prepared, code_context_lines, code_context_mode)
    log(f"Split into {len(candidates)} candidate finding(s)")

    # Prioritise and cut off. Default ANALYZER_PRIORITY_STRATEGY="all" returns the
    # list untouched, so a run without the setting is unchanged (EXPERIMENTS.md 56-60).
    total_candidates = len(candidates)
    selected = priority.select(candidates, logger=log)
    kept_ids = {id(c) for c in selected}
    skipped = [{"index": i, "rule_id": getattr(c, 'identifier', None)}
               for i, c in enumerate(candidates, 1) if id(c) not in kept_ids]
    if skipped:
        log_message(dataset_name, "INFO",
                    f"{extension_id} - priority cutoff: "
                    f"{len(selected)}/{total_candidates} candidates analyzed, "
                    f"{len(skipped)} skipped")
    candidates = selected

    return MultiJob(
        extension_id=extension_id,
        dataset_name=dataset_name,
        candidates=candidates,
        categories=prompt_builder.get_enabled_categories(),
        code_context_lines=code_context_lines,
        base_mode=code_context_mode,
        current=current,
        total=total,
        start_time=time.time(),
        total_candidates=total_candidates,
        priority_strategy=str(getattr(config, 'ANALYZER_PRIORITY_STRATEGY', 'all')),
        priority_n=int(getattr(config, 'ANALYZER_PRIORITY_N', 0) or 0),
        skipped=skipped,
    )


def analyze_one_candidate(job: MultiJob, cand, idx: int, client) -> Optional[dict]:
    """Run the 3-step chain for a single candidate (safe to call from any worker)."""
    # A worker thread may hop between extensions, so re-tag its log prefix each time.
    set_worker_extension(job.extension_id)
    return _analyze_candidate(cand, idx, client, job.dataset_name, job.categories,
                              job.code_context_lines, job.base_mode)


def finalize_multi(job: MultiJob) -> None:
    """Assemble the collected candidate results and write the extension's file."""
    set_worker_extension(job.extension_id)
    vulns = job.ordered_vulns()
    result = {"extension_id": job.extension_id, "vulnerabilities": vulns}
    # Record the cutoff so a result file says what was NOT analyzed. Written only
    # when a cutoff actually dropped something, so files from an uncut run are
    # byte-identical to before.
    if job.skipped:
        result["priority"] = {
            "strategy": job.priority_strategy,
            "n": job.priority_n,
            "total_candidates": job.total_candidates,
            "analyzed": len(job.candidates),
            "skipped": job.skipped,
        }
    common.write_result(job.dataset_name, job.extension_id, result)

    elapsed = time.time() - job.start_time
    cut = (f", Skipped: {len(job.skipped)}/{job.total_candidates}"
           if job.skipped else "")
    log_message(job.dataset_name, "TIMING",
                f"{job.extension_id} - Candidates: {len(job.candidates)}{cut}, "
                f"Total: {elapsed:.2f}s")
    log(f"Vulnerabilities: {len(vulns)}{cut} | Total: {elapsed:.2f}s")


def analyze_extension_multi(unit, client, dataset_config, current, total) -> None:
    """Whole-extension path: prepare -> candidates in order -> finalize.

    Used by the sequential and `inter` schedules (one worker owns the extension).
    """
    common.stagger_start()
    job = prepare_multi(unit, dataset_config, current, total)
    if job is None:
        return
    for idx, cand in enumerate(job.candidates, 1):
        vuln = analyze_one_candidate(job, cand, idx, client)
        if vuln is not None:
            job.record(idx, vuln)
    finalize_multi(job)


# Pipeline-agnostic names for the three candidate-granular entry points. The
# scheduler drives every candidate-based pipeline (multi, single_vulnerability)
# through this trio, so `intra` and `rolling` need no per-mode branch.
prepare = prepare_multi
finalize = finalize_multi


def _pack_budget(system_prompt, build_message) -> int:
    """Token budget for "packed": what MAX_PROMPT_TOKENS leaves after everything else.

    `config.context_pack_budget()` is a blind fraction of the cap, which is not the
    same thing -- measured, it let a packed prompt reach 72_201 tokens against a
    68_000 cap, because the report and manifest of that finding ate more than the
    fraction assumed. Measuring the real overhead (the same message rendered with no
    code block) is what makes "cannot overflow" true rather than approximately true.
    """
    cap = getattr(config, "MAX_PROMPT_TOKENS", None)
    if not cap:
        return config.context_pack_budget()
    overhead = estimate_token_count(system_prompt + "\n" + build_message(None))
    reserve = getattr(config, "CONTEXT_PACK_RESERVE_TOKENS", 512)
    return max(0, cap - overhead - reserve)


def _candidate_context(cand, mode, base_mode, code_context_lines, hints=None,
                       pack_budget=None):
    """Render this candidate's code context at `mode`.

    The pre-built string is reused for the base scope, except when the scope depends
    on something outside the file: "symbols" renders from what the model asked for on
    the previous attempt, so the same mode can legitimately produce a different
    string on each attempt and must never be served from the cache.
    """
    contextual = mode in CONTEXTUAL_MODES
    if mode == base_mode and cand.code_context is not None and not contextual:
        return cand.code_context
    if not cand.code_dir:
        return cand.code_context or ""
    return extract_code_context(
        cand.code_dir, cand.line_refs, code_context_lines, mode=mode,
        all_line_refs=cand.all_line_refs,
        requested_symbols=(hints or {}).get("requested_symbols"),
        # "packed" ranks the file's chunks against the finding's own report text.
        query=cand.report_snippet,
        pack_budget=pack_budget if pack_budget is not None
        else config.context_pack_budget(),
    )


def _analyze_candidate(cand, idx, client, dataset_name, categories,
                       code_context_lines, base_mode):
    tag = f"{idx}_{_safe(cand.identifier)}"
    loopback = getattr(config, "CONFIDENCE_LOOPBACK_ENABLED", False)
    # Block order is decided once from the dataset's own context mode, not from
    # the (possibly escalated) mode of an individual attempt -- reordering blocks
    # mid-extension would break the prefix it is meant to preserve.
    shared_code = prompt_builder.code_shared_across_findings(base_mode)

    # ---- step 1: categorize -------------------------------------------
    # When enabled, derive the category straight from the CodeQL rule_id (which
    # encodes it) and skip the LLM call -- a weak model can't miscategorize, and one
    # request per finding is saved. Unknown/ambiguous rule_ids return None -> ask the
    # model as before.
    category = None
    cat_shrunk_from = None
    if getattr(config, "ANALYZER_CATEGORY_FROM_RULE_ID", False):
        category = prompt_builder.category_for_rule_id(cand.identifier, categories)

    if category is not None:
        log(f"[{tag}] category = {category} (from rule_id '{cand.identifier}')")
        if config.DRY_RUN_MODE:
            return {"rule_id": cand.identifier, "vulnerability_category": category,
                    "note": "DRY_RUN_MODE - LLM call skipped"}
    else:
        cat_sys, cat_task = prompt_builder.build_categorize_prompt(categories)

        def build_categorize(mode, hints=None):
            def message(ctx):
                return prompt_builder.build_user_message(
                    cand.extension_id, cand.tool_type, cand.report_snippet,
                    cand.manifest_content, ctx or None, task=cat_task,
                    shared_code=shared_code,
                )
            budget = _pack_budget(cat_sys, message) if mode == "packed" else None
            ctx = _candidate_context(cand, mode, base_mode, code_context_lines,
                                     hints, budget)
            return cat_sys, message(ctx)

        # Descent runs before the LLM call, same as classify/payload: a candidate
        # whose BASE scope alone is oversized (a giant single-block minified bundle
        # makes even "block" collapse to nearly the whole file -- EXPERIMENTS.md 41)
        # gets judged at a narrower scope instead of failing outright.
        cat_mode, cat_shrunk_from = common._apply_shrink(
            build_categorize, base_mode, dataset_name, cand.extension_id, tag,
            step="categorize")
        _, cat_user = build_categorize(cat_mode)
        save_prompt(dataset_name, cand.extension_id, f"step1_categorize__{tag}", cat_sys, cat_user)

        if config.DRY_RUN_MODE:
            return {"rule_id": cand.identifier, "note": "DRY_RUN_MODE - LLM call skipped"}

        try:
            category = _run(cat_sys, cat_user, categorize_schema(categories), client)["vulnerability_category"]
        except (LLMError, KeyError, Exception) as e:
            log(f"[{tag}] categorize failed: {e}", "ERROR")
            return {"rule_id": cand.identifier, "error": f"categorize: {e}"}

        log(f"[{tag}] category = {category}")

    # ---- steps 2+3: classify (TP/FP) then payload, escalated together ---
    # The two steps are driven by ONE loop because the decision they jointly produce
    # is only as trustworthy as its weaker half: a confident TP whose attacker_source
    # was a coin flip still yields a payload aimed at the wrong context. So both
    # verdict tokens are measured, and EITHER falling short decides to widen the code
    # context and try again; each is judged against its own threshold
    # (CONFIDENCE_THRESHOLD_CLASS / _SOURCE, see CONFIDENCE_INCLUDE_SOURCE).
    def build_classify(mode, hints=None):
        cls_sys, cls_task = prompt_builder.build_classify_prompt(category)

        def message(ctx):
            return prompt_builder.build_user_message(
                cand.extension_id, cand.tool_type, cand.report_snippet,
                cand.manifest_content, ctx or None,
                extra=f"The determined vulnerability_category is: {category}",
                task=cls_task, shared_code=shared_code,
            )

        budget = _pack_budget(cls_sys, message) if mode == "packed" else None
        ctx = _candidate_context(cand, mode, base_mode, code_context_lines,
                                 hints, budget)
        return cls_sys, message(ctx)

    def build_payload(mode, hints=None):
        # Pin attacker_source up front when the manifest settles it, so the payload
        # is written for the right context instead of corrected into one afterwards.
        extra = f"This finding is a confirmed TP with vulnerability_category: {category}"
        pinned = domains.pinned_source_note(cand.manifest_content, cand.extension_id,
                                            cand.report_snippet)
        if pinned:
            extra = f"{extra}\n\n{pinned}"
        pay_sys, pay_task = prompt_builder.build_payload_prompt(category)

        def message(ctx):
            return prompt_builder.build_user_message(
                cand.extension_id, cand.tool_type, cand.report_snippet,
                cand.manifest_content, ctx or None, extra=extra,
                task=pay_task, shared_code=shared_code,
            )

        budget = _pack_budget(pay_sys, message) if mode == "packed" else None
        ctx = _candidate_context(cand, mode, base_mode, code_context_lines,
                                 hints, budget)
        return pay_sys, message(ctx)

    try:
        classification, payload, diag = common.classify_and_payload_with_loopback(
            build_classify, build_payload,
            classify_schema(include_confidence=loopback), payload_schema(), client,
            base_mode=base_mode, dataset_name=dataset_name,
            extension_id=cand.extension_id, tag=tag,
        )
    except common.PromptTooLarge as e:
        log(f"[{tag}] classify failed: {e}", "ERROR")
        return {"rule_id": cand.identifier, "vulnerability_category": category,
                "error": f"classify: {e}"}
    except (LLMError, Exception) as e:
        log(f"[{tag}] classify failed: {e}", "ERROR")
        return {"rule_id": cand.identifier, "vulnerability_category": category,
                "error": f"classify: {e}"}

    result = classification.get("result", "FP")
    vuln = {
        "rule_id": cand.identifier,
        "vulnerability_category": category,
        "result": result,
        "fp_explanation": classification.get("fp_explanation"),
        "attacker_payload": None,
        "attacker_source": None,
        "verification_instructions": None,
        "verification_details": dict(_NULL_DETAILS),
    }
    vuln.update(diag)  # confidence_class / confidence_source, trace, NA info
    if cat_shrunk_from:
        vuln["category_context_shrunk_from"] = cat_shrunk_from

    if result == "TP" and payload:
        vuln["attacker_payload"] = payload.get("attacker_payload")
        vuln["attacker_source"] = payload.get("attacker_source")
        vuln["verification_instructions"] = payload.get("verification_instructions")
        vuln["verification_details"] = {**_NULL_DETAILS, **(payload.get("verification_details") or {})}
        # The payload step routinely leaves specific_domain empty and mislabels
        # attacker_source; the manifest answers both deterministically, so apply it
        # rather than losing the restriction (or verifying an impossible route).
        for field, change in domains.apply_to_vulnerability(
                vuln, cand.manifest_content, evidence=cand.report_snippet).items():
            log(f"[{tag}] {field} corrected from manifest: {change}")
    elif result == "TP" and diag.get("payload_error"):
        vuln["error"] = f"payload: {diag['payload_error']}"

    log(f"[{tag}] result = {result}")
    return vuln


def _run(system_prompt, user_message, schema, client) -> dict:
    if not common.check_token_limit(system_prompt + "\n" + user_message,
                                    state.CURRENT_DATASET_NAME, "candidate"):
        raise LLMError("prompt exceeds MAX_PROMPT_TOKENS")
    return query_structured(system_prompt, user_message, schema, client)
