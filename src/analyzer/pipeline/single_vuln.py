"""Single-call-per-vulnerability pipeline ("single_vulnerability").

The third pipeline shape, sitting exactly between the two that already existed:

    single (single_extension)  1 call  per EXTENSION, all findings, all steps
    single_vulnerability       1 call  per FINDING,  all steps
    multi                      3 calls per FINDING,  one step each

So it isolates ONE variable against each neighbour. Against `single` it changes only
the unit of work (one finding per call instead of the whole report) while keeping the
one-shot whole-task prompt. Against `multi` it changes only the number of calls
(categorize + classify + payload answered together instead of in a chain) while
keeping the per-finding unit. That is the whole point of the mode, and it is why the
candidate split, the job bookkeeping and the result writing are IMPORTED from
pipeline.multi rather than reimplemented: if the two modes split findings even
slightly differently, an A/B between them measures the plumbing too.

What it inherits from multi that `single` never picked up:

  * per-finding candidates, so a big report is never one giant prompt;
  * the rule_id category shortcut (config.ANALYZER_CATEGORY_FROM_RULE_ID) -- here it
    pins the schema's category enum instead of saving a call, since there is no
    separate categorize call to save. config.RULE_INFER_CATEGORY_PROMPT additionally
    drops the OTHER categories' text from a PINNED candidate's prompt (definitions +
    payload triggers move to a one-category tail -- build_category_block); an
    unpinned candidate is untouched by the flag, since it needs the full set
    regardless and that text is cheaper to leave in the cacheable system prompt than
    to relocate. Off by default, and gated separately from the schema pinning above,
    because shrinking the prompt costs the model visibility into every category it
    didn't get pinned to;
  * the manifest-pinned attacker_source note (domains.pinned_source_note), so the
    payload is written for the right context in the first place;
  * `shared_code` prompt ordering, which only makes sense when consecutive calls
    carry the same code block and a different finding;
  * measured (logprob) confidence for the verdict. PIPELINE_CHANGES.md 15 records
    logprob confidence as "not applicable" to the single pipeline because a
    whole-extension call has many verdicts and no single decisive token. Splitting the
    call per finding removes exactly that objection: there is one `result` token per
    call again, so the confidence loopback, the thresholds and the NA fallback all
    work here just as they do in multi.

The cost of the shape, accepted deliberately (see common.combined_with_loopback):
the payload is written even for findings that turn out FP or get downgraded to NA,
and there is no payload-specific thinking budget -- the run-wide
VLLM_THINKING_TOKEN_BUDGET (the classify budget) covers the whole call and
PAYLOAD_THINKING is ignored.
"""

from typing import Optional

import config

from .. import domains, prompt_builder
from ..llm_client import LLMError
from ..logging_utils import log, set_worker_extension
from ..results_store import save_prompt
from ..schemas import candidate_result_schema
from . import common
from .multi import (_NULL_DETAILS, _candidate_context, _pack_budget, _safe,
                    finalize_multi, prepare_multi)

# Shared with multi on purpose -- see the module docstring. The scheduler drives
# both pipelines through this same trio (prepare / analyze_one_candidate / finalize),
# so `intra` and `rolling` schedule this mode at candidate granularity too.
prepare = prepare_multi
finalize = finalize_multi


def analyze_extension_single_vuln(unit, client, dataset_config, current, total) -> None:
    """Whole-extension path: prepare -> candidates in order -> finalize.

    Used by the sequential and `inter` schedules (one worker owns the extension).
    """
    common.stagger_start()
    job = prepare(unit, dataset_config, current, total)
    if job is None:
        return
    for idx, cand in enumerate(job.candidates, 1):
        vuln = analyze_one_candidate(job, cand, idx, client)
        if vuln is not None:
            job.record(idx, vuln)
    finalize(job)


def analyze_one_candidate(job, cand, idx: int, client) -> Optional[dict]:
    """Run the one combined call for a single candidate (safe from any worker)."""
    set_worker_extension(job.extension_id)
    return _analyze_candidate(cand, idx, client, job.dataset_name, job.categories,
                              job.code_context_lines, job.base_mode)


def _analyze_candidate(cand, idx, client, dataset_name, categories,
                       code_context_lines, base_mode):
    tag = f"{idx}_{_safe(cand.identifier)}"
    loopback = getattr(config, "CONFIDENCE_LOOPBACK_ENABLED", False)
    # Decided from the dataset's context mode, not from an escalated attempt's --
    # reordering blocks mid-extension would break the prefix the order preserves.
    shared_code = prompt_builder.code_shared_across_findings(base_mode)

    # The rule_id shortcut, adapted: multi uses it to SKIP the categorize call, which
    # this pipeline does not have. Here it pins the answer instead -- the schema enum
    # collapses to the one category and the tail note states it -- so a weak model
    # still cannot miscategorize, and the two modes agree on the category for exactly
    # the same findings.
    pinned_category = None
    if getattr(config, "ANALYZER_CATEGORY_FROM_RULE_ID", False):
        pinned_category = prompt_builder.category_for_rule_id(cand.identifier, categories)
    if pinned_category:
        log(f"[{tag}] category = {pinned_category} (from rule_id '{cand.identifier}')")

    schema = candidate_result_schema(
        [pinned_category] if pinned_category else categories,
        include_confidence=loopback,
    )
    # config.RULE_INFER_CATEGORY_PROMPT: gated on THIS candidate actually being
    # pinned, not on the flag alone. An unpinned candidate needs the full category
    # text regardless -- there is nothing to shrink -- so it stays exactly where
    # flag=off puts it: baked into the system prompt, ahead of `report` in the
    # rendered token stream, where a prompt cache can actually reuse it. Moving it to
    # the tail (after `report`, which differs every candidate and so already breaks
    # any cached prefix by the time the tail is reached) would only forfeit that
    # reuse for zero savings -- the earlier version of this code did exactly that,
    # unconditionally, which was strictly worse than leaving it alone.
    #
    # A PINNED candidate has no such prefix to protect: its category varies with
    # WHICH rule_id resolved, so its content was never going to be identical between
    # two differently-pinned candidates no matter where it lived. Shrinking it (and
    # only it) to the tail is pure upside -- fewer tokens sent, and as a bonus every
    # pinned candidate's system prompt becomes the SAME text regardless of which
    # category got pinned (omit_categories=True never embeds a category name), so
    # pinned-to-pinned calls stay just as cacheable on the constant portion as they
    # were before this flag existed.
    omit_categories = (bool(getattr(config, "RULE_INFER_CATEGORY_PROMPT", False))
                       and pinned_category is not None)
    system_prompt = prompt_builder.build_single_vulnerability_system(
        categories, omit_categories=omit_categories)
    category_task = (prompt_builder.build_category_block([pinned_category])
                     if omit_categories else None)

    # `extra` is the "do not contradict" tail note, last in the message. Both entries
    # are facts already implied by the manifest hints block above them; stating them
    # here is what makes the model act on them (multi does the same at its payload step).
    notes = []
    if pinned_category:
        notes.append(f"The determined vulnerability_category is: {pinned_category}")
    pinned_source = domains.pinned_source_note(cand.manifest_content, cand.extension_id,
                                               cand.report_snippet)
    if pinned_source:
        notes.append(pinned_source)
    extra = "\n\n".join(notes) or None

    def build(mode, hints=None):
        def message(ctx):
            return prompt_builder.build_user_message(
                cand.extension_id, cand.tool_type, cand.report_snippet,
                cand.manifest_content, ctx or None, extra=extra,
                task=category_task, shared_code=shared_code,
            )

        budget = _pack_budget(system_prompt, message) if mode == "packed" else None
        ctx = _candidate_context(cand, mode, base_mode, code_context_lines,
                                 hints, budget)
        return system_prompt, message(ctx)

    if config.DRY_RUN_MODE:
        # Dump the prompt that WOULD be sent, descent included, so a dry run sizes
        # the real thing.
        dry_mode, _ = common._apply_shrink(build, base_mode, dataset_name,
                                           cand.extension_id, tag, step="single")
        sys_p, user_p = build(dry_mode)
        save_prompt(dataset_name, cand.extension_id, f"single_vuln__{tag}", sys_p, user_p)
        common.check_token_limit(sys_p + "\n" + user_p, dataset_name, cand.extension_id)
        return {"rule_id": cand.identifier,
                "vulnerability_category": pinned_category,
                "note": "DRY_RUN_MODE - LLM call skipped"}

    try:
        answer, diag = common.combined_with_loopback(
            build, schema, client, base_mode=base_mode, dataset_name=dataset_name,
            extension_id=cand.extension_id, tag=tag,
        )
    except (common.PromptTooLarge, LLMError, Exception) as e:
        log(f"[{tag}] analysis failed: {e}", "ERROR")
        return {"rule_id": cand.identifier,
                "vulnerability_category": pinned_category,
                "error": f"single_vulnerability: {e}"}

    category = pinned_category or answer.get("vulnerability_category")
    result = answer.get("result", "FP")
    vuln = {
        "rule_id": cand.identifier,
        "vulnerability_category": category,
        "result": result,
        "fp_explanation": answer.get("fp_explanation"),
        "attacker_payload": None,
        "attacker_source": None,
        "verification_instructions": None,
        "verification_details": dict(_NULL_DETAILS),
    }
    vuln.update(diag)  # confidence_class / confidence_source, trace, NA info

    payload = {
        "attacker_payload": answer.get("attacker_payload"),
        "attacker_source": answer.get("attacker_source"),
        "verification_instructions": answer.get("verification_instructions"),
        "verification_details": {**_NULL_DETAILS,
                                 **(answer.get("verification_details") or {})},
    }
    if result == "TP":
        vuln.update(payload)
        # Same deterministic corrections the multi pipeline applies after its payload
        # step: the model routinely leaves specific_domain empty and mislabels
        # attacker_source, and the manifest answers both.
        for field, change in domains.apply_to_vulnerability(
                vuln, cand.manifest_content, evidence=cand.report_snippet).items():
            log(f"[{tag}] {field} corrected from manifest: {change}")
    elif payload["attacker_payload"]:
        # An FP/NA has nothing to exploit, so the payload fields the verifier reads
        # stay null -- but the model wrote one anyway, and that is precisely the cost
        # this pipeline shape pays. Keeping it under a separate key makes the cost
        # measurable afterwards (how often, and what it would have attacked) without
        # putting an unverifiable payload where the verifier would pick it up.
        vuln["discarded_payload"] = payload

    log(f"[{tag}] category = {category} | result = {result}")
    return vuln
