"""Shared helpers for the analysis pipelines."""

import collections
import json
import random
import time
from pathlib import Path

import config

from .. import state
from ..extension_io import CONTEXT_MODES, canonical_mode
from ..logging_utils import log, log_message, set_worker_extension
from ..llm_client import (LLMError, estimate_token_count, last_call_diagnostics,
                          query_structured, query_structured_ex, supports_logprobs)
from ..results_store import save_prompt
from ..schemas import ATTACKER_SOURCES, result_values


def result_path(dataset_name: str, extension_id: str) -> Path:
    return state.CURRENT_RESULTS_DIR / dataset_name / f"{extension_id}_result.json"


def already_processed(dataset_name: str, extension_id: str) -> bool:
    return result_path(dataset_name, extension_id).exists()


def write_result(dataset_name: str, extension_id: str, result: dict) -> None:
    out = result_path(dataset_name, extension_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding='utf-8')


def stagger_start() -> None:
    """Jitter parallel workers so they don't all hit the LLM simultaneously."""
    if config.PARALLEL_WORKERS > 1:
        time.sleep(random.uniform(0, config.PARALLEL_WORKERS * 0.5))


def begin(extension_id: str) -> None:
    set_worker_extension(extension_id)


def check_token_limit(text: str, dataset_name: str, extension_id: str) -> bool:
    """Return True if within limit; log + return False if the prompt is too big."""
    tokens = estimate_token_count(text)
    log(f"Prompt: {len(text)} chars, ~{tokens} tokens")
    if config.MAX_PROMPT_TOKENS and tokens > config.MAX_PROMPT_TOKENS:
        log(f"SKIPPED: prompt exceeds token limit ({tokens} > {config.MAX_PROMPT_TOKENS})", "ERROR")
        log_message(dataset_name, "SKIPPED",
                    f"{extension_id} - Tokens: {tokens} (limit: {config.MAX_PROMPT_TOKENS})")
        return False
    return True


# ---- confidence-based context loopback (feature 4) ---------------------

class PromptTooLarge(LLMError):
    """Raised when a (re)built prompt exceeds MAX_PROMPT_TOKENS."""


def escalation_order():
    """The ladder escalation walks: config.CONTEXT_ESCALATION_ORDER, validated.

    Unknown names and duplicates are dropped (with a warning), and an order that
    validates to nothing falls back to the full CONTEXT_MODES rank order.
    """
    configured = getattr(config, "CONTEXT_ESCALATION_ORDER", None) or CONTEXT_MODES
    seen, clean = set(), []
    for raw in configured:
        m = canonical_mode(raw, default="")
        if not m:
            log(f"CONTEXT_ESCALATION_ORDER: ignoring unknown scope '{raw}'", "WARNING")
            continue
        if m not in seen:
            seen.add(m)
            clean.append(m)
    return clean or list(CONTEXT_MODES)


def _rank(mode: str) -> int:
    return CONTEXT_MODES.index(mode) if mode in CONTEXT_MODES else -1


def narrower_modes(mode: str):
    """Rungs strictly narrower than `mode`, widest first.

    Prefers the run's own ladder -- that is the set of scopes the run declared
    acceptable -- and falls back to the full rank order when the ladder has nothing
    below `mode`.
    """
    ladder = [m for m in escalation_order() if _rank(m) < _rank(mode)]
    if not ladder:
        ladder = [m for m in CONTEXT_MODES if _rank(m) < _rank(mode)]
    return sorted(ladder, key=_rank, reverse=True)


def shrink_to_fit(build, mode: str, dataset_name: str, extension_id: str, tag: str = ""):
    """Widest scope at or below `mode` whose built prompt fits MAX_PROMPT_TOKENS.

    The descent counterpart to escalation, and it runs BEFORE any verdict exists:
    escalation widens a finding the model was unsure about, this one narrows a
    finding the model was never able to see at all. Costs one render per rung tried
    and no LLM call.

    Returns (mode_or_None, [(mode, tokens), ...]); None when even the narrowest
    scope is over the cap.
    """
    cap = getattr(config, "MAX_PROMPT_TOKENS", None)
    tried = []
    for candidate in [mode] + narrower_modes(mode):
        system_prompt, user_message = build(candidate, {})
        tokens = estimate_token_count(system_prompt + "\n" + user_message)
        tried.append((candidate, tokens))
        if not cap or tokens <= cap:
            return candidate, tried
    return None, tried


def _apply_shrink(build, mode, dataset_name, extension_id, tag, step):
    """Run the descent when enabled for `step`; returns (mode, shrunk_from_or_None).

    `step` is one of "categorize"/"classify"/"payload" -- CONTEXT_SHRINK_TO_FIT is a
    per-step set (config._env_step_set), not a single on/off switch, because a run can
    be too big at the categorize step alone (EXPERIMENTS.md 41) even with the
    classify/payload chain unaffected, or vice versa.

    "single" is a fourth, special value of `step`: the ONE call of a single-call
    pipeline (single.py's whole-extension call, or single_vuln.py's per-finding
    call). It has no listable name in CONTEXT_SHRINK_TO_FIT -- there is nothing to
    name a genuine SUBSET of, since it is the run's only call -- so instead of
    membership it fires whenever the configured set already means "shrink
    everything" (true/all/1/yes/on, or an explicit list that happens to spell out
    every known step): a run's CONTEXT_SHRINK_TO_FIT=true covers whichever pipeline
    that run's PIPELINE_MODE actually selects, with no separate opt-in required.
    """
    enabled = getattr(config, "CONTEXT_SHRINK_TO_FIT", frozenset())
    if step == "single":
        if enabled != getattr(config, "CONTEXT_SHRINK_TO_FIT_STEPS", frozenset()):
            return mode, None
    elif step not in enabled:
        return mode, None
    if not getattr(config, "MAX_PROMPT_TOKENS", None):
        return mode, None
    fitted, tried = shrink_to_fit(build, mode, dataset_name, extension_id, tag)
    if fitted == mode or not tried:
        return mode, None
    if fitted is None:
        log(f"[{tag}] no scope fits MAX_PROMPT_TOKENS "
            f"(narrowest '{tried[-1][0]}' = {tried[-1][1]} tokens)", "WARNING")
        return mode, None
    log(f"[{tag}] '{mode}' is {tried[0][1]} tokens > MAX_PROMPT_TOKENS; "
        f"descending to '{fitted}' ({dict(tried)[fitted]} tokens)", "WARNING")
    log_message(dataset_name, "SHRINK",
                f"{extension_id} - {mode} -> {fitted} "
                f"({tried[0][1]} -> {dict(tried)[fitted]} tokens)")
    return fitted, mode


def _next_context_mode(mode: str, requested=None):
    """Next scope after `mode` on the configured escalation ladder.

    The ladder is walked POSITIONALLY, exactly as configured -- a custom
    CONTEXT_ESCALATION_ORDER is an order, not a hint, so a run may deliberately
    skip rungs or visit them out of cost order.

    `mode` need not be on the ladder: CODE_CONTEXT_MODE is the starting scope and
    is independent of it, so a run can start in the middle (or on a rung the ladder
    omits entirely). In that case the walk enters at the first rung that is wider
    than `mode` by the canonical CONTEXT_MODES cost rank.

    Honours the model's `requested_context_scope` when it sits at or beyond the
    plain next step; otherwise steps up one rung. Returns None at the end.
    """
    order = escalation_order()
    # Both sides are canonicalised: `mode` may arrive as a pre-26.8 alias from an env
    # file, and `requested` comes from the model, which will happily answer
    # "function" because that is the word its training data uses.
    mode = canonical_mode(mode, default="")
    requested = canonical_mode(requested, default="") if requested else ""
    if mode in order:
        idx = order.index(mode) + 1
    else:
        idx = next((i for i, m in enumerate(order) if _rank(m) > _rank(mode)), len(order))
    if idx >= len(order):
        return None
    if requested in order and order.index(requested) >= idx:
        return requested
    return order[idx]


def _measure(system_prompt, user_message, schema, client, dataset_name, extension_id,
             label, field, values, *, temperature=None, seed_offset=0, save=True,
             thinking_budget=None, extra_fields=None):
    """One structured call at a fixed context scope, with its verdict confidence.

    Saves the prompt, enforces MAX_PROMPT_TOKENS, and asks for logprobs on `field`
    when the feature is on and the provider supports them. `temperature`/`seed_offset`
    override the sampling for self-consistency votes; `save=False` skips re-dumping an
    identical prompt on repeated votes. `thinking_budget` overrides the request's
    `thinking_token_budget` for this call only (None = the run's shared default).
    `extra_fields` -- [(field, allowed_values), ...] -- measures further enums of the
    SAME response, read back from last_call_diagnostics()["extra_confidence"]; only
    the single_vulnerability pipeline needs it, since only it decides more than one
    enum per call.

    Returns (result_dict, confidence, dist) -- see query_structured_ex.
    """
    combined = system_prompt + "\n" + user_message
    if not check_token_limit(combined, dataset_name, extension_id):
        # Dump a stub, not the prompt: an oversized escalation render reaches
        # megabytes and is never sent (4.6 GB of such files in the 08-23 run).
        save_prompt(dataset_name, extension_id, f"{label}__TOO_LARGE", system_prompt,
                    f"[NOT SENT: ~{estimate_token_count(combined)} tokens > "
                    f"MAX_PROMPT_TOKENS={config.MAX_PROMPT_TOKENS}]\n\n"
                    f"{user_message[:4000]}\n\n...[truncated]\n")
        raise PromptTooLarge("prompt exceeds MAX_PROMPT_TOKENS")
    if save:
        save_prompt(dataset_name, extension_id, label, system_prompt, user_message)
    use = bool(field) and getattr(config, "CONFIDENCE_FROM_LOGPROBS", False) \
        and supports_logprobs()
    return query_structured_ex(system_prompt, user_message, schema, client,
                               logprob_field=field if use else None,
                               logprob_values=values if use else None,
                               extra_logprob_fields=extra_fields if use else None,
                               temperature=temperature, seed_offset=seed_offset,
                               thinking_budget=thinking_budget)


def _below(value, threshold) -> bool:
    """True when `value` is a number strictly under `threshold`.

    The tolerance keeps a value that should exactly MEET the threshold (e.g. a 3:2
    vote giving margin 0.6-0.4, which floats to 0.19999998) from being failed.
    Shared by both loopback drivers so they cannot drift apart.
    """
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and value < threshold - 1e-9)


def _margin_of(dist):
    """Winner-share minus runner-up-share of a {label: prob} distribution."""
    if not dist:
        return None
    top = sorted(dist.values(), reverse=True)
    return top[0] - (top[1] if len(top) > 1 else 0.0)


def _extra_conf(diag: dict, field: str):
    """Confidence of a secondary enum measured from the same response, or None.

    See llm_client.last_call_diagnostics()["extra_confidence"].
    """
    return ((diag.get("extra_confidence") or {}).get(field) or {}).get("confidence")


def _diag_fields(d: dict) -> dict:
    """The subset of last_call_diagnostics worth writing into an attempt record.

    `completion_tokens` is the load-bearing one: with a reasoning parser it counts
    the thinking trace, so it is how the run answers "how long did it think, and is
    the output budget doing anything". `logprob_censored` marks an attempt whose
    confidence is a lower bound rather than a measurement.
    """
    keep = ("completion_tokens", "prompt_tokens", "logprob_censored",
            "logprob_missing", "logprob_floor", "logprob_raw_total", "logprob_topn")
    return {k: d[k] for k in keep if d.get(k) is not None}


def classify_and_payload_with_loopback(build_classify, build_payload, classify_schema_,
                                       payload_schema_, client, *, base_mode,
                                       dataset_name, extension_id, tag):
    """Run classify (+payload when TP) at one scope, widening while either is unsure.

    The pair is escalated together because the finding's usefulness depends on both:
    the TP/FP/NA verdict AND the attacker_source the payload is written for. Each is
    a discrete enum token, so both are measured from logprobs and each is compared
    against ITS OWN threshold (CONFIDENCE_THRESHOLD_CLASS / _SOURCE). The finding is
    unsure when EITHER fails -- deliberately not "their minimum", so a borderline
    source cannot be masked by a certain verdict, and raising one threshold does not
    drag the other along. CONFIDENCE_INCLUDE_SOURCE decides whether the source
    measurement votes at all; it is recorded either way. Escalating re-runs both,
    since more code can change either answer.

    When something is still under threshold after CONFIDENCE_MAX_LOOPBACKS extra
    tries, the verdict is downgraded to "NA" (when the selected RESULT_RULES variant
    defines NA) and the payload is dropped -- an undecidable finding has no confirmed
    flow to write an exploit for.

    Escalation is non-destructive. A wider scope whose prompt exceeds
    MAX_PROMPT_TOKENS makes that RUNG unavailable, not the finding: the last viable
    attempt is restored and reported, with `escalation_aborted` in the diagnostics.
    (Before this, PromptTooLarge escaped the loop uncaught and discarded a
    classification that had already succeeded -- 1_848 findings, 34.8% of all
    escalations, in the 08-23 run. See EXPERIMENTS.md 25.1.) Only attempt 0 -- the
    base scope, which no escalation chose -- still raises.

    Returns (classification, payload_or_None, diagnostics).
    """
    policy = str(getattr(config, "CONFIDENCE_LOOPBACK", "argmax")).strip().lower()
    if not getattr(config, "CONFIDENCE_LOOPBACK_ENABLED", True):
        policy = "none"                       # legacy alias forces the feature off
    enabled = policy != "none"
    shared = getattr(config, "CONFIDENCE_THRESHOLD", 0.7)
    thr_class = getattr(config, "CONFIDENCE_THRESHOLD_CLASS", shared)
    thr_source = getattr(config, "CONFIDENCE_THRESHOLD_SOURCE", shared)
    thr_margin = getattr(config, "CONFIDENCE_THRESHOLD_MARGIN", 0.2)
    max_loops = getattr(config, "CONFIDENCE_MAX_LOOPBACKS", 2) if enabled else 0
    vote_source = getattr(config, "CONFIDENCE_INCLUDE_SOURCE", False)
    trigger = str(getattr(config, "CONFIDENCE_ESCALATE_TRIGGER", "both")).strip().lower()
    fail_na = bool(getattr(config, "CONFIDENCE_FAIL_CLASSIFY_NA", False))
    n_votes = max(1, int(getattr(config, "CONFIDENCE_VOTES", 5)))
    vote_temp = getattr(config, "CONFIDENCE_VOTE_TEMPERATURE", 0.6)

    verdicts = result_values()
    mode = canonical_mode(base_mode)
    trace = []
    classification, payload, payload_error = {}, None, None
    cls_conf = src_conf = cls_dist = cls_margin = None
    pay_shrunk_from = None
    failed = []

    # Descent runs before anything else: if the configured scope cannot even be sent,
    # judging the finding at a narrower one beats not judging it at all.
    mode, shrunk_from = _apply_shrink(build_classify, mode, dataset_name,
                                      extension_id, tag, step="classify")

    def _hints():
        """What the previous attempt asked for, handed to the next render.

        Only `requested_symbols` today, and only when the feature is on -- this is
        the channel that lets the model say WHAT it is missing rather than only how
        much more it wants.
        """
        if not getattr(config, "CONTEXT_SYMBOL_REQUEST", False):
            return {}
        return {"requested_symbols": classification.get("requested_symbols") or []}

    def _vote_classify(m, suffix):
        """Self-consistency: n_votes samples at vote_temp; plurality wins.

        Returns (representative_classification, winner_share, {label: share}, tally).
        The prompt is saved once; each vote uses a distinct seed so a pinned
        VLLM_SEED still yields diverse draws.
        """
        tally = collections.Counter()
        reps = {}
        hints = _hints()
        for i in range(n_votes):
            cls_sys, cls_user = build_classify(m, hints)
            c, _, _ = _measure(
                cls_sys, cls_user, classify_schema_, client, dataset_name,
                extension_id, f"step2_classify__{tag}{suffix}", "result", verdicts,
                temperature=vote_temp, seed_offset=i, save=(i == 0))
            _vote_classify.diag = last_call_diagnostics()
            r = c.get("result", "FP")
            tally[r] += 1
            reps.setdefault(r, c)
        winner = tally.most_common(1)[0][0]
        dist = {k: v / n_votes for k, v in tally.items()}
        return reps[winner], dist[winner], dist, tally

    escalation_aborted = None
    for attempt in range(max_loops + 1):
        suffix = "" if attempt == 0 else f"__retry{attempt}_ctx-{mode}"
        # Snapshot the last viable decision before touching it: if this wider scope
        # turns out not to fit, the finding must fall back to what it already had.
        viable = (classification, payload, payload_error, cls_conf, src_conf,
                  cls_dist, cls_margin, failed, pay_shrunk_from)
        try:
            payload, payload_error, src_conf, pay_shrunk_from = None, None, None, None
            tally = None

            if policy == "vote_margin":
                classification, cls_conf, cls_dist, tally = _vote_classify(mode, suffix)
                cls_diag = getattr(_vote_classify, "diag", {})
            else:
                cls_sys, cls_user = build_classify(mode, _hints())
                classification, cls_conf, cls_dist = _measure(
                    cls_sys, cls_user, classify_schema_, client, dataset_name, extension_id,
                    f"step2_classify__{tag}{suffix}", "result", verdicts)
                # Read the diagnostics HERE, before the payload call below overwrites
                # this thread's slot -- they describe the classify decision, not the payload.
                cls_diag = last_call_diagnostics()
            result = classification.get("result", "FP")
            cls_margin = _margin_of(cls_dist)

            # Payload only for a TP; an FP/NA has nothing to exploit. Payload is drawn
            # greedily even in vote mode -- only the classify verdict is voted on.
            if result == "TP":
                # Payload's own descent, independent of classify's: the two prompts
                # differ (payload adds the pinned-source note and its own task text),
                # so a scope that fits classify is not guaranteed to fit payload too.
                # Never widens past `mode` -- only classify's escalation loop does that.
                pay_mode, pay_shrunk_from = _apply_shrink(
                    build_payload, mode, dataset_name, extension_id,
                    f"{tag}{suffix}", step="payload")
                pay_sys, pay_user = build_payload(pay_mode, _hints())
                try:
                    payload, src_conf, _ = _measure(
                        pay_sys, pay_user, payload_schema_, client, dataset_name,
                        extension_id, f"step3_payload__{tag}{suffix}",
                        "attacker_source", ATTACKER_SOURCES,
                        thinking_budget=config.payload_thinking_budget())
                except PromptTooLarge:
                    raise
                except Exception as e:
                    # A failed payload must not lose the classification we already have.
                    log(f"[{tag}] payload failed: {e}", "ERROR")
                    payload_error = str(e)
        except PromptTooLarge as e:
            if attempt == 0:
                raise  # the CONFIGURED scope does not fit: a real error, not a rung
            # This rung is unavailable. Restore the previous attempt wholesale --
            # including its payload, which the reset at the top of the body cleared.
            (classification, payload, payload_error, cls_conf, src_conf,
             cls_dist, cls_margin, failed, pay_shrunk_from) = viable
            escalation_aborted = f"{mode}: {e}"
            unavailable, mode = mode, trace[-1]["context_mode"]
            log(f"[{tag}] '{unavailable}' context exceeds MAX_PROMPT_TOKENS; "
                f"keeping the '{mode}' result", "WARNING")
            break

        # The classify decision is judged by the active policy; the source decision
        # (when it votes) always uses its own argmax threshold.
        failed = []
        if policy in ("logprob_margin", "vote_margin"):
            if _below(cls_margin, thr_margin):
                failed.append(f"class-margin {cls_margin:.3f}<{thr_margin}"
                              if cls_margin is not None else "class-margin unmeasured")
        elif policy == "argmax":
            if _below(cls_conf, thr_class):
                failed.append(f"class {cls_conf:.3f}<{thr_class}")
        if vote_source and _below(src_conf, thr_source):
            failed.append(f"source {src_conf:.3f}<{thr_source}")

        measured = [c for c in (cls_conf, src_conf) if c is not None]
        needs = bool(classification.get("needs_more_context"))
        # Fall back to the self-reported number only when nothing was measured
        # (argmax policy only; the margin policies have no scalar to compare).
        self_reported = classification.get("confidence")
        if policy == "argmax" and not measured and _below(self_reported, thr_class):
            failed.append(f"self-reported {self_reported}<{thr_class}")

        entry = {
            "attempt": attempt, "context_mode": mode,
            "confidence_class": cls_conf, "confidence_source": src_conf,
            "confidence_margin": (round(cls_margin, 4) if cls_margin is not None else None),
            "below_threshold": list(failed), "needs_more_context": needs,
            "method": ("votes" if policy == "vote_margin"
                       else ("logprobs" if measured else "self-reported")),
        }
        entry.update(_diag_fields(cls_diag))
        for lab, p in (cls_dist or {}).items():
            entry[f"confidence_{lab.lower()}"] = round(p, 4)
        if tally is not None:
            entry["votes"] = dict(tally)
        trace.append(entry)

        # Escalation trigger: `both` (unsure OR the model asked), `confidence`
        # (unsure only), or `request` (only when the model explicitly asked).
        if trigger == "request":
            want_more = needs
        elif trigger == "confidence":
            want_more = bool(failed)
        else:
            want_more = bool(failed) or needs
        if attempt >= max_loops or not want_more:
            break
        nxt = _next_context_mode(mode, classification.get("requested_context_scope"))
        if nxt is None:
            log(f"[{tag}] still unsure ({', '.join(failed) or 'needs_more_context'}) "
                f"but context is already at the widest scope '{mode}'", "WARNING")
            break
        log(f"[{tag}] unsure ({', '.join(failed) or 'needs_more_context'}): "
            f"escalating code context {mode} -> {nxt}")
        mode = nxt

    measured = [c for c in (cls_conf, src_conf) if c is not None]
    diag = {}
    if enabled:
        # `confidence` is the weaker of the two, kept as a single sortable number for
        # reporting only -- the retry/NA decision above uses the per-field thresholds.
        diag["confidence"] = min(measured) if measured else classification.get("confidence")
        diag["confidence_class"] = cls_conf
        diag["confidence_source"] = src_conf
        diag["confidence_margin"] = (round(cls_margin, 4) if cls_margin is not None else None)
        diag["confidence_method"] = trace[-1]["method"] if trace else None
        diag["confidence_policy"] = policy
        diag["final_context_mode"] = mode
        diag["context_attempts"] = trace
    if shrunk_from:
        diag["context_shrunk_from"] = shrunk_from
    if pay_shrunk_from:
        diag["payload_context_shrunk_from"] = pay_shrunk_from
    if escalation_aborted:
        diag["escalation_aborted"] = escalation_aborted
    if payload_error:
        diag["payload_error"] = payload_error

    # Abstain when still unsure after the last attempt. The verdict is stamped NA
    # when the enum already offers NA, OR when CONFIDENCE_FAIL_CLASSIFY_NA lets the
    # gate abstain on a 2-way enum the model was asked to always commit to.
    na_allowed = ("NA" in verdicts) or fail_na
    if enabled and failed and na_allowed and classification.get("result") != "NA":
        original = classification.get("result")
        classification["result"] = "NA"
        diag["result_before_na"] = original
        diag["na_reason"] = (f"{'; '.join(failed)} after {len(trace)} attempt(s); "
                             f"model leaned {original}")
        log(f"[{tag}] {'; '.join(failed)} after {len(trace)} attempt(s): "
            f"{original} -> NA")
        payload = None  # undecidable -> no exploit to hand the verifier

    return classification, payload, diag


def combined_with_loopback(build, schema, client, *, base_mode, dataset_name,
                           extension_id, tag, label="single_vuln"):
    """One call deciding category + verdict + payload, widened while it is unsure.

    The single_vulnerability counterpart of classify_and_payload_with_loopback, and
    deliberately the same decision procedure -- same policies, same two thresholds,
    same NA fallback, same non-destructive escalation -- so that a run of this
    pipeline differs from a multi run in the number of CALLS and nothing else. What
    changes is where the two measurements come from: multi reads `result` from the
    classify call and `attacker_source` from the payload call, whereas here both
    enums live in ONE response and are read from the same token stream (see
    llm_client's `extra_logprob_fields`).

    Two consequences of the shape, both accepted rather than worked around:

      * The payload is written on every attempt, including for findings that turn
        out FP and for attempts that are about to be escalated or downgraded to NA.
        Those payloads are simply not used. Making the call conditional would mean
        splitting it in two, which is the multi pipeline.
      * There is no separate payload thinking budget. `config.payload_thinking_budget()`
        exists to give the payload STEP its own cap; with one call there is no such
        step, so the request carries the run-wide VLLM_THINKING_TOKEN_BUDGET -- the
        one the classify step uses -- and PAYLOAD_THINKING is ignored here.

    Returns (answer, diagnostics); the caller assembles the vulnerability record.
    """
    policy = str(getattr(config, "CONFIDENCE_LOOPBACK", "argmax")).strip().lower()
    if not getattr(config, "CONFIDENCE_LOOPBACK_ENABLED", True):
        policy = "none"                       # legacy alias forces the feature off
    enabled = policy != "none"
    shared = getattr(config, "CONFIDENCE_THRESHOLD", 0.7)
    thr_class = getattr(config, "CONFIDENCE_THRESHOLD_CLASS", shared)
    thr_source = getattr(config, "CONFIDENCE_THRESHOLD_SOURCE", shared)
    thr_margin = getattr(config, "CONFIDENCE_THRESHOLD_MARGIN", 0.2)
    max_loops = getattr(config, "CONFIDENCE_MAX_LOOPBACKS", 2) if enabled else 0
    vote_source = getattr(config, "CONFIDENCE_INCLUDE_SOURCE", False)
    trigger = str(getattr(config, "CONFIDENCE_ESCALATE_TRIGGER", "both")).strip().lower()
    fail_na = bool(getattr(config, "CONFIDENCE_FAIL_CLASSIFY_NA", False))
    n_votes = max(1, int(getattr(config, "CONFIDENCE_VOTES", 5)))
    vote_temp = getattr(config, "CONFIDENCE_VOTE_TEMPERATURE", 0.6)

    verdicts = result_values()
    extra_fields = [("attacker_source", ATTACKER_SOURCES)]
    mode = canonical_mode(base_mode)
    trace = []
    answer = {}
    cls_conf = src_conf = cls_dist = cls_margin = None
    failed = []

    mode, shrunk_from = _apply_shrink(build, mode, dataset_name, extension_id, tag,
                                      step="single")

    def _hints():
        if not getattr(config, "CONTEXT_SYMBOL_REQUEST", False):
            return {}
        return {"requested_symbols": answer.get("requested_symbols") or []}

    def _one(m, suffix, *, temperature=None, seed_offset=0, save=True):
        """One combined call at scope `m`; returns (answer, cls_conf, cls_dist, src_conf)."""
        sys_p, user_p = build(m, _hints())
        a, c, d = _measure(
            sys_p, user_p, schema, client, dataset_name, extension_id,
            f"{label}__{tag}{suffix}", "result", verdicts, extra_fields=extra_fields,
            temperature=temperature, seed_offset=seed_offset, save=save)
        return a, c, d, _extra_conf(last_call_diagnostics(), "attacker_source")

    def _vote(m, suffix):
        """Self-consistency over the whole combined call; plurality on `result`.

        Costs n_votes payloads as well as n_votes verdicts -- the price of voting on
        a pipeline whose call is indivisible.
        """
        tally = collections.Counter()
        reps = {}
        for i in range(n_votes):
            a, _, _, s = _one(m, suffix, temperature=vote_temp, seed_offset=i,
                              save=(i == 0))
            _vote.diag = last_call_diagnostics()
            r = a.get("result", "FP")
            tally[r] += 1
            reps.setdefault(r, (a, s))
        winner = tally.most_common(1)[0][0]
        dist = {k: v / n_votes for k, v in tally.items()}
        rep, rep_src = reps[winner]
        return rep, dist[winner], dist, rep_src, tally

    escalation_aborted = None
    for attempt in range(max_loops + 1):
        suffix = "" if attempt == 0 else f"__retry{attempt}_ctx-{mode}"
        viable = (answer, cls_conf, src_conf, cls_dist, cls_margin, failed)
        try:
            tally = None
            if policy == "vote_margin":
                answer, cls_conf, cls_dist, src_conf, tally = _vote(mode, suffix)
                call_diag = getattr(_vote, "diag", {})
            else:
                answer, cls_conf, cls_dist, src_conf = _one(mode, suffix)
                call_diag = last_call_diagnostics()
            cls_margin = _margin_of(cls_dist)
        except PromptTooLarge as e:
            if attempt == 0:
                raise  # the CONFIGURED scope does not fit: a real error, not a rung
            (answer, cls_conf, src_conf, cls_dist, cls_margin, failed) = viable
            escalation_aborted = f"{mode}: {e}"
            unavailable, mode = mode, trace[-1]["context_mode"]
            log(f"[{tag}] '{unavailable}' context exceeds MAX_PROMPT_TOKENS; "
                f"keeping the '{mode}' result", "WARNING")
            break

        failed = []
        if policy in ("logprob_margin", "vote_margin"):
            if _below(cls_margin, thr_margin):
                failed.append(f"class-margin {cls_margin:.3f}<{thr_margin}"
                              if cls_margin is not None else "class-margin unmeasured")
        elif policy == "argmax":
            if _below(cls_conf, thr_class):
                failed.append(f"class {cls_conf:.3f}<{thr_class}")
        # An FP carries no attacker_source (the schema allows null), so there is
        # nothing to measure and nothing to fail on -- exactly as in the multi
        # pipeline, where an FP never reaches the payload step at all.
        if vote_source and _below(src_conf, thr_source):
            failed.append(f"source {src_conf:.3f}<{thr_source}")

        measured = [c for c in (cls_conf, src_conf) if c is not None]
        needs = bool(answer.get("needs_more_context"))
        self_reported = answer.get("confidence")
        if policy == "argmax" and not measured and _below(self_reported, thr_class):
            failed.append(f"self-reported {self_reported}<{thr_class}")

        entry = {
            "attempt": attempt, "context_mode": mode,
            "confidence_class": cls_conf, "confidence_source": src_conf,
            "confidence_margin": (round(cls_margin, 4) if cls_margin is not None else None),
            "below_threshold": list(failed), "needs_more_context": needs,
            "method": ("votes" if policy == "vote_margin"
                       else ("logprobs" if measured else "self-reported")),
        }
        entry.update(_diag_fields(call_diag))
        for lab, p in (cls_dist or {}).items():
            entry[f"confidence_{lab.lower()}"] = round(p, 4)
        if tally is not None:
            entry["votes"] = dict(tally)
        trace.append(entry)

        if trigger == "request":
            want_more = needs
        elif trigger == "confidence":
            want_more = bool(failed)
        else:
            want_more = bool(failed) or needs
        if attempt >= max_loops or not want_more:
            break
        nxt = _next_context_mode(mode, answer.get("requested_context_scope"))
        if nxt is None:
            log(f"[{tag}] still unsure ({', '.join(failed) or 'needs_more_context'}) "
                f"but context is already at the widest scope '{mode}'", "WARNING")
            break
        log(f"[{tag}] unsure ({', '.join(failed) or 'needs_more_context'}): "
            f"escalating code context {mode} -> {nxt}")
        mode = nxt

    measured = [c for c in (cls_conf, src_conf) if c is not None]
    diag = {}
    if enabled:
        diag["confidence"] = min(measured) if measured else answer.get("confidence")
        diag["confidence_class"] = cls_conf
        diag["confidence_source"] = src_conf
        diag["confidence_margin"] = (round(cls_margin, 4) if cls_margin is not None else None)
        diag["confidence_method"] = trace[-1]["method"] if trace else None
        diag["confidence_policy"] = policy
        diag["final_context_mode"] = mode
        diag["context_attempts"] = trace
    if shrunk_from:
        diag["context_shrunk_from"] = shrunk_from
    if escalation_aborted:
        diag["escalation_aborted"] = escalation_aborted

    na_allowed = ("NA" in verdicts) or fail_na
    if enabled and failed and na_allowed and answer.get("result") != "NA":
        original = answer.get("result")
        answer["result"] = "NA"
        diag["result_before_na"] = original
        diag["na_reason"] = (f"{'; '.join(failed)} after {len(trace)} attempt(s); "
                             f"model leaned {original}")
        log(f"[{tag}] {'; '.join(failed)} after {len(trace)} attempt(s): "
            f"{original} -> NA")

    return answer, diag


def query_with_loopback(build, schema, client, *, base_mode, dataset_name,
                        extension_id, label, verdict_field=None):
    """Structured query that widens code context while the model stays unsure.

    Args:
        build: callable(mode) -> (system_prompt, user_message); rebuilds the
            prompt with the finding's source rendered at the given context scope.
        schema: JSON schema for structured output (already built with the
            confidence fields when the feature is on).
        base_mode: the starting context scope (config.CODE_CONTEXT_MODE).
        label: prompt-dump label; retries get a "__retryN_ctx-<mode>" suffix.

    Behaviour: runs once at `base_mode`. When the loopback feature is enabled and
    confidence < CONFIDENCE_THRESHOLD (or needs_more_context), re-runs at the
    next-wider scope, up to CONFIDENCE_MAX_LOOPBACKS extra times. With the feature
    off it is exactly one plain query at `base_mode`.

    `verdict_field` (e.g. "result") switches the confidence source to the model's
    token logprobs for that field when CONFIDENCE_FROM_LOGPROBS is on and the
    provider supports them -- a real probability instead of the number the model
    writes into `confidence`, which in practice pins to 1.0 and never triggers the
    loopback. If the decision is STILL below threshold once the retries run out, the
    verdict is downgraded to "NA" (when the RESULT_RULES variant defines it) rather than
    keeping a coin-flip TP/FP.

    Returns (result, trace). Raises PromptTooLarge if a built prompt is too big.
    """
    enabled = getattr(config, "CONFIDENCE_LOOPBACK_ENABLED", False)
    threshold = getattr(config, "CONFIDENCE_THRESHOLD_CLASS",
                        getattr(config, "CONFIDENCE_THRESHOLD", 0.7))
    max_loops = getattr(config, "CONFIDENCE_MAX_LOOPBACKS", 2) if enabled else 0

    use_logprobs = (verdict_field
                    and getattr(config, "CONFIDENCE_FROM_LOGPROBS", False)
                    and supports_logprobs())
    verdict_values = result_values() if use_logprobs else None

    mode = canonical_mode(base_mode)
    trace = []
    result: dict = {}
    low_conf = False
    escalation_aborted = None
    mode, shrunk_from = _apply_shrink(build, mode, dataset_name, extension_id, label,
                                      step="single")
    for attempt in range(max_loops + 1):
        lbl = label if attempt == 0 else f"{label}__retry{attempt}_ctx-{mode}"
        try:
            hints = ({"requested_symbols": result.get("requested_symbols") or []}
                     if getattr(config, "CONTEXT_SYMBOL_REQUEST", False) else {})
            system_prompt, user_message = build(mode, hints)
            combined = system_prompt + "\n" + user_message
            if not check_token_limit(combined, dataset_name, extension_id):
                save_prompt(dataset_name, extension_id, f"{lbl}__TOO_LARGE",
                            system_prompt,
                            f"[NOT SENT: ~{estimate_token_count(combined)} tokens > "
                            f"MAX_PROMPT_TOKENS={config.MAX_PROMPT_TOKENS}]\n\n"
                            f"{user_message[:4000]}\n\n...[truncated]\n")
                raise PromptTooLarge("prompt exceeds MAX_PROMPT_TOKENS")
            save_prompt(dataset_name, extension_id, lbl, system_prompt, user_message)
        except PromptTooLarge as e:
            # Same contract as classify_and_payload_with_loopback: an unavailable
            # rung falls back to the last viable answer; only the configured base
            # scope failing to fit is a real error.
            if attempt == 0:
                raise
            escalation_aborted = f"{mode}: {e}"
            unavailable, mode = mode, trace[-1]["context_mode"]
            log(f"[{label}] '{unavailable}' context exceeds MAX_PROMPT_TOKENS; "
                f"keeping the '{mode}' result", "WARNING")
            break

        result, logprob_conf, logprob_dist = query_structured_ex(
            system_prompt, user_message, schema, client,
            logprob_field=verdict_field if use_logprobs else None,
            logprob_values=verdict_values,
        )
        # Prefer the measured probability; fall back to the self-reported number
        # when the provider gave us nothing (or the token could not be located).
        conf = logprob_conf if logprob_conf is not None else result.get("confidence")
        if logprob_conf is not None:
            result["confidence_method"] = "logprobs"
            result["confidence_class"] = round(logprob_conf, 4)
        needs = bool(result.get("needs_more_context"))
        entry = {"attempt": attempt, "context_mode": mode,
                 "confidence": conf, "needs_more_context": needs,
                 "method": "logprobs" if logprob_conf is not None else "self-reported"}
        entry.update(_diag_fields(last_call_diagnostics()))
        for lab, p in (logprob_dist or {}).items():
            entry[f"confidence_{lab.lower()}"] = round(p, 4)
        trace.append(entry)

        low_conf = isinstance(conf, (int, float)) and not isinstance(conf, bool) \
            and conf < threshold
        if attempt >= max_loops:
            break
        if not (low_conf or needs):
            break
        nxt = _next_context_mode(mode, result.get("requested_context_scope"))
        if nxt is None:
            log(f"[{label}] still unsure (confidence={conf}) but context is already "
                f"at the widest scope '{mode}'", "WARNING")
            break
        log(f"[{label}] confidence={conf} needs_more={needs}: "
            f"escalating code context {mode} -> {nxt}")
        mode = nxt

    # Retries exhausted and still unsure -> record it as undecidable instead of
    # letting a barely-decided verdict through as a confident one.
    if enabled and low_conf and verdict_field and "NA" in result_values():
        original = result.get(verdict_field)
        if original != "NA":
            result[verdict_field] = "NA"
            result["na_reason"] = (
                f"confidence {conf:.3f} < {threshold} after {len(trace)} attempt(s); "
                f"model leaned {original}" if isinstance(conf, (int, float))
                else f"unresolved after {len(trace)} attempt(s); model leaned {original}"
            )
            result["result_before_na"] = original
            log(f"[{label}] confidence {conf} < {threshold} after {len(trace)} "
                f"attempt(s): {original} -> NA")

    if enabled:
        result["final_context_mode"] = mode
        result["context_attempts"] = trace
        if shrunk_from:
            result["context_shrunk_from"] = shrunk_from
        if escalation_aborted:
            result["escalation_aborted"] = escalation_aborted
    return result, trace
