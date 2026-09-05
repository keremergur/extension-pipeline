"""Assemble prompts from the composable sections.

Three axes of control:

  * Pipeline shape -- one whole-task prompt for the whole extension (single), the
    same whole-task prompt for ONE finding (single_vulnerability), or one small
    prompt per step (categorize / classify / payload) for the multi pipeline.
  * Category inclusion -- only emit the sections for the enabled vulnerability
    categories (config.ANALYZER_VULNERABILITY_CATEGORIES). Off by default (None =
    all categories), as requested.
  * Prompt-cache layout -- where each section is placed, so consecutive requests
    share as long a common prefix as possible (config.PROMPT_CACHE_OPTIMIZED).

Prefix caching in a nutshell: Ollama (llama.cpp) keeps the attention state of the
previous prompt per slot and re-uses it only for the LONGEST COMMON PREFIX with
the next prompt -- everything from the first differing token on is prefilled
again. So the layout rule is "stable content first, volatile content last", and
the volatility ranking here is:

    system prompt (constant)  >  manifest.json + domain hints (per extension)
    >  the two per-finding blocks  >  step instructions (per pipeline step)

Which of the two per-finding blocks goes first depends on the run (see
`shared_code` in build_user_message): under a whole-file context mode the multi
pipeline hands every finding of an extension the same code block while the report
snippet changes, so the code belongs in front; when the code is what changes --
one call per extension, a per-finding context mode, or a loopback re-render --
the report belongs in front.

The multi pipeline is what makes this pay off: it fires three calls per finding
whose *data* is identical and whose *instructions* differ. With the original
layout (step instructions in the system prompt, report before manifest/code) the
common prefix between those calls was the shared INTRO paragraph, so all three
prefilled the whole report+code from scratch. With the cache layout the system
prompt is one run-wide constant, the step instructions move to the tail of the
user message, and steps 2/3 re-use everything up to that tail.

No section is added or dropped by the cache layout -- the model sees the same
content, just in a different place -- so it stays a clean A/B ablation.
"""

from typing import List, Optional, Tuple

import config

from . import domains
from . import prompt_sections as S
from . import schemas

STORAGE_CATEGORIES = {"storage", "data_exfiltration"}


def get_enabled_categories() -> Optional[List[str]]:
    """Return the configured category allow-list, or None for all categories."""
    cats = getattr(config, "ANALYZER_VULNERABILITY_CATEGORIES", None)
    if not cats:
        return None
    if isinstance(cats, str):
        cats = [cats]
    return [c for c in cats if c in S.CATEGORY_DEFINITIONS]


def _category_defs(categories: Optional[List[str]]) -> str:
    cats = categories or list(S.CATEGORY_DEFINITIONS.keys())
    return "\n".join(S.CATEGORY_DEFINITIONS[c] for c in cats)


def _payload_defs(categories: Optional[List[str]]) -> str:
    cats = categories or list(S.PAYLOAD_BY_CATEGORY.keys())
    return "\n".join(S.PAYLOAD_BY_CATEGORY[c] for c in cats)


def _needs_storage(categories: Optional[List[str]]) -> bool:
    cats = set(categories) if categories else set(S.CATEGORY_DEFINITIONS.keys())
    return bool(cats & STORAGE_CATEGORIES)


def _flag(name: str) -> bool:
    """Read an optional-feature toggle from config (default off if unset)."""
    return bool(getattr(config, name, False))


def result_rules_block() -> str:
    """The verdict-rules section for the configured RESULT_RULES variant.

    Empty string when RESULT_RULES is "none" (ablation: no verdict guidance at
    all). The heading names exactly the verdicts the schema will accept.
    """
    key = schemas.result_rules_variant()
    if key == "none":
        return ""
    heading = "RESULT (" + "/".join(schemas.result_values()) + ")\n"
    return heading + S.RESULT_RULES_VARIANTS[key]


def reasoning_prompt_variant() -> str:
    """The configured REASONING_PROMPT key, or "none" when unset/unknown.

    Unknown falls back to "none" rather than raising, matching
    schemas.result_rules_variant(); main.py warns so a typo is not silent.
    """
    key = str(getattr(config, "REASONING_PROMPT", "none") or "none").strip().lower()
    return key if key in S.REASONING_PROMPT_VARIANTS else "none"


def reasoning_prompt_block() -> str:
    """Thinking-block instructions for the configured variant ("" when none).

    Only the prompts whose `result` logprob is measured carry this -- see the
    header comment on S.REASONING_PROMPT_VARIANTS.
    """
    key = reasoning_prompt_variant()
    return S.REASONING_PROMPT_VARIANTS[key] if key != "none" else ""


def cache_optimized() -> bool:
    """True when prompts are laid out for the Ollama prefix cache (feature 7)."""
    return _flag("PROMPT_CACHE_OPTIMIZED")


# Code-context modes whose rendered block repeats across the findings of one
# extension: "used" always builds it from the WHOLE report's refs, so every
# finding gets byte-identical code, and "file" repeats whenever consecutive
# findings sit in the same file (the common case -- findings arrive grouped by
# file). In those modes the code block is more stable than the per-finding report
# snippet and therefore belongs in front of it. Every other scope -- "lines",
# "block", and the middle rungs "callsites"/"symbols"/"module"/"toplevel"/
# "skeleton"/"packed" -- pins
# to the finding's own line_refs and re-renders per finding, so there the report is
# the stable block.
SHARED_CODE_MODES = {"file", "used"}


def code_shared_across_findings(mode: Optional[str] = None) -> bool:
    """True when the code block at `mode` repeats across an extension's findings."""
    return (mode or getattr(config, "CODE_CONTEXT_MODE", "lines")) in SHARED_CODE_MODES


def category_for_rule_id(rule_id: Optional[str],
                         categories: Optional[List[str]] = None) -> Optional[str]:
    """Map a CodeQL rule_id to a category via config.ANALYZER_RULE_ID_CATEGORY_MAP.

    CodeQL rule_ids encode the category (e.g. "chrome/trigger/storage/set" -> storage),
    so the multi pipeline can skip the LLM categorize step for a weak model. Longest
    matching '/'-prefix wins ("chrome/trigger/storage/set" also matches a key of
    "chrome/trigger/storage"). Returns None -- meaning "ask the model" -- when:
      * the feature map is empty or the rule_id has no entry (unknown/ambiguous, e.g.
        a network-request trigger that could be 1way or 2way);
      * the mapped value is not a real category; or
      * a category allow-list is active and the mapped value is not in it.
    """
    if not rule_id:
        return None
    mapping = getattr(config, "ANALYZER_RULE_ID_CATEGORY_MAP", None) or {}
    parts = rule_id.split("/")
    for i in range(len(parts), 0, -1):
        cat = mapping.get("/".join(parts[:i]))
        if cat:
            break
    else:
        return None
    if cat not in S.CATEGORY_DEFINITIONS:
        return None
    if categories and cat not in categories:
        return None
    return cat


def _assemble(blocks: List[str]) -> Tuple[str, str]:
    """Split a step's sections into (system_prompt, task_tail).

    `blocks[0]` is always S.INTRO. Original layout: every section forms the system
    prompt and the tail is empty. Cache layout: only INTRO stays in the system
    prompt -- identical for every call of the whole run, so a slot always starts
    from a cached prefix -- and the step's own instructions become the tail that
    build_user_message appends AFTER the data they talk about.
    """
    blocks = [b for b in blocks if b]  # RESULT_RULES="none" contributes an empty block
    if not cache_optimized():
        return "\n\n".join(blocks), ""
    body = [b for b in blocks if b != S.INTRO]
    return S.INTRO, "\n\n".join(body)


def build_user_message(extension_id: str, tool_type: str, report_content: str,
                       manifest_content: Optional[str], code_context: Optional[str],
                       extra: Optional[str] = None, task: Optional[str] = None,
                       shared_code: bool = False) -> str:
    """Build the shared report-contents block handed to the model.

    With the cache layout on, blocks are emitted in the volatility order of the
    module docstring: manifest.json + hints first (identical for every finding of
    this extension), then the two per-finding blocks, then `extra`, then the step
    instructions. The original layout put the report first, which pushed the
    differing bytes to the front and invalidated the manifest and code behind it.

    `shared_code` decides the order of the two per-finding blocks, and only the
    caller knows it: pass True when the next requests will carry the SAME code
    block but a different report snippet (the multi pipeline under a
    SHARED_CODE_MODES context mode), so the big code block sits in the cached
    prefix and only the report + tail get prefilled again. Pass False when the
    code is the block that changes -- one call per extension (single pipeline), or
    a per-finding context mode -- so the report stays cached instead, which is
    also what a confidence loopback re-render wants.
    """
    report_filename = "analysis.json" if tool_type in ("doublex", "codeql") else "analysis.txt"
    header = [
        "# REPORT CONTENTS\n\n",
        f"- Extension ID: {extension_id}\n",
        f"- Analysis Tool: {tool_type.upper()}\n\n",
    ]
    report = [f"{report_filename}\n\n{report_content}\n\n"]
    manifest = []
    if manifest_content:
        manifest.append(f"manifest.json\n\n{manifest_content}\n\n")
        hints = domains.format_hints(manifest_content)
        if hints:
            manifest.append(f"{hints}\n\n")

    if not cache_optimized():
        parts = header + report + manifest + (["---\n\n", code_context] if code_context else [])
        # `task` is empty for every _assemble()-driven caller here (the cache layout
        # is what moves step instructions out of the system prompt in the first
        # place, so with it off they are already IN the system prompt and this is a
        # no-op) -- but single_vulnerability's RULE_INFER_CATEGORY_PROMPT can pass a
        # real one regardless of cache layout (it is a separate axis: what varies per
        # candidate, not where the constant/volatile split happens), so it must not
        # be silently dropped here.
        if task:
            parts.append(f"\n\n---\n\n# TASK\n\n{task}\n")
        # Original recency: the authoritative per-finding note is the last thing
        # the model reads (step instructions live in the system prompt).
        if extra:
            parts.append(f"\n\n---\n\n{extra}\n")
        return "".join(parts)

    if shared_code and code_context:
        parts = header + manifest + ["---\n\n", code_context, "\n\n---\n\n"] + report
    else:
        parts = header + manifest + report + (["---\n\n", code_context] if code_context else [])

    # `task` (this step's instructions) comes off the system prompt and rides the
    # tail so consecutive steps share the prefix above it. `extra` -- the pinned,
    # "do not contradict" per-finding note -- stays LAST, exactly as it was in the
    # original layout: on a small local model the closing tokens carry the most
    # weight, and burying that note mid-prompt made gemma4 drop instructions it
    # had followed before (e.g. the required extension-id first argument). Both
    # are step-specific, so ordering them within the tail costs no cache.
    if task:
        parts.append(f"\n\n---\n\n# TASK\n\n{task}\n")
    if extra:
        parts.append(f"\n\n---\n\n{extra}\n")
    return "".join(parts)


# ---- single pipeline ---------------------------------------------------

def build_single_system(categories: Optional[List[str]] = None) -> str:
    """The full whole-task analysis prompt (single pipeline).

    Deliberately NOT split by the cache layout: the single pipeline issues one
    call per extension with the same instructions every time, so this whole block
    already is the constant prefix every request re-uses. Moving it behind the
    per-extension data would shrink that prefix to nothing. Only the user-message
    block order changes for this pipeline (it keeps the manifest and report ahead
    of the code context a loopback retry re-renders).
    """
    blocks = [
        S.INTRO,
        "VULNERABILITY CATEGORIES\n" + _category_defs(categories),
        result_rules_block(),
        # Single pipeline emits the whole array itself, so it -- unlike the multi
        # pipeline, which splits candidates in code -- must group results itself.
        S.RESULT_COMBINATION,
    ]
    if _flag("PROMPT_INCLUDE_STORAGE_TP_HINT"):
        blocks.append(S.STORAGE_TP_HINT)
    if _flag("PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE"):
        blocks.append(S.EXTERNALLY_CONNECTABLE_NOTE)
    if _flag("PROMPT_INCLUDE_RESULT_EXAMPLES"):
        blocks.append(S.RESULT_EXAMPLES)
    blocks += [
        "ATTACKER PAYLOAD\n" + S.PAYLOAD_INTRO + "\n" + _payload_defs(categories)
        + "\n" + S.PAYLOAD_OUTRO,
        S.ATTACKER_SOURCE_RULES,
        S.VERIFICATION_INSTRUCTIONS_RULES,
        S.DOMAIN_RESTRICTION_RULES,
        S.VERIFICATION_DETAILS_COMMON
        + ("\n" + S.VERIFICATION_DETAILS_STORAGE if _needs_storage(categories) else ""),
        S.REMINDERS,
    ]
    if _flag("CONFIDENCE_LOOPBACK_ENABLED"):
        blocks.append(S.CONFIDENCE_INSTRUCTIONS)
        if _flag("CONTEXT_SYMBOL_REQUEST"):
            blocks.append(S.SYMBOL_REQUEST_INSTRUCTIONS)
    # Last: an instruction about HOW to think is followed best when it is the most
    # recent thing said, and the position is fixed so the cache prefix still holds.
    blocks.append(reasoning_prompt_block())
    return "\n\n".join(b for b in blocks if b)


# ---- single_vulnerability pipeline -------------------------------------

def build_category_block(categories: Optional[List[str]] = None) -> str:
    """The category-dependent content, standalone -- for the RULE_INFER_CATEGORY_PROMPT
    per-candidate tail (see build_single_vulnerability_system's `omit_categories`).

    Exactly the two blocks that would otherwise sit in the system prompt: the
    category definitions and the per-category payload trigger recipes. Only called
    for a PINNED candidate, and only with that one category -- there is nothing to
    gain moving an UNPINNED candidate's (full) category set here instead of leaving
    it in the system prompt; see the pipeline module's own comment on `pinned_category`
    for why the two cases are handled asymmetrically.
    """
    return ("VULNERABILITY CATEGORIES\n" + _category_defs(categories)
            + "\n\nPAYLOAD TRIGGER (per category)\n" + _payload_defs(categories))


def build_single_vulnerability_system(categories: Optional[List[str]] = None,
                                      omit_categories: bool = False) -> str:
    """The whole-task prompt for ONE finding (single_vulnerability pipeline).

    The same content as build_single_system with two deliberate differences:

      * S.RESULT_COMBINATION is dropped and S.SINGLE_VULNERABILITY_TASK takes its
        place -- the candidate split already decided what one result is, so the model
        must be told to judge exactly the finding it is shown, not to group findings.
      * S.CQL_NETWORK_HINT is included (under its own flag). It lives in the multi
        pipeline's categorize step, which is the step this prompt absorbs; the
        whole-extension prompt never picked it up.

    Like build_single_system this is NOT split by the cache layout (PROMPT_CACHE_OPTIMIZED),
    and for the same reason -- one call per candidate with identical instructions every
    time, so the whole block is the constant prefix every request of the run re-uses.
    What varies per candidate (the pinned attacker_source) rides the user message's
    tail instead, exactly as the multi pipeline's steps do.

    `omit_categories` (config.RULE_INFER_CATEGORY_PROMPT, and only for a candidate
    whose category rule_id already resolved) drops the two category-dependent
    blocks -- "VULNERABILITY CATEGORIES" and the per-category payload trigger list --
    so the caller can put just the one pinned category's version in the per-candidate
    tail instead (build_category_block([pinned_category])). Pass False (the default)
    for an UNPINNED candidate even when the flag is on: that candidate needs every
    category regardless, and this content sits ahead of `report` in the rendered
    prompt, so leaving it here keeps it inside whatever prefix a cache can still
    reuse -- moving it to the tail (which always sits AFTER `report`, and `report`
    differs every candidate) would only forfeit that for no token savings.

    A nice side effect of gating this on PINNING rather than on the flag alone: every
    call that DOES omit categories produces the exact same system prompt regardless
    of which category ended up pinned (no category name is embedded here either
    way), so pinned-to-pinned calls stay just as cacheable on this constant portion
    as unpinned-to-unpinned calls always were.
    """
    blocks = [
        S.INTRO,
        S.SINGLE_VULNERABILITY_TASK,
    ]
    if _flag("PROMPT_CQL_NETWORK_HINT"):
        blocks.append(S.CQL_NETWORK_HINT)
    if not omit_categories:
        blocks.append("VULNERABILITY CATEGORIES\n" + _category_defs(categories))
    blocks.append(result_rules_block())
    if _flag("PROMPT_INCLUDE_STORAGE_TP_HINT"):
        blocks.append(S.STORAGE_TP_HINT)
    if _flag("PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE"):
        blocks.append(S.EXTERNALLY_CONNECTABLE_NOTE)
    if _flag("PROMPT_INCLUDE_RESULT_EXAMPLES"):
        blocks.append(S.RESULT_EXAMPLES)
    payload_block = ("ATTACKER PAYLOAD\n" + S.PAYLOAD_INTRO + "\n" + S.PAYLOAD_OUTRO
                     if omit_categories else
                     "ATTACKER PAYLOAD\n" + S.PAYLOAD_INTRO + "\n" + _payload_defs(categories)
                     + "\n" + S.PAYLOAD_OUTRO)
    blocks += [
        payload_block,
        S.ATTACKER_SOURCE_RULES,
        S.VERIFICATION_INSTRUCTIONS_RULES,
        S.DOMAIN_RESTRICTION_RULES,
        S.VERIFICATION_DETAILS_COMMON
        + ("\n" + S.VERIFICATION_DETAILS_STORAGE if _needs_storage(categories) else ""),
        S.REMINDERS,
    ]
    if _flag("CONFIDENCE_LOOPBACK_ENABLED"):
        blocks.append(S.CONFIDENCE_INSTRUCTIONS)
        if _flag("CONTEXT_SYMBOL_REQUEST"):
            blocks.append(S.SYMBOL_REQUEST_INSTRUCTIONS)
    blocks.append(reasoning_prompt_block())   # last -- see build_single_system
    return "\n\n".join(b for b in blocks if b)


# ---- multi pipeline steps ----------------------------------------------
# Each returns (system_prompt, task_tail); the tail is empty unless the cache
# layout is on, in which case it belongs at the end of the user message (pass it
# to build_user_message(task=...)).

def build_categorize_prompt(categories: Optional[List[str]] = None) -> Tuple[str, str]:
    blocks = [S.INTRO, S.CATEGORIZE_TASK]
    if _flag("PROMPT_CQL_NETWORK_HINT"):
        blocks.append(S.CQL_NETWORK_HINT)
    blocks.append("VULNERABILITY CATEGORIES\n" + _category_defs(categories))
    return _assemble(blocks)


def build_classify_prompt(category: str) -> Tuple[str, str]:
    definition = S.CATEGORY_DEFINITIONS.get(category, "")
    blocks = [
        S.INTRO,
        f"The finding's category is: {category}\n{definition}",
        result_rules_block(),
    ]
    # Category-specific, so only the storage/data_exfiltration classify prompts carry it.
    if _flag("PROMPT_INCLUDE_STORAGE_TP_HINT") and category in STORAGE_CATEGORIES:
        blocks.append(S.STORAGE_TP_HINT)
    if _flag("PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE"):
        blocks.append(S.EXTERNALLY_CONNECTABLE_NOTE)
    if _flag("PROMPT_INCLUDE_RESULT_EXAMPLES"):
        blocks.append(S.RESULT_EXAMPLES)
    if _flag("CONFIDENCE_LOOPBACK_ENABLED"):
        blocks.append(S.CONFIDENCE_INSTRUCTIONS)
        if _flag("CONTEXT_SYMBOL_REQUEST"):
            blocks.append(S.SYMBOL_REQUEST_INSTRUCTIONS)
    blocks.append(reasoning_prompt_block())   # last -- see build_single_system
    return _assemble(blocks)


def build_payload_prompt(category: str) -> Tuple[str, str]:
    trigger = S.PAYLOAD_BY_CATEGORY.get(category, "")
    storage = "\n" + S.VERIFICATION_DETAILS_STORAGE if category in STORAGE_CATEGORIES else ""
    blocks = [
        S.INTRO,
        f"The finding is a confirmed TP with category: {category}",
        "ATTACKER PAYLOAD\n" + S.PAYLOAD_INTRO + "\n" + trigger + "\n" + S.PAYLOAD_OUTRO,
        S.ATTACKER_SOURCE_RULES,
    ]
    # externally_connectable directly informs whether attacker_source can be "Extension".
    if _flag("PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE"):
        blocks.append(S.EXTERNALLY_CONNECTABLE_NOTE)
    blocks += [
        S.VERIFICATION_INSTRUCTIONS_RULES,
        S.DOMAIN_RESTRICTION_RULES,
        S.VERIFICATION_DETAILS_COMMON + storage,
        S.REMINDERS,
    ]
    return _assemble(blocks)
