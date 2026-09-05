"""JSON schemas for structured LLM output.

The prompts no longer contain "output valid JSON in exactly this shape"
boilerplate; instead these schemas are handed to the provider's structured-output
mechanism (Ollama `format`, Gemini `response_schema`, OpenAI json_schema, ...)
so the model is constrained to emit conforming JSON.

Schemas are built as functions so the allowed `vulnerability_category` enum can
be narrowed when the run is restricted to a subset of categories.
"""

from typing import List, Optional

import config

# Canonical vulnerability categories.
ALL_CATEGORIES = [
    "code_execution", "1way_request", "2way_request",
    "download", "data_exfiltration", "storage",
]

DOMAIN_RESTRICTION_SOURCES = ["manifest", "code", "both"]

# The payload step's discrete decision: which context the exploit runs from. Shared
# so the logprob measurement normalises over exactly the enum the schema allows.
ATTACKER_SOURCES = ["Website", "Extension"]

# Storage/read + write APIs referenced by storage & data_exfiltration findings.
STORAGE_APIS = [
    "chrome.bookmarks.create", "chrome.bookmarks.remove", "chrome.bookmarks.removeTree",
    "chrome.cookies.remove", "chrome.cookies.set", "chrome.history.addUrl",
    "chrome.history.deleteAll", "chrome.history.deleteRange", "chrome.history.deleteUrl",
    "chrome.management.setEnabled", "chrome.management.uninstall",
    "chrome.management.uninstallSelf", "chrome.declarativeNetRequest.updateDynamicRules",
    "chrome.storage.local.clear", "chrome.storage.sync.clear", "chrome.storage.session.clear",
    "chrome.storage.local.remove", "chrome.storage.sync.remove", "chrome.storage.session.remove",
    "chrome.storage.local.set", "chrome.storage.sync.set", "chrome.storage.session.set",
    "localStorage.clear", "localStorage.removeItem", "localStorage.setItem",
    "sessionStorage.clear", "sessionStorage.removeItem", "sessionStorage.setItem",
    "chrome.bookmarks.get", "chrome.bookmarks.getRecent", "chrome.bookmarks.getTree",
    "chrome.bookmarks.search", "chrome.cookies.get", "chrome.cookies.getAll",
    "chrome.history.getVisits", "chrome.history.search", "chrome.topSites.get",
    "chrome.management.get", "chrome.management.getAll", "chrome.management.getSelf",
    "chrome.storage.local.get", "chrome.storage.sync.get", "chrome.storage.session.get",
    "localStorage.getItem",
]


def _nullable(type_name: str) -> dict:
    return {"type": [type_name, "null"]}


def result_rules_variant() -> str:
    """The selected config.RESULT_RULES key, or "none" when disabled/unknown."""
    from . import prompt_sections as S
    key = str(getattr(config, "RESULT_RULES", "none") or "none").strip().lower()
    return key if key in S.RESULT_RULES_VARIANTS else "none"


def result_values() -> List[str]:
    """Allowed values of the verdict, incl. "NA" when the chosen variant defines it.

    Single source of truth: the schema enum, the prompt block explaining the
    verdicts, and the logprob normalisation all derive from the SAME selected
    RESULT_RULES variant, so the model can never be offered a verdict the prompt
    never described (or vice versa).
    """
    from . import prompt_sections as S
    if result_rules_variant() in S.RESULT_RULES_WITH_NA:
        return ["TP", "FP", "NA"]
    return ["TP", "FP"]


def _categories(categories: Optional[List[str]]) -> List[str]:
    return list(categories) if categories else list(ALL_CATEGORIES)


# Scopes the model may request more code at (feature 4: confidence loopback).
# Sourced from the renderer so the enum cannot drift from what exists; the pre-26.8
# aliases stay in the enum too, since a model that has seen "function" in training
# will offer it and canonical_mode() maps it back.
def _context_scopes():
    from .extension_io import CONTEXT_MODES, MODE_ALIASES
    return list(CONTEXT_MODES) + list(MODE_ALIASES)


CONTEXT_SCOPES = _context_scopes()


def _add_confidence(props: dict, required: List[str], include: bool):
    """Optionally extend a schema with the confidence-loopback fields.

    Returns (properties, required). When `include` is False the inputs are
    returned unchanged, so schemas are identical to the original when the
    loopback feature is off.
    """
    if not include:
        return props, required
    props = {
        **props,
        "confidence": _nullable("number"),
        "needs_more_context": _nullable("boolean"),
        "requested_context_scope": {
            "type": ["string", "null"],
            "enum": CONTEXT_SCOPES + [None],
        },
    }
    required = required + ["confidence", "needs_more_context", "requested_context_scope"]
    # Only present when the feature is on, so a run without it produces a schema
    # byte-identical to every earlier run and stays a clean A/B control.
    if getattr(config, "CONTEXT_SYMBOL_REQUEST", False):
        props = {**props, "requested_symbols": {
            "type": ["array", "null"],
            "items": {"type": "string"},
        }}
        required = required + ["requested_symbols"]
    return props, required


def verification_details_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "specific_domain": _nullable("string"),
            "domain_restriction_source": {
                "type": ["string", "null"],
                "enum": DOMAIN_RESTRICTION_SOURCES + [None],
            },
            "storage_api": {
                "type": ["string", "null"],
                "enum": STORAGE_APIS + [None],
            },
            "storage_key": _nullable("string"),
            "storage_domain": _nullable("string"),
        },
        "required": [
            "specific_domain", "domain_restriction_source",
            "storage_api", "storage_key", "storage_domain",
        ],
    }


def vulnerability_schema(categories: Optional[List[str]] = None) -> dict:
    """Schema for a single analyzed vulnerability object."""
    return {
        "type": "object",
        "properties": {
            "rule_id": {"type": "string"},
            "vulnerability_category": {"type": "string", "enum": _categories(categories)},
            "result": {"type": "string", "enum": result_values()},
            "fp_explanation": _nullable("string"),
            "attacker_payload": _nullable("string"),
            "attacker_source": {
                "type": ["string", "null"],
                "enum": ATTACKER_SOURCES + [None],
            },
            "verification_instructions": _nullable("string"),
            "verification_details": verification_details_schema(),
        },
        "required": [
            "rule_id", "vulnerability_category", "result",
            "fp_explanation", "attacker_payload", "attacker_source",
            "verification_instructions", "verification_details",
        ],
    }


def final_result_schema(categories: Optional[List[str]] = None,
                        include_confidence: bool = False) -> dict:
    """Schema for the whole-extension analysis result (single pipeline).

    With `include_confidence`, adds top-level confidence-loopback fields so the
    model can report how sure it is and optionally ask for wider code context.
    """
    props = {
        "extension_id": {"type": "string"},
        "vulnerabilities": {
            "type": "array",
            "items": vulnerability_schema(categories),
        },
    }
    required = ["extension_id", "vulnerabilities"]
    props, required = _add_confidence(props, required, include_confidence)
    return {"type": "object", "properties": props, "required": required}


# ---- one-call-per-finding schema (single_vulnerability pipeline) --------

def candidate_result_schema(categories: Optional[List[str]] = None,
                            include_confidence: bool = False) -> dict:
    """Schema for ONE finding judged end to end in a single call.

    The union of the multi pipeline's three step schemas, minus `rule_id`: the
    candidate's identifier is already known from the report split, so asking the
    model to echo it only spends tokens and invites a mismatch (the multi pipeline
    stamps it in code for the same reason).

    Field ORDER is load-bearing, because guided decoding emits the properties in the
    order the schema declares them and each one is generated in the context of the
    ones before it. Hence: category, then the verdict, then -- when the loopback is on
    -- the confidence/needs-more-context fields, and only then the payload. The model
    therefore commits to the verdict and to how sure it is BEFORE it starts writing an
    exploit, rather than rationalising the verdict backwards from a payload it has
    already written. `attacker_payload` and friends stay nullable so an FP can decline
    to write one.
    """
    props = {
        "vulnerability_category": {"type": "string", "enum": _categories(categories)},
        "result": {"type": "string", "enum": result_values()},
        "fp_explanation": _nullable("string"),
    }
    required = ["vulnerability_category", "result", "fp_explanation"]
    props, required = _add_confidence(props, required, include_confidence)
    props.update({
        "attacker_payload": _nullable("string"),
        "attacker_source": {
            "type": ["string", "null"],
            "enum": ATTACKER_SOURCES + [None],
        },
        "verification_instructions": _nullable("string"),
        "verification_details": verification_details_schema(),
    })
    required = required + ["attacker_payload", "attacker_source",
                           "verification_instructions", "verification_details"]
    return {"type": "object", "properties": props, "required": required}


# ---- per-step schemas (multi pipeline) ---------------------------------

def categorize_schema(categories: Optional[List[str]] = None) -> dict:
    return {
        "type": "object",
        "properties": {
            "vulnerability_category": {"type": "string", "enum": _categories(categories)},
        },
        "required": ["vulnerability_category"],
    }


def classify_schema(include_confidence: bool = False) -> dict:
    props = {
        "result": {"type": "string", "enum": result_values()},
        "fp_explanation": _nullable("string"),
    }
    required = ["result", "fp_explanation"]
    props, required = _add_confidence(props, required, include_confidence)
    return {"type": "object", "properties": props, "required": required}


def payload_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "attacker_payload": {"type": "string"},
            "attacker_source": {"type": "string", "enum": ATTACKER_SOURCES},
            "verification_instructions": {"type": "string"},
            "verification_details": verification_details_schema(),
        },
        "required": [
            "attacker_payload", "attacker_source",
            "verification_instructions", "verification_details",
        ],
    }
