"""Analysis pipelines.

  single (alias: single_extension)
      one structured LLM call produces the whole-extension result.
  single_vulnerability
      one structured LLM call per FINDING produces that finding's whole result
      (category + verdict + payload together).
  multi
      per-finding chain (categorize -> classify -> payload) so a small local model
      with a small context window only ever sees one finding and only the prompt
      sections relevant to its category.

All three are selected via config.PIPELINE_MODE, which is normalised through
`canonical_pipeline_mode` -- an unknown value RAISES rather than falling back,
because the scheduler's old `if single ... else multi` shape meant a typo'd mode
silently ran a different pipeline, which is the one failure an A/B must never have.
"""

from .multi import analyze_extension_multi
from .single import analyze_extension_single
from .single_vuln import analyze_extension_single_vuln

# Canonical mode -> accepted spellings. `single_extension` names what `single`
# actually is, now that a second single-call mode exists; `single` stays canonical so
# every existing env file, results folder and cited run keeps its label.
PIPELINE_MODES = {
    "single": ("single", "single_extension"),
    "single_vulnerability": ("single_vulnerability", "single_vuln"),
    "multi": ("multi",),
}

_ALIASES = {alias: canonical
            for canonical, aliases in PIPELINE_MODES.items()
            for alias in aliases}


def canonical_pipeline_mode(mode) -> str:
    """Normalise a configured PIPELINE_MODE; raise on anything unknown."""
    key = str(mode or "").strip().lower()
    if key in _ALIASES:
        return _ALIASES[key]
    raise ValueError(
        f"Unknown PIPELINE_MODE: {mode!r} (expected one of "
        f"{', '.join(sorted(_ALIASES))})")


def analyze_extension(unit, client, dataset_config, current, total, mode):
    """Dispatch to the configured pipeline."""
    mode = canonical_pipeline_mode(mode)
    if mode == "single":
        return analyze_extension_single(unit, client, dataset_config, current, total)
    if mode == "single_vulnerability":
        return analyze_extension_single_vuln(unit, client, dataset_config, current, total)
    return analyze_extension_multi(unit, client, dataset_config, current, total)


__all__ = ["analyze_extension", "analyze_extension_single",
           "analyze_extension_single_vuln", "analyze_extension_multi",
           "canonical_pipeline_mode", "PIPELINE_MODES"]
