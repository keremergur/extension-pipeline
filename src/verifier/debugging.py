#!/usr/bin/env python3
"""
Failure-artifact capture for the Verifier (Phase 1 debuggability)
========================================================================

When a vulnerability does NOT verify (or optionally when it does), dump everything needed to
diagnose it offline — so a single run yields enough to iterate without re-running:

  * <run>/_debug_artifacts/<extension_id>/<rule_id>/screenshot.png  — what the page looked like
  * .../page.html    — the rendered DOM at detection time
  * .../payload.js   — the exact payload executed (post extension-ID replacement)
  * .../debug.json   — nav_url, category, diagnostics, failure_reason, extension ids, spoofing flag

Everything here is best-effort and fully guarded: artifact capture must NEVER raise, break, or
meaningfully slow a verification run. On any error it logs a note and returns None.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import config
from .logging_utils import log_error


# The run directory main.py points us at; benchmark/other callers fall back to RESULTS_VERIFICATION_DIR.
_artifact_root: Optional[Path] = None


def set_artifact_root(path) -> None:
    """Point failure-artifact capture at the current run directory (called once from main)."""
    global _artifact_root
    try:
        _artifact_root = Path(path)
    except Exception:
        _artifact_root = None


def _root() -> Path:
    if _artifact_root is not None:
        return _artifact_root
    base = getattr(config, "RESULTS_VERIFICATION_DIR", None) or "."
    return Path(base) / "_debug_artifacts"


def _safe(name) -> str:
    """Filesystem-safe path segment (avoid odd rule_id/extension_id characters on Windows)."""
    keep = "-_."
    s = "".join(c if (c.isalnum() or c in keep) else "_" for c in str(name if name else "unknown"))
    return s[:80] or "unknown"


async def capture_failure_artifacts(
    page,
    *,
    extension_id,
    rule_id,
    vulnerability_category,
    nav_url=None,
    executed_payload=None,
    target_extension_id=None,
    spoofing_applied=False,
    diagnostics=None,
    failure_reason=None,
    verification_status=None,
    on_success=False,
) -> Optional[str]:
    """Best-effort dump of screenshot + DOM + payload + debug.json for one vulnerability.

    Returns the artifact directory (str) if anything was written, else None. Never raises.
    Honors config.CAPTURE_FAILURE_ARTIFACTS (failures) / CAPTURE_ARTIFACTS_ON_SUCCESS (successes).
    """
    try:
        if on_success:
            if not getattr(config, "CAPTURE_ARTIFACTS_ON_SUCCESS", False):
                return None
        elif not getattr(config, "CAPTURE_FAILURE_ARTIFACTS", True):
            return None

        out = _root() / _safe(extension_id) / _safe(rule_id or vulnerability_category)
        out.mkdir(parents=True, exist_ok=True)

        # Screenshot — page may be closed or on an error page; guard independently.
        try:
            if page is not None and not page.is_closed():
                await page.screenshot(path=str(out / "screenshot.png"), full_page=False)
        except Exception:
            pass

        # Rendered DOM.
        try:
            if page is not None and not page.is_closed():
                html = await page.content()
                (out / "page.html").write_text(html, encoding="utf-8")
        except Exception:
            pass

        # Exact payload that executed (after extension-ID replacement).
        try:
            if executed_payload:
                (out / "payload.js").write_text(str(executed_payload), encoding="utf-8")
        except Exception:
            pass

        # Structured debug record — the single most useful file for triage.
        try:
            record = {
                "timestamp": datetime.now().isoformat(),
                "extension_id": extension_id,
                "target_extension_id": target_extension_id,
                "rule_id": rule_id,
                "vulnerability_category": vulnerability_category,
                "verification_status": verification_status,
                "failure_reason": failure_reason,
                "nav_url": nav_url,
                "spoofing_applied": bool(spoofing_applied),
                "diagnostics": diagnostics or {},
            }
            (out / "debug.json").write_text(
                json.dumps(record, indent=2, default=str), encoding="utf-8"
            )
        except Exception:
            pass

        return str(out)
    except Exception as e:  # absolute last-resort guard
        try:
            log_error(f"Artifact capture failed (ignored): {e}")
        except Exception:
            pass
        return None
