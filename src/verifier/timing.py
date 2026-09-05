"""Lightweight timing instrumentation for the verifier.

Records how long each verifier step takes (especially the steps governed by the
timeout variables in config.py), plus the total duration of each vulnerability
and each extension. The collected tree is written to ``time.json`` in the run
folder by main.py.

A single module-level ``timer`` instance is used. The "current extension /
current vulnerability" cursors are held in ContextVars rather than plain
attributes, so that when VERIFIER_PARALLEL runs several verifications
concurrently each asyncio task gets its own cursor (a task inherits a *copy* of
the context at creation) and their steps cannot land in each other's records.
The ``run["extensions"]`` list they append into is shared, which is safe: asyncio
tasks interleave only at await points and list.append is atomic.

All public methods are defensive: instrumentation must never break a
verification run, so failures here are swallowed.
"""

import contextvars
import time
from contextlib import asynccontextmanager
from datetime import datetime

import config

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
except Exception:  # pragma: no cover - playwright should always be present
    class PlaywrightTimeoutError(Exception):
        pass

import asyncio


# Verification statuses that mean the vulnerability ran to completion without
# crashing (whether or not a detection happened).
_FINISHED_STATUSES = {
    "verified", "no_detection", "skipped", "missing_payload",
}


def _round(seconds: float) -> float:
    return round(seconds, 3)


def _classify_vuln(verification_status, steps) -> str:
    """Bucket a vulnerability into finished / timeout / error.

    Preference order:
    - a recognised "finished" verification_status wins (a normal completion,
      even if a detection wait internally timed out — that is expected),
    - otherwise an abnormal timeout (e.g. a navigation that hit its limit),
    - otherwise an error.
    """
    if verification_status in _FINISHED_STATUSES:
        return "finished"
    if verification_status == "page_load_failed" or any(
        s.get("outcome") == "timeout" for s in steps
    ):
        return "timeout"
    if verification_status is None and not any(
        s.get("outcome") in ("timeout", "error") for s in steps
    ):
        # Nothing went wrong and no terminal status recorded -> treat as finished.
        return "finished"
    return "error"


def _aggregate(statuses) -> str:
    if any(s == "error" for s in statuses):
        return "error"
    if any(s == "timeout" for s in statuses):
        return "timeout"
    return "finished"


def _strip_internal(obj):
    """Recursively drop keys starting with ``_`` (internal bookkeeping)."""
    if isinstance(obj, dict):
        return {k: _strip_internal(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_internal(v) for v in obj]
    return obj


# Per-task cursors (see module docstring): each concurrent verification gets its
# own "current extension"/"current vulnerability" without threading state around.
_ext_var = contextvars.ContextVar("timer_current_extension", default=None)
_vuln_var = contextvars.ContextVar("timer_current_vuln", default=None)


class _Timer:
    def __init__(self):
        self.run = None

    # `_ext`/`_vuln` stay plain attribute syntax at every call site, but read and
    # write the task-local ContextVars underneath.
    @property
    def _ext(self):
        return _ext_var.get()

    @_ext.setter
    def _ext(self, value):
        _ext_var.set(value)

    @property
    def _vuln(self):
        return _vuln_var.get()

    @_vuln.setter
    def _vuln(self, value):
        _vuln_var.set(value)

    # -- run -----------------------------------------------------------------
    def start_run(self):
        self.run = {
            "start": datetime.now().isoformat(),
            "_t0": time.monotonic(),
            "extensions": [],
        }

    def end_run(self):
        if not self.run:
            return
        self._finalize_vuln()
        self.run["end"] = datetime.now().isoformat()
        self.run["duration_s"] = _round(time.monotonic() - self.run["_t0"])
        self.run["status"] = _aggregate([e.get("status") for e in self.run["extensions"]])

    # -- extension -----------------------------------------------------------
    def start_extension(self, extension_id):
        self._finalize_vuln()
        self._ext = {
            "extension_id": extension_id,
            "_t0": time.monotonic(),
            "vulnerabilities": [],
        }
        if self.run is not None:
            self.run["extensions"].append(self._ext)

    def end_extension(self, vuln_records=None):
        """Finish the current extension.

        ``vuln_records`` (the orchestrator's ``vulnerabilities_with_detection``
        list, in the same order as the recorded vulns) is used to attach the
        real ``verification_status`` to each timed vulnerability and recompute
        its finished/timeout/error bucket.
        """
        self._finalize_vuln()
        if self._ext is None:
            return
        vulns = self._ext["vulnerabilities"]
        if vuln_records:
            for v, record in zip(vulns, vuln_records):
                status = (record or {}).get("verification_status")
                v["verification_status"] = status
                v["status"] = _classify_vuln(status, v.get("steps", []))
        self._ext["duration_s"] = _round(time.monotonic() - self._ext["_t0"])
        self._ext["status"] = _aggregate([v.get("status") for v in vulns])
        self._ext = None

    # -- vulnerability -------------------------------------------------------
    def start_vuln(self, rule_id, attacker_source=None):
        self._finalize_vuln()
        self._vuln = {
            "rule_id": rule_id,
            "attacker_source": attacker_source,
            "_t0": time.monotonic(),
            "steps": [],
        }
        if self._ext is not None:
            self._ext["vulnerabilities"].append(self._vuln)

    def _finalize_vuln(self):
        if self._vuln is None:
            return
        if "duration_s" not in self._vuln:
            self._vuln["duration_s"] = _round(time.monotonic() - self._vuln["_t0"])
        # Provisional status from steps; refined in end_extension once the
        # verification_status is known.
        self._vuln.setdefault(
            "status", _classify_vuln(None, self._vuln.get("steps", []))
        )
        self._vuln = None

    # -- steps ---------------------------------------------------------------
    @asynccontextmanager
    async def step(self, name, config_timeout=None):
        """Time a single step, tagging it with its outcome (ok/timeout/error).

        ``config_timeout`` is the name of the governing config variable (e.g.
        ``"PAGE_NAVIGATION_TIMEOUT"``); its configured value is recorded too.
        The wrapped exception is always re-raised so existing control flow is
        unchanged.
        """
        rec = {"name": name, "outcome": "ok"}
        if config_timeout:
            rec["config_timeout"] = config_timeout
            rec["timeout_s"] = getattr(config, config_timeout, None)
        t0 = time.monotonic()
        try:
            yield
        except (asyncio.TimeoutError, PlaywrightTimeoutError):
            rec["outcome"] = "timeout"
            raise
        except Exception:
            rec["outcome"] = "error"
            raise
        finally:
            rec["duration_s"] = _round(time.monotonic() - t0)
            target = self._vuln if self._vuln is not None else self._ext
            if target is not None:
                target.setdefault("steps", []).append(rec)

    # -- output --------------------------------------------------------------
    def as_dict(self):
        return _strip_internal(self.run) if self.run else {}


timer = _Timer()
