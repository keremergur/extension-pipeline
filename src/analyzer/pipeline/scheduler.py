"""Parallelism strategies for a dataset run (config.PARALLEL).

Chooses how the config.PARALLEL_WORKERS threads are spent:

    none    - one request in flight (sequential over extensions and candidates).
    inter   - parallel ACROSS extensions; each worker owns one extension and runs
              its candidate chain sequentially (the original PARALLEL_WORKERS>1
              behaviour).
    intra   - one extension at a time, ITS candidates spread across the workers.
              Highest prompt-cache locality (all in-flight requests share the same
              extension's prefix). Candidate-based pipelines only.
    rolling - a global candidate queue that prioritises the current extension and
              backfills spare slots with the next extensions' candidates.
              Candidate-based pipelines only.

The candidate-based pipelines (multi, single_vulnerability -- see
_CANDIDATE_PIPELINES below) each expose prepare/analyze_one_candidate/finalize, so
intra and rolling schedule them at candidate granularity through the same code. The single
pipeline has no per-candidate step, so intra runs sequentially and rolling behaves
like inter for it.
"""

import functools
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Semaphore

import config

from ..logging_utils import log
from . import multi
from . import single_vuln

_VALID_MODES = ("none", "intra", "inter", "rolling")

# Candidate-granular pipelines, keyed by canonical PIPELINE_MODE. A mode absent here
# has no per-candidate step and falls back to a whole-extension schedule.
_CANDIDATE_PIPELINES = {
    "multi": multi,
    "single_vulnerability": single_vuln,
}


def parallel_mode() -> str:
    """Normalise config.PARALLEL to one of _VALID_MODES (default 'inter')."""
    raw = str(getattr(config, "PARALLEL", "inter") or "").strip().lower()
    if raw in ("none", "false", "off", "0", "no"):
        return "none"
    return raw if raw in _VALID_MODES else "inter"


def _run_whole(unit, client, dataset_config, idx, total, pipeline_mode) -> None:
    """Process one whole extension with the configured pipeline (sequential/inter)."""
    # Dispatched through the package's own table, which raises on an unknown mode --
    # the previous `if single ... else multi` silently ran multi for a typo'd
    # PIPELINE_MODE, quietly invalidating the A/B it was set for. Imported here
    # rather than at module scope so the package's import graph stays acyclic.
    from . import analyze_extension
    analyze_extension(unit, client, dataset_config, idx, total, pipeline_mode)


def process_dataset(units, client, dataset_config, pipeline_mode) -> int:
    """Run all `units` under the configured parallel strategy; return count done."""
    mode = parallel_mode()
    workers = max(1, int(getattr(config, "PARALLEL_WORKERS", 1)))
    total = len(units)
    pipeline = _CANDIDATE_PIPELINES.get(pipeline_mode)

    if mode == "none" or workers <= 1:
        return _sequential(units, client, dataset_config, pipeline_mode, total)

    if mode == "inter":
        return _inter(units, client, dataset_config, pipeline_mode, workers, total)

    if mode == "intra":
        if pipeline:
            log(f"Parallel: intra, {workers} workers, one extension at a time")
            return _intra_candidates(units, client, dataset_config, workers, total, pipeline)
        log(f"Parallel: intra has no per-candidate work in the {pipeline_mode} "
            f"pipeline; running sequentially")
        return _sequential(units, client, dataset_config, pipeline_mode, total)

    if mode == "rolling":
        if pipeline:
            log(f"Parallel: rolling, {workers} workers, extension-priority candidate queue")
            return _rolling_candidates(units, client, dataset_config, workers, total, pipeline)
        log(f"Parallel: rolling falls back to inter for the {pipeline_mode} pipeline")
        return _inter(units, client, dataset_config, pipeline_mode, workers, total)

    return _inter(units, client, dataset_config, pipeline_mode, workers, total)


# ---- strategies --------------------------------------------------------

def _sequential(units, client, dataset_config, pipeline_mode, total) -> int:
    log("Parallel: none (sequential)")
    processed = 0
    for idx, unit in enumerate(units, 1):
        try:
            _run_whole(unit, client, dataset_config, idx, total, pipeline_mode)
            processed += 1
        except Exception as e:
            log(f"Error processing {idx}/{total} ({getattr(unit, 'name', unit)}): {e}", "ERROR")
            traceback.print_exc()
    return processed


def _inter(units, client, dataset_config, pipeline_mode, workers, total) -> int:
    log(f"Parallel: inter, {workers} workers across extensions")
    processed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_run_whole, unit, client, dataset_config, idx, total, pipeline_mode):
                (idx, unit)
            for idx, unit in enumerate(units, 1)
        }
        for fut in as_completed(futures):
            idx, unit = futures[fut]
            try:
                fut.result()
                processed += 1
            except Exception as e:
                log(f"Error processing {idx}/{total} ({getattr(unit, 'name', unit)}): {e}", "ERROR")
                traceback.print_exc()
    return processed


def _prepare(pipeline, unit, dataset_config, idx, total):
    """pipeline.prepare with its own guard so one bad report can't abort the dataset."""
    try:
        return pipeline.prepare(unit, dataset_config, idx, total)
    except Exception as e:
        log(f"Error preparing {idx}/{total} ({getattr(unit, 'name', unit)}): {e}", "ERROR")
        traceback.print_exc()
        return None


def _intra_candidates(units, client, dataset_config, workers, total, pipeline) -> int:
    """One extension at a time; its candidates fan out across the workers."""
    processed = 0
    for idx, unit in enumerate(units, 1):
        job = _prepare(pipeline, unit, dataset_config, idx, total)
        if job is None:
            continue
        candidates = job.candidates
        if candidates:
            n = min(workers, len(candidates))
            with ThreadPoolExecutor(max_workers=n) as executor:
                futures = {
                    executor.submit(pipeline.analyze_one_candidate, job, cand, cidx, client): cidx
                    for cidx, cand in enumerate(candidates, 1)
                }
                for fut in as_completed(futures):
                    cidx = futures[fut]
                    try:
                        vuln = fut.result()
                        if vuln is not None:
                            job.record(cidx, vuln)
                    except Exception as e:
                        log(f"[cand {cidx}] error: {e}", "ERROR")
                        traceback.print_exc()
        pipeline.finalize(job)
        processed += 1
    return processed


def _rolling_candidates(units, client, dataset_config, workers, total, pipeline) -> int:
    """Global candidate queue: prioritise the current extension, backfill with the next.

    Candidates are submitted in (extension order, candidate order). A semaphore caps
    in-flight work at `workers`, so the driver only advances to the next extension's
    candidates once the current one's are all submitted and a slot is free -- that is
    the intra-priority-with-inter-backfill behaviour. Each extension's result is
    written by the callback that finishes its last candidate.
    """
    sem = Semaphore(workers)
    lock = Lock()
    finalized = 0

    def on_done(job, cidx, fut):
        nonlocal finalized
        try:
            try:
                vuln = fut.result()
                if vuln is not None:
                    job.record(cidx, vuln)
            except Exception as e:
                log(f"[{job.extension_id[:12]}][cand {cidx}] error: {e}", "ERROR")
                traceback.print_exc()
            with lock:
                job.pending -= 1
                last = job.pending == 0
            if last:
                try:
                    pipeline.finalize(job)
                except Exception as e:
                    log(f"finalize failed for {job.extension_id[:12]}: {e}", "ERROR")
                    traceback.print_exc()
                with lock:
                    finalized += 1
        finally:
            sem.release()  # always free the slot, even on an unexpected error

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for idx, unit in enumerate(units, 1):
            job = _prepare(pipeline, unit, dataset_config, idx, total)
            if job is None:
                continue
            if not job.candidates:
                pipeline.finalize(job)  # nothing to run; write an empty result
                with lock:
                    finalized += 1
                continue
            job.pending = len(job.candidates)
            for cidx, cand in enumerate(job.candidates, 1):
                sem.acquire()  # blocks until a slot frees -> keeps the queue ext-ordered
                fut = executor.submit(pipeline.analyze_one_candidate, job, cand, cidx, client)
                fut.add_done_callback(functools.partial(on_done, job, cidx))
        # executor.__exit__ waits for all in-flight candidates (and their callbacks).
    return finalized
