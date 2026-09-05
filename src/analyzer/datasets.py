"""Dataset discovery: collect, filter and validate the units to analyze.

A "unit" is either an extension directory (coco/doublex) or a report JSON file
(codeql); the per-tool differences live in the tool adapters, this module just
drives them.
"""

from pathlib import Path
from typing import List

import config

from .logging_utils import log, log_message
from .tools import get_adapter


def get_extensions_for_dataset(dataset_config: dict) -> List[Path]:
    """Return the validated list of units (dirs or report files) for a dataset."""
    dataset_name = dataset_config["name"]
    adapter = get_adapter(dataset_config["tool"])
    reports_dir = config.DATASETS_DIR / dataset_name

    if not reports_dir.exists():
        log(f"Directory not found: {reports_dir}", "ERROR")
        return []

    all_units = adapter.collect_units(reports_dir)
    units = _filter_units(all_units, dataset_config)
    return _validate_units(units, dataset_config, adapter)


def _filter_units(units: List[Path], dataset_config: dict) -> List[Path]:
    """Apply the `specific` allow-list or the `limit` cap."""
    specific = dataset_config.get("specific")
    limit = dataset_config.get("limit")

    if specific:
        units = [u for u in units if u.name in specific]
        log(f"Filtered to {len(units)} specific extensions")
        return units

    units = sorted(units)
    if limit and limit > 0:
        units = units[:limit]
        log(f"Limited to {limit} extensions")
    return units


def _validate_units(units: List[Path], dataset_config: dict, adapter) -> List[Path]:
    """Keep only units that actually have a readable report."""
    dataset_name = dataset_config["name"]
    valid = []
    invalid_count = 0

    for unit in units:
        report_path = adapter.get_report_path(unit, dataset_name)
        if report_path and report_path.exists():
            valid.append(unit)
        else:
            invalid_count += 1
            log_message(dataset_name, "INVALID", f"{unit.name} - Missing report")

    if invalid_count > 0:
        log(f"Skipped {invalid_count} extensions without datasets")
    return valid
