"""CodeQL adapter.

Units are SARIF/compact JSON report files. Code is downloaded/extracted from the
remote server on demand. This adapter implements a real preprocessing step
(dropping noise, normalizing old SARIF -> compact) and true per-result candidate
splitting for the multi-step pipeline.
"""

import json
from pathlib import Path
from typing import List, Optional

import config
from helpers.extension_downloader import download_crx, extract_crx

from ..extension_io import extract_code_context, read_file_safe
from .base import Candidate, PreparedReport, ToolAdapter


class CodeQLAdapter(ToolAdapter):
    tool_type = "codeql"

    def collect_units(self, reports_dir: Path) -> List[Path]:
        return sorted(f for f in reports_dir.iterdir()
                      if f.is_file() and f.suffix == '.json')

    def get_report_path(self, unit: Path, dataset_name: str) -> Optional[Path]:
        # For CodeQL the unit *is* the report file.
        return unit if unit.is_file() and unit.suffix == '.json' else None

    def extension_id_for(self, unit: Path) -> str:
        return unit.stem

    # -- processing step between the raw query result and the analysis -----
    def preprocess(self, report_content: str) -> str:
        """Handle both old SARIF and new compact format.

        New format (already server-side filtered) is returned as-is. Old SARIF
        is reduced to its results, minus chrome/manifest-version noise.
        """
        try:
            data = json.loads(report_content)
        except json.JSONDecodeError:
            return report_content

        if 'artifacts' in data and 'results' in data:
            return report_content  # already filtered

        results = []
        if data.get('runs'):
            run = data['runs'][0]
            results = [r for r in run.get('results', [])
                       if r.get('ruleId') != 'chrome/manifest-version']
        return json.dumps({"results": results}, indent=2)

    def extract_line_refs(self, report_content: str) -> dict:
        return _line_refs_from_results(_results_of(report_content))

    # -- code availability -------------------------------------------------
    def ensure_code(self, unit: Path, extension_id: str, logger=None) -> None:
        crx_file = config.EXTENSION_CODE_DIR / f"{extension_id}.crx"
        code_dir = config.EXTENSION_CODE_DIR / extension_id
        file_filter = config.EXTRACT_FILE_EXTENSIONS if config.EXTRACT_ONLY_CODE_FILES else None
        if download_crx(extension_id, crx_file, config, logger):
            extract_crx(crx_file, code_dir, logger, file_filter)

    def code_dir_for(self, unit: Path) -> Path:
        return config.EXTENSION_CODE_DIR / unit.stem

    def load_manifest_for(self, unit: Path, extension_id: str) -> Optional[str]:
        return read_file_safe(config.EXTENSION_CODE_DIR / extension_id / "manifest.json")

    # -- per-result candidate splitting -----------------------------------
    def split_candidates(self, prepared: PreparedReport, code_context_lines: int,
                         code_context_mode: str = "lines") -> List[Candidate]:
        results = _results_of(prepared.processed_report)
        if not results:
            return []

        # For mode="used" every candidate is shown all files the whole report
        # references (prepared.line_refs), not just its own.
        all_refs = prepared.line_refs

        candidates: List[Candidate] = []
        for idx, result in enumerate(results):
            rule_id = result.get('query') or result.get('ruleId') or f"result-{idx}"
            snippet = json.dumps({"results": [result]}, indent=2)
            line_refs = _line_refs_from_results([result])
            code_context = extract_code_context(prepared.code_dir, line_refs,
                                                code_context_lines,
                                                mode=code_context_mode,
                                                all_line_refs=all_refs)
            candidates.append(Candidate(
                extension_id=prepared.extension_id,
                tool_type=self.tool_type,
                identifier=rule_id,
                report_snippet=snippet,
                code_context=code_context,
                manifest_content=prepared.manifest_content,
                code_dir=prepared.code_dir,
                line_refs=line_refs,
                all_line_refs=all_refs,
            ))
        return candidates


def _results_of(report_content: str) -> list:
    """Return the results list from either SARIF or compact format."""
    try:
        data = json.loads(report_content)
    except json.JSONDecodeError:
        return []
    if 'results' in data:
        return data.get('results', [])
    return data.get('runs', [{}])[0].get('results', [])


def _loc_fields(loc: dict):
    """Return (file, start_line, end_line) from a location object.

    Handles the super-compact format (file/startLine/endLine directly on the
    location, as produced by the remote '…-super-compact' export) as well as the
    SARIF shape (artifactLocation.file / region.startLine).
    """
    if 'artifactLocation' in loc or 'region' in loc:
        art = loc.get('artifactLocation', {})
        region = loc.get('region', {})
        return art.get('file', ''), region.get('startLine', 0), region.get('endLine', 0)
    return loc.get('file', ''), loc.get('startLine', 0), loc.get('endLine', 0)


def _line_refs_from_results(results: list) -> dict:
    """Extract {filename: [(start, end), ...]} from CodeQL results.

    Covers both the super-compact schema (locations[] + flow[]) and SARIF
    (locations[] with artifactLocation/region + codeFlows[].threadFlows[]).
    """
    line_refs: dict = {}

    def add(loc: dict):
        filename, start_line, end_line = _loc_fields(loc)
        if filename and start_line and start_line > 0:
            line_refs.setdefault(filename, []).append((start_line, end_line or start_line))

    for result in results:
        for loc in result.get('locations', []):
            add(loc)
        # super-compact data-flow path
        for flow_loc in result.get('flow', []):
            add(flow_loc)
        # SARIF data-flow path
        for flow in result.get('codeFlows', []):
            for thread_flow in flow.get('threadFlows', []):
                for flow_loc in thread_flow.get('locations', []):
                    add(flow_loc.get('location', {}))
    return line_refs
