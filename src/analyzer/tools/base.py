"""Tool-adapter abstraction.

Each static-analysis tool (CodeQL, CoCo, DoubleX, ...) plugs in here. An adapter
is responsible for everything that is *tool-specific* about turning a raw report
into something the LLM pipeline can analyze:

    collect_units      discover the dataset's units on disk
    get_report_path    locate a unit's report file
    prepare            load report + manifest + code (download/extract if needed)
    preprocess         << PROCESSING STEP BETWEEN QUERY RESULT AND ANALYSIS >>
                       normalize/filter the raw report before the LLM sees it
    extract_line_refs  map report -> {filename: [(start, end), ...]}
    split_candidates   break a report into per-vulnerability Candidates (multi
                       pipeline). Adapters may return a single whole-report
                       candidate when finer splitting is not implemented yet.

The analysis prompt itself is tool-agnostic (see analyzer.prompt_builder); only
the report text and code excerpt differ per tool, which is what keeps the tools
interchangeable.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ..extension_io import extract_code_context, read_file_safe


@dataclass
class PreparedReport:
    """Everything needed to build a whole-report (single) analysis prompt."""
    extension_id: str
    tool_type: str
    processed_report: str          # after preprocess()
    manifest_content: Optional[str]
    code_context: str              # excerpt covering all findings
    code_dir: Path                 # where the extension's code lives on disk
    line_refs: dict = field(default_factory=dict)
    raw_report: str = ""


@dataclass
class Candidate:
    """A single vulnerability finding to analyze on its own (multi pipeline)."""
    extension_id: str
    tool_type: str
    identifier: str                # e.g. rule_id or a synthetic index
    report_snippet: str            # the sub-report text for just this finding
    code_context: str
    manifest_content: Optional[str] = None
    # Kept so the confidence loopback can re-render this finding's context at a
    # wider scope. code_dir + line_refs describe THIS finding; all_line_refs is
    # the whole extension's referenced files (used by mode="used").
    code_dir: Optional[Path] = None
    line_refs: dict = field(default_factory=dict)
    all_line_refs: dict = field(default_factory=dict)


class ToolAdapter(ABC):
    """Base class; subclasses implement the tool-specific pieces."""

    tool_type: str = "base"

    # -- discovery ---------------------------------------------------------
    @abstractmethod
    def collect_units(self, reports_dir: Path) -> List[Path]:
        ...

    @abstractmethod
    def get_report_path(self, unit: Path, dataset_name: str) -> Optional[Path]:
        ...

    # -- processing step between the raw query result and the analysis -----
    def preprocess(self, report_content: str) -> str:
        """Normalize/filter the raw report before analysis.

        Default is a pass-through. Adapters override this to add tool-specific
        cleanup. This is the deliberate extension point for "processing steps
        between the query result and the analysis"; leave it as-is (empty) for
        tools that do not need it yet.
        """
        return report_content

    @abstractmethod
    def extract_line_refs(self, report_content: str) -> dict:
        ...

    # -- code location -----------------------------------------------------
    def code_dir_for(self, unit: Path) -> Path:
        """Directory holding the extension's source for context extraction."""
        return unit

    def load_manifest(self, unit: Path) -> Optional[str]:
        return read_file_safe(unit / "manifest.json")

    # -- report preparation ------------------------------------------------
    def prepare(self, unit: Path, dataset_name: str, code_context_lines: int,
                logger=None, code_context_mode: str = "lines") -> Optional[PreparedReport]:
        """Load and normalize a unit into a PreparedReport (or None to skip)."""
        extension_id = self.extension_id_for(unit)
        report_path = self.get_report_path(unit, dataset_name)
        if not report_path or not report_path.exists():
            return None

        raw = read_file_safe(report_path)
        if not raw:
            return None

        self.ensure_code(unit, extension_id, logger)
        code_dir = self.code_dir_for(unit)
        manifest = self.load_manifest_for(unit, extension_id)

        processed = self.preprocess(raw)
        line_refs = self.extract_line_refs(raw)
        code_context = extract_code_context(code_dir, line_refs, code_context_lines,
                                            mode=code_context_mode, all_line_refs=line_refs)

        return PreparedReport(
            extension_id=extension_id,
            tool_type=self.tool_type,
            processed_report=processed,
            manifest_content=manifest,
            code_context=code_context,
            code_dir=code_dir,
            line_refs=line_refs,
            raw_report=raw,
        )

    # -- multi-step splitting ---------------------------------------------
    def split_candidates(self, prepared: PreparedReport, code_context_lines: int,
                         code_context_mode: str = "lines") -> List[Candidate]:
        """Split a prepared report into per-finding candidates.

        Default: a single candidate covering the whole report. Tools that can
        isolate individual findings (e.g. CodeQL per-result) override this.
        """
        return [Candidate(
            extension_id=prepared.extension_id,
            tool_type=self.tool_type,
            identifier=prepared.extension_id,
            report_snippet=prepared.processed_report,
            code_context=prepared.code_context,
            manifest_content=prepared.manifest_content,
            code_dir=prepared.code_dir,
            line_refs=prepared.line_refs,
            all_line_refs=prepared.line_refs,
        )]

    # -- hooks that most adapters share -----------------------------------
    def extension_id_for(self, unit: Path) -> str:
        return unit.name

    def ensure_code(self, unit: Path, extension_id: str, logger=None) -> None:
        """Make the extension's code available on disk (no-op by default)."""
        return None

    def load_manifest_for(self, unit: Path, extension_id: str) -> Optional[str]:
        return self.load_manifest(unit)
