"""CoCo adapter.

Units are extension directories. The preprocess step strips code snippets from
the CoCo text report (keeping metadata); code excerpts are re-derived cleanly
from the original source via line references.
"""

from pathlib import Path
from typing import List, Optional

import config

from .base import ToolAdapter


class CoCoAdapter(ToolAdapter):
    tool_type = "coco"

    def collect_units(self, reports_dir: Path) -> List[Path]:
        return [d for d in reports_dir.iterdir() if d.is_dir()]

    def get_report_path(self, unit: Path, dataset_name: str) -> Optional[Path]:
        return unit / "opgen_generated_files" / "used_time.txt"

    # -- processing step between the raw query result and the analysis -----
    def preprocess(self, report_content: str) -> str:
        """Remove code snippets from a CoCo report, keeping only metadata."""
        if not report_content:
            return ""

        cleaned_lines = []
        in_code_block = False
        for line in report_content.split('\n'):
            if line.strip().startswith('Line '):
                in_code_block = True
                continue
            if in_code_block:
                if (line.startswith('$FilePath$') or line.startswith('~~~') or
                        line.startswith('===') or line.startswith('([') or
                        line.strip().startswith('Line ') or not line.strip()):
                    in_code_block = False
                else:
                    continue
            cleaned_lines.append(line)
        return '\n'.join(cleaned_lines)

    def extract_line_refs(self, report_content: str) -> dict:
        line_refs: dict = {}
        current_file = None
        for line in report_content.split('\n'):
            if line.startswith('$FilePath$'):
                file_path = line.replace('$FilePath$', '').strip()
                if '/opgen_generated_files/' in file_path:
                    file_path = file_path.split('/opgen_generated_files/')[-1]
                current_file = file_path
                line_refs.setdefault(current_file, [])
            elif line.strip().startswith('Line ') and current_file:
                try:
                    line_num = int(line.strip().split()[1])
                    line_refs[current_file].append((line_num, line_num))
                except (ValueError, IndexError):
                    pass
        return line_refs

    # split_candidates: inherits the whole-report default. Per-finding splitting
    # for CoCo is not implemented yet (intentionally left empty).
