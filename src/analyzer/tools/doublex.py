"""DoubleX adapter.

Units are extension directories; the report is a sibling <id>-analysis.json.
No preprocessing is required today, so preprocess() is intentionally left as the
inherited pass-through -- the hook exists if future filtering is needed.
"""

import json
from pathlib import Path
from typing import List, Optional

import config

from .base import ToolAdapter


class DoubleXAdapter(ToolAdapter):
    tool_type = "doublex"

    def collect_units(self, reports_dir: Path) -> List[Path]:
        return [d for d in reports_dir.iterdir() if d.is_dir()]

    def get_report_path(self, unit: Path, dataset_name: str) -> Optional[Path]:
        return config.DATASETS_DIR / dataset_name / f"{unit.name}-analysis.json"

    # preprocess(): inherited pass-through (no DoubleX-specific step yet).

    def extract_line_refs(self, report_content: str) -> dict:
        line_refs: dict = {}
        try:
            data = json.loads(report_content)
        except json.JSONDecodeError:
            return line_refs

        for section in ['cs', 'bp']:
            if section not in data:
                continue
            for danger_type in ['direct_dangers', 'indirect_dangers', 'exfiltration_dangers']:
                for danger_info in data[section].get(danger_type, {}).values():
                    filename = danger_info.get('filename', '')
                    if '/' in filename:
                        filename = filename.split('/')[-1]
                    line_refs.setdefault(filename, [])

                    line_range = str(danger_info.get('line', ''))
                    if ' - ' in line_range:
                        try:
                            start, end = line_range.split(' - ')
                            line_refs[filename].append((int(start), int(end)))
                        except ValueError:
                            pass
                    else:
                        try:
                            line_num = int(line_range)
                            line_refs[filename].append((line_num, line_num))
                        except ValueError:
                            pass
        return line_refs

    # split_candidates: inherits the whole-report default (per-finding splitting
    # not implemented yet).
