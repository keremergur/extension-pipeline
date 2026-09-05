"""Tool-adapter registry.

Add a new static-analysis tool by implementing a ToolAdapter subclass and
registering it here; the rest of the pipeline is tool-agnostic.
"""

from .base import Candidate, PreparedReport, ToolAdapter
from .codeql import CodeQLAdapter
from .coco import CoCoAdapter
from .doublex import DoubleXAdapter

_ADAPTERS = {
    "codeql": CodeQLAdapter,
    "coco": CoCoAdapter,
    "doublex": DoubleXAdapter,
}


def get_adapter(tool_type: str) -> ToolAdapter:
    """Return an adapter instance for the given tool type."""
    try:
        return _ADAPTERS[tool_type]()
    except KeyError:
        raise ValueError(f"Unknown tool type: {tool_type!r}. "
                         f"Known: {', '.join(sorted(_ADAPTERS))}")


__all__ = ["get_adapter", "ToolAdapter", "PreparedReport", "Candidate"]
