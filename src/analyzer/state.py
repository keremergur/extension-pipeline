"""Run-time globals shared across the analyzer package.

The original single-file script used module-level globals (CURRENT_RESULTS_DIR,
CURRENT_DATASET_NAME) for logging and output paths. Keeping them in one tiny
module lets every sub-module read/write the same run context without threading a
context object through every function signature.
"""

from pathlib import Path
from typing import Optional

# Directory for the current run (results_<model>_<timestamp>/), set in main().
CURRENT_RESULTS_DIR: Optional[Path] = None

# Name of the dataset currently being processed, used for per-dataset logging.
CURRENT_DATASET_NAME: Optional[str] = None
