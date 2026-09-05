from pathlib import Path

import config

# src/ directory (parent of the verifier package)
SRC_DIR = Path(__file__).resolve().parent.parent

# Read-only template directory shipped with the image.
VERIFIER_EXTENSIONS_TEMPLATE_DIR = SRC_DIR / "verifier_extensions"

# Writable per-run working directory for verifier extension copies.
VERIFIER_EXTENSIONS_DIR = config.VERIFIER_EXTENSIONS_DIR
