"""Backward-compatible entry point for the extension analyzer.

The analyzer was refactored from this single file into the `analyzer/` package.
Running `python analyze_extensions.py` still works and behaves as before; the
implementation now lives in analyzer/ (see analyzer/main.py). You can equally run
it as a module: `python -m analyzer`.
"""

from analyzer.main import main

if __name__ == "__main__":
    main()
