import sys
from pathlib import Path

# Make src/ importable so `import config`, `from mock_server ...`, and
# `from helpers... ` resolve exactly as they did in the original script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
