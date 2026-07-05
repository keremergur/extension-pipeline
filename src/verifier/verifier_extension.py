import shutil
from pathlib import Path
from typing import Optional
from .logging_utils import log_error, log_success
from .paths import VERIFIER_EXTENSIONS_DIR


def prepare_verifier_extension(extension_id: str, payload: str) -> Optional[Path]:
    """Copy verifier extension template and inject payload."""
    try:
        verifier_template = VERIFIER_EXTENSIONS_DIR / "_original"
        if not verifier_template.exists():
            log_error(f"Verifier extension template not found: {verifier_template}")
            return None

        # Create directory for this specific verification
        verifier_dir = VERIFIER_EXTENSIONS_DIR / f"{extension_id}_verifier"

        # Remove old version if exists
        if verifier_dir.exists():
            shutil.rmtree(verifier_dir)

        verifier_dir.mkdir(parents=True, exist_ok=True)

        # Copy manifest.json
        manifest_src = verifier_template / "manifest.json"
        manifest_dst = verifier_dir / "manifest.json"
        shutil.copy(manifest_src, manifest_dst)

        # Read content_script template
        content_script_template = verifier_template / "content_script.js"
        with open(content_script_template, 'r', encoding='utf-8') as f:
            content = f.read()

        # Inject payload
        content = content.replace(
            "// ===== PAYLOAD_PLACEHOLDER_START =====\n      // The actual payload will be inserted here by the verifier\n      // ===== PAYLOAD_PLACEHOLDER_END =====",
            payload
        )

        # Write modified content_script.js
        content_script_dst = verifier_dir / "content_script.js"
        with open(content_script_dst, 'w', encoding='utf-8') as f:
            f.write(content)

        log_success(f"Verifier extension prepared for {extension_id}")
        return verifier_dir

    except Exception as e:
        log_error(f"Failed to prepare verifier extension: {e}")
        return None
