import json
from pathlib import Path
from typing import Optional
import config
from helpers.extension_downloader import download_crx, extract_crx
from .logging_utils import log_error, log_info


def get_extension_code_dir(extension_id: str) -> Optional[Path]:
    """Download and extract extension .crx file."""
    extension_dir = config.EXTENSION_CODE_DIR / extension_id
    crx_file = config.EXTENSION_CODE_DIR / f"{extension_id}.crx"

    # Logger wrapper for helper functions
    def logger(msg: str, level: str = "INFO"):
        if level == "ERROR":
            log_error(msg)
        else:
            log_info(msg)

    if config.RESET_EXTENSION_CODE:
        # Force fresh extraction from .crx file
        # Priority: .crx file (local or download) -> extract
        # Fallback: If .crx unavailable but directory exists -> use directory with warning

        if crx_file.exists():
            # Local .crx exists -> extract
            if not extract_crx(crx_file, extension_dir, logger):
                return None
        else:
            # Local .crx doesn't exist -> try download
            if download_crx(extension_id, crx_file, config, logger):
                # Download successful -> extract
                if not extract_crx(crx_file, extension_dir, logger):
                    return None
            else:
                # Download failed -> check if directory exists as fallback
                if extension_dir.exists() and (extension_dir / "manifest.json").exists():
                    log_info(f"WARNING: No .crx file available, using existing extracted directory")
                    log_info(f"Directory: {extension_dir}")
                    return extension_dir
                return None

        # Validate extraction
        if (extension_dir / "manifest.json").exists():
            return extension_dir
        return None

    else:
        # Prefer existing directory (skip re-extraction to preserve manual changes)
        # Priority: Existing directory
        # Fallback: .crx file (local or download) -> extract

        if extension_dir.exists() and (extension_dir / "manifest.json").exists():
            log_info(f"Using existing extension code (RESET_EXTENSION_CODE=False)")
            return extension_dir

        # Directory doesn't exist -> get .crx and extract
        if crx_file.exists():
            # Local .crx exists -> extract
            if not extract_crx(crx_file, extension_dir, logger):
                return None
        else:
            # Local .crx doesn't exist -> try download
            if download_crx(extension_id, crx_file, config, logger):
                # Download successful -> extract
                if not extract_crx(crx_file, extension_dir, logger):
                    return None
            else:
                # Download failed -> check if directory exists as fallback
                if extension_dir.exists() and (extension_dir / "manifest.json").exists():
                    log_info(f"WARNING: No .crx file available, using existing extracted directory")
                    log_info(f"Directory: {extension_dir}")
                    return extension_dir
                return None

        # Validate extraction
        if (extension_dir / "manifest.json").exists():
            return extension_dir
        return None


def validate_extension_structure(extension_dir: Path) -> bool:
    """Validate extension structure (manifest.json exists and is valid)."""
    manifest = extension_dir / "manifest.json"
    if not manifest.exists():
        log_error("No manifest.json found")
        return False

    try:
        with open(manifest, 'r', encoding='utf-8') as f:
            json.load(f)
        return True
    except Exception as e:
        log_error(f"Invalid manifest.json: {e}")
        return False
