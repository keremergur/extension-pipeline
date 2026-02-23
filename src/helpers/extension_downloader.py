"""
Helper module for downloading and extracting Chrome extensions.

Provides shared functionality for downloading .crx files via SSH and extracting them.
Used by both analyze_extensions.py and verify_extensions.py.
"""

import shutil
import zipfile
import io
import tarfile
from pathlib import Path
from typing import Optional
import paramiko


def download_crx(extension_id: str, local_crx_path: Path, config, logger_func=None) -> bool:
    """
    Download .crx file from remote server via SFTP.

    Args:
        extension_id: The extension ID to download
        local_crx_path: Local file path where to save the .crx file
        config: Config module with SSH credentials
        logger_func: Optional logging function (signature: func(message, level))

    Returns:
        True if download successful, False otherwise
    """
    def log(msg: str, level: str = "INFO"):
        if logger_func:
            logger_func(msg, level)

    # Check if already exists locally
    if local_crx_path.exists():
        log(f"CRX file already exists: {local_crx_path.name}", "INFO")
        return True

    # Check SSH credentials
    if not all([config.FILES_SSH_USER, config.FILES_SSH_PASSWORD]):
        log("SSH credentials not configured for file server", "ERROR")
        return False

    try:
        # Connect via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=config.FILES_SSH_HOST,
            port=config.FILES_SSH_PORT,
            username=config.FILES_SSH_USER,
            password=config.FILES_SSH_PASSWORD,
            timeout=30
        )

        # Open SFTP connection
        sftp = ssh.open_sftp()

        # Remote path for this extension's .crx file
        remote_crx = f"{config.FILES_SSH_EXTENSIONS_DATASET_DIR}/{extension_id}.crx"

        # Check if remote file exists
        try:
            sftp.stat(remote_crx)
        except IOError:
            log(f"CRX file not found on server: {extension_id}.crx", "ERROR")
            sftp.close()
            ssh.close()
            return False

        # Create local directory
        local_crx_path.parent.mkdir(parents=True, exist_ok=True)

        # Download the .crx file
        sftp.get(remote_crx, str(local_crx_path))
        sftp.close()
        ssh.close()

        log(f"Downloaded CRX file: {extension_id}.crx", "INFO")
        return True

    except Exception as e:
        log(f"Failed to download CRX: {e}", "ERROR")
        return False


def extract_crx(crx_path: Path, extract_dir: Path, logger_func=None,
               filter_extensions: list = None) -> bool:
    """
    Extract .crx file to directory, handling both modern and legacy formats.

    Args:
        crx_path: Path to the .crx file
        extract_dir: Directory where to extract the contents
        logger_func: Optional logging function (signature: func(message, level))
        filter_extensions: Optional list of file extensions to extract (e.g. ['.js', '.json', '.html'])
                          If None, extracts all files. Directories are always extracted.

    Returns:
        True if extraction successful, False otherwise
    """
    def log(msg: str, level: str = "INFO"):
        if logger_func:
            logger_func(msg, level)

    def should_extract(filename: str) -> bool:
        """Check if file should be extracted based on filter."""
        if not filter_extensions:
            return True  # No filter, extract everything

        # Always extract directories (needed for structure)
        if filename.endswith('/'):
            return True

        # Check if file matches any of the allowed extensions
        return any(filename.lower().endswith(ext.lower()) for ext in filter_extensions)

    # Remove existing extraction directory
    if extract_dir.exists():
        shutil.rmtree(extract_dir)

    try:
        extract_dir.mkdir(parents=True, exist_ok=True)

        # Try direct extraction first (modern CRX)
        try:
            with zipfile.ZipFile(crx_path, 'r') as zip_ref:
                if filter_extensions:
                    # Extract only filtered files
                    for file_info in zip_ref.filelist:
                        if should_extract(file_info.filename):
                            zip_ref.extract(file_info, extract_dir)
                else:
                    # Extract everything
                    zip_ref.extractall(extract_dir)

            log_msg = f"Extracted CRX: {crx_path.name}"
            if filter_extensions:
                log_msg += f" (filtered: {', '.join(filter_extensions)})"
            log(log_msg, "INFO")
            return True
        except:
            # Try with offset (legacy CRX - skip first 16 bytes)
            with open(crx_path, 'rb') as f:
                f.seek(16)
                with zipfile.ZipFile(io.BytesIO(f.read()), 'r') as zip_ref:
                    if filter_extensions:
                        # Extract only filtered files
                        for file_info in zip_ref.filelist:
                            if should_extract(file_info.filename):
                                zip_ref.extract(file_info, extract_dir)
                    else:
                        # Extract everything
                        zip_ref.extractall(extract_dir)

            log_msg = f"Extracted CRX (legacy format): {crx_path.name}"
            if filter_extensions:
                log_msg += f" (filtered: {', '.join(filter_extensions)})"
            log(log_msg, "INFO")
            return True

    except Exception as e:
        log(f"Failed to extract CRX: {e}", "ERROR")
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        return False


def get_extension_code(
    extension_id: str,
    extension_code_dir: Path,
    crx_file: Path,
    config,
    logger_func=None,
    skip_if_exists: bool = False,
    filter_extensions: list = None
) -> Optional[Path]:
    """
    Download and extract extension code.

    Combines download_crx() and extract_crx() with additional logic for
    skipping re-extraction if desired.

    Args:
        extension_id: Extension ID to download
        extension_code_dir: Directory where to extract the extension
        crx_file: Path to the .crx file (will be downloaded if missing)
        config: Config module with paths and SSH credentials
        logger_func: Optional logging function (signature: func(message, level))
        skip_if_exists: If True, skip extraction if directory already exists with manifest.json
        filter_extensions: Optional list of file extensions to extract (e.g. ['.js', '.json', '.html'])

    Returns:
        Path to extracted extension directory if successful, None otherwise
    """
    def log(msg: str, level: str = "INFO"):
        if logger_func:
            logger_func(msg, level)

    # Check if we should skip re-extraction
    if skip_if_exists:
        if extension_code_dir.exists() and (extension_code_dir / "manifest.json").exists():
            log(f"Using existing extension code: {extension_id}", "INFO")
            return extension_code_dir

    # Download .crx if needed
    if not crx_file.exists():
        if not download_crx(extension_id, crx_file, config, logger_func):
            return None

    # Extract extension code
    if not extract_crx(crx_file, extension_code_dir, logger_func, filter_extensions):
        return None

    # Validate extraction
    if (extension_code_dir / "manifest.json").exists():
        return extension_code_dir

    log(f"No manifest.json found in extracted extension: {extension_id}", "ERROR")
    return None


def download_extensions_tar(local_extract_dir: Path, config, logger_func=None) -> bool:
    """
    Download all extensions as a single tar file (MUCH faster than individual downloads).

    This is the recommended approach for large datasets (8k+ extensions).

    Args:
        local_extract_dir: Directory where to extract .crx files
        config: Config module with SSH credentials and tar path
        logger_func: Optional logging function (signature: func(message, level))

    Returns:
        True if download and extraction successful, False otherwise
    """
    def log(msg: str, level: str = "INFO"):
        if logger_func:
            logger_func(msg, level)

    # Check if tar download is enabled
    if not config.USE_TAR_DOWNLOAD:
        log("Tar download disabled in config", "INFO")
        return False

    # Check SSH credentials
    if not all([config.FILES_SSH_USER, config.FILES_SSH_PASSWORD, config.FILES_SSH_TAR_PATH]):
        log("SSH credentials or tar path not configured", "ERROR")
        return False

    try:
        log(f"Downloading extensions tar file (this may take a while)...", "INFO")

        # Connect via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=config.FILES_SSH_HOST,
            port=config.FILES_SSH_PORT,
            username=config.FILES_SSH_USER,
            password=config.FILES_SSH_PASSWORD,
            timeout=60
        )

        # Open SFTP connection
        sftp = ssh.open_sftp()

        # Check if remote tar exists
        try:
            sftp.stat(config.FILES_SSH_TAR_PATH)
        except IOError:
            log(f"Tar file not found on server: {config.FILES_SSH_TAR_PATH}", "ERROR")
            sftp.close()
            ssh.close()
            return False

        # Download tar to temp location
        local_tar_path = local_extract_dir / "extensions_download.tar.gz"
        local_extract_dir.mkdir(parents=True, exist_ok=True)

        log(f"Downloading: {config.FILES_SSH_TAR_PATH}", "INFO")
        sftp.get(config.FILES_SSH_TAR_PATH, str(local_tar_path))
        sftp.close()
        ssh.close()

        log(f"Download complete. Extracting tar file...", "INFO")

        # Extract tar file
        with tarfile.open(local_tar_path, 'r:gz') as tar:
            tar.extractall(local_extract_dir)

        # Clean up tar file
        local_tar_path.unlink()

        log(f"✓ Extensions tar extracted successfully", "INFO")
        return True

    except Exception as e:
        log(f"Failed to download/extract tar: {e}", "ERROR")
        return False
