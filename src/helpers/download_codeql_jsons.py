#!/usr/bin/env python3
"""
Download CodeQL JSON result files from remote server.

Only downloads files with non-empty 'results' array (actual vulnerabilities).
Uses tar archive for efficient batch download instead of individual file transfers.

JSON Format:
{
    "artifacts": [...],  # File mappings
    "results": [...]     # Vulnerability findings (filtered server-side)
}
"""

import os
import json
import tarfile
import tempfile
from pathlib import Path
from dotenv import load_dotenv
import paramiko

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================

# SSH Connection
SSH_HOST = "kuria.plai.ifi.lmu.de"
SSH_PORT = int(os.getenv("FILES_SSH_PORT", "54321"))
SSH_USER = os.getenv("FILES_SSH_USER")
SSH_PASSWORD = os.getenv("FILES_SSH_PASSWORD")

# Paths
REMOTE_DIR = "/home/gobbi/experiment/RESULTS/codeql/1771076517-results/1771076517-super-compact"
LOCAL_DIR = Path(__file__).parent.parent / "datasets" / "codeql_2026_final"


# ============================================================================
# SSH CONNECTION
# ============================================================================

def connect_ssh():
    """Establish SSH connection to remote server."""
    print(f"Connecting to {SSH_USER}@{SSH_HOST}:{SSH_PORT}...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=SSH_HOST,
        port=SSH_PORT,
        username=SSH_USER,
        password=SSH_PASSWORD,
        timeout=30
    )

    print("✓ Connected successfully\n")
    return ssh


# ============================================================================
# FILE DISCOVERY
# ============================================================================

def find_files_with_results(ssh):
    """Find all JSON files with non-empty results array on remote server.

    Returns:
        List of absolute file paths on remote server
    """
    print(f"Searching for files with vulnerabilities in {REMOTE_DIR}...")
    print("(This may take a few minutes...)\n")

    # Strategy: Find files with "query" field (only present in non-empty results)
    # Non-empty results have: "results": [ { "query": "..." } ]
    # Empty results have: "results": []
    # This is more reliable than complex pattern matching
    command = (
        f'find {REMOTE_DIR} -maxdepth 1 -name "*.json" -type f '
        f'-exec grep -l \'"query"\' {{}} \\; 2>/dev/null'
    )

    stdin, stdout, stderr = ssh.exec_command(command, timeout=1200)

    # Parse results
    files = []
    for line in stdout:
        filepath = line.strip()
        if filepath and filepath.endswith('.json'):
            files.append(filepath)

    files.sort()

    # Display summary
    print(f"✓ Found {len(files)} files with vulnerabilities\n")
    if files:
        print("Sample files (first 5):")
        for f in files[:5]:
            print(f"  • {Path(f).name}")
        print()

    return files


# ============================================================================
# FILE DOWNLOAD
# ============================================================================

def get_files_to_download(remote_files):
    """Determine which files need to be downloaded (not already local).

    Args:
        remote_files: List of remote file paths

    Returns:
        Tuple of (files_to_download, skipped_count)
    """
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)

    existing_files = {f.name for f in LOCAL_DIR.glob("*.json")}
    files_to_download = [f for f in remote_files if Path(f).name not in existing_files]
    skipped_count = len(remote_files) - len(files_to_download)

    if skipped_count > 0:
        print(f"Skipping {skipped_count} files (already exist locally)")

    return files_to_download, skipped_count


def download_via_tar(ssh, remote_files):
    """Download files by creating tar archive on server and transferring it.

    Args:
        ssh: Active SSH connection
        remote_files: List of absolute file paths on remote server

    Returns:
        Number of successfully downloaded files
    """
    if not remote_files:
        print("No files to download\n")
        return 0

    print(f"\nDownloading {len(remote_files)} files via tar archive...")

    # Temporary file names
    remote_filelist = f"/tmp/codeql_filelist_{os.getpid()}.txt"
    remote_tarfile = f"/tmp/codeql_download_{os.getpid()}.tar.gz"

    try:
        sftp = ssh.open_sftp()

        # 1. Create file list on server (just basenames)
        print("  1/4 Creating file list on server...")
        filenames = [Path(f).name for f in remote_files]
        with sftp.file(remote_filelist, 'w') as f:
            f.write("\n".join(filenames))

        # 2. Create tar archive on server
        print("  2/4 Creating tar archive on server...")
        tar_command = f'cd {REMOTE_DIR} && tar -czf {remote_tarfile} -T {remote_filelist}'
        stdin, stdout, stderr = ssh.exec_command(tar_command, timeout=600)
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            error_msg = stderr.read().decode()
            raise Exception(f"Failed to create tar archive: {error_msg}")

        # Get archive size
        stdin, stdout, stderr = ssh.exec_command(f'stat -c%s {remote_tarfile}')
        tar_size = int(stdout.read().decode().strip())
        tar_size_mb = tar_size / (1024 * 1024)
        print(f"      Archive size: {tar_size_mb:.1f} MB")

        # 3. Download tar archive
        print("  3/4 Downloading archive...")
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
            local_tarfile = tmp.name

        sftp.get(remote_tarfile, local_tarfile)
        sftp.close()

        # 4. Extract files
        print("  4/4 Extracting files...")
        try:
            with tarfile.open(local_tarfile, 'r:gz') as tar:
                tar.extractall(path=LOCAL_DIR)

            print(f"✓ Extracted {len(remote_files)} files to {LOCAL_DIR.name}/\n")
            return len(remote_files)

        finally:
            # Cleanup local temp file
            if os.path.exists(local_tarfile):
                os.unlink(local_tarfile)

    finally:
        # Cleanup remote temp files
        print("Cleaning up temporary files...")
        ssh.exec_command(f'rm -f {remote_filelist} {remote_tarfile}')


# ============================================================================
# VERIFICATION
# ============================================================================

def verify_local_files():
    """Verify that downloaded files have non-empty results array.

    Returns:
        Tuple of (valid_count, invalid_count)
    """
    print("\nVerifying downloaded files...")

    json_files = list(LOCAL_DIR.glob("*.json"))
    valid = 0
    invalid = 0
    invalid_files = []

    for idx, file_path in enumerate(json_files, 1):
        # Progress indicator
        if idx % 500 == 0:
            print(f"  Checked {idx}/{len(json_files)} files...")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check: results array exists and is not empty
            if 'results' in data and isinstance(data['results'], list) and len(data['results']) > 0:
                valid += 1
            else:
                invalid += 1
                invalid_files.append(file_path.name)

        except Exception as e:
            invalid += 1
            invalid_files.append(file_path.name)
            print(f"  Error reading {file_path.name}: {e}")

    # Summary
    print(f"\n✓ Verification complete:")
    print(f"    Valid (non-empty results): {valid}")
    print(f"    Invalid (empty results):   {invalid}")

    # Show invalid files (if not too many)
    if invalid_files and len(invalid_files) <= 10:
        print(f"\n  Invalid files:")
        for f in invalid_files:
            print(f"    • {f}")
    elif invalid > 0:
        print(f"\n  {invalid} files have empty results (not shown)")

    return valid, invalid


# ============================================================================
# MAIN WORKFLOW
# ============================================================================

def main():
    """Main workflow: connect, find, download, verify."""
    print("=" * 80)
    print("CodeQL JSON Downloader")
    print("=" * 80)
    print()

    # Validate configuration
    if not all([SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD]):
        print("ERROR: SSH credentials not found in .env file")
        print("Required: FILES_SSH_USER, FILES_SSH_PASSWORD, FILES_SSH_PORT")
        return

    try:
        # 1. Connect to server
        ssh = connect_ssh()

        # 2. Find files with vulnerabilities
        remote_files = find_files_with_results(ssh)

        if not remote_files:
            print("No files found with vulnerabilities")
            ssh.close()
            return

        # 3. Determine what to download
        files_to_download, skipped = get_files_to_download(remote_files)

        if not files_to_download:
            print(f"\n✓ All {len(remote_files)} files already exist locally")
            ssh.close()
            verify_local_files()
            return

        # 4. Confirm download
        print(f"\nReady to download:")
        print(f"  • New files:      {len(files_to_download)}")
        print(f"  • Already local:  {skipped}")
        print(f"  • Total:          {len(remote_files)}")
        print(f"  • Destination:    {LOCAL_DIR}")
        print()

        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            print("Download cancelled")
            ssh.close()
            return

        # 5. Download files
        downloaded = download_via_tar(ssh, files_to_download)
        ssh.close()
        print("✓ SSH connection closed\n")

        # 6. Verify downloads
        if downloaded > 0:
            verify_local_files()

        # Final summary
        print("\n" + "=" * 80)
        print(f"Download complete: {downloaded} new, {skipped} skipped")
        print("=" * 80)

    except KeyboardInterrupt:
        print("\n\nDownload interrupted by user")

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
