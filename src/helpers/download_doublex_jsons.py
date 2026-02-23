#!/usr/bin/env python3
"""
Download DoubleX analysis JSON files from SSH server that contain "dataflow": true.
Excludes files ending with -war.json.
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv
import paramiko

# Try to import tqdm, use simple progress if not available
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, desc="Progress"):
        """Simple fallback for tqdm if not installed."""
        return iterable

# Load environment variables
load_dotenv()

# SSH Configuration for kuria server (where the analysis results are stored)
SSH_HOST = "kuria.plai.ifi.lmu.de"
SSH_PORT = int(os.getenv("SSH_PORT", "54321"))
SSH_USER = os.getenv("SSH_USER")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")

# Remote and local paths
REMOTE_DIR = "/home/gobbi/experiment/RESULTS/doublex/analysis/matias_original_patrick"
LOCAL_DIR = Path(__file__).parent / "datasets" / "doublex"

def connect_ssh():
    """Establish SSH connection to server."""
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
    print("✓ Connected successfully")
    return ssh

def find_dataflow_files(ssh):
    """Find all JSON files containing 'dataflow': true on remote server (excluding -war.json files)."""
    print(f"\nSearching for files with 'dataflow': true in {REMOTE_DIR}...")
    print("(This may take several minutes due to 300k+ files)")

    # Use find + xargs + grep to handle large number of files
    # find: locate all .json files excluding -war.json
    # xargs: pass files to grep in batches
    # grep: search for "dataflow": true pattern
    command = f'find {REMOTE_DIR} -maxdepth 1 -name "*.json" ! -name "*-war.json" -type f | xargs grep -l "\\"dataflow\\".*:.*true" 2>/dev/null'

    print(f"Searching with find + xargs + grep...")
    stdin, stdout, stderr = ssh.exec_command(command, timeout=1200)

    # Read results
    files = []
    for line in stdout:
        filepath = line.strip()
        if filepath:
            # Extract just the filename from full path
            filename = os.path.basename(filepath)
            if filename.endswith('.json') and not filename.endswith('-war.json'):
                files.append(filename)

    # Check for errors
    error = stderr.read().decode('utf-8').strip()
    if error and "grep:" not in error and "xargs:" not in error:
        print(f"Warning: {error}")

    print(f"✓ Found {len(files)} files with 'dataflow': true")
    return files

def download_files(ssh, files):
    """Download files from remote server via SFTP."""
    # Create local directory if it doesn't exist
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\nDownloading {len(files)} files to {LOCAL_DIR}...")

    # Open SFTP connection
    sftp = ssh.open_sftp()

    downloaded = 0
    skipped = 0
    failed = 0

    try:
        if HAS_TQDM:
            iterator = tqdm(files, desc="Downloading")
        else:
            iterator = files
            print("Progress: ", end="", flush=True)

        for idx, filename in enumerate(iterator, 1):
            remote_path = f"{REMOTE_DIR}/{filename}"
            local_path = LOCAL_DIR / filename

            # Skip if file already exists locally
            if local_path.exists():
                skipped += 1
                continue

            try:
                sftp.get(remote_path, str(local_path))
                downloaded += 1

                # Manual progress indicator if tqdm not available
                if not HAS_TQDM and idx % 10 == 0:
                    print(f"{idx}/{len(files)} ", end="", flush=True)

            except Exception as e:
                print(f"\nError downloading {filename}: {e}")
                failed += 1

        if not HAS_TQDM:
            print()  # Newline after progress

    finally:
        sftp.close()

    print(f"\n✓ Download complete:")
    print(f"  - Downloaded: {downloaded} files")
    print(f"  - Skipped (already exists): {skipped} files")
    if failed > 0:
        print(f"  - Failed: {failed} files")

    return downloaded, skipped, failed

def verify_downloads():
    """Verify that downloaded files actually contain 'dataflow': true."""
    print("\nVerifying downloaded files...")

    json_files = list(LOCAL_DIR.glob("*.json"))
    valid = 0
    invalid = 0

    if HAS_TQDM:
        iterator = tqdm(json_files, desc="Verifying")
    else:
        iterator = json_files
        print("Progress: ", end="", flush=True)

    for idx, file_path in enumerate(iterator, 1):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if data.get("dataflow") == True:
                    valid += 1
                else:
                    invalid += 1
                    print(f"\nWarning: {file_path.name} does not have 'dataflow': true")
        except Exception as e:
            invalid += 1
            print(f"\nError reading {file_path.name}: {e}")

        # Manual progress indicator if tqdm not available
        if not HAS_TQDM and idx % 100 == 0:
            print(f"{idx}/{len(json_files)} ", end="", flush=True)

    if not HAS_TQDM:
        print()  # Newline after progress

    print(f"\n✓ Verification complete:")
    print(f"  - Valid files: {valid}")
    print(f"  - Invalid files: {invalid}")

    return valid, invalid

def main():
    """Main function."""
    print("="*80)
    print("DoubleX Dataflow File Downloader")
    print("="*80)

    # Check SSH credentials
    if not all([SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD]):
        print("ERROR: SSH credentials not found in .env file")
        print("Please ensure SSH_HOST, SSH_PORT, SSH_USER, and SSH_PASSWORD are set")
        return

    try:
        # Connect to SSH server
        ssh = connect_ssh()

        # Find files with dataflow: true
        files = find_dataflow_files(ssh)

        if not files:
            print("No files found with 'dataflow': true")
            ssh.close()
            return

        # Ask user for confirmation
        print(f"\nReady to download {len(files)} files to {LOCAL_DIR}")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            print("Download cancelled")
            ssh.close()
            return

        # Download files
        downloaded, skipped, failed = download_files(ssh, files)

        # Close SSH connection
        ssh.close()
        print("\n✓ SSH connection closed")

        # Verify downloads
        if downloaded > 0:
            verify_downloads()

        print("\n" + "="*80)
        print("Download complete!")
        print("="*80)

    except KeyboardInterrupt:
        print("\n\nDownload interrupted by user")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
