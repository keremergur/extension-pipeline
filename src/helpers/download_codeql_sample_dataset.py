#!/usr/bin/env python3
"""
Download a representative sample dataset of CodeQL JSON files.

For each unique query type present in the dataset, selects up to
SAMPLES_PER_QUERY JSON files. This creates a small, balanced sample
that covers all vulnerability categories — useful for testing the
analysis pipeline without downloading the full dataset.

Strategy:
  A Python scanner runs on the remote server in a single pass through
  all JSON files. It groups files by query type and collects the first
  N files per query. The selected files are then transferred via tar.

Output:
  src/datasets/codeql_sample/
    <extension_id>.json       downloaded sample files
    _sample_index.json        index mapping each query to its sample files

JSON Format (per file):
  {
      "artifacts": [...],
      "results": [{"query": "chrome/trigger/network-request", ...}, ...]
  }
"""

import os
import json
import tarfile
import tempfile
from pathlib import Path
from dotenv import load_dotenv
import paramiko

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
LOCAL_DIR = Path(__file__).parent.parent / "datasets" / "codeql_sample"
STATS_FILE = Path(__file__).parent.parent / "docs" / "stats" / "stats.json"

# How many example files to collect per unique query type
SAMPLES_PER_QUERY = 2


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
# REMOTE FILE SELECTION
# ============================================================================

# Server-side scanner script (placeholders replaced before upload)
_SCANNER_SCRIPT = """\
import json, os, sys
from pathlib import Path

REMOTE_DIR = "__REMOTE_DIR__"
N = __SAMPLES_PER_QUERY__

# query_name -> list of filenames (up to N entries)
query_samples = {}

filenames = sorted(
    fn for fn in os.listdir(REMOTE_DIR) if fn.endswith(".json")
)
total = len(filenames)

for i, fn in enumerate(filenames):
    if i % 5000 == 0:
        print(f"PROGRESS:{i}/{total}", flush=True)

    try:
        with open(os.path.join(REMOTE_DIR, fn)) as f:
            data = json.load(f)
    except Exception:
        continue

    results = data.get("results", [])
    if not results:
        continue

    for r in results:
        q = r.get("query")
        if not q:
            continue
        bucket = query_samples.setdefault(q, [])
        if fn not in bucket and len(bucket) < N:
            bucket.append(fn)

# Output: one line per (query, file) pair
for q in sorted(query_samples):
    for fn in query_samples[q]:
        print(f"SAMPLE:{q}\\t{fn}")

print(f"DONE:{len(query_samples)}", flush=True)
"""


def select_files_remotely(ssh):
    """Upload and run the scanner script on the server.

    Returns:
        Tuple of:
          - query_files: dict mapping query -> [filename, ...]
          - all_filenames: sorted list of unique filenames to download
    """
    print("Uploading scanner script to remote server...")
    script_content = (
        _SCANNER_SCRIPT
        .replace("__REMOTE_DIR__", REMOTE_DIR)
        .replace("__SAMPLES_PER_QUERY__", str(SAMPLES_PER_QUERY))
    )

    remote_script = f"/tmp/codeql_sample_scan_{os.getpid()}.py"
    sftp = ssh.open_sftp()
    with sftp.file(remote_script, "w") as f:
        f.write(script_content)
    sftp.close()

    print("Running single-pass scan on server (may take several minutes)...\n")

    try:
        stdin, stdout, stderr = ssh.exec_command(
            f"python3 {remote_script}",
            timeout=3600
        )

        query_files = {}   # query -> [filename, ...]
        total_queries = 0

        for line in stdout:
            line = line.strip()
            if not line:
                continue

            if line.startswith("SAMPLE:"):
                # Format: SAMPLE:chrome/trigger/network-request\tfilename.json
                payload = line[7:]
                query, filename = payload.split("\t", 1)
                query_files.setdefault(query, []).append(filename)

            elif line.startswith("PROGRESS:"):
                current, total = line[9:].split("/")
                pct = int(current) / int(total) * 100
                print(f"  Scanning: {current}/{total} ({pct:.0f}%)  ", end="\r")

            elif line.startswith("DONE:"):
                total_queries = int(line[5:])
                print()  # clear progress line

        # Show any server-side errors
        errors = stderr.read().decode().strip()
        if errors:
            print(f"\n  Server warnings:\n{errors}\n")

    finally:
        ssh.exec_command(f"rm -f {remote_script}")

    # Collect unique filenames (preserving discovery order per query)
    seen = set()
    all_filenames = []
    for files in query_files.values():
        for fn in files:
            if fn not in seen:
                seen.add(fn)
                all_filenames.append(fn)
    all_filenames.sort()

    # Summary
    partial = {q: files for q, files in query_files.items()
               if len(files) < SAMPLES_PER_QUERY}

    print(f"✓ Scan complete:")
    print(f"    Query types found:   {len(query_files)}")
    print(f"    Unique files needed: {len(all_filenames)}")
    if partial:
        print(f"    Partial (< {SAMPLES_PER_QUERY} examples found):")
        for q, files in sorted(partial.items()):
            print(f"      ⚠ {q}: {len(files)} example(s) only")
    print()

    return query_files, all_filenames


# ============================================================================
# FILE DOWNLOAD
# ============================================================================

def get_files_to_download(all_filenames):
    """Filter out files that are already present locally.

    Args:
        all_filenames: Sorted list of remote basenames

    Returns:
        Tuple of (files_to_download, skipped_count)
    """
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)

    existing = {f.name for f in LOCAL_DIR.glob("*.json")}
    to_download = [fn for fn in all_filenames if fn not in existing]
    skipped = len(all_filenames) - len(to_download)

    if skipped > 0:
        print(f"Skipping {skipped} files (already exist locally)")

    return to_download, skipped


def download_via_tar(ssh, filenames):
    """Download files by creating a tar archive on the server and transferring it.

    Args:
        ssh: Active SSH connection
        filenames: List of basenames to download

    Returns:
        Number of files successfully downloaded
    """
    if not filenames:
        print("No files to download\n")
        return 0

    print(f"\nDownloading {len(filenames)} files via tar archive...")

    remote_filelist = f"/tmp/codeql_sample_filelist_{os.getpid()}.txt"
    remote_tarfile = f"/tmp/codeql_sample_tar_{os.getpid()}.tar.gz"

    try:
        sftp = ssh.open_sftp()

        # 1. Write file list on server
        print("  1/4 Creating file list on server...")
        with sftp.file(remote_filelist, "w") as f:
            f.write("\n".join(filenames))

        # 2. Create tar archive
        print("  2/4 Creating tar archive on server...")
        tar_cmd = f"cd {REMOTE_DIR} && tar -czf {remote_tarfile} -T {remote_filelist}"
        stdin, stdout, stderr = ssh.exec_command(tar_cmd, timeout=600)
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            raise Exception(f"tar failed: {stderr.read().decode()}")

        stdin, stdout, stderr = ssh.exec_command(f"stat -c%s {remote_tarfile}")
        tar_mb = int(stdout.read().decode().strip()) / (1024 * 1024)
        print(f"      Archive size: {tar_mb:.1f} MB")

        # 3. Transfer archive
        print("  3/4 Downloading archive...")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
            local_tarfile = tmp.name

        sftp.get(remote_tarfile, local_tarfile)
        sftp.close()

        # 4. Extract
        print("  4/4 Extracting files...")
        try:
            with tarfile.open(local_tarfile, "r:gz") as tar:
                tar.extractall(path=LOCAL_DIR)
            print(f"✓ Extracted {len(filenames)} files to {LOCAL_DIR.name}/\n")
            return len(filenames)
        finally:
            if os.path.exists(local_tarfile):
                os.unlink(local_tarfile)

    finally:
        print("Cleaning up remote temp files...")
        ssh.exec_command(f"rm -f {remote_filelist} {remote_tarfile}")


# ============================================================================
# SAMPLE INDEX
# ============================================================================

def save_sample_index(query_files):
    """Write a JSON index mapping each query to its downloaded sample files.

    Args:
        query_files: dict mapping query -> [filename, ...]
    """
    index = {
        "meta": {
            "samples_per_query": SAMPLES_PER_QUERY,
            "total_queries": len(query_files),
            "total_files": len({fn for files in query_files.values() for fn in files}),
        },
        "queries": {q: files for q, files in sorted(query_files.items())},
    }

    index_path = LOCAL_DIR / "_sample_index.json"
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)

    print(f"✓ Saved sample index → {index_path.name}\n")


def load_known_queries():
    """Load the list of expected query types from the local stats file."""
    if not STATS_FILE.exists():
        print("  (stats.json not found — skipping query coverage check)")
        return set()

    with open(STATS_FILE, encoding="utf-8") as f:
        stats = json.load(f)
    return set(stats.get("queries", {}).keys())


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 80)
    print("CodeQL Sample Dataset Downloader")
    print(f"Goal: up to {SAMPLES_PER_QUERY} files per query type, all query types covered")
    print("=" * 80)
    print()

    if not all([SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD]):
        print("ERROR: SSH credentials not found in .env file")
        print("Required: FILES_SSH_USER, FILES_SSH_PASSWORD, FILES_SSH_PORT")
        return

    try:
        ssh = connect_ssh()

        # 1. Discover files on server
        query_files, all_filenames = select_files_remotely(ssh)

        if not all_filenames:
            print("No files selected. Exiting.")
            ssh.close()
            return

        # 2. Cross-check against known queries
        known_queries = load_known_queries()
        if known_queries:
            missing = known_queries - set(query_files.keys())
            if missing:
                print(f"  ⚠ {len(missing)} expected queries had zero results on server:")
                for q in sorted(missing):
                    print(f"      • {q}")
                print()

        # 3. Determine what still needs downloading
        to_download, skipped = get_files_to_download(all_filenames)

        print(f"\nReady to download:")
        print(f"  • Query types:    {len(query_files)}")
        print(f"  • Files to get:   {len(to_download)}")
        print(f"  • Already local:  {skipped}")
        print(f"  • Total unique:   {len(all_filenames)}")
        print(f"  • Destination:    {LOCAL_DIR}")
        print()

        response = input("Continue? (y/n): ")
        if response.lower() != "y":
            print("Download cancelled.")
            ssh.close()
            return

        # 4. Download
        downloaded = download_via_tar(ssh, to_download)
        ssh.close()
        print("✓ SSH connection closed\n")

        # 5. Save index
        save_sample_index(query_files)

        # Final summary
        print("=" * 80)
        print(f"Done: {downloaded} downloaded, {skipped} skipped")
        print(f"Sample dataset: {LOCAL_DIR}")
        print("=" * 80)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
