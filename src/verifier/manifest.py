import json
from pathlib import Path
from typing import List, Optional
import config
from .logging_utils import log_error


# A fixed RSA public key injected into unpacked extensions that have no 'key' of their own and no
# background context. Chrome derives an extension's ID from its manifest 'key' when present, otherwise
# from the load path. Content-script-only extensions expose no background/service-worker target, so
# their path-derived runtime ID cannot be discovered — seeding and storage verification then navigate
# to the wrong chrome-extension:// origin and abort (measured: 82% of data_exfiltration seeding_failed
# used the wrong ID). Pinning a known key makes the ID deterministic and computable, so those
# navigations hit the right origin. The key is arbitrary (generated once); it is safe to reuse across
# extensions because each verification runs in its own isolated browser context.
_PINNING_KEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1+J+FqSXvaTee4LIWl5Ml5+LEeHQAw7DUVCPwprK7U7ywx"
    "qMHnp/7pCc63SQ35flvzyJQe403yvYqMeZ8aHRRCj6Rxblia6+Jm0r5fHFXMLIkl+oKVHbrOyeDMpd+U5JuCT4dkszE"
    "9Iq81tfdx0Y4VJQws8PiMWg06/lhsYilP0gZeKUsWbXYGrTW33/tbD0pM3SRuSKEIl9okvXsF/cl5SRoDAm1sjREqFl"
    "rwfwmb9UE2jKHyBT+aeprLRPW2/hDzJFgpEERo69K+ya8uEBhzK+nI/PdGwxIJCEK/9T59iCuROI7iUtAWhpW6NSoUb"
    "mWlyzq/ZxB0FK1+asxQWfQIDAQAB"
)
#: The extension ID Chrome computes from ``_PINNING_KEY_B64`` (sha256 of the DER public key, first
#: 128 bits mapped to a-p). Precomputed so no key work happens at runtime.
_PINNING_EXT_ID = "nekdljaflldlhkhnmiflclddiepbehnf"


def pin_extension_id(extension_dir: Path) -> Optional[str]:
    """Inject the fixed manifest ``key`` so an unpacked extension loads under a known ID.

    Returns the pinned extension ID on success, or ``None`` when pinning is skipped (the extension
    already carries its own ``key``, so its ID is already fixed to the packed ID and must not be
    overridden) or on error. Intended for content-script-only extensions, whose runtime ID is
    otherwise undiscoverable.
    """
    manifest_path = extension_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        if 'key' in manifest:
            return None  # already has a fixed ID — do not override the packed identity
        manifest['key'] = _PINNING_KEY_B64
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
        return _PINNING_EXT_ID
    except Exception as e:
        log_error(f"Failed to pin extension id: {e}")
        return None


def has_background_context(extension_dir: Path) -> bool:
    """Check if extension has a background page or service worker.

    Extensions without a background context (content-script-only) have no discoverable
    chrome-extension:// URLs, so runtime extension ID discovery always times out for them.
    """
    try:
        with open(extension_dir / "manifest.json", 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        bg = manifest.get('background', {})
        if isinstance(bg, dict):
            return bool(bg.get('service_worker') or bg.get('page') or bg.get('scripts'))
        return False
    except Exception:
        return False


def has_fixed_extension_id(extension_dir: Path) -> bool:
    """
    Check if extension has a fixed ID (via 'key' in manifest.json).

    Extensions with 'key' field have deterministic IDs that match the .crx filename.
    Extensions without 'key' get random IDs when loaded unpacked.

    Args:
        extension_dir: Path to unpacked extension directory

    Returns:
        True if manifest.json contains 'key' field, False otherwise
    """
    try:
        manifest_path = extension_dir / "manifest.json"
        if not manifest_path.exists():
            return False

        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        return 'key' in manifest
    except Exception as e:
        log_error(f"Failed to read manifest for key check: {e}")
        return False


def modify_manifest_for_verification(extension_dir: Path) -> tuple:
    """Modify manifest.json to allow verification on the configured page host.
    Always replaces all matches unconditionally:
      - content_scripts / web_accessible_resources: <all_urls>
      - externally_connectable: config.EXTERNALLY_CONNECTABLE_MATCH
        (Chrome rejects <all_urls> here). This is *://example.com/* by default, or
        http://127.0.0.1/* when USE_LOCAL_VERIFICATION_SERVER is enabled.
    """
    manifest_path = extension_dir / "manifest.json"
    modifications = {
        "manifest_modified": False,
        "content_scripts_modified": 0,
        "web_accessible_resources_modified": 0,
        "externally_connectable_modified": 0,
    }

    if not manifest_path.exists():
        return False, modifications

    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        # content_scripts: set all matches to <all_urls>
        if "content_scripts" in manifest:
            for script in manifest["content_scripts"]:
                if isinstance(script, dict) and "matches" in script:
                    if script["matches"] != ["<all_urls>"]:
                        script["matches"] = ["<all_urls>"]
                        modifications["content_scripts_modified"] += 1

        # web_accessible_resources: set all matches to <all_urls>
        if "web_accessible_resources" in manifest:
            for resource in manifest["web_accessible_resources"]:
                if isinstance(resource, dict) and "matches" in resource:
                    if resource["matches"] != ["<all_urls>"]:
                        resource["matches"] = ["<all_urls>"]
                        modifications["web_accessible_resources_modified"] += 1

        # externally_connectable: set matches to the configured page host.
        # Chrome does NOT support <all_urls> for externally_connectable.
        ext_match = config.EXTERNALLY_CONNECTABLE_MATCH
        if "externally_connectable" in manifest:
            if isinstance(manifest["externally_connectable"], dict) and "matches" in manifest["externally_connectable"]:
                if manifest["externally_connectable"]["matches"] != [ext_match]:
                    manifest["externally_connectable"]["matches"] = [ext_match]
                    modifications["externally_connectable_modified"] = 1

        # Only write if something actually changed
        if modifications["content_scripts_modified"] or modifications["web_accessible_resources_modified"] or modifications["externally_connectable_modified"]:
            modifications["manifest_modified"] = True
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)

        return True, modifications

    except Exception as e:
        log_error(f"Manifest modification: {e}")
        return False, modifications


def prepare_extension_storage_verification(extension_dir: Path, vulnerabilities: List[dict]):
    """Write verify_storage.html into the extension directory before browser launch.

    This minimal page is navigated to by the verifier whenever Chrome APIs need to be
    called from extension context (storage checks, seeding, data verification).
    Registered in web_accessible_resources so Chrome permits navigation to it.
    """
    (extension_dir / 'verify_storage.html').write_text(
        '<!DOCTYPE html><html><body></body></html>', encoding='utf-8'
    )

    # Register verify_storage.html as web_accessible_resource so Chrome allows navigation.
    manifest_path = extension_dir / 'manifest.json'
    if not manifest_path.exists():
        return
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        manifest_version = manifest.get('manifest_version', 2)

        if manifest_version >= 3:
            # MV3: web_accessible_resources is an array of objects
            entry = {"resources": ["verify_storage.html"], "matches": ["<all_urls>"]}
            if "web_accessible_resources" not in manifest:
                manifest["web_accessible_resources"] = [entry]
            else:
                already_listed = any(
                    isinstance(r, dict) and "verify_storage.html" in r.get("resources", [])
                    for r in manifest["web_accessible_resources"]
                )
                if not already_listed:
                    manifest["web_accessible_resources"].append(entry)
        else:
            # MV2: web_accessible_resources is a flat array of strings
            if "web_accessible_resources" not in manifest:
                manifest["web_accessible_resources"] = ["verify_storage.html"]
            elif "verify_storage.html" not in manifest["web_accessible_resources"]:
                manifest["web_accessible_resources"].append("verify_storage.html")

        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
    except Exception as e:
        log_error(f"Failed to register verify_storage.html in manifest: {e}")
