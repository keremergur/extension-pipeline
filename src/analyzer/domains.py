"""Manifest-derived domain reasoning.

`verification_details.specific_domain` says which site the verifier has to be on
for a payload to work. It is derivable from manifest.json without an LLM, so this
module owns that logic once and serves two consumers:

  * prompt_builder -- renders the "Manifest domain hints" block into the user
    message, so the model can fill the field itself.
  * the pipelines  -- fill the field deterministically when the model left it
    empty (config.ANALYZER_FILL_DOMAIN_FROM_MANIFEST), and normalise whatever the
    model did produce ("https://Foo.com/" -> "foo.com").

Only the surfaces an attacking *web page* can travel through restrict a payload
by URL: `externally_connectable.matches` (runtime messaging into
onMessageExternal) and `content_scripts.matches` (postMessage/DOM into an
injected content script). `host_permissions` says where the extension may act,
not who may attack it, so it is shown as a hint but never used for inference.
"""

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import config

# Surfaces used for inference, in the order they are preferred.
ATTACK_SURFACES = ("externally_connectable", "content_scripts")


@dataclass(frozen=True)
class Surface:
    """One manifest match-list, in both a display and a normalised form."""
    name: str
    declared: bool
    unrestricted: bool          # at least one catch-all pattern (<all_urls>, *://*/*)
    display: Tuple[str, ...]    # hosts as written, e.g. "*.retailcrm.services"
    hosts: Tuple[str, ...]      # normalised hosts, e.g. "retailcrm.services"


def extension_route_open(manifest_content: Optional[str]) -> bool:
    """Whether another *extension* can reach onMessageExternal/onConnectExternal.

    Chrome inverts the defaults once `externally_connectable` is declared: an
    ABSENT block lets every extension connect, while a declared block without
    `ids` lets none. So a declared-but-ids-less block closes the extension route
    entirely, leaving the pages in `matches` as the only way in.
    """
    try:
        manifest = json.loads(manifest_content) if manifest_content else None
    except Exception:
        manifest = None
    if not isinstance(manifest, dict):
        return True  # unknown manifest -> assume the permissive default
    ext_conn = manifest.get("externally_connectable")
    if not isinstance(ext_conn, dict):
        return True  # block absent -> Chrome's default: all extensions may connect
    return bool(ext_conn.get("ids"))


def match_host(pattern: str) -> Optional[str]:
    """Host portion of a match pattern, keeping any leading "*." (display form)."""
    if not isinstance(pattern, str):
        return None
    pattern = pattern.strip()
    if not pattern:
        return None
    if "://" not in pattern:
        return pattern
    host = pattern.split("://", 1)[1].split("/", 1)[0].strip()
    return host or None


def normalize_host(value: Optional[str]) -> Optional[str]:
    """Reduce a match pattern / URL / hostname to a bare hostname.

    Drops the scheme, path, a numeric port, every leading "*." and a leading
    "www.". Returns None for anything that does not name a concrete host (empty
    string, "*", "<all_urls>") so callers can treat "no restriction" uniformly.
    """
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if not host:
        return None
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip()
    if ":" in host:
        head, _, tail = host.rpartition(":")
        if head and tail.isdigit():
            host = head
    while host.startswith("*."):
        host = host[2:]
    if host.startswith("www."):
        host = host[4:]
    if not host or host == "*" or host == "<all_urls>":
        return None
    return host


def _is_all_urls(pattern: str) -> bool:
    """True for patterns that match every site, so nothing is restricted."""
    if (pattern or "").strip() == "<all_urls>":
        return True
    return match_host(pattern) == "*"


def _surface(name: str, patterns, declared: bool) -> Surface:
    raw = [p for p in patterns if isinstance(p, str) and p.strip()]
    display = [h for h in (match_host(p) for p in raw) if h and h != "*"]
    hosts = [h for h in (normalize_host(p) for p in raw) if h]
    return Surface(
        name=name,
        declared=declared,
        unrestricted=any(_is_all_urls(p) for p in raw),
        display=tuple(dict.fromkeys(display)),
        hosts=tuple(dict.fromkeys(hosts)),
    )


def manifest_scopes(manifest_content: Optional[str]) -> Dict[str, Surface]:
    """Parse manifest.json into the three domain-bearing surfaces."""
    try:
        manifest = json.loads(manifest_content) if manifest_content else None
    except Exception:
        manifest = None
    if not isinstance(manifest, dict):
        manifest = {}

    ext_conn = manifest.get("externally_connectable")
    ext_conn = ext_conn if isinstance(ext_conn, dict) else None

    content_scripts = manifest.get("content_scripts") or []
    cs_matches: List[str] = []
    for script in content_scripts:
        if isinstance(script, dict):
            cs_matches.extend(script.get("matches") or [])

    return {
        "externally_connectable": _surface(
            "externally_connectable.matches",
            (ext_conn or {}).get("matches") or [],
            declared=ext_conn is not None,
        ),
        "content_scripts": _surface(
            "content_scripts.matches", cs_matches, declared=bool(content_scripts),
        ),
        "host_permissions": _surface(
            "host_permissions", manifest.get("host_permissions") or [],
            declared="host_permissions" in manifest,
        ),
    }


# ---- prompt rendering ---------------------------------------------------

_HINTS_OUTRO = """\
These are the ONLY sites the extension is reachable from through the listed surfaces.
Unless the relevant surface is a catch-all, the finding IS domain-restricted: set
specific_domain to the matching hostname (drop any leading "*.") and
domain_restriction_source to "manifest" -- or to "both" when the code checks the
origin as well.\
"""


def format_hints(manifest_content: Optional[str]) -> str:
    """The "Manifest domain hints" block appended to the user message."""
    scopes = manifest_scopes(manifest_content)
    lines = []
    for key, surface in scopes.items():
        if surface.unrestricted:
            lines.append(f"- {surface.name}: <all urls> (catch-all, no domain restriction)")
        elif surface.display:
            lines.append(f"- {surface.name}: {', '.join(surface.display)}")
        # State the extension-reachability verdict rather than leaving the model
        # to re-derive Chrome's inverted externally_connectable defaults.
        if key == "externally_connectable" and surface.declared:
            if extension_route_open(manifest_content):
                lines.append('- externally_connectable.ids: declared -> other extensions CAN connect.')
            else:
                lines.append('- externally_connectable.ids: NOT declared -> NO other extension can '
                             'connect. onMessageExternal/onConnectExternal is reachable ONLY from the '
                             'pages listed above, so attacker_source must be "Website".')
    if not lines:
        return ""
    return "Manifest domain hints\n\n" + "\n".join(lines) + "\n\n" + _HINTS_OUTRO


# ---- deterministic inference -------------------------------------------

def infer_specific_domain(manifest_content: Optional[str],
                          attacker_source: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Derive (specific_domain, domain_restriction_source) from the manifest.

    A "Website" attacker is always gated by the match lists. An "Extension"
    attacker normally is not -- it reaches onMessageExternal through
    `externally_connectable.ids`, which is not a URL restriction -- but only when
    that route is actually open. When the manifest closes it, every remaining
    route into the extension runs through a page, so the match lists gate the
    payload no matter which attacker_source the model picked. That matters
    because small models mislabel attacker_source, and a wrong label must not
    silently drop a restriction the manifest states outright.
    """
    if (attacker_source or "").strip().lower() != "website" \
            and extension_route_open(manifest_content):
        return None, None

    scopes = manifest_scopes(manifest_content)
    ext_conn, content = scopes["externally_connectable"], scopes["content_scripts"]
    if ext_conn.unrestricted or content.unrestricted:
        return None, None  # the attacker page may be any site

    # A host reachable through both surfaces is the safest bet; otherwise prefer
    # externally_connectable, the more direct page -> extension channel.
    shared = [h for h in ext_conn.hosts if h in set(content.hosts)]
    candidates = shared or list(ext_conn.hosts) or list(content.hosts)
    if not candidates:
        return None, None
    return candidates[0], "manifest"


# APIs that only ever cross an extension boundary via externally_connectable.
_EXTERNAL_MESSAGE_RE = re.compile(
    r"onmessageexternal|onconnectexternal|runtime\.sendmessage|runtime\.connect",
    re.IGNORECASE,
)

# The external-message *listener* specifically. Used by the reverse (Website->Extension)
# correction, which must be stricter than the forward one: the broad regex above also
# matches runtime.sendMessage/connect, which a content script uses for INTERNAL messaging
# -- forcing Extension on such a finding would be wrong. A listener API, by contrast, only
# ever exists to receive an EXTERNAL message, so its presence pins the route.
_EXTERNAL_LISTENER_RE = re.compile(r"onmessageexternal|onconnectexternal", re.IGNORECASE)


def _source_mode() -> str:
    """Normalised ANALYZER_CORRECT_ATTACKER_SOURCE mode (config already normalises it)."""
    return str(getattr(config, "ANALYZER_CORRECT_ATTACKER_SOURCE", "extweb") or "none")


def reverse_forced_source(manifest_content: Optional[str],
                          *evidence: Optional[str]) -> Optional[str]:
    """"Extension" when the manifest leaves no other possible attacker, else None.

    The mirror of forced_attacker_source. When `externally_connectable` is ABSENT,
    Chrome lets NO web page reach onMessageExternal/onConnectExternal (only other
    extensions, by default), so a finding labelled "Website" is provably wrong and
    the only external attacker is an Extension.

    Deliberately narrow (see _EXTERNAL_LISTENER_RE): it requires a listener API in
    the evidence, and returns None whenever a web page COULD reach the handler
    (block declared with `matches`) or when nothing could (block declared without
    `ids` and without `matches` -- a reachability/TP question, not a source one).
    """
    if not any(_EXTERNAL_LISTENER_RE.search(t) for t in evidence if isinstance(t, str)):
        return None
    ext_conn = manifest_scopes(manifest_content)["externally_connectable"]
    can_web = ext_conn.declared and (bool(ext_conn.hosts) or ext_conn.unrestricted)
    if can_web:
        return None  # a page can reach it -> "Website" is genuinely possible
    if not extension_route_open(manifest_content):
        return None  # no extension can reach it either -> leave for TP/FP review
    return "Extension"


def forced_attacker_source(manifest_content: Optional[str],
                           *evidence: Optional[str]) -> Optional[str]:
    """"Website" when the manifest leaves no other possible attacker, else None.

    When `externally_connectable` is declared without `ids`, Chrome lets NO
    extension connect, so an external-message finding cannot be exploited by an
    attacking extension -- only by a page in `matches`. The verifier rewrites
    `matches` for verification but never adds `ids`, so an extension-mode payload
    fails there too and the finding is written off as unverified.

    Deliberately narrow: it requires the finding to actually travel an
    external-message route, and leaves content-script flows alone (an attacking
    extension can genuinely co-reside on the page there).
    """
    if extension_route_open(manifest_content):
        return None
    if not any(_EXTERNAL_MESSAGE_RE.search(text) for text in evidence
               if isinstance(text, str)):
        return None
    # With no `matches` either, nothing can reach the handler at all -- that is a
    # TP/FP question, not an attacker_source one, so leave it for review.
    ext_conn = manifest_scopes(manifest_content)["externally_connectable"]
    if not (ext_conn.hosts or ext_conn.unrestricted):
        return None
    return "Website"


def pinned_source_note(manifest_content: Optional[str], extension_id: str,
                       evidence: Optional[str]) -> str:
    """Constraint handed to the payload step when the manifest settles the source.

    Pinning it up front is what makes the decision useful: a payload written for
    the wrong attacker context is unusable even once attacker_source is corrected
    afterwards. Only pins directions the active mode would also correct.
    """
    mode = _source_mode()
    if mode == "none":
        return ""

    # Website (extweb): externally_connectable declared without ids.
    if mode in ("extweb", "bidirectional") \
            and forced_attacker_source(manifest_content, evidence) == "Website":
        ext_conn = manifest_scopes(manifest_content)["externally_connectable"]
        note = [
            'DETERMINED FROM manifest.json (do not contradict): `externally_connectable` is',
            'declared WITHOUT `ids`, so NO other extension can connect to this extension.',
            'attacker_source MUST be "Website".',
            f'A page reaches the handler with chrome.runtime.sendMessage("{extension_id}", message)',
            '-- from a page the extension id is a REQUIRED first argument.',
        ]
        if ext_conn.hosts and not ext_conn.unrestricted:
            note.append(f'specific_domain MUST be one of: {", ".join(ext_conn.hosts)}.')
        return "\n".join(note)

    # Extension (webext): externally_connectable absent -> no web page can connect.
    if mode in ("webext", "bidirectional") \
            and reverse_forced_source(manifest_content, evidence) == "Extension":
        return "\n".join([
            'DETERMINED FROM manifest.json (do not contradict): manifest.json declares NO',
            '`externally_connectable`, so NO web page can reach onMessageExternal/',
            'onConnectExternal -- only another extension can (Chrome\'s default).',
            'attacker_source MUST be "Extension". The payload runs from a second test',
            'extension that messages this one; it is not domain-restricted, so leave',
            'specific_domain empty.',
        ])

    return ""


def correct_attacker_source(vuln: dict, manifest_content: Optional[str],
                            evidence: Optional[str] = None) -> Optional[str]:
    """Safety net for when the model ignores the pin. Returns the old value.

    Direction depends on the mode: extweb rewrites Extension->Website, webext
    rewrites Website->Extension, bidirectional does both. Each direction only fires
    when the manifest makes the model's label provably impossible (see
    forced_attacker_source / reverse_forced_source).
    """
    mode = _source_mode()
    if mode == "none":
        return None
    original = (vuln.get("attacker_source") or "").strip()
    low = original.lower()
    forced = None
    if low == "extension" and mode in ("extweb", "bidirectional"):
        forced = forced_attacker_source(manifest_content, evidence,
                                        vuln.get("attacker_payload"),
                                        vuln.get("verification_instructions"))
    elif low == "website" and mode in ("webext", "bidirectional"):
        forced = reverse_forced_source(manifest_content, evidence,
                                       vuln.get("attacker_payload"),
                                       vuln.get("verification_instructions"))
    if not forced or forced == original:
        return None
    vuln["attacker_source"] = forced
    vuln["attacker_source_original"] = original
    return original


def _restriction_source(domain: str, manifest_content: Optional[str]) -> str:
    """Where a domain the model produced came from."""
    known = set()
    for surface in manifest_scopes(manifest_content).values():
        known.update(surface.hosts)
    return "manifest" if domain in known else "code"


def apply_to_vulnerability(vuln: dict, manifest_content: Optional[str],
                           evidence: Optional[str] = None) -> Dict[str, str]:
    """Apply every manifest-derived correction to one vulnerability.

    Runs the attacker_source correction first, since the domain inference reads
    that field. Returns a dict describing what was changed deterministically --
    keys "attacker_source" and/or "specific_domain" -- so callers can log it.
    Empty when the model's own answers already stood.
    """
    changes: Dict[str, str] = {}
    was = correct_attacker_source(vuln, manifest_content, evidence)
    if was:
        changes["attacker_source"] = f"{was} -> {vuln.get('attacker_source')}"

    details = vuln.get("verification_details")
    if not isinstance(details, dict):
        return changes

    # "" and null both mean "not set"; keep null so results stay comparable.
    domain = normalize_host(details.get("specific_domain"))
    details["specific_domain"] = domain
    for key in ("domain_restriction_source", "storage_domain"):
        value = details.get(key)
        if isinstance(value, str) and not value.strip():
            details[key] = None

    if domain:
        if not details["domain_restriction_source"]:
            details["domain_restriction_source"] = _restriction_source(domain, manifest_content)
        return changes

    # An FP carries no payload, so a domain restriction on it is meaningless noise.
    if not getattr(config, "ANALYZER_FILL_DOMAIN_FROM_MANIFEST", True) \
            or (vuln.get("result") or "TP").upper() == "FP":
        return changes

    inferred, source = infer_specific_domain(manifest_content, vuln.get("attacker_source"))
    if inferred:
        details["specific_domain"] = inferred
        details["domain_restriction_source"] = source
        changes["specific_domain"] = inferred
    return changes
