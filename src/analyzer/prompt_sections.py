"""Composable prompt content.

The original single Prompt_CodeQL.md blob is broken into named sections here so
that the prompt builder can:

  * assemble a single whole-task prompt (single pipeline), or
  * assemble small, focused prompts for each step (multi pipeline), and
  * include only the sections for the enabled vulnerability categories.

All "output valid JSON in exactly this shape" boilerplate has been removed --
the output shape is enforced by structured output (see analyzer.schemas), so the
prompts only describe the *task* and the *meaning* of each field.
"""

INTRO = """\
You are a security review program that inspects a Chrome Extension using a
provided static-analysis report and excerpts of the extension's original source
code. Your job is to judge the correctness and verifiability of the potential
vulnerabilities the report found.

Use the snippets inside the provided report together with the extra source-code
lines given below to reach your conclusions. Base every decision on evidence in
the report, the code, and the manifest.json.\
"""

# Per-category definitions (the "vulnerability_category" explanations).
CATEGORY_DEFINITIONS = {
    "code_execution": """\
- code_execution:
  - The attacker can exploit the extension to execute arbitrary attacker-controlled
    JavaScript in a privileged context, gaining access to Chrome APIs beyond the
    restrictions on regular web content.
  - The JavaScript must run under the extension's privileges, otherwise it is of no
    use to the attacker and is not a vulnerability.
  - Triggering APIs: `eval`, `chrome.tabs.executeScript`, `setTimeout`, `setInterval`.\
""",
    "1way_request": """\
- 1way_request:
  - The attacker can exploit the extension to make a network request (http,
    websocket, etc.) to an arbitrary URL, executed under extension privileges.
  - Only a TP if the attacker can send data to ANY URL. If the request target's
    hostname is hardcoded in the extension, it is a FP.
  - Triggering APIs: all APIs that issue a request to an endpoint.\
""",
    "2way_request": """\
- 2way_request:
  - Like 1way_request, but the response is passed back to the attacker.
  - Only a TP if the attacker can send/receive data to/from ANY URL. Hardcoded
    hostnames make it a FP.
  - Triggering APIs: all APIs that issue a request to an endpoint.\
""",
    "download": """\
- download:
  - The attacker can exploit the extension to download a file to the user's
    computer under extension privileges.
  - Triggering APIs: `chrome.downloads.download`.\
""",
    "data_exfiltration": """\
- data_exfiltration:
  - The attacker can exploit the extension to read user-sensitive data under
    extension privilege from: bookmarks, history, cookies, topSites, management,
    local storage, sync storage, session storage.
  - Only a TP if the sensitive information is passed back to the attacker.
  - For `localStorage.getItem`/`sessionStorage.getItem`: only a TP if called from an
    extension page context (popup, options, background) -- not from a content
    script or MV3 service worker.
  - Triggering APIs: `chrome.bookmarks.get`, `chrome.bookmarks.getRecent`,
    `chrome.bookmarks.getTree`, `chrome.bookmarks.search`, `chrome.cookies.get`,
    `chrome.cookies.getAll`, `chrome.history.getVisits`, `chrome.history.search`,
    `chrome.topSites.get`, `chrome.management.get*`, `chrome.storage.*.get`,
    `localStorage.getItem`, `sessionStorage.getItem`.\
""",
    "storage": """\
- storage:
  - The attacker can exploit the extension to write data under extension privilege
    into: bookmarks, cookies, topSites, local/sync/session storage. Using
    `management.setEnabled` also counts as "storage".
  - Simply setting a key-value pair or changing a value is already a vulnerability.
  - For `localStorage.*`/`sessionStorage.*`: only a TP if called from an extension
    page context (popup, options, background) -- not from a content script or MV3
    service worker.
  - Triggering APIs: `chrome.bookmarks.create/remove/removeTree`,
    `chrome.cookies.remove/set`, `chrome.history.addUrl/deleteAll/deleteRange/deleteUrl`,
    `chrome.management.setEnabled/uninstall/uninstallSelf`,
    `chrome.declarativeNetRequest.updateDynamicRules`, `chrome.storage.*.clear/remove/set`,
    `localStorage.clear/setItem/removeItem`, `sessionStorage.clear/setItem/removeItem`.\
""",
}

CATEGORIZE_TASK = """\
Determine the single vulnerability_category that best describes this finding,
using the report and the original extension code.\
"""

# The single_vulnerability pipeline's framing. It replaces RESULT_COMBINATION: that
# section exists to tell the whole-extension prompt how to GROUP many findings, and
# here the grouping has already happened in code (adapter.split_candidates), so the
# opposite instruction is needed -- judge exactly the one finding shown and nothing
# else. Without it a whole-task prompt fed a one-result report still tends to hunt
# for neighbouring findings in the code excerpt.
SINGLE_VULNERABILITY_TASK = """\
You are judging ONE finding. The report below contains exactly that single result.
In one answer: determine its vulnerability_category, decide whether it is a true or
a false positive, and -- only if it is a true positive -- write the attacker payload
and the verification details for it.

Do not analyse, merge or report any other potential vulnerability, even if the code
excerpt shows one. Judge only the finding in the report.\
"""

# Gated by config.PROMPT_CQL_NETWORK_HINT (default on). See the config.py comment
# above PROMPT_CQL_NETWORK_HINT and EXPERIMENTS.md 45-46 for why this exists: the
# one CodeQL rule_id left unmapped in ANALYZER_RULE_ID_CATEGORY_MAP was observed
# drifting into categories its own query cannot produce.
CQL_NETWORK_HINT = """\
In CodeQL reports, a finding whose query id ends in "/network-request" (e.g.
chrome/trigger/network-request, chrome/exfiltration/network-request) can ONLY be
1way_request or 2way_request -- never any other category. Decide between the two by
whether the response is passed back to the attacker.\
"""

# ============================================================================
# RESULT (verdict) RULES -- selectable variants, chosen by config.RESULT_RULES
# ============================================================================
# Each variant is a COMPLETE, SELF-CONTAINED block, deliberately NOT composed from
# shared fragments: editing one must never move the others, so a comparison
# between two variants stays valid even after later prompt edits. Add a new
# numbered entry rather than modifying one you have already run.
RESULT_RULES_VARIANTS = {

    # -- 1: the original wording, TP/FP only (historical baseline) -----------
    # NOTE the known bias: it declares wrong FPs "even worse" than wrong TPs, which
    # pushes the model to resolve any doubt as TP (measured ~96% TP, with logprob
    # confidence pinned at 1.0). Variants 3/4 correct this.
    "1": """\
Decide whether the finding is a real vulnerability (TP) or not (FP).

- Definition: an extension has a vulnerability if there is a data flow from an
  external actor (a web page or another extension) to a security- or
  privacy-critical API inside the extension.
- It is only a TP if the vulnerability can be triggered by an external attacker
  AND is executed under extension privileges.
- Finding one of the listed APIs does NOT by itself make a TP.
- You MUST check the manifest.json before deciding.
- If there is no possible exploit, flag it FP.
- If it cannot be exploited by a website or another extension, flag it FP. Exception:
  a vulnerability exploitable only from specific (non-arbitrary) websites is still a
  TP, since such sites may come under attacker control (e.g. via XSS); set
  specific_domain accordingly.
- Setting incorrect TPs is strictly forbidden. Creating wrong FPs is even worse --
  if you assess a finding as FP, double-check first.
- fp_explanation: only when result is FP, give a brief reason (otherwise leave empty).\
""",

    # -- 2: the original wording + the NA verdict ----------------------------
    "2": """\
Decide whether the finding is a real vulnerability (TP), not one (FP), or whether the
evidence does not settle it (NA).

- Definition: an extension has a vulnerability if there is a data flow from an
  external actor (a web page or another extension) to a security- or
  privacy-critical API inside the extension.
- It is only a TP if the vulnerability can be triggered by an external attacker
  AND is executed under extension privileges.
- Finding one of the listed APIs does NOT by itself make a TP.
- You MUST check the manifest.json before deciding.
- If there is no possible exploit, flag it FP.
- If it cannot be exploited by a website or another extension, flag it FP. Exception:
  a vulnerability exploitable only from specific (non-arbitrary) websites is still a
  TP, since such sites may come under attacker control (e.g. via XSS); set
  specific_domain accordingly.
- Setting incorrect TPs is strictly forbidden. Creating wrong FPs is even worse --
  if you assess a finding as FP, double-check first.
- fp_explanation: only when result is FP, give a brief reason (otherwise leave empty).

THIRD VERDICT -- "NA" (undecidable):
- Use NA when the material you were shown does not settle the question: the code that
  would prove or disprove the flow is not present, the tainted value's origin is not
  visible, or you would have to guess at how a helper behaves.
- NA is NOT a softer FP and NOT a hedge. FP means you have evidence there is no
  exploitable flow; NA means you cannot tell from what is in front of you.
- Prefer a definite TP or FP whenever the evidence supports one. Only fall back to NA
  when it genuinely does not.
- When you answer NA, use fp_explanation to say WHAT is missing (which file, function
  or value you would need to see).\
""",

    # -- 3: symmetric, evidence-based wording, TP/FP only --------------------
    # Replaces the asymmetric "wrong FPs are even worse" pressure with an explicit
    # burden of proof on BOTH verdicts: each must be justifiable by something the
    # model can actually name in the material shown.
    "3": """\
Decide whether the finding is a real vulnerability (TP) or not (FP).

- Definition: an extension has a vulnerability if there is a data flow from an
  external actor (a web page or another extension) to a security- or
  privacy-critical API inside the extension.
- It is only a TP if the vulnerability can be triggered by an external attacker
  AND is executed under extension privileges.
- Finding one of the listed APIs does NOT by itself make a TP. The report lists
  CANDIDATES; deciding which of them are real is exactly your job.
- You MUST check the manifest.json before deciding.

BURDEN OF PROOF -- both verdicts are claims, and both can be wrong:
- TP claims you can trace an exploitable path. To answer TP you must be able to name
  all three of: (a) the attacker-controlled entry point (the handler/listener/API a
  web page or another extension reaches), (b) the path carrying that input to the
  sink, and (c) why the sink runs with extension privileges. If any of the three is
  missing from the material shown, it is not a TP.
- FP claims you can rule the path out. To answer FP you must be able to name the
  specific thing that breaks it -- a hardcoded value the attacker cannot influence, a
  sink that never runs under extension privileges, a handler no external party can
  reach, an origin/sender check, or an unreachable branch.
- A wrong TP and a wrong FP are equally damaging: one invents a vulnerability, the
  other hides a real one. Neither is the safe default, so do not resolve doubt by
  reaching for whichever feels less risky.
- A vulnerability exploitable only from specific (non-arbitrary) websites is still a
  TP, since such sites may come under attacker control (e.g. via XSS); set
  specific_domain accordingly.
- fp_explanation: only when result is FP, name the specific blocker you identified
  (otherwise leave empty).\
""",

    # -- 4: symmetric wording + the NA verdict -------------------------------
    # Variant 3's burden of proof plus an explicit escape hatch: when NEITHER
    # burden is met, NA is the correct answer rather than a coin flip.
    "4": """\
Decide whether the finding is a real vulnerability (TP), not one (FP), or whether the
evidence does not settle it (NA).

- Definition: an extension has a vulnerability if there is a data flow from an
  external actor (a web page or another extension) to a security- or
  privacy-critical API inside the extension.
- It is only a TP if the vulnerability can be triggered by an external attacker
  AND is executed under extension privileges.
- Finding one of the listed APIs does NOT by itself make a TP. The report lists
  CANDIDATES; deciding which of them are real is exactly your job.
- You MUST check the manifest.json before deciding.

BURDEN OF PROOF -- both verdicts are claims, and both can be wrong:
- TP claims you can trace an exploitable path. To answer TP you must be able to name
  all three of: (a) the attacker-controlled entry point (the handler/listener/API a
  web page or another extension reaches), (b) the path carrying that input to the
  sink, and (c) why the sink runs with extension privileges.
- FP claims you can rule the path out. To answer FP you must be able to name the
  specific thing that breaks it -- a hardcoded value the attacker cannot influence, a
  sink that never runs under extension privileges, a handler no external party can
  reach, an origin/sender check, or an unreachable branch.
- A wrong TP and a wrong FP are equally damaging: one invents a vulnerability, the
  other hides a real one. Neither is the safe default.
- A vulnerability exploitable only from specific (non-arbitrary) websites is still a
  TP, since such sites may come under attacker control (e.g. via XSS); set
  specific_domain accordingly.

THIRD VERDICT -- "NA" (undecidable):
- If you can meet neither burden above -- you cannot name the three TP elements, and
  you cannot name a concrete blocker for FP -- then the evidence does not settle the
  question and the correct answer is NA.
- Typical NA cases: the code that would prove or disprove the flow is not shown, the
  tainted value's origin is not visible, or you would have to guess how a helper
  behaves.
- NA is NOT a softer FP and NOT a general hedge. FP asserts a blocker you identified;
  NA says the material shown does not let you assert either verdict.
- Where the evidence does support a verdict, give it: answer TP or FP whenever one of
  the two burdens is actually met. But when you are genuinely torn between TP and FP,
  answer NA rather than guessing -- a wrong guess corrupts the result, whereas NA
  marks the finding for a human to settle.
- When you answer NA, use fp_explanation to say WHAT is missing (which file, function
  or value you would need to see).\
""",

    # -- 5: exploitability-strict, TP/FP only (uncertainty -> FP) ------------
    # Built to cut UNEXPLOITABLE TPs (see PIPELINE_CHANGES §6b): it treats CodeQL's
    # SOURCE as a claim to verify, demands a genuinely external + unguarded +
    # attacker-controlled flow, cancels the "a write is automatically a vuln" nudge,
    # and -- like the high-FP Gemini/Prompt_CodeQL.md baseline -- resolves an
    # unconfirmed finding to FP. Higher precision on TP at the cost of recall.
    "5": """\
Decide whether the finding is a real, EXPLOITABLE vulnerability (TP) or not (FP).

- Definition: an extension is vulnerable if an EXTERNAL actor (a web page or another
  extension) can drive ATTACKER-CONTROLLED input into a security- or privacy-critical
  API that runs under EXTENSION privilege.
- The report was produced by a HIGH-RECALL static analysis: it over-reports. Its
  "SOURCE" label is a claim, not proof -- confirm the source yourself from the code.
- You MUST check the manifest.json before deciding.

BURDEN OF PROOF -- answer FP unless you can positively establish all three, from the
evidence actually shown:
  (a) EXTERNAL ENTRY: name the exact handler/listener/API an outside party reaches --
      onMessageExternal/onConnectExternal, or a content-script message from a page in
      content_scripts.matches. INTERNAL flows are NOT external entries and are FP: a
      content script messaging its own background, a bundled library's postMessage, a
      value read from a packaged file or the extension's own config, a hardcoded value.
  (b) ATTACKER CONTROL, UNGUARDED: the attacker actually controls the value reaching
      the sink AND no check gates the path -- no sender/origin/id validation on the
      handler, no allow-list, no format/content validation that would reject attacker
      input. If a guard is present, or the value is fixed or derived internally, it is FP.
  (c) PRIVILEGE: the sink executes under extension privilege, not in the page context.
- Category triggers do NOT lower this bar. A storage / bookmark / cookie / history
  WRITE reached from an external message is a TP ONLY when (a)-(c) all hold; an
  externally-triggered write is NOT automatically a vulnerability. Disregard any
  earlier wording that "simply setting a value" is enough on its own.
- 1way/2way_request: TP only if the attacker controls the request DESTINATION (an
  arbitrary URL/host). A hardcoded host is FP.
- data_exfiltration: TP only if the sensitive read is actually RETURNED to the
  attacker. A read with no return path is FP.
- A finding exploitable only from specific (non-arbitrary) websites is still a TP (such
  sites may fall to XSS); set specific_domain accordingly.
- CRUCIAL: if the deciding evidence is NOT shown -- the handler body, a possible guard,
  or the tainted value's origin is outside the code you were given -- you cannot
  establish (a)-(c), so answer FP. Do NOT assume the absence of a guard you cannot see.
- fp_explanation: name the specific reason -- which of (a)/(b)/(c) fails, or the guard /
  hardcoded value / internal source that blocks it.\
""",

    # -- 6: exploitability-strict + NA (uncertainty -> NA) -------------------
    # Variant 5's strictness, but an unconfirmed-because-unseen finding becomes NA
    # (human review) instead of FP -- keeps precision without silently discarding real
    # vulns as false. The recommended default for a paper: NA is honest about "could
    # not tell", FP is not.
    "6": """\
Decide whether the finding is a real, EXPLOITABLE vulnerability (TP), not one (FP), or
whether the evidence does not settle it (NA).

- Definition: an extension is vulnerable if an EXTERNAL actor (a web page or another
  extension) can drive ATTACKER-CONTROLLED input into a security- or privacy-critical
  API that runs under EXTENSION privilege.
- The report was produced by a HIGH-RECALL static analysis: it over-reports. Its
  "SOURCE" label is a claim, not proof -- confirm the source yourself from the code.
- You MUST check the manifest.json before deciding.

BURDEN OF PROOF -- a TP must positively establish all three, from the evidence shown:
  (a) EXTERNAL ENTRY: name the exact handler/listener/API an outside party reaches --
      onMessageExternal/onConnectExternal, or a content-script message from a page in
      content_scripts.matches. INTERNAL flows are NOT external entries and are FP: a
      content script messaging its own background, a bundled library's postMessage, a
      value read from a packaged file or the extension's own config, a hardcoded value.
  (b) ATTACKER CONTROL, UNGUARDED: the attacker actually controls the value reaching
      the sink AND no check gates the path -- no sender/origin/id validation on the
      handler, no allow-list, no format/content validation that would reject attacker
      input. If a guard is present, or the value is fixed or derived internally, it is FP.
  (c) PRIVILEGE: the sink executes under extension privilege, not in the page context.
- Category triggers do NOT lower this bar. A storage / bookmark / cookie / history
  WRITE reached from an external message is a TP ONLY when (a)-(c) all hold; an
  externally-triggered write is NOT automatically a vulnerability. Disregard any
  earlier wording that "simply setting a value" is enough on its own.
- 1way/2way_request: TP only if the attacker controls the request DESTINATION (an
  arbitrary URL/host). A hardcoded host is FP.
- data_exfiltration: TP only if the sensitive read is actually RETURNED to the
  attacker. A read with no return path is FP.
- A finding exploitable only from specific (non-arbitrary) websites is still a TP (such
  sites may fall to XSS); set specific_domain accordingly.

THIRD VERDICT -- "NA" (undecidable), the deliberate split from variant 5:
- FP means you IDENTIFIED a blocker (an internal source, a guard, a hardcoded value, no
  privilege). NA means the deciding evidence is simply NOT SHOWN -- the handler body, a
  possible sender/origin check, or the tainted value's origin lies outside the code you
  were given -- so you can neither confirm (a)-(c) nor point to a concrete blocker.
- Do NOT assume the absence of a guard you cannot see: when the flow's decisive code is
  missing, answer NA, not TP and not FP.
- Where the evidence IS sufficient, commit: give TP when (a)-(c) all hold, FP when you
  can name the blocker. Reserve NA for genuine missing-evidence cases.
- When you answer NA, use fp_explanation to say WHAT is missing (which file, function,
  or value you would need to see).\
""",
}

# Which variants describe the NA verdict. This is authoritative for the SCHEMA too
# (schemas.result_values reads it), so the verdicts the model is told about can never
# drift from the verdicts it is allowed to emit. Keep in sync when adding a variant --
# the assertion below catches a key typo, not a forgotten entry.
RESULT_RULES_WITH_NA = frozenset({"2", "4", "6"})
assert RESULT_RULES_WITH_NA <= set(RESULT_RULES_VARIANTS), \
    "RESULT_RULES_WITH_NA names a variant that does not exist"

# Result-combination rule. Only the single pipeline emits the whole vulnerabilities
# array in one shot, so only it needs to be told how to group the report's results.
# The multi pipeline derives one vulnerability per candidate deterministically
# (adapter.split_candidates), so it must NOT carry this section.
RESULT_COMBINATION = """\
COMBINING RESULTS:
- Output one object per distinct vulnerability. If the report holds multiple results for
  the same or very similar vulnerability (same attacker-controlled trigger/entry AND same
  sink mechanism), combine them into a single object.
- Do NOT combine dissimilar results -- in particular, never merge results with different
  rule_id values.\
"""

PAYLOAD_INTRO = """\
Produce an attacker_payload: put the most effort here.

- Provide a JavaScript snippet a browser-puppeteer verifier can run to confirm the
  vulnerability. It is fed either into a website's console or into another
  extension's code.
- The payload must exercise the vulnerability in a harmless way that simulates the
  COMPLETE data flow.\
"""

# Per-category payload trigger requirements.
PAYLOAD_BY_CATEGORY = {
    "code_execution": """\
- code_execution: make the vulnerable extension execute exactly this JS under
  extension privilege:
  fetch('http://127.0.0.1:3000/api/data?ext=' + (chrome.runtime?.id || 'web')).
  Only this exact snippet lets the verifier confirm the vulnerability.\
""",
    "1way_request": """\
- 1way_request: trigger the extension to make a request to
  http://127.0.0.1:3000/api/data.\
""",
    "2way_request": """\
- 2way_request: trigger the extension to request http://127.0.0.1:3000/api/data
  AND ensure the response returns to the website. The response has a "token" field;
  log it to console with the prefix "[2WAY]" (e.g. console.log('[2WAY]', response.token)).\
""",
    "download": """\
- download: trigger the extension to download a file, either by defining the file
  or by passing the endpoint 127.0.0.1:3000/api/file.\
""",
    "data_exfiltration": """\
- data_exfiltration: trigger the extension to retrieve the value at storage_key from
  storage_api and pass it back by logging it with the prefix "[EXFIL]"
  (e.g. console.log('[EXFIL]', data)).\
""",
    "storage": """\
- storage: trigger the extension to set the attribute named storage_key at storage_api.
  The value the extension writes into storage_key MUST be the bare marker: exactly the
  string "exploit" (or, only if the field accepts integers alone, 123456789) with nothing
  added, appended, or reformatted. The verifier reads storage_key back and only accepts an
  exact match, so a marker embedded in something longer -- an email address, a URL, a
  sentence -- does NOT count.
  So send "exploit" verbatim in every attacker-controlled message field that could reach
  storage_key, regardless of what the field is named: a field called email, url, name or
  token still gets the value "exploit", NOT an address or link built around it. If one
  message writes several keys and you are unsure which the verifier watches, set every
  written field to "exploit".\
""",
}

PAYLOAD_OUTRO = """\
- The verifier must be able to confirm the vulnerability purely from the triggered
  action.
- The payload MUST be executable from the attacker_source context (a website's
  console OR another extension's script).
- If attacker_source is "Website", the payload must run directly in a website's
  browser console -- use only APIs available there.
- If attacker_source is "Extension", the payload runs from the content script of a
  second, minimal, auto-assembled test extension (NOT the examined extension). That
  test extension only executes your payload at DOMContentLoaded.
- If multiple steps are needed (e.g. exploit, then log the result), include all of
  them in this one payload; use timeouts to enforce ordering when necessary.
- The payload must reach the sink: copy message property names VERBATIM from the
  handler (if it dispatches on request.script, use "script" -- never substitute
  action/type/cmd) and include every property the guards on that path read.\
"""

ATTACKER_SOURCE_RULES = """\
attacker_source: decide whether the attacker is a web page ("Website") or another
extension ("Extension"). This determines the execution context of the payload.\
"""

VERIFICATION_INSTRUCTIONS_RULES = """\
verification_instructions: a short description of how to use the payload.
- Website example: "open browser, run payload in console of xy.com, observe request
  to 127.0.0.1:3000".
- Extension example: "run from content script of malicious extension, check console
  for exfiltrated data".\
"""

VERIFICATION_DETAILS_COMMON = """\
verification_details: extra data the verifier needs.
- specific_domain: the hostname (no scheme, no "www.", no leading "*.") of the site the
  attacker must be on for this payload to work. Fill it whenever the extension exposes
  the exploited surface to a limited set of sites -- in particular when the "Manifest
  domain hints" block lists concrete hostnames instead of a catch-all. Leave it empty
  ONLY when the payload works from an ARBITRARY site. Never invent a domain: it must
  appear in manifest.json or in the extension's code.
- domain_restriction_source: REQUIRED whenever specific_domain is set -- where the
  restriction comes from: "manifest" (only manifest.json, e.g. content_scripts.matches,
  externally_connectable.matches, host_permissions), "code" (only a runtime check in
  JS), or "both". Leave empty only if there is no restriction.\
"""

# Domain-restriction reasoning. RESULT_RULES carries this for the TP/FP decision, but
# the multi pipeline's payload step never sees RESULT_RULES -- without this block it
# gets the specific_domain *field description* and no rule for deciding the value.
DOMAIN_RESTRICTION_RULES = """\
DOMAIN RESTRICTION (drives specific_domain):
- A finding reachable only from a limited set of sites is still a TP -- the verifier
  simply has to run the payload on one of those sites. That is what specific_domain is
  for, so an empty specific_domain is a claim that ANY site works.
- Decide it from the manifest surface the exploit travels through:
    - the attacker page messages the extension via chrome.runtime.sendMessage/connect
      (onMessageExternal/onConnectExternal) -> externally_connectable.matches restricts it;
    - the attacker page reaches the extension through an injected content script
      (window.postMessage, DOM events, shared globals) -> content_scripts.matches does.
- If that list is a catch-all (`<all_urls>`, `*://*/*`), there is no restriction: leave
  specific_domain empty. If it names concrete hosts, set specific_domain to the matching
  host and domain_restriction_source to "manifest".
- A hostname compared in the JS itself (e.g. against sender.url/origin/referrer) is
  "code"; when the manifest restricts it too, use "both".
- An Extension attacker is normally NOT domain-restricted, since it reaches
  onMessageExternal through externally_connectable.ids rather than a URL -- but only
  when that route is open. If externally_connectable is declared WITHOUT `ids`, no
  extension can connect at all: attacker_source is then "Website" and the matches list
  restricts it. Do not choose "Extension" to avoid naming a domain.\
"""
 
VERIFICATION_DETAILS_STORAGE = """\
- storage_api: the specific storage/read API used (only for storage or
  data_exfiltration findings). The verifier monitors this API.
- storage_key: the tainted key for storage/data_exfiltration findings. It is the
  identifying argument passed to the API call, not a key-value key. For runtime IDs
  (e.g. bookmark IDs) use a human-readable identifier instead.
  Examples by API group:
    - chrome.bookmarks.create/get/remove/removeTree/search/getTree: bookmark title (e.g. "exploit")
    - chrome.bookmarks.getRecent: numberOfItems (e.g. "5")
    - chrome.cookies.set/get/remove: cookie name (e.g. "exploit"); getAll: empty
    - chrome.history.addUrl/deleteUrl: URL (e.g. "http://exploit.test/"); search: text; deleteAll: empty
    - chrome.storage.local/sync/session set/get/remove: storage key (e.g. "exploit"); clear: empty
    - localStorage/sessionStorage setItem/getItem/removeItem: key (e.g. "exploit"); clear: empty
  For chrome.bookmarks APIs with runtime IDs, use the title as storage_key; if the
  extension does not look IDs up itself, your payload must search by title first.
  If the attacker can freely choose the key, use "exploit".
- storage_domain: only for chrome.cookies.* -- the target website's hostname if the
  API call targets a specific domain, otherwise empty. For all other APIs leave empty.\
"""

REMINDERS = """\
IMPORTANT REMINDERS:
- A verification simulates an attacker exploiting the vulnerability to confirm it.
- The attacker is by definition a website or another extension, so the payload MUST
  be executable from a website's console OR from another extension's content script.
- If attacker_source is a website, use only APIs available in a website's console or
  service worker / background page.
- The JavaScript payload MUST be syntactically valid.\
"""

# --- optional section (1): externally_connectable manifest nuance -----------
# Toggled by config.PROMPT_INCLUDE_EXTERNALLY_CONNECTABLE. This corrects a common
# misreading of the manifest when deciding whether another extension can reach an
# onMessageExternal / onConnectExternal handler (attacker_source = "Extension").
EXTERNALLY_CONNECTABLE_NOTE = """\
EXTERNALLY_CONNECTABLE (manifest.json nuance -- affects attacker_source = "Extension"):
- If manifest.json does NOT declare `externally_connectable` at all, Chrome's default
  applies: ALL other extensions/apps CAN connect via chrome.runtime.connect /
  chrome.runtime.sendMessage (reaching onMessageExternal / onConnectExternal handlers),
  although NO web page can. So an external-message handler in an extension WITHOUT an
  `externally_connectable` block IS reachable by an attacker Extension.
- If `externally_connectable` IS declared, the defaults invert (declaring it is more
  restrictive, not less):
    - `ids` omitted or empty     -> NO extension/app can connect.
    - `matches` omitted or empty -> NO web page can connect.
  Only the extension IDs listed in `ids` (or the wildcard `"*"`) can connect, and only
  pages whose URL matches `matches` can connect.
- Consequence for your decision: a MISSING externally_connectable block is MORE
  permissive to other extensions than an empty/partial one. Treat an onMessageExternal
  handler as Extension-reachable when the block is absent or lists `"ids": ["*"]`; treat
  it as NOT Extension-reachable when the block is present without `ids` (or without the
  attacker's id). This does not affect content scripts, which use normal message
  passing regardless of externally_connectable.\
"""

# --- optional section (2): worked TP/FP result examples (few-shot) ----------
# Toggled by config.PROMPT_INCLUDE_RESULT_EXAMPLES. Illustrative calibration only --
# the JSON shape is still enforced by the schema, so these describe the *reasoning*,
# not the output format.
RESULT_EXAMPLES = """\
RESULT EXAMPLES (calibration only -- these are NOT the finding under review; do not
copy their verdicts, apply the same reasoning to the actual evidence):

- Example A -- 1way_request, TP: the report flags `fetch(url)` in the background
  service worker where `url` arrives from a chrome.runtime.onMessageExternal handler.
  An external sender controls the whole destination, and the request runs with
  extension privileges. Data can be sent to an ARBITRARY endpoint -> TP.

- Example B -- 1way_request, FP: the same `fetch(url)` sink, but
  `url = "https://api.vendor-fixed.com/v1/" + path`. The hostname is hardcoded; the
  attacker influences only the path, never the destination host, so data cannot reach
  an arbitrary endpoint -> FP (fp_explanation: "request hostname is hardcoded").

- Example C -- data_exfiltration, FP (execution context): `localStorage.getItem("t")`
  reached only from a content script. In a content script localStorage is the web
  PAGE's storage, not the extension's, and the rules require an extension page context
  (popup/options/background). No extension-privileged sensitive read -> FP.

- Example D -- code_execution, FP (no external flow): `eval(cfg)` where `cfg` is read
  from a file bundled in the extension and is never influenced by a web page or another
  extension. Finding a sink API is not enough without an attacker-controlled source -> FP.

- Example E -- storage, TP: a web page listed in content_scripts.matches posts a
  message that the background handler writes verbatim via `chrome.storage.local.set`.
  The write runs with extension privileges and the key/value are attacker-influenced;
  simply setting a value already qualifies -> TP.\
"""

# --- optional section: storage/data_exfiltration TP reminder ----------------
# Toggled by config.PROMPT_INCLUDE_STORAGE_TP_HINT. Targets the two FP mistakes
# weaker local models make on storage findings: (a) demanding exfiltration/return
# for a plain WRITE, and (b) treating attacker-controlled input as a reason for FP
# rather than the thing that makes it a TP. Also restates that domain restriction
# does not disqualify a TP.
STORAGE_TP_HINT = """\
STORAGE / DATA_EXFILTRATION -- AVOID THESE FP MISTAKES:
- For the "storage" category the WRITE itself is the vulnerability. An externally
  triggered write (onMessageExternal/onMessage -> chrome.storage.*.set, a
  bookmarks/cookies/history write, or localStorage.setItem from an extension page) is a
  TP. The data does NOT need to be read back or exfiltrated -- that is a DIFFERENT
  category. Simply setting a key-value pair or changing a value already qualifies.
- The stored key/value coming from the attacker's own message is exactly what makes it
  a TP -- NOT a reason to call it FP. Attacker-controlled input reaching the sink under
  extension privilege IS the vulnerability.
- "data_exfiltration" is the one that additionally requires the read value to be passed
  back to the attacker; a read with no return path is FP. Do not apply that requirement
  to "storage".
- A finding reachable only from specific (non-arbitrary) sites is still a TP -- set
  specific_domain; domain restriction is never by itself an FP reason.\
"""

# --- optional feature (4): confidence + context-request instructions --------
# Only injected when config.CONFIDENCE_LOOPBACK_ENABLED. Explains the extra output
# fields that drive the context-escalation loopback in the pipeline.
CONFIDENCE_INSTRUCTIONS = """\
CONFIDENCE & CONTEXT REQUESTS:
- confidence: your calibrated confidence in THIS judgement, from 0.0 (pure guess) to
  1.0 (certain), based only on the evidence actually shown to you.
- needs_more_context: set true ONLY if you genuinely cannot decide reliably because
  relevant code is not shown (e.g. a called helper, or the file that defines a tainted
  value). If what you were shown is sufficient, set it false.
- requested_context_scope: when needs_more_context is true, how much more source to
  reveal on the next pass -- "block" (the enclosing blocks), "module" (the enclosing
  bundler module), "file" (the whole files involved), or "used" (all source the
  report references). Otherwise null.
Still return your best result/category every time; never lower confidence just to
defer a decision.\
"""

# Appended to CONFIDENCE_INSTRUCTIONS only when config.CONTEXT_SYMBOL_REQUEST is on.
# Naming what is missing is far cheaper to satisfy than widening the scope: the
# resolver pastes in those definitions instead of the whole 300k-line bundle. The
# length rule is not politeness -- compressed extensions rename every identifier to
# one or two characters, and such a name cannot be resolved to anything meaningful.
SYMBOL_REQUEST_INSTRUCTIONS = """\
- requested_symbols: when needs_more_context is true, ALSO list the specific
  identifiers whose definition you need to decide -- e.g. ["decodeToken",
  "ALLOWED_ORIGINS"]. Naming them gets you their definitions verbatim, which is more
  useful than a wider excerpt. Rules: at most 8 names; each at least 3 characters;
  give the name exactly as it appears in the code. Do NOT list one- or two-character
  names -- this code has been through a minifier and those are ambiguous. Use [] when
  you have nothing specific to ask for.\
"""


# ============================================================================
# REASONING (thinking-block) INSTRUCTIONS -- selectable, chosen by
# config.REASONING_PROMPT. Default "none": no section, i.e. every run before this
# existed.
# ============================================================================
# Purpose (EXPERIMENTS.md §21.2, §21.11 / D48). With a vLLM reasoning parser the
# trace states a verdict and the JSON field then merely COPIES it, so the verdict
# token's logprob measures transcription rather than decision: 57% of verdict
# tokens had no runner-up at all and 69/156 candidates tied at exactly 1.0. These
# variants tell the model to complete the analysis but NOT to announce a verdict
# inside the thinking, so the decision actually happens at the measured token.
#
# Two failure modes are deliberately designed against, and both are why the
# wording is what it is:
#   * FABRICATED EVIDENCE. "Argue both sides" is an instruction to ADVOCATE, and a
#     model with nothing to advocate invents a guard or a caller to comply. Every
#     variant below therefore asks it to RECORD what the shown code contains, says
#     outright that an empty side is a normal result, and forbids filling one in.
#   * LOST REASONING QUALITY. The point is to keep the accuracy reasoning buys
#     (§20.1: the verdicts were fine either way) and only move WHERE the decision
#     is made. So each variant states that analysis depth is unchanged and only
#     the concluding sentence is withheld.
#
# Only the CLASSIFY step carries this (multi pipeline) plus the single pipeline's
# whole-task prompt -- those are the prompts whose `result` logprob is measured.
# The payload step is untouched: its `attacker_source` confidence was never
# affected by the trace (see llm_client._verdict_confidence).
#
# Has NO effect without a server-side reasoning parser: with the grammar
# constraining from token 0 the model cannot emit a thinking block at all (§20.2),
# and this section is then dead prompt weight.
#
# As with RESULT_RULES_VARIANTS, each entry is COMPLETE and SELF-CONTAINED: add a
# new numbered entry rather than editing one you have already run, or a comparison
# between two variants stops being valid.
REASONING_PROMPT_VARIANTS = {

    # -- 1: conclusion suppression only ---------------------------------------
    # The minimal intervention, and the clean A/B against "none": exactly one
    # variable changes (whether the trace announces a verdict). Prefer this one
    # for the first measurement -- if it moves the censoring rate, the mechanism
    # in §21.2 is confirmed without any confound from the ledger wording.
    "1": """\
REASONING (thinking):
- Work through the finding completely before you answer: trace the flow from the
  entry point to the sink and check each link against the code you were shown.
- Do NOT state a verdict inside your thinking -- not "so this is TP", not
  "therefore it is a false positive", not even provisionally or as a running
  guess. Complete the analysis and leave the decision itself to the JSON field.
- Your analysis is unchanged in depth; only the concluding sentence is withheld.
  Reason exactly as thoroughly as you otherwise would.\
""",

    # -- 2: evidence ledger + conclusion suppression --------------------------
    # Adds an explicit two-sided record so the trace carries the material for BOTH
    # readings up to the decision point, instead of narrowing early and spending
    # the rest of the trace confirming itself. The "one side is often empty" line
    # is load-bearing: it is what stops the ledger from becoming an invitation to
    # invent a blocker that is not in the code.
    "2": """\
REASONING (thinking):
- Work through the finding completely: trace the flow from the entry point to the
  sink and check each link against the code you were shown.
- As you go, keep two records: what in the shown code supports this being a real
  vulnerability, and what in the shown code supports it being not exploitable.
  Cite concrete lines, symbols or values -- what the code actually contains, never
  what it might contain.
- One of the two records is often empty, and that is a normal, expected outcome.
  If a side has no support in the shown code, record it as "none". Do NOT invent a
  guard, a sanitiser, a caller, or an attack path to balance the records: a
  manufactured entry is far worse than an empty side.
- Do NOT state a verdict inside your thinking -- not "so this is TP", not
  "therefore it is a false positive", not even provisionally. Complete the
  analysis and leave the decision itself to the JSON field.
- Your analysis is unchanged in depth; only the concluding sentence is withheld.\
""",

    # -- 3: ledger + both readings held open + name the missing evidence -------
    # The strongest anti-lock-in wording. Highest risk of over-hedging an easy
    # case, which would compress confidence at the EASY end and cost ranking power
    # rather than gain it (§21.11) -- hence the explicit "do not talk yourself into
    # a doubt the code does not support". Compare against 1 and 2 before adopting.
    "3": """\
REASONING (thinking):
- Work through the finding completely: trace the flow from the entry point to the
  sink and check each link against the code you were shown.
- As you go, keep two records: what in the shown code supports this being a real
  vulnerability, and what in the shown code supports it being not exploitable.
  Cite concrete lines, symbols or values -- what the code actually contains, never
  what it might contain.
- One of the two records is often empty, and that is a normal, expected outcome.
  If a side has no support in the shown code, record it as "none". Do NOT invent a
  guard, a sanitiser, a caller, or an attack path to balance the records: a
  manufactured entry is far worse than an empty side.
- Hold both readings open until you reach the JSON field. Where the evidence has
  already settled the question, the other record simply stays empty -- that is the
  correct result, and you must not talk yourself into a doubt the code does not
  support.
- If the shown code genuinely does not settle it, name the ONE thing that would:
  the specific function, caller, manifest entry or value you were not shown. Do
  not resolve the gap by picking whichever answer feels safer.
- Do NOT state a verdict inside your thinking -- not "so this is TP", not
  "therefore it is a false positive", not even provisionally. Complete the
  analysis and leave the decision itself to the JSON field.
- Your analysis is unchanged in depth; only the concluding sentence is withheld.\
""",
}
