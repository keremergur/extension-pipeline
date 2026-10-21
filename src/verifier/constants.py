# API Categories for verification
BOOKMARKS_APIS = {
    'chrome.bookmarks.create', 'chrome.bookmarks.remove', 'chrome.bookmarks.removeTree',
    'chrome.bookmarks.get', 'chrome.bookmarks.getRecent', 'chrome.bookmarks.getTree',
    'chrome.bookmarks.search'
}

COOKIES_APIS = {
    'chrome.cookies.set', 'chrome.cookies.remove',
    'chrome.cookies.get', 'chrome.cookies.getAll'
}

HISTORY_APIS = {
    'chrome.history.addUrl', 'chrome.history.deleteUrl', 'chrome.history.deleteAll',
    'chrome.history.deleteRange', 'chrome.history.getVisits', 'chrome.history.search'
}

MANAGEMENT_APIS = {
    'chrome.management.uninstall', 'chrome.management.uninstallSelf', 'chrome.management.setEnabled',
    'chrome.management.get', 'chrome.management.getAll', 'chrome.management.getSelf'
}

DNR_APIS = {'chrome.declarativeNetRequest.updateDynamicRules'}
TOPSITES_APIS = {'chrome.topSites.get'}
# Web-storage APIs (localStorage AND sessionStorage). sessionStorage.* was previously absent,
# so those findings hit no routing branch and always missed; check_web_storage / seeding already
# handle the sessionStorage case, they just needed to be routed here.
LOCALSTORAGE_APIS = {
    'localStorage.setItem', 'localStorage.getItem', 'localStorage.removeItem', 'localStorage.clear',
    'sessionStorage.setItem', 'sessionStorage.getItem', 'sessionStorage.removeItem', 'sessionStorage.clear',
}

# APIs skipped during verification by default. Several now HAVE working handlers
# (check_management uninstall/uninstallSelf, check_history deleteRange) or a working
# data-exfiltration read path (verify_exfiltrated_data covers management/topSites/history
# reads), so they are only skipped for backward-compatibility with the thesis baseline.
# EXTRA_VERIFY_APIS lets a run enable them without a code change:
#   unset/empty        -> skip all of the below (baseline behaviour, unchanged)
#   "all"              -> skip nothing (attempt every API; precision is still guarded by the
#                         marker / no-op control, so an un-handled API just yields a miss, not an FP)
#   "a,b,c"            -> remove exactly those APIs from the skip set
import os as _os

_DEFAULT_SKIPPED_APIS = {
    'chrome.history.deleteRange',
    'chrome.history.getVisits',
    'chrome.management.uninstall',
    'chrome.management.uninstallSelf',
    'chrome.management.setEnabled',
    'chrome.management.get',
    'chrome.management.getAll',
    'chrome.management.getSelf',
    'chrome.topSites.get'
}
_extra_verify = (_os.getenv("EXTRA_VERIFY_APIS") or "").strip()
if _extra_verify.lower() == "all":
    SKIPPED_APIS = set()
elif _extra_verify:
    SKIPPED_APIS = _DEFAULT_SKIPPED_APIS - {a.strip() for a in _extra_verify.split(",") if a.strip()}
else:
    SKIPPED_APIS = set(_DEFAULT_SKIPPED_APIS)
CHROME_STORAGE_APIS = {
    'chrome.storage.local.set', 'chrome.storage.local.get', 'chrome.storage.local.remove', 'chrome.storage.local.clear',
    'chrome.storage.sync.set', 'chrome.storage.sync.get', 'chrome.storage.sync.remove', 'chrome.storage.sync.clear',
    'chrome.storage.session.set', 'chrome.storage.session.get', 'chrome.storage.session.remove', 'chrome.storage.session.clear'
}

# Marker values written by the verifier when seeding test data. A storage value
# equal to one of these confirms the payload actually wrote/kept attacker data.
# Used both for Python membership checks and to build the equivalent JS condition.
EXPLOIT_MARKERS = ("exploit", "123456789")

# Categories for which a retry after no detection is worthwhile (warm-up / timing issues)
RETRY_CATEGORIES: set = set()  # Disabled: retries cost time without reliable benefit


class Color:
    """Terminal color and formatting codes."""
    BOLD = '\033[1m'
    END = '\033[0m'
