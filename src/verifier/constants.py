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
LOCALSTORAGE_APIS = {'localStorage.setItem', 'localStorage.getItem', 'localStorage.removeItem', 'localStorage.clear'}

# APIs that are skipped during verification (not implemented yet)
SKIPPED_APIS = {
    'chrome.history.deleteRange',
    'chrome.history.getVisits',
    'chrome.management.uninstall',
    'chrome.management.uninstallSelf',
    'chrome.management.setEnabled',
    'chrome.management.get',
    'chrome.management.getAll',
    'chrome.management.getSelf',
    'chrome.declarativeNetRequest.updateDynamicRules',
    'chrome.topSites.get'
}
CHROME_STORAGE_APIS = {
    'chrome.storage.local.set', 'chrome.storage.local.get', 'chrome.storage.local.remove', 'chrome.storage.local.clear',
    'chrome.storage.sync.set', 'chrome.storage.sync.get', 'chrome.storage.sync.remove', 'chrome.storage.sync.clear',
    'chrome.storage.session.set', 'chrome.storage.session.get', 'chrome.storage.session.remove', 'chrome.storage.session.clear'
}

# Marker values written by the verifier when seeding test data. A storage value
# equal to one of these confirms the payload actually wrote/kept attacker data.
# Used both for Python membership checks and to build the equivalent JS condition.
EXPLOIT_MARKERS = ("exploit", "123456789")

# Categories whose detection reads the process-wide mock server (its request log
# and the per-test token it hands out on reset). Verifications of these cannot run
# concurrently -- they would reset and mis-attribute each other's state -- so
# config.VERIFIER_PARALLEL keeps any extension containing one of them sequential.
# Everything else (storage -> the extension's own chrome.storage; data_exfiltration
# -> the [EXFIL] marker on its own page console) is independent per browser context.
MOCK_SERVER_CATEGORIES = frozenset({
    "1way_request", "2way_request", "code_execution", "download",
})

# Categories for which a retry after no detection is worthwhile (warm-up / timing issues)
RETRY_CATEGORIES: set = set()  # Disabled: retries cost time without reliable benefit

# Filename and marker of the page the verifier writes into every target extension to
# get a chrome-extension:// context with Chrome API access. The marker lets ID
# recovery tell "our page in the target extension" apart from an unrelated
# chrome-extension:// origin (the verifier extension, a Chrome component extension,
# or an extension that happens to ship a file of the same name).
STORAGE_PAGE_FILENAME = "verify_storage.html"
STORAGE_PAGE_MARKER = "chrome-ext-verifier-storage-page"
STORAGE_PAGE_HTML = (
    '<!DOCTYPE html><html><head>'
    f'<meta name="verifier-storage-page" content="{STORAGE_PAGE_MARKER}">'
    '</head><body></body></html>'
)


class Color:
    """Terminal color and formatting codes."""
    BOLD = '\033[1m'
    END = '\033[0m'
