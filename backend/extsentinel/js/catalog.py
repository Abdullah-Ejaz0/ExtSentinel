"""Knowledge base for the taint engine: what counts as sensitive data, where
it comes from, and which APIs move it out of the browser or execute code.

Keeping this declarative means the rules can be reviewed (and cited in the
report) independently of the analysis machinery in taint.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class Label:
    name: str
    phrase: str  # used in sentences: "Sends {phrase} to ..."
    sensitivity: Severity | None  # None = not user data (used only for code-execution analysis)
    page_derived: bool  # True if it only exists when the code runs inside a web page
    permission: str | None = None  # manifest permission needed for the source to work


LABELS: dict[str, Label] = {
    l.name: l
    for l in [
        Label("PASSWORD", "passwords typed into password fields", Severity.CRITICAL, True),
        Label("KEYSTROKES", "what you type (individual keystrokes)", Severity.CRITICAL, True),
        Label("COOKIES", "your browser cookies, including login sessions", Severity.CRITICAL, False, "cookies"),
        Label("PAGE_COOKIES", "the cookies of websites you visit", Severity.HIGH, True),
        Label("FORM_INPUT", "text you enter into forms on websites", Severity.HIGH, True),
        Label("REQUEST_DATA", "data your browser sends to websites (form posts or request headers)", Severity.HIGH, False, "webRequest"),
        Label("HISTORY", "your browsing history", Severity.HIGH, False, "history"),
        Label("CLIPBOARD", "the contents of your clipboard", Severity.HIGH, False),
        Label("SCREENSHOT", "screenshots or recordings of your tabs or screen", Severity.HIGH, False),
        Label("IDENTITY", "your Google account identity or access tokens", Severity.HIGH, False, "identity"),
        Label("GEOLOCATION", "your physical location", Severity.HIGH, False),
        Label("BROWSING", "the addresses of pages you open", Severity.MEDIUM, False),
        Label("PAGE_URL", "the address of each page you visit", Severity.MEDIUM, True),
        Label("PAGE_CONTENT", "the content of web pages you view", Severity.MEDIUM, True),
        Label("SITE_STORAGE", "data websites keep in local storage (may include login tokens)", Severity.MEDIUM, True),
        Label("BOOKMARKS", "your bookmarks", Severity.MEDIUM, False, "bookmarks"),
        Label("TOP_SITES", "your most visited websites", Severity.MEDIUM, False, "topSites"),
        Label("EXTENSIONS_LIST", "the list of extensions you have installed", Severity.LOW, False, "management"),
        # Not user data; drive code-execution findings.
        Label("REMOTE_DATA", "data downloaded from the internet", None, False),
        Label("UNTRUSTED_PAGE", "messages from web pages", None, True),
        Label("EXTERNAL_MESSAGE", "messages from websites or other extensions", None, False),
    ]
}

# Labels whose source API needs the `tabs` permission or host access to return URLs.
URL_LABELS_NEEDING_TABS = {"BROWSING"}

# --- Sources: property reads -------------------------------------------------
# Normalised global path -> (label, note)
SOURCE_PATHS: dict[str, tuple[str, str]] = {
    "document.cookie": ("PAGE_COOKIES", "reads document.cookie"),
    "location": ("PAGE_URL", "reads the page address (location)"),
    "document.location": ("PAGE_URL", "reads the page address (document.location)"),
    "document.URL": ("PAGE_URL", "reads the page address (document.URL)"),
    "document.documentURI": ("PAGE_URL", "reads the page address"),
    "document.referrer": ("PAGE_URL", "reads the previous page address (document.referrer)"),
    "document.title": ("PAGE_CONTENT", "reads the page title"),
    "document.body.innerText": ("PAGE_CONTENT", "reads the visible text of the page"),
    "document.body.innerHTML": ("PAGE_CONTENT", "reads the page HTML"),
    "document.body.outerHTML": ("PAGE_CONTENT", "reads the page HTML"),
    "document.body.textContent": ("PAGE_CONTENT", "reads the page text"),
    "document.documentElement.outerHTML": ("PAGE_CONTENT", "reads the full page HTML"),
    "document.documentElement.innerHTML": ("PAGE_CONTENT", "reads the full page HTML"),
    "document.documentElement.innerText": ("PAGE_CONTENT", "reads the visible text of the page"),
    "localStorage": ("SITE_STORAGE", "reads the website's localStorage"),
    "sessionStorage": ("SITE_STORAGE", "reads the website's sessionStorage"),
}

# Paths that evaluate to DOM elements.
DOM_PATHS = {"document.body", "document.documentElement", "document.forms", "document.activeElement", "document.all"}

KEY_EVENTS = {"keydown", "keypress", "keyup"}
INPUT_EVENTS = {"input", "change", "beforeinput"}
KEY_PROPS = {"key", "keyCode", "which", "code", "charCode", "char"}
TEXT_PROPS = {"innerText", "textContent", "innerHTML", "outerHTML", "outerText"}

# --- Sources: API calls ------------------------------------------------------
# path -> (label, note). Results and callback parameters carry the label.
CALL_SOURCES: dict[str, tuple[str, str]] = {
    "chrome.cookies.get": ("COOKIES", "reads a cookie with chrome.cookies.get"),
    "chrome.cookies.getAll": ("COOKIES", "reads cookies with chrome.cookies.getAll"),
    "chrome.history.search": ("HISTORY", "reads browsing history with chrome.history.search"),
    "chrome.history.getVisits": ("HISTORY", "reads browsing history with chrome.history.getVisits"),
    "chrome.sessions.getRecentlyClosed": ("HISTORY", "reads recently closed tabs"),
    "chrome.sessions.getDevices": ("HISTORY", "reads tabs from your other devices"),
    "chrome.bookmarks.getTree": ("BOOKMARKS", "reads all bookmarks"),
    "chrome.bookmarks.getSubTree": ("BOOKMARKS", "reads bookmarks"),
    "chrome.bookmarks.search": ("BOOKMARKS", "searches bookmarks"),
    "chrome.bookmarks.getRecent": ("BOOKMARKS", "reads recent bookmarks"),
    "chrome.topSites.get": ("TOP_SITES", "reads your most visited sites"),
    "chrome.tabs.query": ("BROWSING", "reads open tabs (including their URLs)"),
    "chrome.tabs.get": ("BROWSING", "reads a tab (including its URL)"),
    "chrome.tabs.getCurrent": ("BROWSING", "reads the current tab"),
    "chrome.tabs.getSelected": ("BROWSING", "reads the selected tab"),
    "chrome.windows.getAll": ("BROWSING", "reads all windows and their tabs"),
    "chrome.windows.getCurrent": ("BROWSING", "reads the current window"),
    "chrome.windows.getLastFocused": ("BROWSING", "reads the focused window"),
    "chrome.tabs.captureVisibleTab": ("SCREENSHOT", "takes a screenshot of the visible tab"),
    "chrome.tabCapture.capture": ("SCREENSHOT", "captures a tab's audio/video"),
    "chrome.tabCapture.getMediaStreamId": ("SCREENSHOT", "captures a tab's audio/video"),
    "chrome.desktopCapture.chooseDesktopMedia": ("SCREENSHOT", "captures your screen"),
    "navigator.clipboard.readText": ("CLIPBOARD", "reads the clipboard"),
    "navigator.clipboard.read": ("CLIPBOARD", "reads the clipboard"),
    "navigator.geolocation.getCurrentPosition": ("GEOLOCATION", "reads your location"),
    "navigator.geolocation.watchPosition": ("GEOLOCATION", "tracks your location"),
    "chrome.identity.getAuthToken": ("IDENTITY", "obtains a Google OAuth token"),
    "chrome.identity.getProfileUserInfo": ("IDENTITY", "reads your Google account email"),
    "chrome.management.getAll": ("EXTENSIONS_LIST", "lists your installed extensions"),
    "localStorage.getItem": ("SITE_STORAGE", "reads the website's localStorage"),
    "sessionStorage.getItem": ("SITE_STORAGE", "reads the website's sessionStorage"),
}

# chrome event -> (label, note); callback parameters carry the label.
EVENT_SOURCES: dict[str, tuple[str, str]] = {
    "chrome.webRequest.onBeforeRequest": ("BROWSING", "observes every request (chrome.webRequest.onBeforeRequest)"),
    "chrome.webRequest.onBeforeSendHeaders": ("BROWSING", "observes outgoing request headers"),
    "chrome.webRequest.onSendHeaders": ("BROWSING", "observes outgoing request headers"),
    "chrome.webRequest.onHeadersReceived": ("BROWSING", "observes response headers"),
    "chrome.webRequest.onResponseStarted": ("BROWSING", "observes every response"),
    "chrome.webRequest.onCompleted": ("BROWSING", "observes every completed request"),
    "chrome.webRequest.onBeforeRedirect": ("BROWSING", "observes redirects"),
    "chrome.webRequest.onErrorOccurred": ("BROWSING", "observes failed requests"),
    "chrome.webRequest.onAuthRequired": ("REQUEST_DATA", "intercepts HTTP authentication prompts"),
    "chrome.webNavigation.onBeforeNavigate": ("BROWSING", "observes every navigation"),
    "chrome.webNavigation.onCommitted": ("BROWSING", "observes every navigation"),
    "chrome.webNavigation.onCompleted": ("BROWSING", "observes every navigation"),
    "chrome.webNavigation.onDOMContentLoaded": ("BROWSING", "observes every navigation"),
    "chrome.webNavigation.onHistoryStateUpdated": ("BROWSING", "observes in-page navigation"),
    "chrome.webNavigation.onReferenceFragmentUpdated": ("BROWSING", "observes in-page navigation"),
    "chrome.webNavigation.onCreatedNavigationTarget": ("BROWSING", "observes new navigations"),
    "chrome.tabs.onUpdated": ("BROWSING", "observes tab URL changes (chrome.tabs.onUpdated)"),
    "chrome.tabs.onCreated": ("BROWSING", "observes new tabs"),
    "chrome.history.onVisited": ("HISTORY", "observes every page visit (chrome.history.onVisited)"),
    "chrome.cookies.onChanged": ("COOKIES", "observes every cookie change"),
    "chrome.runtime.onMessageExternal": ("EXTERNAL_MESSAGE", "receives messages from websites/other extensions"),
    "chrome.runtime.onConnectExternal": ("EXTERNAL_MESSAGE", "accepts connections from websites/other extensions"),
}
# webRequest extraInfoSpec values that expose request contents.
REQUEST_DATA_SPECS = {"requestBody", "requestHeaders", "extraHeaders"}

MESSAGE_LISTENERS = {"chrome.runtime.onMessage", "chrome.extension.onMessage", "chrome.extension.onRequest"}
MESSAGE_SENDS = {"chrome.runtime.sendMessage", "chrome.extension.sendMessage", "chrome.extension.sendRequest"}

# --- Sinks -------------------------------------------------------------------
# path -> (index of URL argument or None, description)
NETWORK_CALLS: dict[str, tuple[int | None, str]] = {
    "fetch": (0, "sends a request with fetch()"),
    "navigator.sendBeacon": (0, "sends data with navigator.sendBeacon()"),
    "$.ajax": (0, "sends a request with jQuery.ajax()"),
    "$.post": (0, "sends a request with jQuery.post()"),
    "$.get": (0, "sends a request with jQuery.get()"),
    "$.getJSON": (0, "sends a request with jQuery.getJSON()"),
    "axios": (0, "sends a request with axios"),
    "axios.get": (0, "sends a request with axios.get()"),
    "axios.post": (0, "sends a request with axios.post()"),
    "axios.put": (0, "sends a request with axios.put()"),
    "axios.patch": (0, "sends a request with axios.patch()"),
    "axios.request": (0, "sends a request with axios.request()"),
    "open": (0, "opens a URL with window.open()"),
    "chrome.runtime.setUninstallURL": (0, "sets a URL opened when the extension is removed"),
}
# URL is a property of the first (object) argument.
NETWORK_URL_PROP_CALLS: dict[str, str] = {
    "chrome.tabs.create": "opens a tab with chrome.tabs.create()",
    "chrome.tabs.update": "navigates a tab with chrome.tabs.update()",
    "chrome.windows.create": "opens a window with chrome.windows.create()",
    "chrome.downloads.download": "downloads a URL",
}
RESPONSE_METHODS = {"text", "json", "blob", "arrayBuffer", "formData"}
MUTATING_METHODS = {"push", "unshift", "splice", "set", "add", "append", "assign"}
DOM_QUERY_METHODS = {
    "querySelector", "querySelectorAll", "getElementById", "getElementsByTagName",
    "getElementsByName", "getElementsByClassName", "closest", "elementFromPoint",
}  # fmt: skip
JQUERY_KEY_METHODS = {"keydown", "keypress", "keyup"}

PASSWORD_SELECTOR_HINTS = ("password",)

# Constant code strings that are well-known benign idioms (e.g. bundler global detection).
BENIGN_CODE_STRINGS = {"return this", "this", "return this;", "return globalThis"}

# Global names used to resolve API paths.
PATH_PREFIX_STRIP = ("window.", "self.", "globalThis.", "top.", "parent.", "frames.")


def normalize_path(path: str) -> str:
    changed = True
    while changed:
        changed = False
        for prefix in PATH_PREFIX_STRIP:
            if path.startswith(prefix) and len(path) > len(prefix):
                path = path[len(prefix) :]
                changed = True
    if path.startswith("browser."):
        path = "chrome." + path[len("browser.") :]
    elif path.startswith("jQuery."):
        path = "$." + path[len("jQuery.") :]
    return path
