"""Manifest parsing and analysis.

A permission is a *capability*, not a behaviour. Manifest findings therefore
describe what the extension is allowed to do and are kept at moderate
severity; the code analysis decides whether the capability is actually used
and how. Severe manifest findings are reserved for declarations that are
risky by themselves (e.g. off-store updates, `debugger`, weakened CSP).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from .findings import FindingCollector
from .models import Category, Confidence, Evidence, Severity
from .package import ExtensionPackage

S = Severity

# permission -> (severity, what it allows, API namespace used to check whether code uses it)
PERMISSIONS: dict[str, tuple[Severity, str, str | None]] = {
    "debugger": (S.HIGH, "Can attach a debugger to your tabs, giving full control over every page it attaches to", "chrome.debugger"),
    "proxy": (S.HIGH, "Can route all your web traffic through a server of its choice", "chrome.proxy"),
    "webAuthenticationProxy": (S.HIGH, "Can intercept passkey and security-key sign-ins", "chrome.webAuthenticationProxy"),
    "nativeMessaging": (S.MEDIUM, "Can exchange data with programs installed on your computer", "chrome.runtime.connectNative|chrome.runtime.sendNativeMessage"),
    "management": (S.MEDIUM, "Can see, disable or uninstall your other extensions (including security tools)", "chrome.management"),
    "cookies": (S.MEDIUM, "Can read and change your cookies, which include login sessions", "chrome.cookies"),
    "history": (S.MEDIUM, "Can read and change your browsing history", "chrome.history"),
    "webRequest": (S.MEDIUM, "Can observe the network requests your browser makes", "chrome.webRequest"),
    "webRequestBlocking": (S.MEDIUM, "Can block or modify network requests in flight", "chrome.webRequest"),
    "webRequestAuthProvider": (S.MEDIUM, "Can answer HTTP authentication prompts", "chrome.webRequest"),
    "clipboardRead": (S.MEDIUM, "Can read what you copy to the clipboard", "navigator.clipboard|document.execCommand"),
    "desktopCapture": (S.MEDIUM, "Can capture your screen", "chrome.desktopCapture"),
    "tabCapture": (S.MEDIUM, "Can record audio and video of your tabs", "chrome.tabCapture"),
    "userScripts": (S.MEDIUM, "Can run user-supplied scripts on websites", "chrome.userScripts"),
    "privacy": (S.MEDIUM, "Can change your browser's privacy settings", "chrome.privacy"),
    "contentSettings": (S.MEDIUM, "Can change per-site settings such as camera, microphone and JavaScript", "chrome.contentSettings"),
    "vpnProvider": (S.MEDIUM, "Can act as a VPN for your traffic", "chrome.vpnProvider"),
    "platformKeys": (S.MEDIUM, "Can use client certificates managed by the system", "chrome.platformKeys"),
    "certificateProvider": (S.MEDIUM, "Can provide certificates for TLS authentication", "chrome.certificateProvider"),
    "tabs": (S.LOW, "Can see the address and title of every tab", "chrome.tabs"),
    "webNavigation": (S.LOW, "Can see every page you navigate to", "chrome.webNavigation"),
    "scripting": (S.LOW, "Can inject scripts into sites it has access to", "chrome.scripting"),
    "declarativeNetRequest": (S.LOW, "Can block or redirect requests using rules", None),
    "declarativeNetRequestWithHostAccess": (S.LOW, "Can block or redirect requests on sites it has access to", None),
    "declarativeNetRequestFeedback": (S.LOW, "Can see which requests matched its rules (reveals pages you visit)", "chrome.declarativeNetRequest"),
    "downloads": (S.LOW, "Can manage your downloads and see download history", "chrome.downloads"),
    "downloads.open": (S.LOW, "Can open files you downloaded", "chrome.downloads"),
    "geolocation": (S.LOW, "Can access your location", "navigator.geolocation"),
    "browsingData": (S.LOW, "Can delete your browsing data", "chrome.browsingData"),
    "identity": (S.LOW, "Can use your Google account sign-in (OAuth tokens)", "chrome.identity"),
    "identity.email": (S.LOW, "Can see your Google account email address", "chrome.identity"),
    "topSites": (S.LOW, "Can see your most visited sites", "chrome.topSites"),
    "bookmarks": (S.LOW, "Can read and change your bookmarks", "chrome.bookmarks"),
    "sessions": (S.LOW, "Can see recently closed tabs and tabs on your other devices", "chrome.sessions"),
    "pageCapture": (S.LOW, "Can save complete copies of pages", "chrome.pageCapture"),
    "processes": (S.LOW, "Can see browser processes", "chrome.processes"),
    "documentScan": (S.LOW, "Can use document scanners", "chrome.documentScan"),
    "background": (S.LOW, "Keeps running after the browser window is closed", None),
    "offscreen": (S.INFO, "Can open hidden background documents", None),
    "clipboardWrite": (S.INFO, "Can change the clipboard", None),
    "activeTab": (S.INFO, "Can access the current page only when you click the extension", None),
    "system.cpu": (S.INFO, "Can read CPU information", None),
    "system.memory": (S.INFO, "Can read memory information", None),
    "system.storage": (S.INFO, "Can read storage device information", None),
    "system.display": (S.INFO, "Can read display information", None),
}
# Permissions that carry no meaningful risk and are not reported.
SILENT_PERMISSIONS = {
    "storage", "unlimitedStorage", "alarms", "notifications", "contextMenus", "idle", "power",
    "tts", "ttsEngine", "sidePanel", "fontSettings", "search", "favicon", "tabGroups",
    "readingList", "printing", "printingMetrics", "printerProvider", "wallpaper", "gcm",
    "dns", "loginState", "accessibilityFeatures.read", "fileBrowserHandler", "fileSystemProvider",
    "enterprise.deviceAttributes", "enterprise.hardwarePlatform", "enterprise.networkingAttributes",
    "enterprise.platformKeys", "audio", "systemLog", "transientBackground", "webview", "experimental",
}  # fmt: skip

ALL_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/"}
WEBSTORE_UPDATE_URLS = (
    "https://clients2.google.com/service/update2/crx",
    "http://clients2.google.com/service/update2/crx",
    "https://update.googleapis.com/service/update2",
)


@dataclass
class ContentScript:
    matches: list[str]
    js: list[str]
    all_frames: bool
    run_at: str
    world: str

    @property
    def all_sites(self) -> bool:
        return any(is_all_hosts(m) for m in self.matches)


@dataclass
class ManifestInfo:
    raw: dict
    name: str
    version: str
    manifest_version: int | None
    description: str | None
    permissions: list[str]
    host_permissions: list[str]
    optional_permissions: list[str]
    optional_host_permissions: list[str]
    content_scripts: list[ContentScript]
    background_scripts: list[str]
    background_pages: list[str]
    extension_pages: list[str]
    web_accessible: list[str]  # resource patterns
    warnings: list[str] = field(default_factory=list)

    @property
    def has_all_hosts(self) -> bool:
        return any(is_all_hosts(h) for h in self.host_permissions) or any(cs.all_sites for cs in self.content_scripts)

    def granted(self, permission: str) -> str:
        """'required', 'optional' or 'missing'."""
        if permission in self.permissions:
            return "required"
        if permission in self.optional_permissions:
            return "optional"
        return "missing"

    def first_party_hosts(self) -> set[str]:
        """Hosts the extension is explicitly scoped to (not wildcards for all sites)."""
        hosts: set[str] = set()
        patterns = list(self.host_permissions) + [m for cs in self.content_scripts for m in cs.matches]
        for p in patterns:
            if is_all_hosts(p):
                continue
            h = host_of_pattern(p)
            if h:
                hosts.add(h)
        for key in ("homepage_url", "author"):
            val = self.raw.get(key)
            if isinstance(val, str) and "://" in val:
                h = urlparse(val).hostname
                if h:
                    hosts.add(h.lower())
        return hosts


def is_all_hosts(pattern: str) -> bool:
    if pattern in ALL_HOST_PATTERNS:
        return True
    m = re.match(r"^(\*|https?|wss?|ftp|file)://([^/]*)/", pattern)
    return bool(m and m.group(2) in ("*", "*:*") and m.group(1) != "file")


def host_of_pattern(pattern: str) -> str | None:
    m = re.match(r"^[a-z*]+://([^/]+)/", pattern)
    if not m:
        return None
    host = m.group(1).split(":")[0].lower()
    return host.lstrip("*.") or None


def host_matches(host: str, first_party: set[str]) -> bool:
    host = host.lower()
    return any(host == fp or host.endswith("." + fp) for fp in first_party)


# --- parsing -----------------------------------------------------------------


def _strip_json_comments(text: str) -> str:
    """Chrome accepts // and /* */ comments in manifest.json."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _as_str_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _localize(pkg: ExtensionPackage, raw: dict, value) -> str | None:
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"__MSG_(\w+)__", value.strip())
    if not m:
        return value
    locale = raw.get("default_locale") or "en"
    for loc in (locale, "en", "en_US"):
        text = pkg.text(f"_locales/{loc}/messages.json")
        if not text:
            continue
        try:
            messages = json.loads(_strip_json_comments(text))
        except ValueError:
            continue
        lowered = {k.lower(): v for k, v in messages.items() if isinstance(v, dict)}
        entry = lowered.get(m.group(1).lower())
        if entry and isinstance(entry.get("message"), str):
            return entry["message"]
    return value


class _PageScripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[tuple[str, int]] = []
        self.inline: list[tuple[str, int]] = []
        self._in_script = False
        self._buf: list[str] = []
        self._line = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attrs = dict(attrs)
            src = attrs.get("src")
            if src:
                self.srcs.append((src, self.getpos()[0]))
            else:
                self._in_script = True
                self._buf = []
                self._line = self.getpos()[0]

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            code = "".join(self._buf)
            if code.strip():
                self.inline.append((code, self._line))

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


def page_scripts(html: str) -> _PageScripts:
    p = _PageScripts()
    try:
        p.feed(html)
    except Exception:  # malformed HTML: keep what was parsed
        pass
    return p


def parse_manifest(pkg: ExtensionPackage) -> ManifestInfo:
    text = pkg.text("manifest.json") or ""
    try:
        raw = json.loads(text)
    except ValueError:
        try:
            raw = json.loads(_strip_json_comments(text))
        except ValueError as exc:
            raise ValueError(f"manifest.json is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("manifest.json is not a JSON object")

    mv = raw.get("manifest_version")
    mv = mv if isinstance(mv, int) else None
    perms = _as_str_list(raw.get("permissions"))
    opt = _as_str_list(raw.get("optional_permissions"))
    host_perms = _as_str_list(raw.get("host_permissions"))
    opt_hosts = _as_str_list(raw.get("optional_host_permissions"))
    # MV2 mixes host patterns into "permissions".
    api_perms = [p for p in perms if not _looks_like_host(p)]
    host_perms += [p for p in perms if _looks_like_host(p)]
    opt_api = [p for p in opt if not _looks_like_host(p)]
    opt_hosts += [p for p in opt if _looks_like_host(p)]

    content_scripts = []
    for cs in raw.get("content_scripts") or []:
        if not isinstance(cs, dict):
            continue
        content_scripts.append(
            ContentScript(
                matches=_as_str_list(cs.get("matches")),
                js=_as_str_list(cs.get("js")),
                all_frames=bool(cs.get("all_frames")),
                run_at=str(cs.get("run_at") or "document_idle"),
                world=str(cs.get("world") or "ISOLATED"),
            )
        )

    bg = raw.get("background") if isinstance(raw.get("background"), dict) else {}
    bg_scripts = _as_str_list(bg.get("scripts")) + _as_str_list(bg.get("service_worker"))
    bg_pages = _as_str_list(bg.get("page"))

    pages: list[str] = []
    for key in ("action", "browser_action", "page_action"):
        section = raw.get(key)
        if isinstance(section, dict):
            pages += _as_str_list(section.get("default_popup"))
    pages += _as_str_list(raw.get("options_page")) + _as_str_list(raw.get("devtools_page"))
    for key in ("options_ui", "side_panel"):
        section = raw.get(key)
        if isinstance(section, dict):
            pages += _as_str_list(section.get("page") or section.get("default_path"))
    overrides = raw.get("chrome_url_overrides")
    if isinstance(overrides, dict):
        pages += [v for v in overrides.values() if isinstance(v, str)]
    sandbox = raw.get("sandbox")
    if isinstance(sandbox, dict):
        pages += _as_str_list(sandbox.get("pages"))

    war: list[str] = []
    for entry in raw.get("web_accessible_resources") or []:
        if isinstance(entry, str):
            war.append(entry)
        elif isinstance(entry, dict):
            war += _as_str_list(entry.get("resources"))

    return ManifestInfo(
        raw=raw,
        name=_localize(pkg, raw, raw.get("name")) or "(unnamed)",
        version=str(raw.get("version") or "0"),
        manifest_version=mv,
        description=_localize(pkg, raw, raw.get("description")),
        permissions=api_perms,
        host_permissions=host_perms,
        optional_permissions=opt_api,
        optional_host_permissions=opt_hosts,
        content_scripts=content_scripts,
        background_scripts=bg_scripts,
        background_pages=bg_pages,
        extension_pages=pages,
        web_accessible=war,
    )


def _looks_like_host(p: str) -> bool:
    return p == "<all_urls>" or "://" in p


# --- analysis ----------------------------------------------------------------

_MANIFEST = "manifest.json"


def _ev(note: str) -> Evidence:
    return Evidence(file=_MANIFEST, note=note)


def analyze_manifest(info: ManifestInfo, pkg: ExtensionPackage, out: FindingCollector) -> None:
    raw = info.raw

    # Host access
    all_hosts = [h for h in info.host_permissions if is_all_hosts(h)]
    if all_hosts:
        out.add(
            "HOST_ALL_SITES", Category.HOST_ACCESS, S.MEDIUM,
            "Can read and change your data on all websites",
            "The extension requests access to every website. This lets its scripts read page content, "
            "form input and site cookies anywhere you browse. Code analysis below shows whether it actually does.",
            _ev(f"host permission: {', '.join(all_hosts)}"),
        )  # fmt: skip
    else:
        specific = sorted({h for h in info.host_permissions if not h.startswith("file:")})
        if len(specific) >= 20:
            out.add(
                "HOST_MANY_SITES", Category.HOST_ACCESS, S.LOW,
                f"Can read and change your data on {len(specific)} websites",
                "The extension requests access to a large number of specific sites.",
                _ev("host permissions: " + ", ".join(specific[:10]) + (" ..." if len(specific) > 10 else "")),
            )  # fmt: skip
    if any(h.startswith("file:") for h in info.host_permissions):
        out.add(
            "HOST_LOCAL_FILES", Category.HOST_ACCESS, S.LOW,
            "Asks to read files on your computer",
            "file:// access lets the extension read local files opened in the browser (only if you enable it in extension settings).",
            _ev("host permission includes file:///"),
        )  # fmt: skip
    opt_all = [h for h in info.optional_host_permissions if is_all_hosts(h)]
    if opt_all and not all_hosts:
        out.add(
            "HOST_ALL_SITES_OPTIONAL", Category.HOST_ACCESS, S.LOW,
            "May ask for access to all websites later",
            "Access to every website is declared as optional; the extension can request it at runtime.",
            _ev(f"optional host permission: {', '.join(opt_all)}"),
        )  # fmt: skip

    # API permissions
    for perm in info.permissions:
        _permission_finding(perm, optional=False, out=out)
    for perm in info.optional_permissions:
        _permission_finding(perm, optional=True, out=out)

    # Content scripts
    for cs in info.content_scripts:
        if cs.all_sites and cs.js:
            details = []
            if cs.all_frames:
                details.append("including embedded frames")
            if cs.run_at == "document_start":
                details.append("before the page itself loads")
            if cs.world.upper() == "MAIN":
                details.append("in the page's own JavaScript context")
            out.add(
                "CONTENT_SCRIPT_ALL_SITES", Category.CONTENT_SCRIPT, S.LOW,
                "Runs its own code inside every website you visit",
                "Content scripts " + ", ".join(cs.js[:5]) + " are injected into all sites"
                + (f" ({'; '.join(details)})" if details else "") + ".",
                _ev(f"content_scripts matches: {', '.join(cs.matches[:5])}"),
            )  # fmt: skip

    # Content Security Policy
    _analyze_csp(info, out)

    # Updates outside the Web Store
    update_url = raw.get("update_url")
    if isinstance(update_url, str) and not update_url.startswith(WEBSTORE_UPDATE_URLS):
        out.add(
            "UPDATE_URL_OFFSTORE", Category.MANIFEST, S.HIGH,
            "Receives updates from outside the Chrome Web Store",
            f"Updates come from {update_url}, so new versions bypass Web Store review.",
            _ev(f"update_url: {update_url}"),
        )  # fmt: skip

    # Externally connectable
    ec = raw.get("externally_connectable")
    if isinstance(ec, dict):
        matches = _as_str_list(ec.get("matches"))
        if any(is_all_hosts(m) for m in matches):
            out.add(
                "EXTERNALLY_CONNECTABLE_ALL", Category.MANIFEST, S.MEDIUM,
                "Any website can send commands to this extension",
                "externally_connectable allows every website to message the extension's background script; "
                "if those messages are trusted, websites can drive the extension.",
                _ev(f"externally_connectable matches: {', '.join(matches)}"),
            )  # fmt: skip
        if "*" in _as_str_list(ec.get("ids")):
            out.add(
                "EXTERNALLY_CONNECTABLE_ANY_EXTENSION", Category.MANIFEST, S.LOW,
                "Any other extension can send commands to this extension",
                "externally_connectable lists ids: ['*'].",
                _ev("externally_connectable ids: *"),
            )  # fmt: skip

    # Web-accessible resources reachable from every site (fingerprinting / page-world injection)
    for entry in raw.get("web_accessible_resources") or []:
        if isinstance(entry, dict) and any(is_all_hosts(m) for m in _as_str_list(entry.get("matches"))):
            js = [r for r in _as_str_list(entry.get("resources")) if r.endswith(".js") or r in ("*", "/*")]
            if js:
                out.add(
                    "WAR_SCRIPTS_ALL_SITES", Category.MANIFEST, S.INFO,
                    "Exposes scripts that any website can load",
                    "Web-accessible scripts are often injected into the page's own context, outside the content-script sandbox.",
                    _ev("web_accessible_resources: " + ", ".join(js[:5])),
                )  # fmt: skip

    # Search / homepage overrides
    cso = raw.get("chrome_settings_overrides")
    if isinstance(cso, dict) and (cso.get("search_provider") or cso.get("homepage") or cso.get("startup_pages")):
        changed = [k for k in ("search_provider", "homepage", "startup_pages") if cso.get(k)]
        out.add(
            "SETTINGS_OVERRIDE", Category.MANIFEST, S.LOW,
            "Changes your search engine or start page",
            "Settings overrides are a common way to monetise searches.",
            _ev("chrome_settings_overrides: " + ", ".join(changed)),
        )  # fmt: skip

    if info.manifest_version == 2:
        out.add(
            "MANIFEST_V2", Category.MANIFEST, S.INFO,
            "Uses the deprecated Manifest V2 platform",
            "Manifest V2 allows remotely hosted code and blocking web requests, which Manifest V3 removed.",
            _ev("manifest_version: 2"),
        )  # fmt: skip

    _analyze_dnr_rules(info, pkg, out)


def _permission_finding(perm: str, optional: bool, out: FindingCollector) -> None:
    if perm in SILENT_PERMISSIONS:
        return
    entry = PERMISSIONS.get(perm)
    if entry is None:
        return
    severity, text, _ = entry
    if severity == S.INFO and not optional:
        return
    if optional:
        severity = severity.lowered()
        text = "May ask to: " + text[0].lower() + text[1:]
    out.add(
        f"PERM_{perm.upper().replace('.', '_')}", Category.PERMISSION, severity, text,
        f"Declared {'optional ' if optional else ''}permission \"{perm}\". A permission shows what the extension "
        "is able to do; whether it uses it is determined by the code analysis.",
        _ev(f"{'optional_' if optional else ''}permissions: {perm}"),
    )  # fmt: skip


def _analyze_csp(info: ManifestInfo, out: FindingCollector) -> None:
    csp = info.raw.get("content_security_policy")
    policies: list[tuple[str, str]] = []
    if isinstance(csp, str):
        policies.append(("extension pages", csp))
    elif isinstance(csp, dict):
        for key in ("extension_pages", "sandbox"):
            if isinstance(csp.get(key), str):
                policies.append((key.replace("_", " "), csp[key]))
    for where, policy in policies:
        script_src = _directive(policy, "script-src") or _directive(policy, "default-src") or ""
        tokens = script_src.split()
        sandbox = where == "sandbox"
        if "'unsafe-eval'" in tokens and not sandbox:
            out.add(
                "CSP_UNSAFE_EVAL", Category.CSP, S.MEDIUM,
                "Weakens its security policy to allow eval()",
                f"The {where} CSP includes 'unsafe-eval', allowing code to be built from strings at runtime.",
                _ev(f"content_security_policy: {policy}"),
            )  # fmt: skip
        remote = [t for t in tokens if re.match(r"^(https?:|\*|[\w*.-]+\.[a-z]{2,})", t) and t not in ("'self'",)]
        if remote and not sandbox:
            out.add(
                "CSP_REMOTE_SCRIPTS", Category.CSP, S.HIGH,
                "Allows loading code from remote servers",
                f"The {where} CSP permits scripts from {', '.join(remote[:5])}; code from those servers "
                "runs with the extension's privileges and can change at any time without an update.",
                _ev(f"content_security_policy: {policy}"),
            )  # fmt: skip


def _directive(policy: str, name: str) -> str | None:
    for part in policy.split(";"):
        part = part.strip()
        if part.lower().startswith(name + " ") or part.lower() == name:
            return part[len(name) :].strip()
    return None


_SECURITY_HEADERS = {"content-security-policy", "x-frame-options", "content-security-policy-report-only"}


def _analyze_dnr_rules(info: ManifestInfo, pkg: ExtensionPackage, out: FindingCollector) -> None:
    dnr = info.raw.get("declarative_net_request")
    if not isinstance(dnr, dict):
        return
    for res in dnr.get("rule_resources") or []:
        path = res.get("path") if isinstance(res, dict) else None
        text = pkg.text(path) if isinstance(path, str) else None
        if not text:
            continue
        try:
            rules = json.loads(text)
        except ValueError:
            continue
        for rule in rules if isinstance(rules, list) else []:
            action = rule.get("action") if isinstance(rule, dict) else None
            if not isinstance(action, dict) or action.get("type") != "modifyHeaders":
                continue
            removed = {
                str(h.get("header", "")).lower()
                for h in (action.get("responseHeaders") or [])
                if isinstance(h, dict) and h.get("operation") == "remove"
            }
            hit = removed & _SECURITY_HEADERS
            if hit:
                out.add(
                    "DNR_STRIPS_SECURITY_HEADERS", Category.NETWORK, S.HIGH,
                    "Removes security protections from websites",
                    "Its network rules delete " + ", ".join(sorted(hit)) + " headers, disabling protections websites use "
                    "against script injection and clickjacking.",
                    Evidence(file=path, note=f"rule {rule.get('id')}: removes {', '.join(sorted(hit))}"),
                )  # fmt: skip
