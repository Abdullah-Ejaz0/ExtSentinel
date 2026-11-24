# ExtSentinel – analysis backend

Static analysis backend for ExtSentinel. This component covers **source retrieval and
unpacking, manifest analysis, JavaScript syntax-tree / data-flow analysis and obfuscation
detection**, exposed through a FastAPI service. Risk scoring, endpoint reputation, update
diffing and the extension UI are separate modules that consume its output.

## Design goal: evidence, not keywords

A keyword scanner flags almost every popular extension: password managers touch password
fields, ad blockers read `document.cookie`, shortcut tools listen to `keydown`. The engine is
built to answer a narrower question: **does sensitive data actually reach a place it should not,
or does code from an untrusted origin actually get executed?** Every behavioural finding is
backed by a concrete trace in the code.

| Situation | Keyword scanner | ExtSentinel |
|---|---|---|
| `keydown` handler that checks `e.key === "k"` for a shortcut | "Keylogger" | LOW / possible: listener present, keys only compared |
| `buffer += e.key` later sent with `fetch` | "Keylogger" | CRITICAL / confirmed, with the trace from `e.key` to `fetch` |
| `chrome.cookies.getAll` result used to count cookies | "Steals cookies" | INFO: read, no path to the network |
| same result passed to `navigator.sendBeacon("https://x…")` | "Steals cookies" | CRITICAL / confirmed, destination `x…` |
| `Function("return this")` (bundler idiom) | "eval" | not reported (constant, known idiom) |
| `fetch(url).then(r => r.text()).then(eval)` | "eval" | CRITICAL / confirmed remote code execution |
| `eval(x)` in an MV3 service worker | "eval" | INFO: Chrome's CSP blocks it; it cannot run |

Each finding records **severity** and **confidence**:

* `confirmed` – a source→sink flow was traced, or the fact is declared (e.g. a permission).
* `likely` – the parts connect only through an assumption (e.g. a script assumed to be injected).
* `possible` – a capability exists but no harmful use was observed, or the file could not be analysed.

### How severity is decided

For a data flow, four facts are taken from the code and manifest rather than assumed:

1. **What data?** Labels have a sensitivity tier (passwords, keystrokes, cookies are critical;
   page URLs medium; …). See `extsentinel/js/catalog.py`.
2. **Can the source exist there?** Page data (keystrokes, form input, `document.cookie`) only exists
   in scripts that run inside web pages. Text typed into the extension's own popup is not page data.
3. **Can it work at all?** The permission the source needs (`cookies`, `history`, `tabs`, …) must be
   declared; `eval` and remote scripts in extension pages must be allowed by the CSP; MV3-removed
   APIs are dead code. Unreachable behaviour is downgraded to INFO with the reason stated.
4. **Where does it go?** One of the sites the extension declares it works with (first party), another
   host (third party), the current site, a native program, or an address computed at runtime.

## Architecture

```
extension ID ──► fetcher.py ──► package.py ──► engine.py ──► ExtensionReport (JSON)
                 (Web Store)    (CRX→ZIP,      │
                                 safe unpack)  ├─ manifest.py      permissions, hosts, CSP, update_url,
                                               │                   externally_connectable, DNR rules
                                               ├─ js/parser.py     tree-sitter → ESTree (js/ts_convert.py);
                                               │                   esprima fallback (+ preprocess.py)
                                               ├─ js/taint.py      data-flow engine (sources → sinks)
                                               ├─ js/scanner.py    regex fallback / keyword baseline
                                               ├─ obfuscation.py   obfuscation vs. minification
                                               └─ behaviors.py     facts → explained, calibrated findings
```

**Script contexts.** Each script is classified as `content_script`, `background`,
`extension_page`, `web_accessible` or `unknown`. Sources: the manifest, `<script>` tags in HTML
pages (inline scripts included), and references found *in code*: `chrome.scripting.executeScript({files})`,
`registerContentScripts`, `executeScript({func})` (the function body is treated as running in the
page), `importScripts` and ES imports.

**Taint engine** (`js/taint.py`). A flow-insensitive, monotone abstract interpreter over the
syntax tree. It runs to a fixed point (bounded rounds, node budget) and supports:

* variables, closures, destructuring, object/array containers (field-insensitive)
* inter-procedural flow via per-function summaries, per-class `this`, and name-based method
  dispatch for unknown receivers. Dispatch is skipped for names shorter than 3 characters or shared
  by more than 8 functions; in minified bundles such links connect unrelated code.
* callbacks and promises (`.then`, `await`), browser event callbacks seeded with labelled data
* **cross-context flows**: data a content script sends with `chrome.runtime.sendMessage` reaches
  the background's `onMessage` handler, and the trace records the hop
* a storage bridge (`chrome.storage` / `localStorage` set → get), so fetch → store → eval is caught
* constant folding to defeat simple evasion: `'coo'+'kies'`, `['get','All'].join('')`,
  `String.fromCharCode(...)`, `atob('…')`, and aliases such as `var c = chrome; c[k]`
* comparisons and boolean operators yield *untainted* values; this is what separates
  "checks which key was pressed" from "records which key was pressed"

**Parsing.** The primary parser is **tree-sitter** (`tree-sitter-javascript` grammar). It is a
C library, so it is fast; it supports current JavaScript (class fields, private names, decorators,
`?.`, `??`, top-level `await`, …); and it is **error-tolerant**. A syntax error only produces an
ERROR region around the broken code, and the rest of the file is still analysed. `js/ts_convert.py`
converts tree-sitter's concrete syntax tree into the ESTree shape the taint engine reads, so the
analysis is independent of the parser. Files with recovered errors are listed in
`coverage.files_with_syntax_errors`. A file counts as unparseable only when more than half of it
sits inside ERROR regions.

**Fallback parser.** If tree-sitter's compiled module cannot be loaded (e.g. Windows Application
Control blocks unsigned DLLs), the engine falls back to **esprima** (pure Python, ES2017) and says
so in `coverage.parser` and `warnings`. For esprima, `js/preprocess.py` rewrites newer syntax while
keeping every newline, so reported line numbers stay correct. Select explicitly with
`EXTSENTINEL_PARSER=auto|tree-sitter|esprima` (default `auto`).

Files that cannot be parsed at all fall back to the regex scanner, are listed in
`coverage.fallback_files`, and only ever produce `possible` findings.

**Obfuscation.** Minification is normal and only noted as INFO. Obfuscation is reported from
measured signals: `_0x…` identifier density, p.a.c.k.e.r, JSFuck, dense `\x` escapes, and base64
blocks that decode to JavaScript. A recognised library banner (jQuery, lodash, …) lowers severity
of code-execution findings by one step only, because banners can be forged.

**Unpacking safety.** Packages are untrusted. CRX2/CRX3 headers are stripped in memory; nothing is
extracted to disk; path traversal entries are dropped; per-file, total-size and file-count limits
protect against zip bombs.

## Setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
pytest -q
```

The test suite runs every analysis test once per parser. With tree-sitter available: 92 passed and
2 skipped (tree-sitter-only features in their esprima variant). Where tree-sitter cannot load, the
tree-sitter variants are skipped and the esprima variants still run.

**tree-sitter on Windows.** If `import tree_sitter` fails with *"An Application Control policy has
blocked this file"*, Windows Smart App Control is blocking the compiled module. Options: run the
backend in WSL or Linux (verified: Ubuntu 24.04, Python 3.12), allow the file in your security
policy, or accept the automatic esprima fallback (slower, no error recovery).

### Run the API

```bash
uvicorn extsentinel.api:app --port 8000
```

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness |
| POST | `/api/analyze` | body `{"extension_ids": [...], "force": false, "mode": "dataflow"}` → `{reports, errors}` |
| GET | `/api/extensions/{id}/report` | analyse one Web Store extension (cached for 6 h) |
| POST | `/api/analyze/upload` | multipart `file` = `.crx` or `.zip` (for test extensions not on the store) |
| GET | `/api/extensions/{id}/versions` | versions downloaded so far |
| GET | `/api/extensions/{id}/versions/{version}` | stored report of a specific version |

CORS allows `chrome-extension://<id>` origins and localhost. Interactive docs: `http://localhost:8000/docs`.

### Command line

```bash
python -m extsentinel ddkjiahejlhfcafbddmgiahcphecmpfh       # Web Store ID
python -m extsentinel path/to/unpacked-extension             # folder
python -m extsentinel suspicious.crx --json                  # full JSON report
python -m extsentinel path/to/ext --mode keyword             # keyword baseline
```

## Output contract (for the scoring module and the UI)

`ExtensionReport` (see `extsentinel/models.py`) contains no score. Each `Finding` has:

* `rule_id` – stable identifier, e.g. `EXFIL_KEYSTROKES`, `REMOTE_CODE_EXECUTION`, `PERM_COOKIES`
* `category`, `severity` (`info…critical`), `confidence` (`confirmed|likely|possible`)
* `title` – a plain-language reason, e.g. "Sends what you type (individual keystrokes) to stats.example"
* `description` – the explanation, including the traced flow and any caveats
* `evidence` – ordered locations (`file`, `line`, `snippet`, `note`); for flows, source → hops → sink
* `tags` – machine-readable details: `label:COOKIES`, `dest_host:…`, `dest_class:third_party`, `exec:eval`

`coverage` reports how much code was actually analysed (parsed / fallback / obfuscated / library
files); a clean report with poor coverage is not evidence of safety. Network destination hosts
appear in the `dest_host:` tags of flow findings.

Stored data (`data/`, configurable with `EXTSENTINEL_DATA_DIR`):
`packages/<id>/<version>.crx` and `reports/<id>/<version>.<mode>.json`. Every audited version is kept.

## Evaluation support

`mode=keyword` runs a naive scanner that reports every suspicious API mention. Running both modes
over the same corpus measures how many false positives the data-flow analysis removes and
whether it loses any true positives.

## Validation so far

Unit tests pair each malicious pattern with a legitimate one using the same APIs. On real Web Store
packages (November 2026):

| Extension | Scripts parsed | Behaviour findings ≥ MEDIUM | tree-sitter | esprima |
|---|---|---|---|---|
| uBlock Origin Lite | 344 / 344 | none | ~7 s | ~25 s |
| Bitwarden Password Manager | 29 / 29 (~10 MB JS) | 1 (see below) | ~57 s | ~120 s+ |

Both have legitimate keyboard listeners, password-field access, `document.cookie` reads and
dynamic `Function` use that a keyword scanner flags; here they appear only as LOW/INFO with the
reason ("read, no path to the network"). The one Bitwarden MEDIUM finding is tab URLs reaching an
XMLHttpRequest whose server address is computed at runtime. That is consistent with Bitwarden
sending a site's address when a login is saved to a configurable (self-hostable) server. The bundle
is minified onto one line, so the trace has not been checked by hand.

## Known limitations

* **Implicit flows** are not tracked: `if (e.key === "a") send("a")` leaks a key through control
  flow without a data flow. This is a deliberate precision trade-off, and evaders can use it.
* Flow-insensitive, field-insensitive analysis can over-approximate in very large bundles
  (it reports a flow that cannot happen in practice); findings carry the full trace so a reviewer can check.
* Name-based method dispatch can connect same-named methods of unrelated objects.
* Cross-file flows are modelled for content script → background messaging; storage written in one
  script and read in another is not yet connected.
* Code fetched at runtime is, by definition, not visible to static analysis; the engine reports
  that remote code is executed, not what it does.
* Under the esprima fallback, syntax it cannot handle even after rewriting (e.g. decorators) sends
  the file to the regex scanner.
* Analysis is CPU-bound and single-threaded per extension. With tree-sitter a ~10 MB extension takes
  about a minute; reports are cached.
