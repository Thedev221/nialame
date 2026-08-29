import pytest
from httpx import ASGITransport, AsyncClient

from nialame.main import app
from nialame.patch import compute_sha256


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_scan_detects_sql_injection(client: AsyncClient):
    source = "def q(uid):\n    return f\"SELECT * FROM t WHERE id={uid}\"\n"
    payload = {
        "language": "python",
        "document": {
            "uri": "file:///app.py",
            "version": 1,
            "sha256": compute_sha256(source),
            "content": source,
        },
        "allow_llm": False,
    }
    resp = await client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert any(f["rule_id"] == "NIA-SQLI-001" for f in body["findings"])
    assert body["llm_used"] is False


async def test_scan_rejects_oversized_document(client: AsyncClient, monkeypatch):
    import dataclasses
    from nialame import main as main_module

    patched_settings = dataclasses.replace(main_module.settings, max_document_bytes=10)
    monkeypatch.setattr(main_module, "settings", patched_settings)
    source = "x = 1\n" * 100
    payload = {
        "language": "python",
        "document": {
            "uri": "file:///app.py",
            "version": 1,
            "sha256": compute_sha256(source),
            "content": source,
        },
        "allow_llm": False,
    }
    resp = await client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 413


async def test_chat_ask_mode_no_patch_without_llm(client: AsyncClient):
    source = "def f():\n    return eval('1+1')\n"
    payload = {
        "mode": "ask",
        "scope": "current_file",
        "message": "Explique ce fichier",
        "language": "python",
        "document": {
            "uri": "file:///app.py",
            "version": 1,
            "sha256": compute_sha256(source),
            "content": source,
        },
    }
    resp = await client.post("/api/v1/chat", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["suggested_patches"] == []
    assert body["privacy"]["llm_used"] is False


async def test_sarif_endpoint(client: AsyncClient):
    payload = {
        "results": [
            {
                "file_path": "app.py",
                "findings": [
                    {
                        "rule_id": "NIA-EVAL-001",
                        "cwe": "CWE-95",
                        "severity": "critical",
                        "confidence": "high",
                        "message": "eval() dangereux",
                        "explanation": "…",
                        "proof": "eval(x)",
                        "location": {
                            "start_line": 2,
                            "start_column": 4,
                            "end_line": 2,
                            "end_column": 12,
                        },
                        "enclosing_symbol": "f",
                        "tier": "tier1_deterministic",
                    }
                ],
            }
        ]
    }
    resp = await client.post("/api/v1/sarif", json=payload)
    assert resp.status_code == 200
    assert resp.json()["sarif"]["version"] == "2.1.0"
