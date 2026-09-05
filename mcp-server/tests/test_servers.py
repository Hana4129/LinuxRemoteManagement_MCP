"""管理コンソールからのノード追加/削除 API と config.yml 永続化のテスト。"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.config import AgentConfig, AppConfig, ConsoleConfig, ServerConfig, load_config
from app.main import create_app


@pytest.fixture()
def config_file(tmp_dir: Path) -> Path:
    """username/password/mcp_http_path など拡張キーを含む実運用に近い config.yml。"""
    path = tmp_dir / "config.yml"
    path.write_text(
        """\
console:
  host: 127.0.0.1
  port: 8080
  data_dir: ./data
  mcp_http: true
  mcp_http_path: /custom/mcp
  username: admin
  password: secret
agent:
  timeout_seconds: 5
  tls_verify: false
  user_agent: linux-mcp-server/0.1
  client_cert: ./data/client.crt
  client_key: ./data/client.key
servers:
  - id: dev-web-01
    name: "Dev Web"
    url: http://127.0.0.1:8443
    env: development
    description: mock
""",
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def client(tmp_dir: Path, store):
    config = AppConfig(
        config_path=tmp_dir / "config.yml",
        servers=(
            ServerConfig(id="dev-web-01", name="Dev Web", url="http://127.0.0.1:8443", env="development"),
        ),
        agent=AgentConfig(timeout_seconds=2.0, tls_verify=False),
        console=ConsoleConfig(data_dir=str(tmp_dir), mcp_http=True, auth_required=False),
    )
    store.create_token(name="test-token", server_ids=["*"], scope="readonly")
    app = create_app(config, store=store)
    return TestClient(app), app


def test_add_server_persists_and_appears(client):
    """POST /api/servers で追加したノードが一覧に現れ、config.yml にも書かれる。"""
    http, app = client
    payload = {
        "id": "prod-web-02",
        "name": "Prod Web #02",
        "url": "https://prod-web-02.internal:8443",
        "env": "production",
        "description": "new from console",
        "issue_token": True,
        "token_name": "console add",
        "token_scope": "operator",
    }
    res = http.post("/api/servers", json=payload)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["server"]["id"] == "prod-web-02"
    assert body["token"], "issue_token=true では生トークンを返す"
    assert body["token_record"]["scope"] == "operator"

    # 一覧に反映される
    listed = http.get("/api/servers").json()["servers"]
    assert any(s["id"] == "prod-web-02" for s in listed)

    # トークンレコードも作成済み
    tokens = http.get("/api/tokens").json()["tokens"]
    assert any(t["name"] == "console add" for t in tokens)

    # config.yml へ永続化 (再読み込みでもノードが見える)
    reloaded = load_config(app.state.config.config_path)
    assert reloaded.server("prod-web-02") is not None
    assert any(s["id"] == "prod-web-02" for s in [x.to_yaml_dict() for x in reloaded.servers])


def test_add_server_keeps_extra_config(config_file, tmp_dir: Path, store):
    """save() が username/password/mcp_http_path/mTLS など未加工キーを保持する。"""
    cfg = load_config(config_file)
    new = cfg.add_server(
        ServerConfig(id="stg-x-01", name="Stg X", url="https://stg-x-01.internal:9443", env="staging")
    )
    new.save()

    raw = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert raw["console"]["mcp_http_path"] == "/custom/mcp"
    assert raw["console"]["username"] == "admin"
    assert raw["console"]["password"] == "secret"
    assert raw["agent"]["client_cert"] == "./data/client.crt"
    assert raw["agent"]["client_key"] == "./data/client.key"

    reloaded = load_config(config_file)
    assert reloaded.console.mcp_http_path == "/custom/mcp"
    assert reloaded.console.username == "admin"
    assert reloaded.server("stg-x-01") is not None


def test_add_server_duplicate_409(client):
    http, _ = client
    payload = {
        "id": "dev-web-01",  # 既存ID
        "name": "dup",
        "url": "https://example.internal:9443",
    }
    res = http.post("/api/servers", json=payload)
    assert res.status_code == 409


def test_add_server_bad_id_400(client):
    http, _ = client
    payload = {"id": "bad id!", "name": "bad", "url": "https://example.internal:9443"}
    res = http.post("/api/servers", json=payload)
    assert res.status_code == 400


def test_delete_server_revokes_tokens(client):
    """DELETE /api/servers/{id} は関連トークンを失効させ、config.yml からも消す。"""
    http, app = client
    # 追加時トークン発行
    payload = {
        "id": "prod-x",
        "name": "Prod X",
        "url": "https://prod-x.internal:9443",
        "issue_token": True,
        "token_name": "prod-x access",
    }
    http.post("/api/servers", json=payload)
    before = http.get("/api/tokens").json()["tokens"]
    target = next(t for t in before if "prod-x" in (t["server_ids"] or []))

    res = http.delete("/api/servers/prod-x")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["deleted"] is True
    # prod-x 専用トークンは必ず失効対象に含まれる
    assert target["id"] in body["revoked_tokens"]

    # prod-x トークンが失効している
    tokens = http.get("/api/tokens").json()["tokens"]
    affected = [t for t in tokens if "prod-x" in (t["server_ids"] or [])]
    assert len(affected) == 1 and affected[0]["enabled"] is False

    # config.yml から削除されている
    reloaded = load_config(app.state.config.config_path)
    assert reloaded.server("prod-x") is None


def test_delete_unknown_server_404(client):
    http, _ = client
    res = http.delete("/api/servers/no-such-node")
    assert res.status_code == 404