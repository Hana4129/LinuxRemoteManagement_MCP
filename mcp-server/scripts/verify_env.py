#!/usr/bin/env python3
"""実環境検証プリフライトチェッカー (verify_env.py)。

Plane残タスク (P0-1/P0-2/P1-4/P1-5/P1-6/P2-9/P2-10/P2-11/P2-12/3.1) の
実環境作業前に、ローカルで確認できる項目を自動チェックする。

使い方:
    python scripts/verify_env.py                     # オフラインチェックのみ
    python scripts/verify_env.py --network           # Agent/OIDC/コンソール到達性も確認
    python scripts/verify_env.py --send-siem-test    # SIEM webhookへテストイベント送信
    python scripts/verify_env.py --json              # JSON出力 (CI向け)
    python scripts/verify_env.py --config path.yml   # 設定ファイルを明示指定

終了コード: FAIL なし=0 / FAIL あり=1
詳細手順: doc/EnvVerification.md
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
MCP_ROOT = _HERE.parent.parent
REPO_ROOT = MCP_ROOT.parent
sys.path.insert(0, str(MCP_ROOT))

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
# 深刻度順 (worst判定用): FAIL が最も深刻
_ORDER = {PASS: 0, WARN: 1, SKIP: 2, FAIL: 3}

# パイプ/リダイレクト時でも日本語出力をUTF-8で統一する
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


@dataclass
class Check:
    task: str
    title: str
    status: str = SKIP
    detail: str = ""
    hint: str = ""


class Report:
    def __init__(self) -> None:
        self.checks: list[Check] = []

    def add(self, task: str, title: str, status: str, detail: str = "", hint: str = "") -> None:
        self.checks.append(Check(task=task, title=title, status=status, detail=detail, hint=hint))

    def counts(self) -> dict[str, int]:
        out = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
        for c in self.checks:
            out[c.status] = out.get(c.status, 0) + 1
        return out

    def worst(self) -> str:
        statuses = [c.status for c in self.checks if c.status in _ORDER]
        return max(statuses, key=lambda s: _ORDER[s]) if statuses else SKIP



# ---------------------------------------------------------------------------
# オフラインチェック
# ---------------------------------------------------------------------------

def check_config(config: Any, report: Report) -> None:
    if config is None:
        report.add("共通", "config.yml 読み込み", FAIL, "設定ファイルを読み込めませんでした", "config.yml のパスと内容を確認")
        return
    report.add(
        "共通",
        "config.yml 読み込み",
        PASS,
        f"servers={list(config.server_ids)}, auth_mode={config.console.auth_mode}",
    )


def check_data_dir(config: Any, report: Report) -> None:
    data_dir = config.data_dir
    if not data_dir.exists():
        report.add("共通", "dataディレクトリ", WARN, f"{data_dir} が存在しない", "初回起動時に自動生成。実環境では 0700 で作成 (Operations.md §1.4)")
        return
    db = data_dir / "tokens.db"
    status = PASS if db.exists() else WARN
    report.add("共通", "dataディレクトリ", status, f"tokens.db {'あり' if db.exists() else 'なし'}")



def check_mtls_certs(config: Any, report: Report) -> None:
    cert_path = getattr(config.agent, "client_cert", "") or ""
    key_path = getattr(config.agent, "client_key", "") or ""
    if not cert_path or not key_path:
        report.add(
            "P0-2/P2-12",
            "mTLS クライアント証明書",
            WARN,
            "client_cert / client_key が未設定",
            "実環境では CA署名済みクライアント証明書を設定 (doc/mTLS.md)。未設定のままでは P0-2/P2-12 を実施できない",
        )
        return
    cert, key = Path(cert_path), Path(key_path)
    if not cert.is_absolute():
        cert = (MCP_ROOT / cert).resolve()
    if not key.is_absolute():
        key = (MCP_ROOT / key).resolve()
    missing = [str(p) for p in (cert, key) if not p.exists()]
    if missing:
        report.add("P0-2/P2-12", "mTLS クライアント証明書", FAIL, f"ファイルが存在しない: {missing}", "証明書を配置するか config.yml を修正")
        return
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        cert_obj = x509.load_pem_x509_certificate(cert.read_bytes())
        key_obj = serialization.load_pem_private_key(key.read_bytes(), password=None)
        cert_pub = cert_obj.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        key_pub = key_obj.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        match = cert_pub == key_pub
        expires = cert_obj.not_valid_after_utc
        days_left = (expires - datetime.now(timezone.utc)).days
        detail = f"subject={cert_obj.subject.rfc4514_string()}, 残り{days_left}日, 鍵一致={'OK' if match else '不一致'}"
        status = PASS
        if not match:
            status = FAIL
            detail += " ← 証明書と鍵が対になっていません"
        elif days_left < 14:
            status = WARN
            detail += " ← 期限切れが近い"
        report.add("P0-2/P2-12", "mTLS クライアント証明書", status, detail)
    except Exception as exc:  # noqa: BLE001
        report.add("P0-2/P2-12", "mTLS クライアント証明書", WARN, f"解析スキップ: {exc}", "cryptography パッケージ導入で詳細確認が可能")



def check_network_boundary(config: Any, report: Report) -> None:
    open_hosts = {"0.0.0.0", "::"}
    problems: list[str] = []
    if config.console.host in open_hosts:
        problems.append(f"console.host={config.console.host} (管理コンソールが全interfaceでlisten)")
    if config.mcp.host in open_hosts:
        problems.append(f"mcp.host={config.mcp.host} (MCP HTTPが全interfaceでlisten)")
    if problems:
        report.add("P2-10", "listen address", WARN, "; ".join(problems), "管理コンソールは管理NWのみ、MCP HTTPは利用者NWのみへ (doc §P2-10)")
    else:
        report.add("P2-10", "listen address", PASS, f"console={config.console.host}, mcp={config.mcp.host}", "firewall/VPN/ACLは実環境で手動確認")

    if not config.agent.tls_verify:
        report.add("P2-10", "Agent TLS検証", WARN, "agent.tls_verify=false", "本番では true にして CA証明書を信頼ストアへ")
    else:
        report.add("P2-10", "Agent TLS検証", PASS, "agent.tls_verify=true")

    auth_ok = config.console.auth_mode == "oidc" or bool(config.console.username and config.console.password)
    if auth_ok:
        report.add("P2-10", "コンソール認証", PASS, f"auth_mode={config.console.auth_mode}")
    else:
        report.add("P2-10", "コンソール認証", WARN, "Basic認証の資格情報が未設定", "LINUX_MCP_CONSOLE_USER/PASS 環境変数 または auth_mode=oidc (P0-1)")


def check_oidc_config(config: Any, report: Report) -> None:
    console = config.console
    if console.auth_mode != "oidc":
        report.add("P0-1/P2-11", "OIDC設定", SKIP, f"auth_mode={console.auth_mode} のため対象外", "実IdP確認には auth_mode=oidc への切替が必要")
        return
    problems: list[str] = []
    if not console.oidc_browser_login:
        problems.append("oidc_browser_login=false (ブラウザログイン無効)")
    for name, val in (("oidc_issuer", console.oidc_issuer), ("oidc_jwks_url", console.oidc_jwks_url)):
        if not val:
            problems.append(f"{name} 未設定")
        elif not str(val).startswith("https://"):
            problems.append(f"{name} が https ではない")
    if problems:
        report.add("P0-1/P2-11", "OIDC設定", WARN, "; ".join(problems), "config.yml の OIDC セクションを修正 (doc/OIDC.md)")
    else:
        report.add("P0-1/P2-11", "OIDC設定", PASS, f"issuer={console.oidc_issuer}, browser_login=True")



def check_siem_config(config: Any, report: Report) -> None:
    webhook = config.console.siem_webhook or ""
    audit_path = config.data_dir / "mcp_audit.log"
    if not webhook:
        report.add("P1-5", "SIEM webhook", WARN, "siem_webhook 未設定", "config.yml console.siem_webhook を設定 (Operations.md §3)")
    else:
        scheme = "https" if webhook.startswith("https://") else "http"
        status = PASS if scheme == "https" else WARN
        hint = "" if scheme == "https" else "本番では https を推奨"
        report.add("P1-5", "SIEM webhook", status, f"設定あり ({scheme})", hint)
    if audit_path.exists():
        report.add("P1-5", "監査ログ (JSONL)", PASS, f"{audit_path.name} {audit_path.stat().st_size / 1024:.1f}KB")
    else:
        report.add("P1-5", "監査ログ (JSONL)", WARN, f"{audit_path} が存在しない", "MCP Server 起動後に生成される")


def check_pending_sync(config: Any, report: Report) -> None:
    db = config.data_dir / "tokens.db"
    pending: int | None = None
    if db.exists():
        try:
            conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
            try:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(agent_credentials)")}
                if "agent_sync_state" in cols:
                    (pending,) = conn.execute(
                        "SELECT COUNT(*) FROM agent_credentials WHERE enabled=1 AND agent_sync_state='pending'"
                    ).fetchone()
                    pending = int(pending)
            finally:
                conn.close()
        except sqlite3.Error:
            pending = None
    if pending is None:
        report.add("P1-6", "失効同期 pending", SKIP, "tokens.db 未存在またはテーブル未作成のため確認不可")
    elif pending == 0:
        report.add("P1-6", "失効同期 pending", PASS, "pending なし")
    else:
        report.add(
            "P1-6",
            "失効同期 pending",
            WARN,
            f"pending {pending}件 (Agent停止中に失効された credential)",
            "Agent復旧後に POST /api/agent-credentials/resync-pending を実行 (Operations.md §4)",
        )


def check_systemd_units(config: Any, report: Report) -> None:
    units = [
        MCP_ROOT / "scripts" / "linux-mcp-console.service",
        MCP_ROOT / "scripts" / "linux-mcp-http.service",
        REPO_ROOT / "lrm-mcp-agent" / "scripts" / "lrm-mcp-agent.service",
    ]
    missing = [u.name for u in units if not u.exists()]
    if missing:
        report.add("P2-9", "systemd unit定義", FAIL, f"unit定義が存在しない: {missing}")
        return
    detail = f"{len(units)} unit定義あり"
    status = PASS
    # Check for security hardening options in unit files
    hardening_flags = ["NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp"]
    advanced_flags = ["MemoryDenyWriteExecute", "RestrictAddressFamilies", "SystemCallArchitectures"]
    hardening_detail = []
    for unit in units:
        content = unit.read_text(encoding="utf-8")
        basic = [f for f in hardening_flags if f in content]
        advanced = [f for f in advanced_flags if f in content]
        hardening_detail.append(f"{unit.name}:{len(basic)}+{len(advanced)}")
    detail += f" (hardening: {', '.join(hardening_detail)})"
    if sys.platform == "linux" and shutil.which("systemctl"):
        for unit in units:
            name = unit.name
            try:
                enabled = subprocess.run(["systemctl", "is-enabled", name], capture_output=True, text=True, timeout=10).stdout.strip()
                active = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=10).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                continue
            detail += f" | {name}: enabled={enabled}, active={active}"
            if active != "active":
                status = WARN
        report.add("P2-9", "systemd unit定義", status, detail, "" if status == PASS else "導入環境での install/enable/status 確認 (doc §P2-9)")
    else:
        report.add("P2-9", "systemd unit定義", PASS, detail + " (実機systemctl確認はLinux環境で実施)")


def check_operational_scripts(config: Any, report: Report) -> None:
    """Check for operational scripts (firewall, backup, monitor, logrotate)."""
    scripts_dir = MCP_ROOT / "scripts"
    agent_scripts_dir = REPO_ROOT / "lrm-mcp-agent" / "scripts"

    # Firewall scripts
    fw_server = scripts_dir / "firewall-setup.sh"
    fw_agent = agent_scripts_dir / "firewall-setup.sh"
    if fw_server.exists() and fw_agent.exists():
        report.add("P2-10", "firewall 設定スクリプト", PASS, "Server/Agent 両方あり")
    elif fw_server.exists() or fw_agent.exists():
        report.add("P2-10", "firewall 設定スクリプト", WARN, "Server または Agent のみ")
    else:
        report.add("P2-10", "firewall 設定スクリプト", WARN, "未作成")

    # Backup scripts
    bk_server = scripts_dir / "backup.sh"
    bk_agent = agent_scripts_dir / "backup.sh"
    if bk_server.exists() and bk_agent.exists():
        report.add("運用", "backup スクリプト", PASS, "Server/Agent 両方あり")
    elif bk_server.exists() or bk_agent.exists():
        report.add("運用", "backup スクリプト", WARN, "Server または Agent のみ")
    else:
        report.add("運用", "backup スクリプト", WARN, "未作成")

    # Monitor scripts
    mon_server = scripts_dir / "monitor.sh"
    if mon_server.exists():
        report.add("運用", "monitor スクリプト", PASS, "あり")
    else:
        report.add("運用", "monitor スクリプト", WARN, "未作成")

    # Logrotate configs
    lr_server = scripts_dir / "logrotate.conf"
    lr_agent = agent_scripts_dir / "logrotate.conf"
    if lr_server.exists() and lr_agent.exists():
        report.add("運用", "logrotate 設定", PASS, "Server/Agent 両方あり")
    elif lr_server.exists() or lr_agent.exists():
        report.add("運用", "logrotate 設定", WARN, "Server または Agent のみ")
    else:
        report.add("運用", "logrotate 設定", WARN, "未作成")



# ---------------------------------------------------------------------------
# ネットワークチェック (--network 指定時のみ)
# ---------------------------------------------------------------------------

def check_agent_health(config: Any, report: Report) -> None:
    import httpx

    from app.config import _build_agent_ssl_context

    agent = config.agent
    client_cert = getattr(agent, "client_cert", "") or ""
    client_key = getattr(agent, "client_key", "") or ""
    has_mtls = bool(client_cert and client_key)
    # httpx 0.28 以降は verify=<CAパス> + cert=tuple でクライアント証明書が
    # 送信されないため、明示的な SSLContext を構築する
    tls_ctx = _build_agent_ssl_context(
        agent.tls_verify,
        client_cert=client_cert,
        client_key=client_key,
    )
    for server in config.servers:
        url = f"{server.url}/v1/health"
        try:
            with httpx.Client(timeout=min(agent.timeout_seconds, 8.0), verify=tls_ctx) as client:
                resp = client.get(url, headers={"User-Agent": agent.user_agent})
        except Exception as exc:  # noqa: BLE001
            report.add("P0-2/P2-12", f"Agent到達性 [{server.id}]", FAIL, f"{url} に接続不可: {str(exc)[:120]}", "Agent起動・URL・firewallを確認 (3.1)")
            continue
        if resp.status_code == 200:
            mtls_note = "mTLS有効" if has_mtls else "mTLS無し (クライアント証明書未設定)"
            report.add("P0-2/P2-12", f"Agent到達性 [{server.id}]", PASS, f"HTTP 200 ({mtls_note})")
        elif resp.status_code in (401, 403):
            report.add("P0-2/P2-12", f"Agent到達性 [{server.id}]", PASS, f"HTTP {resp.status_code} (認証必須だが到達性OK)")
        else:
            report.add("P0-2/P2-12", f"Agent到達性 [{server.id}]", WARN, f"HTTP {resp.status_code}")


def check_oidc_discovery(config: Any, report: Report) -> None:
    import httpx

    issuer = (config.console.oidc_issuer or "").rstrip("/")
    jwks = config.console.oidc_jwks_url or ""
    if not issuer:
        report.add("P0-1/P2-11", "OIDC discovery", SKIP, "oidc_issuer 未設定")
        return
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url)
    except Exception as exc:  # noqa: BLE001
        report.add("P0-1/P2-11", "OIDC discovery", FAIL, f"{url} に接続不可: {str(exc)[:120]}", "IdP到達性・issuer URLを確認 (P0-1)")
        return
    if resp.status_code == 200:
        try:
            body = resp.json()
            ok = body.get("issuer") and (body.get("jwks_uri") or jwks)
            report.add("P0-1/P2-11", "OIDC discovery", PASS if ok else WARN, f"HTTP 200, issuer={body.get('issuer', '?')}")
        except ValueError:
            report.add("P0-1/P2-11", "OIDC discovery", WARN, "HTTP 200 だがJSONでない")
    else:
        report.add("P0-1/P2-11", "OIDC discovery", FAIL, f"HTTP {resp.status_code}", "issuer URL・IdP起動状態を確認")


def check_console_reachable(config: Any, report: Report) -> None:
    import httpx

    url = f"http://{config.console.host}:{config.console.port}/api/meta"
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url)
    except Exception as exc:  # noqa: BLE001
        report.add("P1-4", "コンソール到達性", WARN, f"{url} に接続不可: {str(exc)[:120]}", "管理コンソール (python -m app) を起動してから実ブラウザ確認 (P1-4)")
        return
    if resp.status_code == 200:
        report.add("P1-4", "コンソール到達性", PASS, "HTTP 200")
    elif resp.status_code in (401, 403):
        # 認証必須でも到達性は確認できた (Agent到達性と同じ判定)
        report.add("P1-4", "コンソール到達性", PASS, f"HTTP {resp.status_code} (認証必須だが到達性OK)")
    else:
        report.add("P1-4", "コンソール到達性", WARN, f"HTTP {resp.status_code}", "UI表示は実ブラウザで確認 (doc §P1-4)")


def check_siem_test_send(config: Any, report: Report) -> None:
    import httpx

    webhook = config.console.siem_webhook or ""
    if not webhook:
        report.add("P1-5", "SIEM テスト送信", SKIP, "webhook未設定のためスキップ")
        return
    headers = {"Content-Type": "application/json"}
    if config.console.siem_api_key:
        headers["Authorization"] = f"Bearer {config.console.siem_api_key}"
    payload = {"source": "linux-mcp-verify_env", "event": "preflight_test", "timestamp": datetime.now(timezone.utc).isoformat()}
    try:
        resp = httpx.post(webhook, json=payload, headers=headers, timeout=5.0)
    except Exception as exc:  # noqa: BLE001
        report.add("P1-5", "SIEM テスト送信", WARN, f"送信失敗: {str(exc)[:120]}", "SIEM側endpoint・認証を確認 (P1-5)")
        return
    if 200 <= resp.status_code < 300:
        report.add("P1-5", "SIEM テスト送信", PASS, f"HTTP {resp.status_code}", "SIEM側でテストイベント受信を確認すること")
    else:
        report.add("P1-5", "SIEM テスト送信", WARN, f"HTTP {resp.status_code}", "SIEM側の応答仕様を確認")



# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _load_config(path: str | None) -> tuple[Any, str]:
    from app.config import load_config

    candidate = Path(path) if path else (MCP_ROOT / "config.yml")
    if not candidate.exists():
        return None, str(candidate)
    return load_config(str(candidate)), str(candidate)


def _manual_check(report: Report, task: str, title: str, where: str) -> None:
    report.add(task, title, SKIP, "実環境での手動確認が必要", f"手順: doc/EnvVerification.md §{where}")


def main() -> int:
    parser = argparse.ArgumentParser(description="実環境検証プリフライトチェッカー")
    parser.add_argument("--config", default=None, help="config.yml パス (既定: mcp-server/config.yml)")
    parser.add_argument("--network", action="store_true", help="Agent/OIDC/コンソールへの到達性チェックを実行")
    parser.add_argument("--send-siem-test", action="store_true", help="SIEM webhookへテストイベントを送信 (--network 不要)")
    parser.add_argument("--json", action="store_true", help="JSON出力")
    args = parser.parse_args()

    report = Report()
    config, config_path = None, ""
    try:
        config, config_path = _load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        report.add("共通", "config.yml 読み込み", FAIL, f"{type(exc).__name__}: {str(exc)[:200]}", "config.yml を修正")

    check_config(config, report)
    if config is not None:
        check_data_dir(config, report)
        check_mtls_certs(config, report)
        check_network_boundary(config, report)
        check_oidc_config(config, report)
        check_siem_config(config, report)
        check_pending_sync(config, report)
    check_systemd_units(config, report)
    check_operational_scripts(config, report)

    # 実環境でしか確認できない項目は明示的に SKIP として出力 (ドキュメントの索引も兼ねる)
    _manual_check(report, "P0-1", "実IdPトークンでのOIDCログイン", "P0-1")
    _manual_check(report, "P2-11", "実IdPブラウザログイン / TLS終端位置", "P2-11")
    _manual_check(report, "P1-4", "実ブラウザUI統合", "P1-4")
    _manual_check(report, "P2-10", "firewall / VPN / ACL", "P2-10")
    _manual_check(report, "P2-12", "mTLS 失効・更新時の動作", "P2-12")
    _manual_check(report, "3.1", "別Linuxサーバー Agent統合検証", "3.1")

    if config is not None and args.send_siem_test:
        check_siem_test_send(config, report)
    if config is not None and args.network:
        check_agent_health(config, report)
        check_oidc_discovery(config, report)
        check_console_reachable(config, report)
        if args.send_siem_test:
            pass  # 送信は上で実行済み

    if args.json:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "config": config_path,
            "summary": report.counts(),
            "checks": [
                {"task": c.task, "title": c.title, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in report.checks
            ],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"実環境検証プリフライト  config={config_path or '(未検出)'}")
        print("-" * 100)
        for c in report.checks:
            line = f"[{c.status}] {c.task:<10} {c.title}"
            if c.detail:
                line += f" | {c.detail}"
            print(line)
            if c.hint:
                print(f"           -> {c.hint}")
        counts = report.counts()
        print("-" * 100)
        print(f"summary: PASS={counts[PASS]} WARN={counts[WARN]} FAIL={counts[FAIL]} SKIP={counts[SKIP]}")
        print("手動確認手順: doc/EnvVerification.md")

    return 0 if report.worst() != FAIL else 1


if __name__ == "__main__":
    sys.exit(main())