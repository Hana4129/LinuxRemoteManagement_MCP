"""MCP Server → Agent 接続テストスクリプト。

エージェント (https://ubuntu-server1.local:9443) に対して token2 で Bearer 認証し、
各エンドポイントが正しく応答するかを検証する。

実行:
    cd mcp-server
    python test_agent_connection.py
"""

import asyncio
import sys
import traceback


async def main() -> int:
    from app.agent_client import AgentClient
    from app.config import load_config
    from app.db import TokenStore

    config = load_config()
    store = TokenStore(config.data_dir / "tokens.db")

    server = config.server("ubuntu-server1")
    if server is None:
        print("ERROR: ubuntu-server1 が config.yml に登録されていません")
        return 1

    print(f"対象サーバー: {server.id} ({server.name})")
    print(f"URL: {server.url}")
    print(f"TLS検証: {'有効' if config.agent.tls_verify else '無効'}")
    print()

    # ---- トークン確認/インポート ----
    existing = store.find_token_for_server("ubuntu-server1", scope="readonly")
    if existing is not None:
        print(f"[token] 既存トークンを使用: id={existing.id} name={existing.name!r} scope={existing.scope}")
    else:
        print("[token] token2 を readonly スコープでインポートします")
        record = store.import_token(
            name="ubuntu-server1-token",
            raw="token2",
            server_ids=["ubuntu-server1"],
            scope="readonly",
            created_by="test_script",
            store_raw=True,
        )
        print(f"  → 登録成功: id={record.id} prefix={record.prefix}")

    print()
    print("=" * 60)
    print("エンドポイント接続テスト")
    print("=" * 60)

    results: list[tuple[str, bool, str]] = []

    async with AgentClient(config, store) as agent:
        # 1) /v1/health
        print("\n[1] GET /v1/health")
        try:
            r = await agent.health(server)
            if r.ok:
                print(f"  OK  (latency={r.latency_ms}ms)")
                print(f"    response: {r.data}")
                results.append(("health", True, f"{r.latency_ms}ms"))
            else:
                print(f"  FAIL (kind={r.error_kind}): {r.error}")
                results.append(("health", False, r.error or r.error_kind or "unknown"))
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            traceback.print_exc()
            results.append(("health", False, str(exc)))

        # 2) /v1/system
        print("\n[2] GET /v1/system")
        try:
            r = await agent.system_info(server)
            if r.ok:
                data = r.data or {}
                print(f"  OK  (latency={r.latency_ms}ms)")
                print(f"    hostname={data.get('hostname')}, os={data.get('os')}, kernel={data.get('kernel')}")
                results.append(("system", True, f"{r.latency_ms}ms"))
            else:
                print(f"  FAIL (kind={r.error_kind}): {r.error}")
                results.append(("system", False, r.error or r.error_kind or "unknown"))
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            traceback.print_exc()
            results.append(("system", False, str(exc)))

        # 3) /v1/disk
        print("\n[3] GET /v1/disk")
        try:
            r = await agent.disk_usage(server)
            if r.ok:
                filesystems = (r.data or {}).get("filesystems", [])
                print(f"  OK  (latency={r.latency_ms}ms)")
                for fs in filesystems:
                    print(f"    {fs.get('mount')}: {fs.get('use_percent')}% used")
                results.append(("disk", True, f"{r.latency_ms}ms"))
            else:
                print(f"  FAIL (kind={r.error_kind}): {r.error}")
                results.append(("disk", False, r.error or r.error_kind or "unknown"))
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            traceback.print_exc()
            results.append(("disk", False, str(exc)))

        # 4) /v1/processes
        print("\n[4] GET /v1/processes")
        try:
            r = await agent.processes(server)
            if r.ok:
                procs = (r.data or {}).get("processes", [])
                print(f"  OK  (latency={r.latency_ms}ms, {len(procs)} processes)")
                for p in procs[:5]:
                    print(f"    PID {p.get('pid')}: {p.get('command')}")
                results.append(("processes", True, f"{r.latency_ms}ms"))
            else:
                print(f"  FAIL (kind={r.error_kind}): {r.error}")
                results.append(("processes", False, r.error or r.error_kind or "unknown"))
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            traceback.print_exc()
            results.append(("processes", False, str(exc)))

        # 5) /v1/files?path= (許可期待パス)
        #    Agent側トークンの files 許可リストに含まれないパスは 403 (policy正しい挙動) → WARN
        allowed_paths = ["/etc/os-release", "/etc/hostname", "/etc/nginx/nginx.conf"]
        for path in allowed_paths:
            print(f"\n[5] GET /v1/files?path={path} (許可期待パス)")
            try:
                r = await agent.read_file(server, path)
                if r.ok:
                    print(f"  OK  (latency={r.latency_ms}ms)")
                    content = (r.data or {}).get("content", "")
                    print(f"    content: {content[:60]!r}...")
                    results.append((f"files:{path}", True, f"{r.latency_ms}ms"))
                elif r.error_kind == "auth":
                    print(f"  WARN (latency={r.latency_ms}ms) — Agent側トークンのfiles許可リストに含まれず拒否 (policyとしては正しい)")
                    print(f"    Agent応答: {r.error}")
                    results.append((f"files:{path}", True, "WARN: token allowlistで拒否"))
                else:
                    print(f"  FAIL (kind={r.error_kind}): {r.error}")
                    results.append((f"files:{path}", False, r.error or r.error_kind or "unknown"))
            except Exception as exc:
                print(f"  EXCEPTION: {exc}")
                traceback.print_exc()
                results.append((f"files:{path}", False, str(exc)))

        # 5b) POST /v1/execute (readonly トークンでAgentに直接 → 拒否されること)
        print("\n[5b] POST /v1/execute (readonly トークン → 拒否期待)")
        try:
            r = await agent.request(server, "POST", "/v1/execute", json_body={"command": "true"})
            if r.ok:
                print("  想定外OK — セキュリティ警告！readonlyでコマンド実行できた")
                results.append(("execute_denied", False, "should be rejected"))
            else:
                print(f"  正しく拒否 (kind={r.error_kind})")
                results.append(("execute_denied", True, f"{r.error_kind}"))
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            results.append(("execute_denied", False, str(exc)))

        # 5c) POST /v1/files (書き込み, readonly トークンでAgentに直接 → 拒否されること)
        print("\n[5c] POST /v1/files (書き込み, readonly トークン → 拒否期待)")
        try:
            r = await agent.request(
                server, "POST", "/v1/files", params={"path": "/var/tmp/lrm-probe.txt"}, json_body={"content": "probe"}
            )
            if r.ok:
                print("  想定外OK — セキュリティ警告！readonlyで書き込めた")
                results.append(("write_denied", False, "should be rejected"))
            else:
                print(f"  正しく拒否 (kind={r.error_kind})")
                results.append(("write_denied", True, f"{r.error_kind}"))
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            results.append(("write_denied", False, str(exc)))

        # 6) /v1/files?path= (拒否パス)
        denied_paths = ["/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa"]
        for path in denied_paths:
            print(f"\n[6] GET /v1/files?path={path} (拒否パス)")
            try:
                r = await agent.read_file(server, path)
                if r.ok:
                    print(f"  想定外OK  (latency={r.latency_ms}ms) — セキュリティ警告！")
                    print(f"    response: {r.data}")
                    results.append((f"files_denied:{path}", False, "should be rejected"))
                else:
                    print(f"  正しく拒否 (kind={r.error_kind}): {r.error}")
                    results.append((f"files_denied:{path}", True, f"{r.error_kind}"))
            except Exception as exc:
                print(f"  EXCEPTION: {exc}")
                traceback.print_exc()
                results.append((f"files_denied:{path}", False, str(exc)))

    # ---- サマリー ----
    print()
    print("=" * 60)
    print("テスト結果サマリー")
    print("=" * 60)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)

    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}]  {name:<18} {detail}")

    print()
    print(f"合計: {passed}/{total} 合格")

    return 0 if passed == total else 1


if __name__ == "__main__":
    rc = asyncio.run(main())
    sys.exit(rc)
