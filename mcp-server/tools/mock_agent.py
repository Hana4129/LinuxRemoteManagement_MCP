"""開発・テスト用の簡易 Linux Agent モック。

doc/Design.md のAgent API (/v1/health, /v1/system, /v1/disk, /v1/processes,
/v1/services/{svc}, /v1/files)を模倣する。実運用のGo Agentでは置き換える。

使い方:
    python -m tools.mock_agent --port 8443 --hostname web-01 --os "Ubuntu 24.04.1 LTS" --token dev-token
"""
from __future__ import annotations

import argparse
import platform
import time

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

AGENT_VERSION = "0.1.0-mock"
_SERVICES = {"nginx": "running", "docker": "running", "ssh": "active"}
_LOG_LINES = [
    "{svc}[42]: starting up",
    "{svc}[42]: configuration OK",
    "{svc}[42]: listening on 0.0.0.0:80",
    "{svc}[42]: ready to handle requests",
]


def build_app(token=None, hostname=None, os_name=None, kernel=None, base_uptime=259200, tokens=None):
    hostname = hostname or (platform.node() or "mock-host")
    os_name = os_name or "Ubuntu 24.04.1 LTS"
    kernel = kernel or "6.8.0-45-generic"
    started = time.time()

    app = FastAPI(title="Mock Linux Agent", version=AGENT_VERSION, docs_url=None, redoc_url=None, openapi_url=None)

    # token (単一) または tokens (複数) のどちらかで認証する。両方未指定なら認証なし。
    allowed: set[str] | None = None
    if tokens is not None:
        allowed = {"Bearer " + t for t in tokens}
    elif token is not None:
        allowed = {"Bearer " + token}

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        if allowed is not None and request.headers.get("Authorization") not in allowed:
            return JSONResponse({"error": "unauthorized", "detail": "invalid or missing token"}, status_code=401)
        return await call_next(request)

    def uptime() -> int:
        return int(base_uptime + (time.time() - started))

    @app.get("/v1/health")
    def health():
        return {"status": "ok", "agent_version": AGENT_VERSION, "hostname": hostname}

    @app.get("/v1/system")
    def system():
        return {
            "hostname": hostname,
            "os": os_name,
            "kernel": kernel,
            "arch": "x86_64",
            "platform": "Linux x86_64",
            "uptime_seconds": uptime(),
            "boot_time": "2026-08-26 08:00:00",
            "agent_version": AGENT_VERSION,
            "memory": {"total_mb": 7976, "available_mb": 5123, "used_percent": 36},
        }

    @app.get("/v1/disk")
    def disk():
        return {"filesystems": [
            {"device": "/dev/mapper/root", "mount": "/", "fstype": "ext4", "total_gb": 78.6, "used_gb": 31.2, "available_gb": 43.6, "use_percent": 41.7},
            {"device": "/dev/sdb1", "mount": "/var/lib/docker", "fstype": "xfs", "total_gb": 196.5, "used_gb": 132.4, "available_gb": 54.2, "use_percent": 70.9},
        ]}

    @app.get("/v1/processes")
    def processes():
        return {"processes": [
            {"pid": 1, "user": "root", "cpu_percent": 0.1, "mem_percent": 0.4, "command": "/sbin/init splash"},
            {"pid": 812, "user": "www-data", "cpu_percent": 2.3, "mem_percent": 6.1, "command": "nginx: worker process"},
            {"pid": 944, "user": "root", "cpu_percent": 0.6, "mem_percent": 2.0, "command": "/usr/bin/dockerd -H fd://"},
            {"pid": 1088, "user": "postgres", "cpu_percent": 1.0, "mem_percent": 8.3, "command": "postgres: writer process"},
        ]}

    @app.get("/v1/services/{service}")
    def service_status(service: str):
        if service not in _SERVICES:
            raise HTTPException(status_code=404, detail=f"unknown service: {service}")
        return {"service": service, "active": True, "status": _SERVICES[service], "enabled": True}

    @app.post("/v1/services/{service}/restart")
    def service_restart(service: str):
        if service not in _SERVICES:
            raise HTTPException(status_code=404, detail=f"unknown service: {service}")
        return {"success": True, "service": service, "status": "running"}

    @app.get("/v1/services/{service}/logs")
    def service_logs(service: str, lines: int = Query(default=100, ge=1, le=1000)):
        if service not in _SERVICES:
            raise HTTPException(status_code=404, detail=f"unknown service: {service}")
        base = [line.replace("{svc}", service) for line in _LOG_LINES]
        out = [f"{hostname} {line}" for line in base][:lines]
        return {"service": service, "lines": out, "total": len(out), "truncated": lines < len(base)}

    @app.get("/v1/files")
    def read_file(path: str = Query(...)):
        allowed = {
            "/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n',
            "/etc/hostname": (hostname or "mock-host") + "\n",
            "/etc/nginx/nginx.conf": "# user www-data;\nworker_processes auto;\n",
        }
        if path not in allowed:
            raise HTTPException(status_code=403, detail=f"path not allowed: {path}")
        return {"path": path, "content": allowed[path]}

    @app.post("/v1/files")
    def write_file(path: str = Query(...), payload: dict = Body(default={})):
        # 実機Agentと同じ契約: path は query パラメータ、content は JSON ボディ
        content = payload.get("content")
        if not isinstance(content, str):
            raise HTTPException(status_code=400, detail="content required")
        return {"path": path, "backup": path + ".bak", "status": "written"}

    @app.post("/v1/execute")
    def execute(payload: dict = Body(default={})):
        # 実機Agentと同じ契約: command は JSON ボディ、応答は execResult 形式
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip():
            raise HTTPException(status_code=400, detail="command required")
        return {
            "command": command,
            "exit_code": 0,
            "stdout": f"mock: {command}",
            "stderr": "",
            "duration": "1ms",
            "timed_out": False,
        }

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Linux Agent (開発/テスト用)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--token", default=None, help="要求するBearerトークン (未指定なら認証なし)")
    parser.add_argument("--hostname", default=None)
    parser.add_argument("--os", dest="os_name", default=None)
    parser.add_argument("--kernel", default=None)
    parser.add_argument("--base-uptime", type=int, default=259200)
    args = parser.parse_args()
    import uvicorn
    app = build_app(token=args.token, hostname=args.hostname, os_name=args.os_name, kernel=args.kernel, base_uptime=args.base_uptime)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
