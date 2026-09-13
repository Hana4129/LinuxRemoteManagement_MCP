"""Linux Agent mock with policy engine, rate limiting, and audit logging.

Implements the Agent API from doc/Design.md for development/testing.
Replaced by the real Go Agent in production.
"""
from __future__ import annotations

import argparse
import json
import logging
import platform
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

AGENT_VERSION = "0.1.0-mock"
logger = logging.getLogger("mock_agent")


class Scope:
    READONLY = "readonly"
    OPERATOR = "operator"


class PolicyEngine:
    """Mirrors lrm-mcp-agent/internal/policy/engine.go."""

    def __init__(self, commands=None, services=None, allowed_paths=None,
                 denied_paths=None, write_paths=None) -> None:
        self.commands = commands or []
        self.services = services or ["nginx", "docker", "ssh"]
        self.allowed_paths = allowed_paths or ["/etc/os-release", "/etc/hostname"]
        self.denied_paths = denied_paths or ["/etc/shadow", "/etc/passwd"]
        self.write_paths = write_paths or []
        self._tokens = {}

    def add_token(self, token_id, scope=Scope.READONLY, commands=None,
                  services=None, files=None, disabled=False) -> None:
        self._tokens[token_id] = {"scope": scope, "commands": commands or [],
                                   "services": services or [], "files": files or [],
                                   "disabled": disabled}

    def can_read_file(self, token_id, path):
        if not self._tokens:
            return True, ""
        tok = self._tokens.get(token_id)
        if not tok or tok["disabled"]:
            return False, "unknown or disabled token"
        clean = self._clean_path(path)
        for p in self.denied_paths:
            if self._is_subpath(clean, self._clean_path(p)):
                return False, "path denied"
        if tok["files"]:
            for p in tok["files"]:
                if self._is_subpath(clean, self._clean_path(p)):
                    return True, ""
            return False, "path not in token allowlist"
        for p in self.allowed_paths:
            if self._is_subpath(clean, self._clean_path(p)):
                return True, ""
        return False, "path not in allowlist"

    def can_read_service(self, token_id, service):
        if not self._tokens:
            return True, ""
        tok = self._tokens.get(token_id)
        if not tok or tok["disabled"]:
            return False, "unknown or disabled token"
        if tok["services"]:
            return (True, "") if service in tok["services"] else (False, "service not in token allowlist")
        return (True, "") if service in self.services else (False, "service not in global allowlist")

    def can_manage_service(self, token_id, service):
        if not self._tokens:
            return True, ""
        tok = self._tokens.get(token_id)
        if not tok or tok["disabled"]:
            return False, "unknown or disabled token"
        if tok["scope"] != Scope.OPERATOR:
            return False, "operator scope required"
        return self.can_read_service(token_id, service)

    def can_run_command(self, token_id, command):
        if not self._tokens:
            return True, ""
        tok = self._tokens.get(token_id)
        if not tok or tok["disabled"]:
            return False, "unknown or disabled token"
        if tok["scope"] != Scope.OPERATOR:
            return False, "operator scope required"
        if tok["commands"]:
            return (True, "") if command in tok["commands"] else (False, "command not in token allowlist")
        return (True, "") if command in self.commands else (False, "command not in global allowlist")

    def can_write_file(self, token_id, path):
        if not self._tokens:
            return True, ""
        tok = self._tokens.get(token_id)
        if not tok or tok["disabled"]:
            return False, "unknown or disabled token"
        if tok["scope"] != Scope.OPERATOR:
            return False, "operator scope required"
        clean = self._clean_path(path)
        for p in self.denied_paths:
            if self._is_subpath(clean, self._clean_path(p)):
                return False, "path denied"
        if not self.write_paths:
            return False, "no write path allowlist"
        for p in self.write_paths:
            if self._is_subpath(clean, self._clean_path(p)):
                return True, ""
        return False, "path not in write allowlist"

    @staticmethod
    def _clean_path(p):
        p = p.replace("\\", "/")
        if not p.startswith("/"):
            p = "/" + p
        parts = []
        for part in p.split("/"):
            if part == "..":
                if parts: parts.pop()
            elif part and part != ".":
                parts.append(part)
        return "/" + "/".join(parts)

    @staticmethod
    def _is_subpath(child, parent):
        if child == parent:
            return True
        prefix = parent if parent.endswith("/") else parent + "/"
        return child.startswith(prefix)


class RateLimiter:
    """Token-bucket rate limiter keyed by token."""

    def __init__(self, rate=10.0, burst=20) -> None:
        self._rate, self._burst = rate, burst
        self._buckets = defaultdict(lambda: float(burst))
        self._last = {}
        self._lock = threading.Lock()

    def consume(self, key):
        now = time.monotonic()
        with self._lock:
            elapsed = now - self._last.get(key, now)
            self._buckets[key] = min(self._burst, self._buckets[key] + elapsed * self._rate)
            self._last[key] = now
            if self._buckets[key] >= 1.0:
                self._buckets[key] -= 1.0
                return True
            return False

    def time_to_wait(self, key):
        with self._lock:
            if self._buckets[key] >= 1.0:
                return 0.0
            return (1.0 - self._buckets[key]) / self._rate


class AuditLogger:
    """Writes JSONL audit logs."""

    def __init__(self, log_dir=None) -> None:
        if log_dir is None:
            log_dir = Path.cwd() / "tmp" / "mock-agent-audit"
        self._path = Path(log_dir)
        self._path.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path / "audit.jsonl", "a", encoding="utf-8")
        self._lock = threading.Lock()

    def log(self, action, token_id=None, details=None, ok=True, error=None) -> None:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(),
                 "action": action, "ok": ok}
        if token_id:
            entry["token_id"] = token_id
        if details:
            entry["details"] = details
        if error:
            entry["error"] = error
        with self._lock:
            self._file.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._file.flush()

    def close(self) -> None:
        self._file.close()


def build_app(token=None, hostname=None, os_name=None, kernel=None,
              base_uptime=259200, tokens=None, policy=None,
              rate_limiter=None, audit=None):
    hostname = hostname or (platform.node() or "mock-host")
    os_name = os_name or "Ubuntu 24.04.1 LTS"
    kernel = kernel or "6.8.0-45-generic"
    started = time.time()
    _policy = policy or PolicyEngine()
    _rate = rate_limiter or RateLimiter()
    _audit = audit or AuditLogger()
    _services = {"nginx": "running", "docker": "running", "ssh": "active"}

    app = FastAPI(title="Mock Linux Agent", version=AGENT_VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None)

    allowed = None
    if tokens is not None:
        allowed = {"Bearer " + t for t in tokens}
    elif token is not None:
        allowed = {"Bearer " + token}

    def _token_id(request):
        auth = request.headers.get("Authorization", "")
        return auth[len("Bearer "):] if auth.startswith("Bearer ") else ""

    def _check_rate(tid):
        if not _rate.consume(tid):
            _audit.log("rate_limited", token_id=tid, ok=False)
            return JSONResponse(
                {"error": "rate_limited",
                 "retry_seconds": round(_rate.time_to_wait(tid), 2)},
                status_code=429)
        return None

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        tid = _token_id(request)
        if allowed is not None and ("Bearer " + tid) not in allowed:
            _audit.log("auth_failed", token_id=tid, ok=False)
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if tid and "/v1/health" not in request.url.path:
            limited = _check_rate(tid)
            if limited is not None:
                return limited
        return await call_next(request)

    def uptime():
        return int(base_uptime + (time.time() - started))

    @app.get("/v1/health")
    def health():
        return {"status": "ok", "agent_version": AGENT_VERSION, "hostname": hostname}

    @app.get("/v1/system")
    def system(request: Request):
        tid = _token_id(request)
        _audit.log("system.read", token_id=tid)
        return {"hostname": hostname, "os": os_name, "kernel": kernel,
                "arch": "x86_64", "uptime_seconds": uptime(),
                "agent_version": AGENT_VERSION}

    @app.get("/v1/disk")
    def disk(request: Request):
        _audit.log("disk.read", token_id=_token_id(request))
        return {"filesystems": [
            {"device": "/dev/sda1", "mount": "/", "use_percent": 41.7}]}

    @app.get("/v1/processes")
    def processes():
        _audit.log("processes.read")
        return {"processes": [{"pid": 1, "command": "/sbin/init"}, {"pid": 812, "user": "www-data", "command": "nginx: worker process"}]}

    @app.get("/v1/services/{service}")
    def service_status(service: str, request: Request):
        tid = _token_id(request)
        ok, reason = _policy.can_read_service(tid, service)
        if not ok:
            _audit.log("service.denied", token_id=tid,
                       details={"service": service, "reason": reason}, ok=False)
            raise HTTPException(status_code=403, detail=reason)
        status = _services.get(service)
        if status is None:
            raise HTTPException(status_code=404, detail=f"unknown service: {service}")
        _audit.log("service.status", token_id=tid, details={"service": service})
        return {"service": service, "active": True, "status": status}

    @app.post("/v1/services/{service}/restart")
    def service_restart(service: str, request: Request):
        tid = _token_id(request)
        ok, reason = _policy.can_manage_service(tid, service)
        if not ok:
            _audit.log("service.restart.denied", token_id=tid,
                       details={"service": service, "reason": reason}, ok=False)
            raise HTTPException(status_code=403, detail=reason)
        _audit.log("service.restart", token_id=tid, details={"service": service})
        return {"success": True, "service": service, "status": "running"}

    @app.get("/v1/services/{service}/logs")
    def service_logs(service: str, request: Request, lines: int = Query(default=100, ge=1, le=1000)):
        tid = _token_id(request)
        ok, reason = _policy.can_read_service(tid, service)
        if not ok:
            raise HTTPException(status_code=403, detail=reason)
        _audit.log("service.logs", token_id=tid, details={"service": service})
        return {"service": service, "lines": [f"{service}[42]: sample log"], "total": 1, "truncated": False}

    @app.get("/v1/files")
    def read_file(path: str = Query(...), request: Request = None):
        tid = _token_id(request)
        ok, reason = _policy.can_read_file(tid, path)
        if not ok:
            _audit.log("file.read.denied", token_id=tid,
                       details={"path": path, "reason": reason}, ok=False)
            raise HTTPException(status_code=403, detail=reason)
        allowed = {"/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n',
                   "/etc/hostname": hostname + "\n"}
        if path not in allowed:
            raise HTTPException(status_code=403, detail=f"path not allowed: {path}")
        _audit.log("file.read", token_id=tid, details={"path": path})
        return {"path": path, "content": allowed[path]}

    @app.post("/v1/files")
    def write_file(path: str = Query(...), payload: dict = Body(default={}), request: Request = None):
        tid = _token_id(request)
        ok, reason = _policy.can_write_file(tid, path)
        if not ok:
            _audit.log("file.write.denied", token_id=tid,
                       details={"path": path, "reason": reason}, ok=False)
            raise HTTPException(status_code=403, detail=reason)
        content = payload.get("content")
        if not isinstance(content, str):
            raise HTTPException(status_code=400, detail="content required")
        _audit.log("file.write", token_id=tid, details={"path": path})
        return {"path": path, "backup": path + ".bak", "status": "written"}

    @app.post("/v1/execute")
    def execute(payload: dict = Body(default={}), request: Request = None):
        tid = _token_id(request)
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip():
            raise HTTPException(status_code=400, detail="command required")
        ok, reason = _policy.can_run_command(tid, command)
        if not ok:
            _audit.log("execute.denied", token_id=tid,
                       details={"command": command, "reason": reason}, ok=False)
            raise HTTPException(status_code=403, detail=reason)
        _audit.log("execute", token_id=tid, details={"command": command})
        return {"command": command, "exit_code": 0, "stdout": f"mock: {command}",
                "stderr": "", "duration": "1ms", "timed_out": False}

    return app


def main():
    parser = argparse.ArgumentParser(description="Mock Linux Agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--token", default=None)
    parser.add_argument("--hostname", default=None)
    parser.add_argument("--os", dest="os_name", default=None)
    parser.add_argument("--kernel", default=None)
    parser.add_argument("--base-uptime", type=int, default=259200)
    args = parser.parse_args()
    import uvicorn
    app = build_app(token=args.token, hostname=args.hostname,
                    os_name=args.os_name, kernel=args.kernel,
                    base_uptime=args.base_uptime)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
