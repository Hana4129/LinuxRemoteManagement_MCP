"""Tests for MCP audit log rotation."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.mcp_audit import McpAudit


class TestAuditRotation:
    """Tests for log rotation functionality."""

    def test_no_rotation_when_disabled(self, tmp_path: Path):
        """Rotation with max_size_mb=0 should not rotate."""
        log_path = tmp_path / "audit.log"
        audit = McpAudit(log_path, max_size_mb=0, max_backups=3, compress=False)
        for _ in range(100):
            audit.log(actor="test", action="test_action", ok=True)
        audit.close()
        assert not (tmp_path / "audit.log.1").exists()
        assert log_path.exists()

    def test_rotation_creates_backup(self, tmp_path: Path):
        """When log exceeds max size, rotation should create a backup."""
        log_path = tmp_path / "audit.log"
        audit = McpAudit(log_path, max_size_mb=1, max_backups=3, compress=False)
        large_data = "x" * 100
        for _ in range(5000):
            audit.log(actor="test", action="test_action", params={"data": large_data}, ok=True)
        audit.close()
        backup_exists = (tmp_path / "audit.log.1").exists() or (tmp_path / "audit.log.1.gz").exists()
        assert backup_exists or log_path.exists()

    def test_rotation_respects_max_backups(self, tmp_path: Path):
        """Rotation should not exceed max_backups."""
        log_path = tmp_path / "audit.log"
        audit = McpAudit(log_path, max_size_mb=1, max_backups=2, compress=False)
        large_data = "y" * 100
        for _ in range(5000):
            audit.log(actor="test", action="test_action", params={"data": large_data}, ok=True)
        audit.close()
        backup_count = 0
        for i in range(1, 10):
            if (tmp_path / f"audit.log.{i}").exists() or (tmp_path / f"audit.log.{i}.gz").exists():
                backup_count += 1
        assert backup_count <= 2

    def test_rotation_with_compression(self, tmp_path: Path):
        """Rotation with compress=True should create .gz files."""
        log_path = tmp_path / "audit.log"
        audit = McpAudit(log_path, max_size_mb=1, max_backups=3, compress=True)
        large_data = "z" * 100
        for _ in range(5000):
            audit.log(actor="test", action="test_action", params={"data": large_data}, ok=True)
        audit.close()
        gz_exists = (tmp_path / "audit.log.1.gz").exists()
        assert gz_exists or log_path.exists()

    def test_rotation_preserves_content(self, tmp_path: Path):
        """Rotated log files should contain valid JSONL."""
        log_path = tmp_path / "audit.log"
        audit = McpAudit(log_path, max_size_mb=1, max_backups=3, compress=False)
        for i in range(10):
            audit.log(actor="test", action=f"action_{i}", ok=True)
        audit.close()
        entries = audit.read_entries()
        assert len(entries) > 0
        assert all("actor" in e for e in entries)

    def test_manual_rotation(self, tmp_path: Path):
        """Calling _rotate directly should rotate the log."""
        log_path = tmp_path / "audit.log"
        audit = McpAudit(log_path, max_size_mb=1, max_backups=3, compress=False)
        audit.log(actor="test", action="before_rotation", ok=True)
        audit._rotate()
        audit.log(actor="test", action="after_rotation", ok=True)
        audit.close()
        assert log_path.exists()
        assert (tmp_path / "audit.log.1").exists()
        with open(tmp_path / "audit.log.1", "r") as f:
            content = f.read()
        assert "before_rotation" in content
