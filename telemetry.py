"""Append-only JSONL session and authentication audit telemetry."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Final, Iterable, Literal

from sinkhole import iso_utc_now

_LOGGER = logging.getLogger(__name__)

SESSION_LOG_DIR: Final[Path] = Path("logs") / "sessions"
AUTH_LOG_PATH: Final[Path] = Path("logs") / "auth_attempts.jsonl"

_SAFE_SESSION_CHARS: Final[str] = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)

ExecutionPath = Literal["vfs", "static", "sinkhole", "llm", "cache", "exec_trap"]
EXECUTION_PATHS: Final[frozenset[str]] = frozenset(
    ("vfs", "static", "sinkhole", "llm", "cache", "exec_trap")
)


def _safe_session_id(session_id: str) -> str:
    cleaned = "".join(char for char in session_id if char in _SAFE_SESSION_CHARS)
    return cleaned or "local"


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(record, ensure_ascii=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


async def record_command(
    *,
    session_id: str,
    client_ip: str,
    command: str,
    execution_path: ExecutionPath | str,
    duration_ms: float,
    captured_artifacts: Iterable[str] = (),
    extra: dict[str, Any] | None = None,
) -> None:
    record: dict[str, Any] = {
        "timestamp": iso_utc_now(),
        "session_id": session_id,
        "client_ip": client_ip,
        "command": command,
        "execution_path": execution_path,
        "duration_ms": duration_ms,
        "captured_artifacts": list(captured_artifacts),
    }
    if extra:
        record.update(extra)
    path = SESSION_LOG_DIR / f"{_safe_session_id(session_id)}.jsonl"
    try:
        await asyncio.to_thread(_append_jsonl, path, record)
    except OSError as exc:
        _LOGGER.warning("session telemetry write failed: %s", exc)


async def record_auth_attempt(
    *,
    session_id: str,
    client_ip: str,
    username: str,
    password: str,
    success: bool,
    attempt_count: int = 0,
    limit_exceeded: bool = False,
) -> None:
    record = {
        "timestamp": iso_utc_now(),
        "session_id": session_id,
        "client_ip": client_ip,
        "username": username,
        "password": password,
        "success": success,
        "attempt_count": attempt_count,
        "limit_exceeded": limit_exceeded,
    }
    try:
        await asyncio.to_thread(_append_jsonl, AUTH_LOG_PATH, record)
    except OSError as exc:
        _LOGGER.warning("auth telemetry write failed: %s", exc)
