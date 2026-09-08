"""Quarantine captured payloads without executing them on the host OS."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote, urlparse

QUARANTINE_DIR: Final[Path] = Path("quarantine")


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def filename_from_url(url: str) -> str:
    path = unquote(urlparse(url).path)
    name = path.rsplit("/", 1)[-1]
    return name if name else "index.html"


def mocked_payload(url: str, client_ip: str, timestamp: str) -> str:
    return (
        "#!/bin/sh\n"
        "# Captured payload placeholder\n"
        f"# Source: {url}\n"
        f"# Client: {client_ip}\n"
        f"# Timestamp: {timestamp}\n"
    )


def quarantine_artifact(
    filename: str,
    content: bytes | str,
    client_ip: str,
    source_url: str = "",
) -> dict[str, Any]:
    data = content.encode("utf-8") if isinstance(content, str) else content
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    (QUARANTINE_DIR / sha256).write_bytes(data)
    return {
        "filename": filename,
        "sha256": sha256,
        "md5": md5,
        "size_bytes": len(data),
        "client_ip": client_ip,
        "source_url": source_url,
        "timestamp": iso_utc_now(),
    }
