"""Bounded per-IP VFS and LLM-cache persistence across SSH reconnects."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from vfs import VirtualFileSystem, create_default_vfs

DEFAULT_MAX_SESSIONS = 500
DEFAULT_TTL_SECONDS = 3600.0


@dataclass
class IpSession:
    vfs: VirtualFileSystem
    llm_cache: dict[str, str] = field(default_factory=dict)
    last_seen: float = 0.0


class SessionManager:
    """In-memory LRU+TTL store of isolated per-IP honeypot state."""

    def __init__(
        self,
        *,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        vfs_factory: Callable[[], VirtualFileSystem] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds
        self._vfs_factory = vfs_factory or create_default_vfs
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, IpSession] = OrderedDict()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def __contains__(self, ip: object) -> bool:
        if not isinstance(ip, str):
            return False
        with self._lock:
            return ip in self._sessions

    def get_or_create(self, ip: str) -> IpSession:
        with self._lock:
            now = self._clock()
            self._purge_expired_unlocked(now)
            session = self._sessions.get(ip)
            if session is not None:
                session.last_seen = now
                self._sessions.move_to_end(ip)
                return session
            while len(self._sessions) >= self._max_sessions:
                self._sessions.popitem(last=False)
            session = IpSession(
                vfs=self._vfs_factory(),
                llm_cache={},
                last_seen=now,
            )
            self._sessions[ip] = session
            return session

    def touch(self, ip: str) -> None:
        with self._lock:
            session = self._sessions.get(ip)
            if session is None:
                return
            session.last_seen = self._clock()
            self._sessions.move_to_end(ip)

    def sweep(self) -> int:
        with self._lock:
            before = len(self._sessions)
            self._purge_expired_unlocked(self._clock())
            return before - len(self._sessions)

    def _purge_expired_unlocked(self, now: float) -> None:
        expired = [
            key
            for key, session in self._sessions.items()
            if now - session.last_seen > self._ttl_seconds
        ]
        for key in expired:
            del self._sessions[key]
