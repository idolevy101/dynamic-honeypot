from __future__ import annotations

import asyncio
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import uuid4

from telemetry import record_auth_attempt

DEFAULT_WEAK_PASSWORDS: tuple[str, ...] = (
    "123456",
    "admin",
    "password",
    "toor",
    "root",
    "ubuntu",
)

TARPIT_SECONDS = 2.0
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_MAX_PINS = 500
DEFAULT_TTL_SECONDS = 3600.0


class AuthAttemptLimitExceeded(Exception):
    def __init__(self, session_id: str) -> None:
        super().__init__("Too many authentication failures")
        self.session_id = session_id


@dataclass
class _PinRecord:
    password: str
    last_seen: float


class AuthManager:
    def __init__(
        self,
        passwords: Sequence[str] = DEFAULT_WEAK_PASSWORDS,
        *,
        tarpit_seconds: float = TARPIT_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        max_pins: int = DEFAULT_MAX_PINS,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not passwords:
            raise ValueError("password list must not be empty")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if max_pins < 1:
            raise ValueError("max_pins must be at least 1")
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        self._passwords: tuple[str, ...] = tuple(passwords)
        self._tarpit_seconds = tarpit_seconds
        self._max_attempts = max_attempts
        self._max_pins = max_pins
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._pins: OrderedDict[str, _PinRecord] = OrderedDict()
        self._attempts: dict[str, int] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._pins)

    def __contains__(self, ip: object) -> bool:
        if not isinstance(ip, str):
            return False
        with self._lock:
            return ip in self._pins

    def get_or_pin_password(self, client_ip: str) -> str:
        with self._lock:
            now = self._clock()
            self._purge_expired_unlocked(now)
            pin = self._pins.get(client_ip)
            if pin is not None:
                pin.last_seen = now
                self._pins.move_to_end(client_ip)
                return pin.password
            while len(self._pins) >= self._max_pins:
                self._pins.popitem(last=False)
            password = secrets.choice(self._passwords)
            self._pins[client_ip] = _PinRecord(password=password, last_seen=now)
            return password

    def create_session(self, client_ip: str) -> str:
        self.get_or_pin_password(client_ip)
        session_id = uuid4().hex
        self._attempts[session_id] = 0
        return session_id

    async def validate_login(
        self,
        client_ip: str,
        session_id: str,
        username: str,
        password: str,
    ) -> bool:
        pinned = self.get_or_pin_password(client_ip)
        success = secrets.compare_digest(password, pinned)
        if success:
            await record_auth_attempt(
                session_id=session_id,
                client_ip=client_ip,
                username=username,
                password=password,
                success=True,
                attempt_count=self._attempts.get(session_id, 0),
                limit_exceeded=False,
            )
            return True
        if session_id in self._attempts:
            self._attempts[session_id] += 1
        attempt_count = self._attempts.get(session_id, 0)
        limit_exceeded = attempt_count >= self._max_attempts
        log_task = asyncio.create_task(
            record_auth_attempt(
                session_id=session_id,
                client_ip=client_ip,
                username=username,
                password=password,
                success=False,
                attempt_count=attempt_count,
                limit_exceeded=limit_exceeded,
            )
        )
        try:
            await asyncio.sleep(self._tarpit_seconds)
        finally:
            await log_task
        if limit_exceeded:
            raise AuthAttemptLimitExceeded(session_id)
        return False

    def release_session(self, session_id: str) -> None:
        self._attempts.pop(session_id, None)

    def sweep(self) -> int:
        with self._lock:
            before = len(self._pins)
            self._purge_expired_unlocked(self._clock())
            return before - len(self._pins)

    def _purge_expired_unlocked(self, now: float) -> None:
        expired = [
            key
            for key, pin in self._pins.items()
            if now - pin.last_seen > self._ttl_seconds
        ]
        for key in expired:
            del self._pins[key]
