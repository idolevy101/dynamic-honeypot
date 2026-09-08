from __future__ import annotations

import asyncio
import logging
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import uuid4

from telemetry import record_auth_attempt

_LOGGER = logging.getLogger(__name__)

DEFAULT_WEAK_PASSWORDS: tuple[str, ...] = (
    "123456",
    "admin",
    "password",
    "toor",
    "root",
    "ubuntu",
)

ALLOWED_USERNAME = "root"
TARPIT_SECONDS = 2.0
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_MAX_PINS = 500
DEFAULT_TTL_SECONDS = 3600.0
DEFAULT_ATTEMPT_TTL_SECONDS = 300.0


class AuthAttemptLimitExceeded(Exception):
    def __init__(self, session_id: str) -> None:
        super().__init__("Too many authentication failures")
        self.session_id = session_id


@dataclass
class _PinRecord:
    password: str
    last_seen: float


@dataclass
class _AttemptRecord:
    count: int
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
        attempt_ttl_seconds: float = DEFAULT_ATTEMPT_TTL_SECONDS,
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
        if attempt_ttl_seconds < 0:
            raise ValueError("attempt_ttl_seconds must be non-negative")
        self._passwords: tuple[str, ...] = tuple(passwords)
        self._tarpit_seconds = tarpit_seconds
        self._max_attempts = max_attempts
        self._max_pins = max_pins
        self._ttl_seconds = ttl_seconds
        self._attempt_ttl_seconds = attempt_ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._pins: OrderedDict[str, _PinRecord] = OrderedDict()
        self._attempts: OrderedDict[str, _AttemptRecord] = OrderedDict()

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
        return uuid4().hex

    def is_locked_out(self, client_ip: str) -> bool:
        with self._lock:
            now = self._clock()
            self._purge_expired_unlocked(now)
            record = self._attempts.get(client_ip)
            return record is not None and record.count >= self._max_attempts

    async def validate_login(
        self,
        client_ip: str,
        session_id: str,
        username: str,
        password: str,
    ) -> bool:
        if username != ALLOWED_USERNAME:
            success = False
        else:
            pinned = self.get_or_pin_password(client_ip)
            try:
                success = secrets.compare_digest(str(password), str(pinned))
            except (TypeError, ValueError):
                success = False
        with self._lock:
            now = self._clock()
            self._purge_expired_unlocked(now)
            record = self._attempts.get(client_ip)
            already_locked = record is not None and record.count >= self._max_attempts
            if already_locked:
                attempt_count = record.count if record is not None else self._max_attempts
                limit_exceeded = True
                accepted = False
            elif success:
                if client_ip in self._attempts:
                    del self._attempts[client_ip]
                attempt_count = 0
                limit_exceeded = False
                accepted = True
            else:
                attempt_count = self._register_failure_unlocked(client_ip, now)
                limit_exceeded = attempt_count >= self._max_attempts
                accepted = False
        if accepted:
            await self._record_attempt(
                session_id=session_id,
                client_ip=client_ip,
                username=username,
                password=password,
                success=True,
                attempt_count=attempt_count,
                limit_exceeded=False,
            )
            return True
        log_task = asyncio.create_task(
            self._record_attempt(
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
            try:
                await log_task
            except Exception:
                _LOGGER.warning("auth telemetry task failed", exc_info=True)
        if limit_exceeded:
            raise AuthAttemptLimitExceeded(session_id)
        return False

    async def _record_attempt(
        self,
        *,
        session_id: str,
        client_ip: str,
        username: str,
        password: str,
        success: bool,
        attempt_count: int,
        limit_exceeded: bool,
    ) -> None:
        try:
            await record_auth_attempt(
                session_id=session_id,
                client_ip=client_ip,
                username=username,
                password=password,
                success=success,
                attempt_count=attempt_count,
                limit_exceeded=limit_exceeded,
            )
        except Exception as exc:
            _LOGGER.warning("auth telemetry write failed: %s", exc)

    def release_session(self, session_id: str) -> None:
        _ = session_id

    def sweep(self) -> int:
        with self._lock:
            before = len(self._pins)
            self._purge_expired_unlocked(self._clock())
            return before - len(self._pins)

    def _register_failure_unlocked(self, client_ip: str, now: float) -> int:
        record = self._attempts.get(client_ip)
        if record is None:
            while len(self._attempts) >= self._max_pins:
                self._attempts.popitem(last=False)
            record = _AttemptRecord(count=0, last_seen=now)
            self._attempts[client_ip] = record
        record.count += 1
        record.last_seen = now
        self._attempts.move_to_end(client_ip)
        return record.count

    def _purge_expired_unlocked(self, now: float) -> None:
        expired_pins = [
            key
            for key, pin in self._pins.items()
            if now - pin.last_seen > self._ttl_seconds
        ]
        for key in expired_pins:
            del self._pins[key]
        expired_attempts = [
            key
            for key, record in self._attempts.items()
            if now - record.last_seen > self._attempt_ttl_seconds
        ]
        for key in expired_attempts:
            del self._attempts[key]
