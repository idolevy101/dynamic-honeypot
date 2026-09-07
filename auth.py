from __future__ import annotations

import asyncio
import secrets
from collections.abc import Sequence
from uuid import uuid4

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


class AuthAttemptLimitExceeded(Exception):
    def __init__(self, session_id: str) -> None:
        super().__init__("Too many authentication failures")
        self.session_id = session_id


class AuthManager:
    def __init__(
        self,
        passwords: Sequence[str] = DEFAULT_WEAK_PASSWORDS,
        *,
        tarpit_seconds: float = TARPIT_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        if not passwords:
            raise ValueError("password list must not be empty")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._passwords: tuple[str, ...] = tuple(passwords)
        self._tarpit_seconds = tarpit_seconds
        self._max_attempts = max_attempts
        self._pinned_passwords: dict[str, str] = {}
        self._attempts: dict[str, int] = {}

    def get_or_pin_password(self, client_ip: str) -> str:
        pinned = self._pinned_passwords.get(client_ip)
        if pinned is not None:
            return pinned
        password = secrets.choice(self._passwords)
        self._pinned_passwords[client_ip] = password
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
        _ = username
        pinned = self.get_or_pin_password(client_ip)
        if secrets.compare_digest(password, pinned):
            return True
        if session_id in self._attempts:
            self._attempts[session_id] += 1
        await asyncio.sleep(self._tarpit_seconds)
        if self._attempts.get(session_id, 0) >= self._max_attempts:
            raise AuthAttemptLimitExceeded(session_id)
        return False

    def release_session(self, session_id: str) -> None:
        self._attempts.pop(session_id, None)
