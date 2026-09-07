from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest

from auth import AuthAttemptLimitExceeded, AuthManager, DEFAULT_WEAK_PASSWORDS


@pytest.fixture
def auth() -> AuthManager:
    return AuthManager(tarpit_seconds=0.0)


def test_same_ip_pins_identical_password(auth: AuthManager) -> None:
    first = auth.get_or_pin_password("203.0.113.10")
    second = auth.get_or_pin_password("203.0.113.10")
    third = auth.get_or_pin_password("203.0.113.10")
    assert first == second == third
    assert first in DEFAULT_WEAK_PASSWORDS


def test_create_session_reuses_ip_pin(auth: AuthManager) -> None:
    pinned = auth.get_or_pin_password("198.51.100.7")
    session_a = auth.create_session("198.51.100.7")
    session_b = auth.create_session("198.51.100.7")
    assert session_a != session_b
    assert auth.get_or_pin_password("198.51.100.7") == pinned


def test_different_ips_receive_independent_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    assigned: Iterator[str] = iter(["alpha", "bravo"])

    def choose(_passwords: object) -> str:
        return next(assigned)

    monkeypatch.setattr("auth.secrets.choice", choose)
    auth = AuthManager(passwords=("alpha", "bravo"), tarpit_seconds=0.0)

    ip_a = auth.get_or_pin_password("10.0.0.1")
    ip_b = auth.get_or_pin_password("10.0.0.2")
    assert ip_a == "alpha"
    assert ip_b == "bravo"
    assert auth.get_or_pin_password("10.0.0.1") == "alpha"
    assert auth.get_or_pin_password("10.0.0.2") == "bravo"


def test_max_attempts_raises_on_third_failure() -> None:
    async def scenario() -> None:
        auth = AuthManager(passwords=("secret",), tarpit_seconds=0.0)
        session_id = auth.create_session("192.0.2.1")

        assert await auth.validate_login("192.0.2.1", session_id, "root", "wrong") is False
        assert await auth.validate_login("192.0.2.1", session_id, "root", "nope") is False
        with pytest.raises(AuthAttemptLimitExceeded) as exc:
            await auth.validate_login("192.0.2.1", session_id, "root", "still-wrong")
        assert exc.value.session_id == session_id

    asyncio.run(scenario())


def test_successful_login_does_not_consume_attempts() -> None:
    async def scenario() -> None:
        auth = AuthManager(passwords=("secret",), tarpit_seconds=0.0)
        session_id = auth.create_session("192.0.2.8")
        pinned = auth.get_or_pin_password("192.0.2.8")
        assert await auth.validate_login("192.0.2.8", session_id, "root", pinned) is True
        assert await auth.validate_login("192.0.2.8", session_id, "root", pinned) is True
        assert await auth.validate_login("192.0.2.8", session_id, "root", "bad") is False
        assert await auth.validate_login("192.0.2.8", session_id, "root", "bad") is False
        with pytest.raises(AuthAttemptLimitExceeded):
            await auth.validate_login("192.0.2.8", session_id, "root", "bad")

    asyncio.run(scenario())


def test_reconnect_resets_attempts_but_keeps_pin() -> None:
    async def scenario() -> None:
        auth = AuthManager(passwords=("hunter2",), tarpit_seconds=0.0)
        client_ip = "192.0.2.55"
        first = auth.create_session(client_ip)
        pinned = auth.get_or_pin_password(client_ip)

        with pytest.raises(AuthAttemptLimitExceeded):
            assert await auth.validate_login(client_ip, first, "root", "a") is False
            assert await auth.validate_login(client_ip, first, "root", "b") is False
            await auth.validate_login(client_ip, first, "root", "c")

        auth.release_session(first)
        assert auth.get_or_pin_password(client_ip) == pinned

        second = auth.create_session(client_ip)
        assert second != first
        assert await auth.validate_login(client_ip, second, "root", "wrong") is False
        assert await auth.validate_login(client_ip, second, "root", "wrong") is False
        assert await auth.validate_login(client_ip, second, "root", pinned) is True

    asyncio.run(scenario())


def test_concurrent_sessions_share_pin_but_not_attempt_counters() -> None:
    async def scenario() -> None:
        auth = AuthManager(passwords=("shared",), tarpit_seconds=0.0)
        client_ip = "192.0.2.200"
        session_a = auth.create_session(client_ip)
        session_b = auth.create_session(client_ip)
        pinned = auth.get_or_pin_password(client_ip)

        await auth.validate_login(client_ip, session_a, "root", "bad")
        await auth.validate_login(client_ip, session_a, "root", "bad")
        with pytest.raises(AuthAttemptLimitExceeded):
            await auth.validate_login(client_ip, session_a, "root", "bad")

        assert await auth.validate_login(client_ip, session_b, "root", "bad") is False
        assert await auth.validate_login(client_ip, session_b, "root", pinned) is True

    asyncio.run(scenario())
