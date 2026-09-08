from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

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


def test_lru_evicts_oldest_pin_under_cap() -> None:
    now = 100.0
    auth = AuthManager(
        passwords=("secret",),
        tarpit_seconds=0.0,
        max_pins=2,
        ttl_seconds=3600,
        clock=lambda: now,
    )
    auth.get_or_pin_password("10.0.0.1")
    now = 101.0
    auth.get_or_pin_password("10.0.0.2")
    now = 102.0
    auth.get_or_pin_password("10.0.0.3")

    assert "10.0.0.1" not in auth
    assert "10.0.0.2" in auth
    assert "10.0.0.3" in auth
    assert len(auth) == 2


def test_pin_ttl_expiry_assigns_fresh_password(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_000.0
    assigned: Iterator[str] = iter(["alpha", "bravo"])

    def choose(_passwords: object) -> str:
        return next(assigned)

    monkeypatch.setattr("auth.secrets.choice", choose)
    auth = AuthManager(
        passwords=("alpha", "bravo"),
        tarpit_seconds=0.0,
        ttl_seconds=10,
        clock=lambda: now,
    )
    assert auth.get_or_pin_password("10.0.0.1") == "alpha"
    now = 1_011.0
    assert auth.get_or_pin_password("10.0.0.1") == "bravo"


def test_auth_sweep_clears_expired_pins() -> None:
    now = 50.0
    auth = AuthManager(tarpit_seconds=0.0, ttl_seconds=5, clock=lambda: now)
    auth.get_or_pin_password("192.0.2.10")
    now = 56.0
    assert auth.sweep() == 1
    assert "192.0.2.10" not in auth


async def test_auth_attempt_telemetry_success_and_failure() -> None:
    auth = AuthManager(passwords=("secret",), tarpit_seconds=0.0)
    session_id = auth.create_session("192.0.2.1")
    assert await auth.validate_login("192.0.2.1", session_id, "root", "secret") is True
    assert await auth.validate_login("192.0.2.1", session_id, "admin", "nope") is False

    path = Path("logs/auth_attempts.jsonl")
    assert path.is_file()
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 2
    assert records[0]["success"] is True
    assert records[0]["username"] == "root"
    assert records[0]["password"] == "secret"
    assert records[0]["client_ip"] == "192.0.2.1"
    assert records[0]["session_id"] == session_id
    assert records[0]["limit_exceeded"] is False
    assert records[0]["attempt_count"] == 0
    assert records[1]["success"] is False
    assert records[1]["username"] == "admin"
    assert records[1]["password"] == "nope"
    assert records[1]["attempt_count"] == 1
    assert records[1]["limit_exceeded"] is False
    assert "T" in records[0]["timestamp"]


async def test_auth_attempt_telemetry_records_limit_exceeded() -> None:
    auth = AuthManager(passwords=("secret",), tarpit_seconds=0.0)
    session_id = auth.create_session("192.0.2.9")
    with pytest.raises(AuthAttemptLimitExceeded):
        assert await auth.validate_login("192.0.2.9", session_id, "root", "a") is False
        assert await auth.validate_login("192.0.2.9", session_id, "root", "b") is False
        await auth.validate_login("192.0.2.9", session_id, "root", "c")

    path = Path("logs/auth_attempts.jsonl")
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [row["limit_exceeded"] for row in records] == [False, False, True]
    assert records[-1]["success"] is False
    assert records[-1]["password"] == "c"
