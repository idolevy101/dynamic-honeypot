from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock

from auth import AuthManager
from llm import LLMSimulation, NullLLMProvider
from server import BANNER, HoneypotServer, handle_client, _periodic_sweep
from session_manager import SessionManager
from shell import Shell
from vfs import create_default_vfs

IP_A = "203.0.113.10"
IP_B = "198.51.100.20"


def test_create_default_vfs_instances_are_isolated() -> None:
    first = create_default_vfs()
    second = create_default_vfs()
    first.touch_file("/tmp/test.txt", "/")
    assert first.exists("/tmp/test.txt", "/")
    assert not second.exists("/tmp/test.txt", "/")


async def test_same_ip_persists_vfs_across_reconnects() -> None:
    manager = SessionManager(max_sessions=8, ttl_seconds=3600)
    first = manager.get_or_create(IP_A)
    shell = Shell(first.vfs, llm_provider=NullLLMProvider(), llm_cache=first.llm_cache)
    result = await shell.execute("touch /tmp/test.txt")
    assert result.output == ""
    manager.touch(IP_A)

    second = manager.get_or_create(IP_A)
    assert second is first
    assert second.vfs is first.vfs
    reconnect = Shell(second.vfs, llm_provider=NullLLMProvider(), llm_cache=second.llm_cache)
    listing = await reconnect.execute("ls /tmp")
    assert "test.txt" in listing.output.split("  ")


async def test_different_ips_do_not_share_vfs() -> None:
    manager = SessionManager(max_sessions=8, ttl_seconds=3600)
    session_a = manager.get_or_create(IP_A)
    await Shell(session_a.vfs, llm_provider=NullLLMProvider()).execute("touch /tmp/test.txt")

    session_b = manager.get_or_create(IP_B)
    listing = await Shell(session_b.vfs, llm_provider=NullLLMProvider()).execute("ls /tmp")
    assert "test.txt" not in listing.output.split("  ")
    assert session_a.vfs.exists("/tmp/test.txt", "/")
    assert not session_b.vfs.exists("/tmp/test.txt", "/")


def test_ttl_expiry_resets_to_baseline_vfs() -> None:
    now = 1_000.0
    manager = SessionManager(
        max_sessions=8,
        ttl_seconds=10,
        clock=lambda: now,
    )
    original = manager.get_or_create(IP_A)
    original.vfs.touch_file("/tmp/test.txt", "/")
    original.llm_cache["lscpu"] = "Architecture: x86_64"

    now = 1_011.0
    reset = manager.get_or_create(IP_A)
    assert reset is not original
    assert reset.vfs is not original.vfs
    assert not reset.vfs.exists("/tmp/test.txt", "/")
    assert reset.llm_cache == {}
    assert original.vfs.exists("/tmp/test.txt", "/")


def test_sweep_clears_expired_sessions() -> None:
    now = 50.0
    manager = SessionManager(max_sessions=8, ttl_seconds=5, clock=lambda: now)
    manager.get_or_create(IP_A)
    now = 56.0
    assert manager.sweep() == 1
    assert IP_A not in manager


def test_lru_evicts_least_recently_accessed_ip() -> None:
    now = 100.0
    manager = SessionManager(max_sessions=2, ttl_seconds=3600, clock=lambda: now)
    session_a = manager.get_or_create("10.0.0.1")
    session_a.vfs.touch_file("/tmp/test.txt", "/")
    now = 101.0
    session_b = manager.get_or_create("10.0.0.2")
    session_b.vfs.touch_file("/tmp/kept.txt", "/")
    now = 102.0
    manager.get_or_create("10.0.0.3")

    assert "10.0.0.1" not in manager
    assert "10.0.0.2" in manager
    assert "10.0.0.3" in manager
    assert manager.get_or_create("10.0.0.2").vfs.exists("/tmp/kept.txt", "/")

    revived = manager.get_or_create("10.0.0.1")
    assert not revived.vfs.exists("/tmp/test.txt", "/")


async def test_shared_llm_cache_survives_reconnect() -> None:
    manager = SessionManager(max_sessions=8, ttl_seconds=3600)
    record = manager.get_or_create(IP_A)
    provider = MagicMock()
    provider.generate_response = AsyncMock(
        return_value=LLMSimulation(stdout="Architecture: x86_64")
    )

    first = Shell(record.vfs, llm_provider=provider, llm_cache=record.llm_cache)
    second_shell_session = manager.get_or_create(IP_A)
    second = Shell(
        second_shell_session.vfs,
        llm_provider=provider,
        llm_cache=second_shell_session.llm_cache,
    )
    first_out = await first.execute("systemctl status nginx")
    second_out = await second.execute("systemctl status nginx")
    assert first_out.output == second_out.output
    assert first_out.output == "Architecture: x86_64\n"
    provider.generate_response.assert_called_once()


async def test_periodic_sweep_clears_idle_session_and_pin() -> None:
    now = 10.0
    sessions = SessionManager(max_sessions=8, ttl_seconds=1, clock=lambda: now)
    auth = AuthManager(tarpit_seconds=0.0, ttl_seconds=1, clock=lambda: now)
    sessions.get_or_create("10.0.0.1")
    auth.get_or_pin_password("10.0.0.1")
    now = 20.0
    task = asyncio.create_task(_periodic_sweep(sessions, auth, interval=0.01))
    try:
        await asyncio.sleep(0.05)
        assert "10.0.0.1" not in sessions
        assert "10.0.0.1" not in auth
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_reconnect_retains_cwd_after_cd() -> None:
    manager = SessionManager(max_sessions=8, ttl_seconds=3600)
    first = manager.get_or_create(IP_A)
    shell = Shell(
        first.vfs,
        llm_provider=NullLLMProvider(),
        cwd=first.cwd,
        ip_session=first,
    )
    result = await shell.execute("cd /tmp")
    assert result.exit_code == 0
    assert first.cwd == "/tmp"

    second = manager.get_or_create(IP_A)
    assert second is first
    assert second.cwd == "/tmp"
    reconnect = Shell(
        second.vfs,
        llm_provider=NullLLMProvider(),
        cwd=second.cwd,
        ip_session=second,
    )
    assert reconnect.state.cwd == "/tmp"
    pwd = await reconnect.execute("pwd")
    assert pwd.output == "/tmp"


def test_command_requested_accepts_noninteractive_exec() -> None:
    server = HoneypotServer(AuthManager(), SessionManager())
    assert server.command_requested("id") is True
    assert server.command_requested("cat /etc/passwd") is True


class _FakeStdout:
    def __init__(self) -> None:
        self.chunks: list[str] = []

    def write(self, data: str) -> None:
        self.chunks.append(data)

    @property
    def text(self) -> str:
        return "".join(self.chunks)


class _FakeProcess:
    def __init__(self, command: str | None) -> None:
        self.command = command
        self.stdout = _FakeStdout()
        self.stdin = MagicMock()
        self.stdin.readline = AsyncMock(return_value="")
        self.channel = MagicMock()
        self.channel.get_connection.side_effect = AttributeError
        self.exit_code: int | None = None
        self.closed = False

    def exit(self, code: int) -> None:
        self.exit_code = code

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, _name: str, default: object = None) -> object:
        return default


async def test_noninteractive_exec_runs_without_banner_or_prompt() -> None:
    manager = SessionManager(max_sessions=8, ttl_seconds=3600)
    process = _FakeProcess('echo unwrapped')
    await handle_client(process, NullLLMProvider(), manager)
    assert BANNER not in process.stdout.text
    assert "root@ubuntu-srv" not in process.stdout.text
    assert process.stdout.text == "unwrapped\r\n"
    assert process.exit_code == 0
    assert process.closed is True
    process.stdin.readline.assert_not_called()


async def test_noninteractive_exec_output_ends_with_newline() -> None:
    manager = SessionManager(max_sessions=8, ttl_seconds=3600)
    process = _FakeProcess("pwd")
    await handle_client(process, NullLLMProvider(), manager)
    assert process.stdout.text == "/root\r\n"
    assert process.stdout.text.endswith("\r\n")
    assert process.exit_code == 0
