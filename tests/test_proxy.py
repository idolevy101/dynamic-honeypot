from __future__ import annotations

import asyncio
import os
import signal
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROXY_BIN = ROOT / "proxy" / "build" / "honeypot_proxy"
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"


@pytest.fixture(scope="session")
def proxy_bin() -> Path:
    if not PROXY_BIN.is_file():
        pytest.skip("honeypot_proxy not built; run cmake -B proxy/build -S proxy")
    return PROXY_BIN


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


@asynccontextmanager
async def _echo_server() -> AsyncIterator[int]:
    server = await asyncio.start_server(_echo_handler, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


async def _start_proxy(
    proxy_bin: Path,
    listen_port: int,
    backend_port: int,
    extra_args: list[str] | None = None,
    *,
    send_proxy_protocol: bool = False,
) -> asyncio.subprocess.Process:
    cmd = [
        str(proxy_bin),
        "-l",
        str(listen_port),
        "-b",
        str(backend_port),
        "-h",
        "127.0.0.1",
        "--send-proxy-protocol" if send_proxy_protocol else "--no-send-proxy-protocol",
    ]
    if extra_args:
        cmd.extend(extra_args)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdout is not None
    try:
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
            if not line:
                stderr = b""
                if proc.stderr is not None:
                    stderr = await proc.stderr.read()
                raise RuntimeError(f"proxy exited before ready: {stderr!r}")
            if b"running" in line:
                return proc
    except Exception:
        if proc.returncode is None:
            proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        raise


async def _stop_proxy(proc: asyncio.subprocess.Process) -> int:
    if proc.returncode is not None:
        return int(proc.returncode)
    proc.send_signal(signal.SIGTERM)
    try:
        return int(await asyncio.wait_for(proc.wait(), timeout=5.0))
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise AssertionError("proxy did not exit after SIGTERM") from None


async def test_proxy_help(proxy_bin: Path) -> None:
    proc = await asyncio.create_subprocess_exec(
        str(proxy_bin),
        "--help",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
    assert proc.returncode == 0
    assert b"Usage: honeypot_proxy" in stdout
    assert b"--max-connections" in stdout
    assert b"--max-per-ip" in stdout
    assert b"--rate-limit" in stdout
    assert b"--rate-burst" in stdout
    assert b"--send-proxy-protocol" in stdout
    assert b"--no-send-proxy-protocol" in stdout
    assert stderr == b""


async def test_proxy_echo_ssh_bytes_and_teardown(proxy_bin: Path) -> None:
    payload = SSH_BANNER + bytes(range(256)) + os.urandom(2048)
    async with _echo_server() as backend_port:
        listen_port = _free_port()
        proc = await _start_proxy(proxy_bin, listen_port, backend_port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", listen_port),
                timeout=5.0,
            )
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=5.0)
            assert echoed == payload
            trailing = await asyncio.wait_for(reader.read(), timeout=5.0)
            assert trailing == b""
            writer.close()
            await writer.wait_closed()
        finally:
            rc = await _stop_proxy(proc)
        assert rc == 0


async def test_proxy_backpressure_large_payload(proxy_bin: Path) -> None:
    payload = os.urandom(128 * 1024)
    async with _echo_server() as backend_port:
        listen_port = _free_port()
        proc = await _start_proxy(proxy_bin, listen_port, backend_port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", listen_port),
                timeout=5.0,
            )
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=10.0)
            assert echoed == payload
            writer.close()
            await writer.wait_closed()
        finally:
            rc = await _stop_proxy(proc)
        assert rc == 0


async def test_proxy_sigterm_exits_clean(proxy_bin: Path) -> None:
    async with _echo_server() as backend_port:
        listen_port = _free_port()
        proc = await _start_proxy(proxy_bin, listen_port, backend_port)
        rc = await _stop_proxy(proc)
        assert rc == 0


@asynccontextmanager
async def _limited_proxy(
    proxy_bin: Path,
    extra_args: list[str],
) -> AsyncIterator[int]:
    async with _echo_server() as backend_port:
        listen_port = _free_port()
        proc = await _start_proxy(proxy_bin, listen_port, backend_port, extra_args)
        try:
            yield listen_port
        finally:
            rc = await _stop_proxy(proc)
            assert rc == 0


async def _open_clients(
    port: int,
    count: int,
) -> list[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    async def _one() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=2.0,
        )

    return list(await asyncio.gather(*[_one() for _ in range(count)]))


async def _close_conn(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


async def _close_clients(
    clients: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
) -> None:
    for _reader, writer in clients:
        await _close_conn(writer)


async def _probe_echo(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    payload: bytes = b"ping",
) -> bool:
    try:
        writer.write(payload)
        await writer.drain()
        got = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=1.0)
        return got == payload
    except (
        BrokenPipeError,
        ConnectionResetError,
        TimeoutError,
        asyncio.IncompleteReadError,
        OSError,
    ):
        return False


async def _partition_echo(
    clients: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
) -> tuple[
    list[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
    list[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]:
    live: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    dead: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    for reader, writer in clients:
        if await _probe_echo(reader, writer):
            live.append((reader, writer))
        else:
            dead.append((reader, writer))
    return live, dead


async def test_proxy_global_concurrency_limit(proxy_bin: Path) -> None:
    extra = [
        "--max-connections",
        "3",
        "--max-per-ip",
        "50",
        "--rate-limit",
        "1000",
        "--rate-burst",
        "1000",
    ]
    async with _limited_proxy(proxy_bin, extra) as listen_port:
        clients = await _open_clients(listen_port, 8)
        try:
            await asyncio.sleep(0.15)
            live, dead = await _partition_echo(clients)
            assert len(live) == 3
            assert len(dead) == 5
            for reader, writer in live:
                assert await _probe_echo(reader, writer, b"keep")
        finally:
            await _close_clients(clients)


async def test_proxy_per_ip_concurrency_limit(proxy_bin: Path) -> None:
    extra = [
        "--max-connections",
        "100",
        "--max-per-ip",
        "2",
        "--rate-limit",
        "1000",
        "--rate-burst",
        "1000",
    ]
    async with _limited_proxy(proxy_bin, extra) as listen_port:
        clients = await _open_clients(listen_port, 6)
        try:
            await asyncio.sleep(0.15)
            live, dead = await _partition_echo(clients)
            assert len(live) == 2
            assert len(dead) == 4
            for reader, writer in live:
                assert await _probe_echo(reader, writer, b"keep")
        finally:
            await _close_clients(clients)


async def test_proxy_rate_limiter_burst(proxy_bin: Path) -> None:
    extra = [
        "--max-connections",
        "100",
        "--max-per-ip",
        "100",
        "--rate-limit",
        "1",
        "--rate-burst",
        "3",
    ]
    async with _limited_proxy(proxy_bin, extra) as listen_port:
        clients = await _open_clients(listen_port, 12)
        try:
            await asyncio.sleep(0.15)
            live, dead = await _partition_echo(clients)
            assert len(live) == 3
            assert len(dead) == 9
        finally:
            await _close_clients(clients)


async def test_proxy_counters_decrement_on_close(proxy_bin: Path) -> None:
    extra = [
        "--max-connections",
        "2",
        "--max-per-ip",
        "2",
        "--rate-limit",
        "1000",
        "--rate-burst",
        "1000",
    ]
    async with _limited_proxy(proxy_bin, extra) as listen_port:
        held = await _open_clients(listen_port, 2)
        try:
            await asyncio.sleep(0.15)
            live, dead = await _partition_echo(held)
            assert len(live) == 2
            assert dead == []

            overflow = await _open_clients(listen_port, 1)
            try:
                await asyncio.sleep(0.15)
                overflow_live, overflow_dead = await _partition_echo(overflow)
                assert overflow_live == []
                assert len(overflow_dead) == 1
            finally:
                await _close_clients(overflow)

            await _close_clients(held)
            held = []
            await asyncio.sleep(0.25)

            reused = await _open_clients(listen_port, 1)
            try:
                await asyncio.sleep(0.15)
                live, dead = await _partition_echo(reused)
                assert len(live) == 1
                assert dead == []
            finally:
                await _close_clients(reused)
        finally:
            await _close_clients(held)


def test_parse_proxy_v1_line() -> None:
    from server import parse_proxy_v1_line

    assert parse_proxy_v1_line(b"PROXY TCP4 198.51.100.10 127.0.0.1 54321 2222") == (
        "198.51.100.10",
        54321,
    )
    assert parse_proxy_v1_line(b"PROXY TCP6 ::1 ::1 1234 2222") == ("::1", 1234)
    assert parse_proxy_v1_line(b"PROXY UNKNOWN") is None
    assert parse_proxy_v1_line(b"SSH-2.0-OpenSSH") is None


async def test_read_optional_proxy_fallback_without_header() -> None:
    from server import read_optional_proxy

    reader = asyncio.StreamReader()
    reader.feed_data(SSH_BANNER)
    reader.feed_eof()
    info = await read_optional_proxy(reader, "203.0.113.9")
    assert info.proxied is False
    assert info.client_ip == "203.0.113.9"
    assert info.leftover.startswith(b"SSH-2.0")
    assert info.client_port is None


async def test_read_optional_proxy_strips_header_and_keeps_ssh_bytes() -> None:
    from server import read_optional_proxy

    reader = asyncio.StreamReader()
    reader.feed_data(
        b"PROXY TCP4 198.51.100.10 127.0.0.1 54321 2222\r\n" + SSH_BANNER
    )
    reader.feed_eof()
    info = await read_optional_proxy(reader, "127.0.0.1")
    assert info.proxied is True
    assert info.client_ip == "198.51.100.10"
    assert info.client_port == 54321
    assert info.leftover == SSH_BANNER


async def test_honeypot_server_uses_proxy_protocol_client_ip() -> None:
    from unittest.mock import MagicMock

    from auth import AuthManager
    from server import HoneypotServer, _PROXY_CLIENT_IP
    from session_manager import SessionManager

    server = HoneypotServer(AuthManager(tarpit_seconds=0.0), SessionManager())
    conn = MagicMock()
    conn.get_extra_info.return_value = ("127.0.0.1", 40000)
    token = _PROXY_CLIENT_IP.set("198.51.100.7")
    try:
        server.connection_made(conn)
    finally:
        _PROXY_CLIENT_IP.reset(token)
    conn.set_extra_info.assert_called()
    kwargs = conn.set_extra_info.call_args.kwargs
    assert kwargs["honeypot_client_ip"] == "198.51.100.7"


async def test_proxy_protocol_forwards_real_client_ip(proxy_bin: Path) -> None:
    from server import read_optional_proxy

    captured: list[tuple[str, bytes, bool, int | None, object]] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        fallback = str(peer[0]) if isinstance(peer, tuple) and peer else "unknown"
        try:
            info = await read_optional_proxy(reader, fallback)
            rest = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            captured.append(
                (info.client_ip, info.leftover + rest, info.proxied, info.client_port, peer)
            )
        except TimeoutError:
            captured.append((fallback, b"", False, None, peer))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    backend_port = int(server.sockets[0].getsockname()[1])
    listen_port = _free_port()
    proc = await _start_proxy(
        proxy_bin,
        listen_port,
        backend_port,
        send_proxy_protocol=True,
    )
    sockname: object = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", listen_port),
            timeout=5.0,
        )
        sockname = writer.get_extra_info("sockname")
        writer.write(SSH_BANNER)
        await writer.drain()
        await asyncio.sleep(0.25)
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
    finally:
        rc = await _stop_proxy(proc)
        server.close()
        await server.wait_closed()
    assert rc == 0
    assert captured
    client_ip, payload, proxied, client_port, peer = captured[0]
    assert proxied is True
    assert client_ip == "127.0.0.1"
    assert isinstance(sockname, tuple)
    assert client_port == int(sockname[1])
    assert isinstance(peer, tuple)
    assert client_port != int(peer[1])
    assert not payload.startswith(b"PROXY ")
    assert payload.startswith(SSH_BANNER)


async def test_ssh_backend_records_proxy_protocol_ip() -> None:
    from functools import partial

    import asyncssh

    from auth import AuthManager
    from llm import NullLLMProvider
    from server import (
        HOST_KEY_PATH,
        ensure_host_key,
        handle_client,
        make_server_factory,
        start_ssh_backend,
    )
    from session_manager import SessionManager

    await ensure_host_key(HOST_KEY_PATH)
    auth = AuthManager(passwords=("secret",), tarpit_seconds=0.0)
    sessions = SessionManager()
    server = await start_ssh_backend(
        make_server_factory(auth, sessions),
        "127.0.0.1",
        0,
        server_host_keys=[str(HOST_KEY_PATH)],
        process_factory=partial(
            handle_client,
            llm_provider=NullLLMProvider(),
            session_manager=sessions,
        ),
    )
    port = int(server.sockets[0].getsockname()[1])
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        sock.sendall(b"PROXY TCP4 198.51.100.10 127.0.0.1 54321 2222\r\n")
        async with asyncssh.connect(
            sock=sock,
            username="root",
            password="secret",
            known_hosts=None,
        ) as conn:
            result = await conn.run("echo hi", check=False)
            assert "unwrapped" in result.stdout or "hi" in result.stdout or result.exit_status == 0
        assert "198.51.100.10" in sessions
        assert "127.0.0.1" not in sessions
        sock = None
    finally:
        if sock is not None:
            sock.close()
        server.close()
        await server.wait_closed()


async def test_ssh_backend_falls_back_to_socket_peer() -> None:
    from functools import partial

    import asyncssh

    from auth import AuthManager
    from llm import NullLLMProvider
    from server import (
        HOST_KEY_PATH,
        ensure_host_key,
        handle_client,
        make_server_factory,
        start_ssh_backend,
    )
    from session_manager import SessionManager

    await ensure_host_key(HOST_KEY_PATH)
    auth = AuthManager(passwords=("secret",), tarpit_seconds=0.0)
    sessions = SessionManager()
    server = await start_ssh_backend(
        make_server_factory(auth, sessions),
        "127.0.0.1",
        0,
        server_host_keys=[str(HOST_KEY_PATH)],
        process_factory=partial(
            handle_client,
            llm_provider=NullLLMProvider(),
            session_manager=sessions,
        ),
    )
    port = int(server.sockets[0].getsockname()[1])
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port,
            username="root",
            password="secret",
            known_hosts=None,
        ) as conn:
            result = await conn.run("echo hi", check=False)
            assert result.exit_status == 0
        assert "127.0.0.1" in sessions
        assert "198.51.100.10" not in sessions
    finally:
        server.close()
        await server.wait_closed()
