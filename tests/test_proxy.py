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
) -> asyncio.subprocess.Process:
    cmd = [
        str(proxy_bin),
        "-l",
        str(listen_port),
        "-b",
        str(backend_port),
        "-h",
        "127.0.0.1",
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

