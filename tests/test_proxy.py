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


async def _start_proxy(proxy_bin: Path, listen_port: int, backend_port: int) -> asyncio.subprocess.Process:
    proc = await asyncio.create_subprocess_exec(
        str(proxy_bin),
        "-l",
        str(listen_port),
        "-b",
        str(backend_port),
        "-h",
        "127.0.0.1",
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
