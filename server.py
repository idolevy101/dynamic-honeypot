import asyncio
import contextlib
import logging
from collections.abc import Callable
from contextvars import ContextVar
from functools import partial
from pathlib import Path
from typing import NamedTuple, cast

import asyncssh
from dotenv import load_dotenv

from auth import AuthAttemptLimitExceeded, AuthManager
from llm import LLMProvider, create_llm_provider
from session_manager import SessionManager
from shell import Shell

_LOGGER = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 2222
HOST_KEY_PATH = Path("./ssh_host_key")
BANNER = "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)"
SWEEP_INTERVAL_SECONDS = 60.0

_DISCONNECT_ERRORS = (
    asyncio.IncompleteReadError,
    BrokenPipeError,
    ConnectionError,
    EOFError,
    OSError,
    asyncssh.BreakReceived,
    asyncssh.ConnectionLost,
    asyncssh.DisconnectError,
)

_PROXY_PREFIX = b"PROXY "
_PROXY_MAX_LINE = 107
_PROXY_CLIENT_IP: ContextVar[str | None] = ContextVar("honeypot_proxy_client_ip", default=None)


class ProxyClientInfo(NamedTuple):
    client_ip: str
    leftover: bytes
    proxied: bool
    client_port: int | None = None


def parse_proxy_v1_line(line: bytes) -> tuple[str, int] | None:
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(" ")
    if len(parts) < 2 or parts[0] != "PROXY":
        return None
    family = parts[1]
    if family == "UNKNOWN":
        return None
    if family not in {"TCP4", "TCP6"} or len(parts) < 6:
        return None
    client_ip = parts[2]
    if not client_ip:
        return None
    try:
        client_port = int(parts[4])
    except ValueError:
        return None
    if client_port < 0 or client_port > 65535:
        return None
    return client_ip, client_port


async def read_optional_proxy(
    reader: asyncio.StreamReader,
    fallback_ip: str,
) -> ProxyClientInfo:
    buf = await reader.read(_PROXY_MAX_LINE)
    if not buf:
        return ProxyClientInfo(fallback_ip, b"", False)
    if not buf.startswith(_PROXY_PREFIX):
        return ProxyClientInfo(fallback_ip, buf, False)
    while b"\r\n" not in buf and len(buf) < _PROXY_MAX_LINE:
        chunk = await reader.read(_PROXY_MAX_LINE - len(buf))
        if not chunk:
            break
        buf += chunk
    idx = buf.find(b"\r\n")
    if idx == -1:
        return ProxyClientInfo(fallback_ip, buf, False)
    parsed = parse_proxy_v1_line(buf[:idx])
    leftover = buf[idx + 2 :]
    if parsed is None:
        return ProxyClientInfo(fallback_ip, leftover, True)
    return ProxyClientInfo(parsed[0], leftover, True, parsed[1])


def _peer_ip(source: object) -> str:
    getter = getattr(source, "get_extra_info", None)
    peer = getter("peername") if callable(getter) else None
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    if isinstance(peer, str) and peer:
        return peer
    return "unknown"


def _session_meta(process: asyncssh.SSHServerProcess[str]) -> tuple[str, str]:
    try:
        conn = process.channel.get_connection()
    except (AssertionError, AttributeError, OSError):
        return "local", _peer_ip(process)
    session_id = conn.get_extra_info("honeypot_session_id", "local")
    client_ip = conn.get_extra_info("honeypot_client_ip", None)
    if not isinstance(session_id, str) or not session_id:
        session_id = "local"
    if not isinstance(client_ip, str) or not client_ip:
        client_ip = _peer_ip(process)
    return session_id, client_ip


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self, auth_manager: AuthManager, session_manager: SessionManager) -> None:
        self._auth = auth_manager
        self._sessions = session_manager
        self._conn: asyncssh.SSHServerConnection | None = None
        self._client_ip: str | None = None
        self._session_id: str | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        pending = _PROXY_CLIENT_IP.get()
        if isinstance(pending, str) and pending:
            self._client_ip = pending
        else:
            self._client_ip = _peer_ip(conn)
        self._session_id = self._auth.create_session(self._client_ip)
        conn.set_extra_info(
            honeypot_session_id=self._session_id,
            honeypot_client_ip=self._client_ip,
        )
        _LOGGER.info("session %s client_ip=%s", self._session_id, self._client_ip)

    def connection_lost(self, exc: Exception | None) -> None:
        _ = exc
        ip = self._client_ip
        if ip is not None:
            self._sessions.touch(ip)
        self._conn = None
        self._client_ip = None
        if self._session_id is None:
            return
        self._auth.release_session(self._session_id)
        self._session_id = None

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return False

    def command_requested(self, command: str) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        if self._session_id is None or self._client_ip is None:
            return False
        try:
            accepted = await self._auth.validate_login(
                self._client_ip,
                self._session_id,
                username,
                password,
            )
        except AuthAttemptLimitExceeded:
            accepted = False
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("password authentication callback failed")
            return False
        if (
            not accepted
            and self._client_ip is not None
            and self._auth.is_locked_out(self._client_ip)
        ):
            # Disconnect after this callback returns so AsyncSSH can send
            # USERAUTH_FAILURE instead of aborting the TCP session mid-auth.
            asyncio.get_running_loop().call_soon(self._disconnect_auth_limit)
        return accepted

    def _disconnect_auth_limit(self) -> None:
        conn = self._conn
        if conn is None:
            return
        try:
            conn.disconnect(
                asyncssh.DISC_BY_APPLICATION,
                "Too many authentication failures",
            )
        except _DISCONNECT_ERRORS:
            pass


def make_server_factory(
    auth_manager: AuthManager,
    session_manager: SessionManager,
) -> Callable[[], HoneypotServer]:
    def factory() -> HoneypotServer:
        return HoneypotServer(auth_manager, session_manager)

    return factory


class _ProxyPreambleProtocol(asyncio.Protocol):
    def __init__(self, ssh_factory: Callable[[], asyncssh.SSHServerConnection]) -> None:
        self._ssh_factory = ssh_factory
        self._transport: asyncio.Transport | None = None
        self._buf = bytearray()
        self._fallback_ip = "unknown"
        self._handed_off = False
        self._inner: asyncssh.SSHServerConnection | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)
        peer = transport.get_extra_info("peername")
        if isinstance(peer, tuple) and peer:
            self._fallback_ip = str(peer[0])

    def data_received(self, data: bytes) -> None:
        if self._handed_off:
            if self._inner is not None:
                self._inner.data_received(data)
            return
        self._buf.extend(data)
        self._try_handoff()

    def eof_received(self) -> bool:
        if not self._handed_off:
            if self._buf:
                self._try_handoff(force=True)
            elif self._transport is not None:
                self._complete(self._fallback_ip, b"")
        if self._inner is not None:
            return bool(self._inner.eof_received())
        return False

    def connection_lost(self, exc: Exception | None) -> None:
        if self._inner is not None:
            self._inner.connection_lost(exc)

    def pause_writing(self) -> None:
        if self._inner is not None:
            self._inner.pause_writing()

    def resume_writing(self) -> None:
        if self._inner is not None:
            self._inner.resume_writing()

    def _try_handoff(self, *, force: bool = False) -> None:
        if self._handed_off:
            return
        buf = bytes(self._buf)
        if not buf:
            return
        if not buf.startswith(b"P"):
            self._complete(self._fallback_ip, buf)
            return
        if len(buf) < len(_PROXY_PREFIX):
            if force:
                self._complete(self._fallback_ip, buf)
            return
        if not buf.startswith(_PROXY_PREFIX):
            self._complete(self._fallback_ip, buf)
            return
        idx = buf.find(b"\r\n")
        if idx == -1:
            if force or len(buf) >= _PROXY_MAX_LINE:
                self._complete(self._fallback_ip, buf)
            return
        parsed = parse_proxy_v1_line(buf[:idx])
        leftover = buf[idx + 2 :]
        client_ip = parsed[0] if parsed is not None else self._fallback_ip
        self._complete(client_ip, leftover)

    def _complete(self, client_ip: str, leftover: bytes) -> None:
        if self._handed_off or self._transport is None:
            return
        self._handed_off = True
        self._buf.clear()
        ssh = self._ssh_factory()
        token = _PROXY_CLIENT_IP.set(client_ip)
        try:
            self._transport.set_protocol(ssh)
            ssh.connection_made(self._transport)
            self._inner = ssh
            if leftover:
                ssh.data_received(leftover)
        finally:
            _PROXY_CLIENT_IP.reset(token)


async def start_ssh_backend(
    server_factory: Callable[[], HoneypotServer],
    host: str,
    port: int,
    *,
    server_host_keys: list[str],
    process_factory: Callable[..., object],
) -> asyncio.AbstractServer:
    loop = asyncio.get_running_loop()
    options = await asyncssh.SSHServerConnectionOptions.construct(
        None,
        server_factory=server_factory,
        server_host_keys=server_host_keys,
        process_factory=process_factory,
        host=host,
        port=port,
    )

    def ssh_factory() -> asyncssh.SSHServerConnection:
        return asyncssh.SSHServerConnection(loop, options)

    def protocol_factory() -> _ProxyPreambleProtocol:
        return _ProxyPreambleProtocol(ssh_factory)

    return await loop.create_server(protocol_factory, host, port)


async def ensure_host_key(path: Path) -> None:
    if path.exists():
        return
    key = asyncssh.generate_private_key("ssh-rsa")
    await asyncio.to_thread(key.write_private_key, path)


def normalize_crlf(text: str) -> str:
    """Convert all line endings to explicit ``\\r\\n`` without adding a new terminator."""
    if not text:
        return ""
    unix = text.replace("\r\n", "\n").replace("\r", "\n")
    trailing = unix.endswith("\n")
    body = unix[:-1] if trailing else unix
    converted = body.replace("\n", "\r\n")
    return f"{converted}\r\n" if trailing else converted


def _channel_write(stream: object, text: str, *, complete: bool = False) -> None:
    writer = getattr(stream, "write", None)
    if not callable(writer) or not text:
        return
    payload = text
    if complete and not payload.endswith("\n"):
        payload += "\n"
    writer(normalize_crlf(payload))


async def handle_client(
    process: asyncssh.SSHServerProcess[str],
    llm_provider: LLMProvider,
    session_manager: SessionManager,
) -> None:
    session_id, client_ip = _session_meta(process)
    record = session_manager.get_or_create(client_ip)
    shell = Shell(
        record.vfs,
        llm_provider=llm_provider,
        llm_cache=record.llm_cache,
        session_id=session_id,
        client_ip=client_ip,
        cwd=record.cwd,
        ip_session=record,
    )
    exit_code = 0
    try:
        command = process.command
        if command:
            result = await shell.execute(command)
            if result.output:
                _channel_write(process.stdout, result.output, complete=True)
            exit_code = result.exit_code
        else:
            _channel_write(process.stdout, BANNER, complete=True)
            while True:
                _channel_write(process.stdout, shell.prompt(), complete=False)
                line = await process.stdin.readline()
                if not line:
                    break
                result = await shell.execute(line.rstrip("\r\n"))
                if result.output:
                    _channel_write(process.stdout, result.output, complete=True)
                if result.exit_session:
                    break
    except asyncio.CancelledError:
        raise
    except _DISCONNECT_ERRORS:
        pass
    finally:
        record.cwd = shell.state.cwd
        session_manager.touch(client_ip)
        try:
            process.exit(exit_code)
            process.close()
            await process.wait_closed()
        except _DISCONNECT_ERRORS:
            pass


async def _periodic_sweep(
    session_manager: SessionManager,
    auth_manager: AuthManager,
    interval: float = SWEEP_INTERVAL_SECONDS,
) -> None:
    """Idle TTL cleanup that does not depend on incoming connections."""
    while True:
        await asyncio.sleep(interval)
        session_manager.sweep()
        auth_manager.sweep()


async def main() -> None:
    load_dotenv()
    await ensure_host_key(HOST_KEY_PATH)
    auth_manager = AuthManager()
    session_manager = SessionManager()
    llm_provider = create_llm_provider()
    sweeper = asyncio.create_task(
        _periodic_sweep(session_manager, auth_manager),
        name="honeypot-session-sweep",
    )
    try:
        await start_ssh_backend(
            make_server_factory(auth_manager, session_manager),
            HOST,
            PORT,
            server_host_keys=[str(HOST_KEY_PATH)],
            process_factory=partial(
                handle_client,
                llm_provider=llm_provider,
                session_manager=session_manager,
            ),
        )
        await asyncio.Future()
    finally:
        sweeper.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sweeper


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
