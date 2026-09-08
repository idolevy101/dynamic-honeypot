import asyncio
import contextlib
from collections.abc import Callable
from functools import partial
from pathlib import Path

import asyncssh
from dotenv import load_dotenv

from auth import AuthAttemptLimitExceeded, AuthManager
from llm import LLMProvider, create_llm_provider
from session_manager import SessionManager
from shell import Shell

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
        self._client_ip = _peer_ip(conn)
        self._session_id = self._auth.create_session(self._client_ip)
        conn.set_extra_info(
            honeypot_session_id=self._session_id,
            honeypot_client_ip=self._client_ip,
        )

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

    async def validate_password(self, username: str, password: str) -> bool:
        if self._session_id is None or self._client_ip is None:
            return False
        try:
            return await self._auth.validate_login(
                self._client_ip,
                self._session_id,
                username,
                password,
            )
        except AuthAttemptLimitExceeded:
            self._disconnect_auth_limit()
            return False
        except asyncio.CancelledError:
            raise
        except _DISCONNECT_ERRORS:
            return False

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


async def ensure_host_key(path: Path) -> None:
    if path.exists():
        return
    key = asyncssh.generate_private_key("ssh-rsa")
    await asyncio.to_thread(key.write_private_key, path)


def _stdout_crlf(text: str) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return ""
    return "".join(f"{line}\r\n" for line in lines)


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
    )
    try:
        process.stdout.write(f"{BANNER}\r\n")
        while True:
            process.stdout.write(shell.prompt())
            line = await process.stdin.readline()
            if not line:
                break
            result = await shell.execute(line.rstrip("\r\n"))
            if result.output:
                process.stdout.write(_stdout_crlf(result.output))
            if result.exit_session:
                break
    except asyncio.CancelledError:
        raise
    except _DISCONNECT_ERRORS:
        pass
    finally:
        session_manager.touch(client_ip)
        try:
            process.exit(0)
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
        await asyncssh.create_server(
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
