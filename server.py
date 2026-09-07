import asyncio
from collections.abc import Callable
from functools import partial
from pathlib import Path

import asyncssh
from dotenv import load_dotenv

from auth import AuthAttemptLimitExceeded, AuthManager
from llm import LLMProvider, create_llm_provider
from shell import Shell
from vfs import VirtualFileSystem

HOST = "127.0.0.1"
PORT = 2222
HOST_KEY_PATH = Path("./ssh_host_key")
BANNER = "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-generic x86_64)"

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


def _peer_ip(conn: asyncssh.SSHServerConnection) -> str:
    peer = conn.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    if isinstance(peer, str) and peer:
        return peer
    return "unknown"


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self, auth_manager: AuthManager) -> None:
        self._auth = auth_manager
        self._conn: asyncssh.SSHServerConnection | None = None
        self._client_ip: str | None = None
        self._session_id: str | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        self._client_ip = _peer_ip(conn)
        self._session_id = self._auth.create_session(self._client_ip)

    def connection_lost(self, exc: Exception | None) -> None:
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


def make_server_factory(auth_manager: AuthManager) -> Callable[[], HoneypotServer]:
    def factory() -> HoneypotServer:
        return HoneypotServer(auth_manager)

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
) -> None:
    shell = Shell(VirtualFileSystem(), llm_provider=llm_provider)
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
        try:
            process.exit(0)
            process.close()
            await process.wait_closed()
        except _DISCONNECT_ERRORS:
            pass


async def main() -> None:
    load_dotenv()
    await ensure_host_key(HOST_KEY_PATH)
    auth_manager = AuthManager()
    llm_provider = create_llm_provider()
    await asyncssh.create_server(
        make_server_factory(auth_manager),
        HOST,
        PORT,
        server_host_keys=[str(HOST_KEY_PATH)],
        process_factory=partial(handle_client, llm_provider=llm_provider),
    )
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
