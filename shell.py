"""Command dispatcher for the honeypot shell.

Parses input with ``shlex`` and executes against :class:`vfs.VirtualFileSystem`.
Host OS execution is never used.
"""

from __future__ import annotations

import hashlib
import shlex
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Sequence
from urllib.parse import urlparse

from llm import LLMProvider, NullLLMProvider
from sinkhole import filename_from_url, mocked_payload, quarantine_artifact
from telemetry import record_command
from vfs import (
    DEFAULT_HOME,
    HOSTNAME,
    INode,
    VFSDirectory,
    VirtualFileSystem,
    canonicalize,
    parent_path,
)

_LS_SIX_MONTHS = timedelta(days=183)

_PS_AUX: Final[str] = """\
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.5 167848 11456 ?        Ss   Apr10   0:04 /sbin/init
root           2  0.0  0.0      0     0 ?        S    Apr10   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   Apr10   0:00 [rcu_gp]
root          90  0.0  0.3  47896  6912 ?        Ss   Apr10   0:00 /lib/systemd/systemd-journald
root         119  0.0  0.2  26204  5632 ?        Ss   Apr10   0:00 /lib/systemd/systemd-udevd
systemd+     176  0.0  0.2  16276  5120 ?        Ss   Apr10   0:00 /lib/systemd/systemd-networkd
systemd+     198  0.0  0.3  18012  6784 ?        Ss   Apr10   0:00 /lib/systemd/systemd-resolved
root         241  0.0  0.2  15432  4608 ?        Ss   Apr10   0:00 /usr/sbin/cron -f
message+     244  0.0  0.1   7568  3456 ?        Ss   Apr10   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         258  0.0  0.6  15488 12288 ?        Ss   Apr10   0:00 /usr/sbin/sshd -D
root         301  0.0  0.1   7372  2688 tty1     Ss+  Apr10   0:00 /sbin/agetty -o -p -- \\u --noclear tty1 linux
root         412  0.0  0.3  15408  6912 ?        Ss   01:48   0:00 sshd: root@pts/0
root         418  0.0  0.2   8752  4608 pts/0    Ss   01:48   0:00 -bash
root         441  0.0  0.1   9804  3584 pts/0    R+   01:49   0:00 ps aux
"""

_PS_EF: Final[str] = """\
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 Apr10 ?        00:00:04 /sbin/init
root           2       0  0 Apr10 ?        00:00:00 [kthreadd]
root           3       2  0 Apr10 ?        00:00:00 [rcu_gp]
root          90       1  0 Apr10 ?        00:00:00 /lib/systemd/systemd-journald
root         119       1  0 Apr10 ?        00:00:00 /lib/systemd/systemd-udevd
systemd+     176       1  0 Apr10 ?        00:00:00 /lib/systemd/systemd-networkd
systemd+     198       1  0 Apr10 ?        00:00:00 /lib/systemd/systemd-resolved
root         241       1  0 Apr10 ?        00:00:00 /usr/sbin/cron -f
message+     244       1  0 Apr10 ?        00:00:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         258       1  0 Apr10 ?        00:00:00 /usr/sbin/sshd -D
root         301       1  0 Apr10 ?        00:00:00 /sbin/agetty -o -p -- \\u --noclear tty1 linux
root         412     258  0 01:48 ?        00:00:00 sshd: root@pts/0
root         418     412  0 01:48 pts/0    00:00:00 -bash
root         441     418  0 01:49 pts/0    00:00:00 ps -ef
"""

_DF_H: Final[str] = """\
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           198M  1.1M  197M   1% /run
/dev/vda1        20G  3.2G   16G  17% /
tmpfs           990M     0  990M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/vda15      105M  6.1M   99M   6% /boot/efi
tmpfs           198M  4.0K  198M   1% /run/user/0
"""

_FREE_M: Final[str] = """\
               total        used        free      shared  buff/cache   available
Mem:            1967         248        1421           2         297        1572
Swap:              0           0           0
"""

_UPTIME: Final[str] = " 01:49:12 up 14 days,  3:22,  1 user,  load average: 0.00, 0.01, 0.00"

_STATIC_OUTPUTS: Final[dict[tuple[str, ...], str]] = {
    ("ps", "aux"): _PS_AUX.rstrip("\n"),
    ("ps", "-ef"): _PS_EF.rstrip("\n"),
    ("df", "-h"): _DF_H.rstrip("\n"),
    ("free", "-m"): _FREE_M.rstrip("\n"),
    ("uptime",): _UPTIME,
}

_UNCACHEABLE_LLM_COMMANDS: Final[frozenset[str]] = frozenset(
    {"date", "timedatectl", "hwclock"}
)


def _parse_redirection(tokens: Sequence[str]) -> tuple[list[str], str | None, bool]:
    command: list[str] = []
    redirect_path: str | None = None
    append = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in (">", ">>"):
            if index + 1 >= len(tokens):
                raise ValueError("bash: syntax error near unexpected token `newline'")
            redirect_path = tokens[index + 1]
            append = token == ">>"
            index += 2
            continue
        command.append(token)
        index += 1
    return command, redirect_path, append


@dataclass(frozen=True)
class _ChainSegment:
    command: str
    operator: str


def split_command_chain(line: str) -> list[_ChainSegment]:
    """Split ``;``, ``&&``, and ``||`` outside quotes. Pipes are left intact."""
    segments: list[_ChainSegment] = []
    buf: list[str] = []
    quote: str | None = None
    incoming = ""
    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if quote is None and char == "\\":
            buf.append(char)
            if index + 1 < length:
                buf.append(line[index + 1])
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            buf.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            buf.append(char)
            index += 1
            continue
        if char == ";":
            command = "".join(buf).strip()
            if command:
                segments.append(_ChainSegment(command, incoming))
                incoming = ";"
            buf = []
            index += 1
            continue
        if char == "&" and index + 1 < length and line[index + 1] == "&":
            command = "".join(buf).strip()
            if command:
                segments.append(_ChainSegment(command, incoming))
                incoming = "&&"
            buf = []
            index += 2
            continue
        if char == "|" and index + 1 < length and line[index + 1] == "|":
            command = "".join(buf).strip()
            if command:
                segments.append(_ChainSegment(command, incoming))
                incoming = "||"
            buf = []
            index += 2
            continue
        buf.append(char)
        index += 1
    command = "".join(buf).strip()
    if command:
        segments.append(_ChainSegment(command, incoming))
    return segments


@dataclass(frozen=True)
class _CurlArgs:
    url: str | None
    output_path: str | None
    remote_name: bool
    silent: bool


def _parse_wget_args(args: Sequence[str]) -> tuple[str | None, str | None]:
    output_path: str | None = None
    url: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-O", "--output-document"):
            if index + 1 < len(args):
                output_path = args[index + 1]
                index += 2
                continue
            index += 1
            continue
        if arg.startswith("--output-document="):
            output_path = arg.split("=", 1)[1]
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            index += 1
            continue
        if url is None:
            url = arg
        index += 1
    return url, output_path


def _parse_curl_args(args: Sequence[str]) -> _CurlArgs:
    output_path: str | None = None
    remote_name = False
    silent = False
    url: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-s", "--silent", "-sS"):
            silent = True
            index += 1
            continue
        if arg in ("-O", "--remote-name"):
            remote_name = True
            index += 1
            continue
        if arg in ("-o", "--output"):
            if index + 1 < len(args):
                output_path = args[index + 1]
                index += 2
                continue
            index += 1
            continue
        if arg.startswith("--output="):
            output_path = arg.split("=", 1)[1]
            index += 1
            continue
        if arg.startswith("-o") and arg != "-o":
            output_path = arg[2:]
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            flags = arg[1:]
            if "s" in flags:
                silent = True
            if "O" in flags:
                remote_name = True
            index += 1
            continue
        if url is None:
            url = arg
        index += 1
    return _CurlArgs(url=url, output_path=output_path, remote_name=remote_name, silent=silent)


def _fake_ipv4(host: str) -> str:
    digest = hashlib.sha256(host.encode("utf-8")).digest()
    return f"{1 + digest[0] % 223}.{digest[1]}.{digest[2]}.{1 + digest[3] % 254}"


def _wget_progress(url: str, filename: str, size: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    host = urlparse(url).hostname or url
    ip = _fake_ipv4(host)
    scheme = urlparse(url).scheme or "http"
    port = urlparse(url).port or (443 if scheme == "https" else 80)
    return (
        f"--{now}--  {url}\n"
        f"Resolving {host} ({host})... {ip}\n"
        f"Connecting to {host} ({host})|{ip}|:{port}... connected.\n"
        "HTTP request sent, awaiting response... 200 OK\n"
        f"Length: {size} [application/octet-stream]\n"
        f"Saving to: ‘{filename}’\n"
        "\n"
        f"{filename:<20} 100%[===================>] {size:>7}  --.-KB/s    in 0s\n"
        "\n"
        f"{now} (12.4 MB/s) - ‘{filename}’ saved [{size}/{size}]"
    )


def _curl_progress(size: int) -> str:
    speed = max(size, 1)
    return (
        "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
        "                                 Dload  Upload   Total   Spent    Left  Speed\n"
        f"100  {size:4d}  100  {size:4d}    0     0  {speed:5d}      0 --:--:-- --:--:-- --:--:-- {speed:5d}"
    )


def lookup_static_output(tokens: Sequence[str]) -> str | None:
    """Return a pre-LLM recon template, or None to fall through to the provider."""
    if not tokens:
        return None
    return _STATIC_OUTPUTS.get(tuple(tokens))


def _is_cacheable_llm_command(tokens: Sequence[str]) -> bool:
    return bool(tokens) and tokens[0] not in _UNCACHEABLE_LLM_COMMANDS


@dataclass
class SessionState:
    """Per-connection shell state. Default cwd matches an interactive root login."""

    cwd: str = DEFAULT_HOME
    oldpwd: str | None = None
    home: str = DEFAULT_HOME


@dataclass(frozen=True)
class CommandResult:
    output: str = ""
    exit_session: bool = False
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _fail(output: str, *, exit_code: int = 1) -> CommandResult:
    return CommandResult(output=output, exit_code=exit_code)


class Shell:
    """Tokenize and dispatch simulated bash commands against an in-memory VFS."""

    def __init__(
        self,
        vfs: VirtualFileSystem,
        state: SessionState | None = None,
        llm_provider: LLMProvider | None = None,
        llm_cache: dict[str, str] | None = None,
        *,
        session_id: str = "local",
        client_ip: str = "unknown",
    ) -> None:
        self._vfs = vfs
        self._state = state if state is not None else SessionState(home=vfs.home)
        self._llm_provider = llm_provider if llm_provider is not None else NullLLMProvider()
        self._llm_cache: dict[str, str] = llm_cache if llm_cache is not None else {}
        self._session_id = session_id
        self._client_ip = client_ip
        self._captured_artifacts: list[str] = []
        self._handlers = {
            "pwd": self._cmd_pwd,
            "cd": self._cmd_cd,
            "ls": self._cmd_ls,
            "cat": self._cmd_cat,
            "touch": self._cmd_touch,
            "echo": self._cmd_echo,
            "mkdir": self._cmd_mkdir,
            "rm": self._cmd_rm,
            "rmdir": self._cmd_rmdir,
            "wget": self._cmd_wget,
            "curl": self._cmd_curl,
            "exit": self._cmd_exit,
            "logout": self._cmd_exit,
        }

    @property
    def state(self) -> SessionState:
        return self._state

    def prompt(self) -> str:
        cwd = self._state.cwd
        shown = "~" if cwd == self._state.home else cwd
        return f"root@{HOSTNAME}:{shown}# "

    async def execute(self, line: str) -> CommandResult:
        stripped = line.strip()
        if not stripped:
            return CommandResult()
        segments = split_command_chain(stripped)
        if len(segments) <= 1:
            command = segments[0].command if segments else stripped
            return await self._execute_simple(command)
        return await self._execute_chain(segments)

    async def _execute_chain(self, segments: list[_ChainSegment]) -> CommandResult:
        outputs: list[str] = []
        last = CommandResult()
        last_ok = True
        for segment in segments:
            if segment.operator == "&&" and not last_ok:
                continue
            if segment.operator == "||" and last_ok:
                continue
            last = await self._execute_simple(segment.command)
            last_ok = last.ok
            if last.output:
                outputs.append(last.output)
            if last.exit_session:
                break
        return CommandResult(
            output="".join(outputs),
            exit_session=last.exit_session,
            exit_code=last.exit_code,
        )

    async def _execute_simple(self, line: str) -> CommandResult:
        stripped = line.strip()
        if not stripped:
            return CommandResult()
        started = time.perf_counter()
        self._captured_artifacts = []
        execution_path = "vfs"
        result = CommandResult()
        try:
            try:
                tokens = shlex.split(line, posix=True)
            except ValueError as exc:
                result = _fail(f"bash: {exc}", exit_code=2)
            else:
                if not tokens:
                    result = CommandResult()
                else:
                    try:
                        command_tokens, redirect_path, append = _parse_redirection(tokens)
                    except ValueError as exc:
                        result = _fail(str(exc), exit_code=2)
                    else:
                        if not command_tokens:
                            result = CommandResult()
                        else:
                            dispatch_line = (
                                stripped if redirect_path is None else " ".join(command_tokens)
                            )
                            result, execution_path = await self._dispatch(
                                command_tokens, dispatch_line
                            )
                            if redirect_path is not None:
                                result = self._apply_redirection(
                                    result, redirect_path, append
                                )
        finally:
            duration_ms = (time.perf_counter() - started) * 1000.0
            await record_command(
                session_id=self._session_id,
                client_ip=self._client_ip,
                command=stripped,
                execution_path=execution_path,
                duration_ms=duration_ms,
                captured_artifacts=self._captured_artifacts,
            )
        return result

    def _apply_redirection(
        self,
        result: CommandResult,
        redirect_path: str,
        append: bool,
    ) -> CommandResult:
        try:
            self._vfs.write_file(
                redirect_path, result.output, self._state.cwd, append=append
            )
        except FileNotFoundError:
            return _fail(f"bash: {redirect_path}: No such file or directory")
        except IsADirectoryError:
            return _fail(f"bash: {redirect_path}: Is a directory")
        except NotADirectoryError:
            return _fail(f"bash: {redirect_path}: Not a directory")
        name = redirect_path.rstrip("/").rsplit("/", 1)[-1] or redirect_path
        self._quarantine(name, result.output)
        return CommandResult(exit_session=result.exit_session, exit_code=result.exit_code)

    def _quarantine(
        self,
        filename: str,
        content: str,
        source_url: str = "",
    ) -> None:
        try:
            meta = quarantine_artifact(
                filename, content, self._client_ip, source_url
            )
        except OSError:
            return
        sha256 = meta.get("sha256")
        if isinstance(sha256, str) and sha256:
            self._captured_artifacts.append(sha256)

    async def _dispatch(
        self, tokens: list[str], stripped: str
    ) -> tuple[CommandResult, str]:
        command, *args = tokens
        handler = self._handlers.get(command)
        if handler is not None:
            path = "sinkhole" if command in {"wget", "curl"} else "vfs"
            return handler(args), path
        static = lookup_static_output(tokens)
        if static is not None:
            return CommandResult(static), "static"
        cacheable = _is_cacheable_llm_command(tokens)
        if cacheable and stripped in self._llm_cache:
            output = self._llm_cache[stripped]
            exit_code = 127 if "command not found" in output else 0
            return CommandResult(output, exit_code=exit_code), "cache"
        output = await self._llm_provider.generate_response(
            stripped,
            self._state.cwd,
            self._llm_context(),
        )
        if cacheable:
            self._llm_cache[stripped] = output
        exit_code = 127 if "command not found" in output else 0
        return CommandResult(output, exit_code=exit_code), "llm"

    def _llm_context(self) -> dict[str, Any]:
        try:
            listing = self._vfs.list_dir(".", self._state.cwd)
        except (FileNotFoundError, NotADirectoryError):
            listing = []
        return {
            "hostname": HOSTNAME,
            "user": "root",
            "listing": listing,
        }

    def _cmd_pwd(self, _args: list[str]) -> CommandResult:
        return CommandResult(self._state.cwd)

    def _cmd_cd(self, args: list[str]) -> CommandResult:
        if len(args) > 1:
            return _fail("bash: cd: too many arguments")
        if args and args[0] == "-":
            if self._state.oldpwd is None:
                return _fail("bash: cd: OLDPWD not set")
            raw = self._state.oldpwd
            target = self._state.oldpwd
            announce = True
        else:
            raw = args[0] if args else self._state.home
            target = canonicalize(raw, self._state.cwd, self._state.home)
            announce = False
        try:
            node = self._vfs.resolve(target, self._state.cwd)
        except FileNotFoundError:
            return _fail(f"bash: cd: {raw}: No such file or directory")
        except NotADirectoryError:
            return _fail(f"bash: cd: {raw}: Not a directory")
        if not isinstance(node, VFSDirectory):
            return _fail(f"bash: cd: {raw}: Not a directory")
        self._state.oldpwd = self._state.cwd
        self._state.cwd = target
        return CommandResult(target if announce else "")

    def _cmd_ls(self, args: list[str]) -> CommandResult:
        long_fmt = False
        show_all = False
        paths: list[str] = []
        for arg in args:
            if arg.startswith("-") and arg != "-":
                if "l" in arg[1:]:
                    long_fmt = True
                if "a" in arg[1:]:
                    show_all = True
                continue
            paths.append(arg)
        target = paths[0] if paths else "."
        display = target if paths else self._state.cwd
        try:
            node = self._vfs.resolve(target, self._state.cwd)
        except FileNotFoundError:
            shown = paths[0] if paths else target
            return _fail(f"ls: cannot access '{shown}': No such file or directory")
        except NotADirectoryError:
            shown = paths[0] if paths else target
            return _fail(f"ls: cannot access '{shown}': Not a directory")
        if isinstance(node, VFSDirectory):
            abs_path = canonicalize(target, self._state.cwd, self._state.home)
            return CommandResult(self._format_ls_dir(node, abs_path, long_fmt, show_all))
        return CommandResult(self._format_ls_file(node, display, long_fmt))

    def _cmd_cat(self, args: list[str]) -> CommandResult:
        if not args:
            return _fail(
                "cat: missing file operand\nTry 'cat --help' for more information."
            )
        chunks: list[str] = []
        failed = False
        for path in args:
            try:
                chunks.append(self._vfs.read_file(path, self._state.cwd))
            except FileNotFoundError:
                failed = True
                chunks.append(f"cat: {path}: No such file or directory\n")
            except IsADirectoryError:
                failed = True
                chunks.append(f"cat: {path}: Is a directory\n")
            except NotADirectoryError:
                failed = True
                chunks.append(f"cat: {path}: Not a directory\n")
        return CommandResult("".join(chunks), exit_code=1 if failed else 0)

    def _cmd_echo(self, args: list[str]) -> CommandResult:
        return CommandResult(" ".join(args) + "\n")

    def _cmd_mkdir(self, args: list[str]) -> CommandResult:
        parents = False
        paths: list[str] = []
        for arg in args:
            if arg.startswith("-") and arg != "-":
                if "p" in arg[1:]:
                    parents = True
                continue
            paths.append(arg)
        if not paths:
            return _fail(
                "mkdir: missing operand\nTry 'mkdir --help' for more information."
            )
        chunks: list[str] = []
        for path in paths:
            try:
                self._vfs.mkdir(path, self._state.cwd, parents=parents)
            except FileExistsError:
                chunks.append(f"mkdir: cannot create directory '{path}': File exists\n")
            except FileNotFoundError:
                chunks.append(
                    f"mkdir: cannot create directory '{path}': No such file or directory\n"
                )
            except NotADirectoryError:
                chunks.append(f"mkdir: cannot create directory '{path}': Not a directory\n")
        return CommandResult("".join(chunks), exit_code=1 if chunks else 0)

    def _cmd_rm(self, args: list[str]) -> CommandResult:
        recursive = False
        force = False
        paths: list[str] = []
        for arg in args:
            if arg.startswith("-") and arg != "-":
                flags = arg[1:]
                if "r" in flags or "R" in flags:
                    recursive = True
                if "f" in flags:
                    force = True
                continue
            paths.append(arg)
        if not paths:
            return _fail(
                "rm: missing operand\nTry 'rm --help' for more information."
            )
        chunks: list[str] = []
        for path in paths:
            try:
                if self._vfs.is_dir(path, self._state.cwd) and not recursive:
                    chunks.append(f"rm: cannot remove '{path}': Is a directory\n")
                    continue
                self._vfs.remove(path, self._state.cwd, recursive=recursive)
            except FileNotFoundError:
                if not force:
                    chunks.append(
                        f"rm: cannot remove '{path}': No such file or directory\n"
                    )
            except OSError:
                chunks.append(f"rm: cannot remove '{path}': Directory not empty\n")
            except NotADirectoryError:
                chunks.append(f"rm: cannot remove '{path}': Not a directory\n")
        return CommandResult("".join(chunks), exit_code=1 if chunks else 0)

    def _cmd_rmdir(self, args: list[str]) -> CommandResult:
        paths: list[str] = []
        for arg in args:
            if arg.startswith("-") and arg != "-":
                continue
            paths.append(arg)
        if not paths:
            return _fail(
                "rmdir: missing operand\nTry 'rmdir --help' for more information."
            )
        chunks: list[str] = []
        for path in paths:
            try:
                if self._vfs.exists(path, self._state.cwd) and not self._vfs.is_dir(
                    path, self._state.cwd
                ):
                    chunks.append(f"rmdir: failed to remove '{path}': Not a directory\n")
                    continue
                self._vfs.remove(path, self._state.cwd, recursive=False)
            except FileNotFoundError:
                chunks.append(
                    f"rmdir: failed to remove '{path}': No such file or directory\n"
                )
            except OSError:
                chunks.append(f"rmdir: failed to remove '{path}': Directory not empty\n")
            except NotADirectoryError:
                chunks.append(f"rmdir: failed to remove '{path}': Not a directory\n")
        return CommandResult("".join(chunks), exit_code=1 if chunks else 0)

    def _cmd_touch(self, args: list[str]) -> CommandResult:
        if not args:
            return _fail(
                "touch: missing file operand\nTry 'touch --help' for more information."
            )
        chunks: list[str] = []
        for path in args:
            try:
                self._vfs.touch_file(path, self._state.cwd)
            except FileNotFoundError:
                chunks.append(f"touch: cannot touch '{path}': No such file or directory\n")
            except NotADirectoryError:
                chunks.append(f"touch: cannot touch '{path}': Not a directory\n")
        return CommandResult("".join(chunks), exit_code=1 if chunks else 0)

    def _cmd_wget(self, args: list[str]) -> CommandResult:
        url, output_path = _parse_wget_args(args)
        if url is None:
            return _fail(
                "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n"
            )
        target = output_path if output_path is not None else filename_from_url(url)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = mocked_payload(url, self._client_ip, timestamp)
        try:
            self._vfs.write_file(target, payload, self._state.cwd)
        except FileNotFoundError:
            return _fail(f"wget: {target}: No such file or directory")
        except IsADirectoryError:
            return _fail(f"wget: {target}: Is a directory")
        except NotADirectoryError:
            return _fail(f"wget: {target}: Not a directory")
        name = target.rstrip("/").rsplit("/", 1)[-1] or filename_from_url(url)
        self._quarantine(name, payload, source_url=url)
        return CommandResult(_wget_progress(url, name, len(payload.encode("utf-8"))))

    def _cmd_curl(self, args: list[str]) -> CommandResult:
        parsed = _parse_curl_args(args)
        if parsed.url is None:
            return _fail("curl: no URL specified!")
        url = parsed.url
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = mocked_payload(url, self._client_ip, timestamp)
        target = parsed.output_path
        if target is None and parsed.remote_name:
            target = filename_from_url(url)
        if target is not None:
            try:
                self._vfs.write_file(target, payload, self._state.cwd)
            except FileNotFoundError:
                return _fail("curl: (23) Failure writing output to destination")
            except IsADirectoryError:
                return _fail("curl: (23) Failure writing output to destination")
            except NotADirectoryError:
                return _fail("curl: (23) Failure writing output to destination")
            name = target.rstrip("/").rsplit("/", 1)[-1] or filename_from_url(url)
            self._quarantine(name, payload, source_url=url)
            if parsed.silent:
                return CommandResult()
            return CommandResult(_curl_progress(len(payload.encode("utf-8"))))
        self._quarantine(filename_from_url(url), payload, source_url=url)
        if parsed.silent:
            return CommandResult(payload)
        return CommandResult(payload)

    def _cmd_exit(self, _args: list[str]) -> CommandResult:
        return CommandResult(exit_session=True)

    def _format_ls_dir(
        self,
        directory: VFSDirectory,
        abs_path: str,
        long_fmt: bool,
        show_all: bool,
    ) -> str:
        entries: list[tuple[str, INode]] = []
        if show_all:
            parent = self._vfs.get(parent_path(abs_path), "/")
            entries.append((".", directory))
            entries.append(("..", parent))
        for name, child in directory.children.items():
            if not show_all and name.startswith("."):
                continue
            entries.append((name, child))
        entries.sort(key=lambda item: item[0])
        if not long_fmt:
            return "  ".join(name for name, _node in entries)
        blocks = sum(_ls_blocks(node) for _name, node in entries)
        lines = [f"total {blocks}"]
        rows = [(name, _ls_long_fields(node)) for name, node in entries]
        nlink_w = max((len(fields[1]) for _name, fields in rows), default=1)
        owner_w = max((len(fields[2]) for _name, fields in rows), default=1)
        group_w = max((len(fields[3]) for _name, fields in rows), default=1)
        size_w = max((len(fields[4]) for _name, fields in rows), default=1)
        for name, (mode, nlink, owner, group, size, mtime) in rows:
            lines.append(
                f"{mode} {nlink:>{nlink_w}} {owner:<{owner_w}} {group:<{group_w}} "
                f"{size:>{size_w}} {mtime} {name}"
            )
        return "\n".join(lines)

    def _format_ls_file(self, node: INode, display: str, long_fmt: bool) -> str:
        name = display.rstrip("/").rsplit("/", 1)[-1] or display
        if not long_fmt:
            return name
        mode, nlink, owner, group, size, mtime = _ls_long_fields(node)
        return f"{mode} {nlink} {owner} {group} {size} {mtime} {name}"


def _ls_blocks(node: INode) -> int:
    size = node.size
    return (size + 1023) // 1024


def _ls_long_fields(node: INode) -> tuple[str, str, str, str, str, str]:
    kind = "d" if isinstance(node, VFSDirectory) else "-"
    return (
        kind + _perm_string(node.mode),
        str(node.nlink),
        node.owner,
        node.group,
        str(node.size),
        _ls_mtime(node.mtime),
    )


def _perm_string(mode: int) -> str:
    chars: list[str] = []
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 0o7
        chars.append("r" if bits & 4 else "-")
        chars.append("w" if bits & 2 else "-")
        chars.append("x" if bits & 1 else "-")
    if mode & 0o1000:
        chars[8] = "t" if chars[8] == "x" else "T"
    if mode & 0o2000:
        chars[5] = "s" if chars[5] == "x" else "S"
    if mode & 0o4000:
        chars[2] = "s" if chars[2] == "x" else "S"
    return "".join(chars)


def _ls_mtime(mtime: datetime) -> str:
    now = datetime.now(timezone.utc)
    if mtime.tzinfo is None:
        mtime = mtime.replace(tzinfo=timezone.utc)
    if abs(now - mtime) < _LS_SIX_MONTHS:
        return mtime.strftime("%b %e %H:%M")
    return mtime.strftime("%b %e  %Y")
