"""Command dispatcher for the honeypot shell.

Parses input with ``shlex`` and executes against :class:`vfs.VirtualFileSystem`.
Host OS execution is never used.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Sequence

from llm import LLMProvider, NullLLMProvider
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


class Shell:
    """Tokenize and dispatch simulated bash commands against an in-memory VFS."""

    def __init__(
        self,
        vfs: VirtualFileSystem,
        state: SessionState | None = None,
        llm_provider: LLMProvider | None = None,
        llm_cache: dict[str, str] | None = None,
    ) -> None:
        self._vfs = vfs
        self._state = state if state is not None else SessionState(home=vfs.home)
        self._llm_provider = llm_provider if llm_provider is not None else NullLLMProvider()
        self._llm_cache: dict[str, str] = llm_cache if llm_cache is not None else {}
        self._handlers = {
            "pwd": self._cmd_pwd,
            "cd": self._cmd_cd,
            "ls": self._cmd_ls,
            "cat": self._cmd_cat,
            "touch": self._cmd_touch,
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
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as exc:
            return CommandResult(f"bash: {exc}")
        if not tokens:
            return CommandResult()
        command, *args = tokens
        handler = self._handlers.get(command)
        if handler is not None:
            return handler(args)
        static = lookup_static_output(tokens)
        if static is not None:
            return CommandResult(static)
        cacheable = _is_cacheable_llm_command(tokens)
        if cacheable and stripped in self._llm_cache:
            return CommandResult(self._llm_cache[stripped])
        output = await self._llm_provider.generate_response(
            stripped,
            self._state.cwd,
            self._llm_context(),
        )
        if cacheable:
            self._llm_cache[stripped] = output
        return CommandResult(output)

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
            return CommandResult("bash: cd: too many arguments")
        if args and args[0] == "-":
            if self._state.oldpwd is None:
                return CommandResult("bash: cd: OLDPWD not set")
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
            return CommandResult(f"bash: cd: {raw}: No such file or directory")
        except NotADirectoryError:
            return CommandResult(f"bash: cd: {raw}: Not a directory")
        if not isinstance(node, VFSDirectory):
            return CommandResult(f"bash: cd: {raw}: Not a directory")
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
            return CommandResult(f"ls: cannot access '{shown}': No such file or directory")
        except NotADirectoryError:
            shown = paths[0] if paths else target
            return CommandResult(f"ls: cannot access '{shown}': Not a directory")
        if isinstance(node, VFSDirectory):
            abs_path = canonicalize(target, self._state.cwd, self._state.home)
            return CommandResult(self._format_ls_dir(node, abs_path, long_fmt, show_all))
        return CommandResult(self._format_ls_file(node, display, long_fmt))

    def _cmd_cat(self, args: list[str]) -> CommandResult:
        if not args:
            return CommandResult(
                "cat: missing file operand\nTry 'cat --help' for more information."
            )
        chunks: list[str] = []
        for path in args:
            try:
                chunks.append(self._vfs.read_file(path, self._state.cwd))
            except FileNotFoundError:
                chunks.append(f"cat: {path}: No such file or directory\n")
            except IsADirectoryError:
                chunks.append(f"cat: {path}: Is a directory\n")
            except NotADirectoryError:
                chunks.append(f"cat: {path}: Not a directory\n")
        return CommandResult("".join(chunks))

    def _cmd_touch(self, args: list[str]) -> CommandResult:
        if not args:
            return CommandResult(
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
        return CommandResult("".join(chunks))

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
