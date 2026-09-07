"""Command dispatcher for the honeypot shell.

Parses input with ``shlex`` and executes against :class:`vfs.VirtualFileSystem`.
Host OS execution is never used.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

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
    ) -> None:
        self._vfs = vfs
        self._state = state if state is not None else SessionState(home=vfs.home)
        self._llm_provider = llm_provider if llm_provider is not None else NullLLMProvider()
        self._handlers = {
            "pwd": self._cmd_pwd,
            "cd": self._cmd_cd,
            "ls": self._cmd_ls,
            "cat": self._cmd_cat,
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
        if handler is None:
            output = await self._llm_provider.generate_response(
                stripped,
                self._state.cwd,
                self._llm_context(),
            )
            return CommandResult(output)
        return handler(args)

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
