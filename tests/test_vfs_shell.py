from __future__ import annotations

import pytest

from shell import CommandResult, SessionState, Shell
from vfs import (
    DEFAULT_HOME,
    HOSTNAME,
    OS_RELEASE,
    VFSDirectory,
    VFSFile,
    VirtualFileSystem,
    canonicalize,
)


@pytest.fixture
def vfs() -> VirtualFileSystem:
    return VirtualFileSystem()


@pytest.fixture
def shell(vfs: VirtualFileSystem) -> Shell:
    return Shell(vfs)


def test_canonicalize_relative_paths() -> None:
    assert canonicalize("etc", "/", DEFAULT_HOME) == "/etc"
    assert canonicalize("ubuntu", "/home", DEFAULT_HOME) == "/home/ubuntu"
    assert canonicalize("./passwd", "/etc", DEFAULT_HOME) == "/etc/passwd"
    assert canonicalize("log/../log", "/var", DEFAULT_HOME) == "/var/log"


def test_canonicalize_clamps_dotdot_at_root() -> None:
    assert canonicalize("..", "/", DEFAULT_HOME) == "/"
    assert canonicalize("../..", "/root", DEFAULT_HOME) == "/"
    assert canonicalize("/../../etc", "/", DEFAULT_HOME) == "/etc"
    assert canonicalize("../../../etc/passwd", "/root", DEFAULT_HOME) == "/etc/passwd"
    assert canonicalize("/..", "/tmp", DEFAULT_HOME) == "/"


def test_canonicalize_expands_tilde_to_home() -> None:
    assert canonicalize("~", "/tmp", DEFAULT_HOME) == "/root"
    assert canonicalize("~/", "/tmp", DEFAULT_HOME) == "/root"
    assert canonicalize("~/.bash_history", "/tmp", DEFAULT_HOME) == "/root/.bash_history"
    assert canonicalize("~", "/", "/home/ubuntu") == "/home/ubuntu"


def test_canonicalize_leaves_dash_unresolved() -> None:
    assert canonicalize("-", "/root", DEFAULT_HOME) == "-"


def test_vfs_resolve_absolute_and_relative(vfs: VirtualFileSystem) -> None:
    hostname = vfs.resolve("/etc/hostname", "/")
    assert isinstance(hostname, VFSFile)
    assert hostname.content == f"{HOSTNAME}\n"

    relative = vfs.resolve("hostname", "/etc")
    assert relative is hostname

    home = vfs.resolve("~", "/tmp")
    assert isinstance(home, VFSDirectory)
    assert home.name == "root"


def test_vfs_resolve_missing_and_not_a_directory(vfs: VirtualFileSystem) -> None:
    with pytest.raises(FileNotFoundError) as missing:
        vfs.resolve("/no/such/path", "/")
    assert missing.value.args[0] == "/no/such/path"

    with pytest.raises(NotADirectoryError) as not_dir:
        vfs.resolve("/etc/passwd/extra", "/")
    assert not_dir.value.args[0] == "/etc/passwd"


def test_pwd_prints_cwd(shell: Shell) -> None:
    result = shell.execute("pwd")
    assert result == CommandResult("/root")
    assert not result.exit_session


def test_cd_home_and_tilde(shell: Shell) -> None:
    assert shell.execute("cd /etc").output == ""
    assert shell.state.cwd == "/etc"
    assert shell.execute("cd").output == ""
    assert shell.state.cwd == "/root"
    assert shell.execute("cd ~").output == ""
    assert shell.state.cwd == "/root"
    assert shell.execute("cd ~/../home/ubuntu").output == ""
    assert shell.state.cwd == "/home/ubuntu"


def test_cd_dash_restores_exact_oldpwd(shell: Shell) -> None:
    first = shell.execute("cd /var/log")
    assert first.output == ""
    assert shell.state.cwd == "/var/log"
    assert shell.state.oldpwd == "/root"

    back = shell.execute("cd -")
    assert back.output == "/root"
    assert shell.state.cwd == "/root"
    assert shell.state.oldpwd == "/var/log"

    again = shell.execute("cd -")
    assert again.output == "/var/log"
    assert shell.state.cwd == "/var/log"
    assert shell.state.oldpwd == "/root"


def test_cd_dash_without_oldpwd() -> None:
    shell = Shell(VirtualFileSystem(), SessionState(cwd="/root", oldpwd=None))
    result = shell.execute("cd -")
    assert result.output == "bash: cd: OLDPWD not set"
    assert shell.state.cwd == "/root"


def test_cd_errors(shell: Shell) -> None:
    missing = shell.execute("cd /nope")
    assert missing.output == "bash: cd: /nope: No such file or directory"
    assert shell.state.cwd == "/root"

    not_dir = shell.execute("cd /etc/passwd")
    assert not_dir.output == "bash: cd: /etc/passwd: Not a directory"

    too_many = shell.execute("cd /tmp /var")
    assert too_many.output == "bash: cd: too many arguments"


def test_ls_default_hides_dotfiles(shell: Shell) -> None:
    listing = shell.execute("ls")
    names = listing.output.split("  ")
    assert ".bash_history" not in names
    assert names == sorted(names)

    root_listing = shell.execute("ls /")
    for expected in ("bin", "etc", "home", "root", "tmp", "var"):
        assert expected in root_listing.output.split("  ")


def test_ls_all_shows_hidden_and_dot_entries(shell: Shell) -> None:
    listing = shell.execute("ls -a")
    names = listing.output.split("  ")
    assert "." in names
    assert ".." in names
    assert ".bash_history" in names
    assert names == sorted(names)


def test_ls_long_and_combined_flags(shell: Shell) -> None:
    long_dir = shell.execute("ls -l /tmp")
    assert long_dir.output.startswith("total ")

    combined = shell.execute("ls -la /root")
    lines = combined.output.splitlines()
    assert lines[0].startswith("total ")
    names = [line.rsplit(" ", 1)[-1] for line in lines[1:]]
    assert "." in names
    assert ".." in names
    assert ".bash_history" in names
    history_line = next(line for line in lines[1:] if line.endswith(" .bash_history"))
    assert history_line.startswith("-rw-------")
    dot_line = next(line for line in lines[1:] if line.endswith(" .") and not line.endswith(" .."))
    assert dot_line.startswith("d")

    file_short = shell.execute("ls /etc/hostname")
    assert file_short.output == "hostname"

    file_long = shell.execute("ls -l /etc/hostname")
    assert file_long.output.startswith("-")
    assert file_long.output.endswith(" hostname")


def test_ls_missing_path(shell: Shell) -> None:
    result = shell.execute("ls /does-not-exist")
    assert result.output == (
        "ls: cannot access '/does-not-exist': No such file or directory"
    )


def test_cat_file_directory_and_missing(shell: Shell) -> None:
    os_release = shell.execute("cat /etc/os-release")
    assert os_release.output == OS_RELEASE

    directory = shell.execute("cat /etc")
    assert directory.output == "cat: /etc: Is a directory\n"

    missing = shell.execute("cat /no/file")
    assert missing.output == "cat: /no/file: No such file or directory\n"

    mixed = shell.execute("cat /etc /etc/hostname /missing")
    assert "Is a directory" in mixed.output
    assert HOSTNAME in mixed.output
    assert "No such file or directory" in mixed.output

    no_operand = shell.execute("cat")
    assert "missing file operand" in no_operand.output


def test_empty_and_whitespace_input_is_noop(shell: Shell) -> None:
    assert shell.execute("") == CommandResult()
    assert shell.execute("   ") == CommandResult()
    assert shell.execute("\t") == CommandResult()


def test_unknown_command_message(shell: Shell) -> None:
    result = shell.execute("whoami")
    assert result.output == "bash: whoami: command not found"
    assert not result.exit_session


def test_shlex_quote_handling(shell: Shell) -> None:
    quoted = shell.execute("cat '/etc/hostname'")
    assert quoted.output == f"{HOSTNAME}\n"

    double = shell.execute('ls "/etc"')
    assert "hostname" in double.output
    assert "os-release" in double.output

    unknown_quoted = shell.execute('id "root"')
    assert unknown_quoted.output == "bash: id: command not found"


def test_exit_and_logout(shell: Shell) -> None:
    assert shell.execute("exit").exit_session is True
    assert shell.execute("logout").exit_session is True
