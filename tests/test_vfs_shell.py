from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from llm import NullLLMProvider
from shell import CommandResult, SessionState, Shell, lookup_static_output
from vfs import (
    DEFAULT_HOME,
    HOSTNAME,
    KERNEL_RELEASE,
    OS_RELEASE,
    PROC_VERSION,
    UNAME_A,
    VFSDirectory,
    VFSFile,
    VirtualFileSystem,
    canonicalize,
)


class RecordingLLMProvider(NullLLMProvider):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    async def generate_response(
        self,
        command: str,
        cwd: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        self.calls.append((command, cwd, context))
        return "uid=0(root) gid=0(root) groups=0(root)"


@pytest.fixture
def vfs() -> VirtualFileSystem:
    return VirtualFileSystem()


@pytest.fixture
def shell(vfs: VirtualFileSystem) -> Shell:
    return Shell(vfs, llm_provider=NullLLMProvider())


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


async def test_pwd_prints_cwd(shell: Shell) -> None:
    result = await shell.execute("pwd")
    assert result == CommandResult("/root")
    assert not result.exit_session


async def test_cd_home_and_tilde(shell: Shell) -> None:
    assert (await shell.execute("cd /etc")).output == ""
    assert shell.state.cwd == "/etc"
    assert (await shell.execute("cd")).output == ""
    assert shell.state.cwd == "/root"
    assert (await shell.execute("cd ~")).output == ""
    assert shell.state.cwd == "/root"
    assert (await shell.execute("cd ~/../home/ubuntu")).output == ""
    assert shell.state.cwd == "/home/ubuntu"


async def test_cd_dash_restores_exact_oldpwd(shell: Shell) -> None:
    first = await shell.execute("cd /var/log")
    assert first.output == ""
    assert shell.state.cwd == "/var/log"
    assert shell.state.oldpwd == "/root"

    back = await shell.execute("cd -")
    assert back.output == "/root"
    assert shell.state.cwd == "/root"
    assert shell.state.oldpwd == "/var/log"

    again = await shell.execute("cd -")
    assert again.output == "/var/log"
    assert shell.state.cwd == "/var/log"
    assert shell.state.oldpwd == "/root"


async def test_cd_dash_without_oldpwd() -> None:
    shell = Shell(
        VirtualFileSystem(),
        SessionState(cwd="/root", oldpwd=None),
        llm_provider=NullLLMProvider(),
    )
    result = await shell.execute("cd -")
    assert result.output == "bash: cd: OLDPWD not set"
    assert shell.state.cwd == "/root"


async def test_cd_errors(shell: Shell) -> None:
    missing = await shell.execute("cd /nope")
    assert missing.output == "bash: cd: /nope: No such file or directory"
    assert shell.state.cwd == "/root"

    not_dir = await shell.execute("cd /etc/passwd")
    assert not_dir.output == "bash: cd: /etc/passwd: Not a directory"

    too_many = await shell.execute("cd /tmp /var")
    assert too_many.output == "bash: cd: too many arguments"


async def test_ls_default_hides_dotfiles(shell: Shell) -> None:
    listing = await shell.execute("ls")
    names = listing.output.split("  ")
    assert ".bash_history" not in names
    assert names == sorted(names)

    root_listing = await shell.execute("ls /")
    for expected in ("bin", "etc", "home", "proc", "root", "tmp", "var"):
        assert expected in root_listing.output.split("  ")


async def test_ls_all_shows_hidden_and_dot_entries(shell: Shell) -> None:
    listing = await shell.execute("ls -a")
    names = listing.output.split("  ")
    assert "." in names
    assert ".." in names
    assert ".bash_history" in names
    assert names == sorted(names)


async def test_ls_long_and_combined_flags(shell: Shell) -> None:
    long_dir = await shell.execute("ls -l /tmp")
    assert long_dir.output.startswith("total ")

    combined = await shell.execute("ls -la /root")
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

    file_short = await shell.execute("ls /etc/hostname")
    assert file_short.output == "hostname"

    file_long = await shell.execute("ls -l /etc/hostname")
    assert file_long.output.startswith("-")
    assert file_long.output.endswith(" hostname")


async def test_ls_missing_path(shell: Shell) -> None:
    result = await shell.execute("ls /does-not-exist")
    assert result.output == (
        "ls: cannot access '/does-not-exist': No such file or directory"
    )


async def test_cat_file_directory_and_missing(shell: Shell) -> None:
    os_release = await shell.execute("cat /etc/os-release")
    assert os_release.output == OS_RELEASE

    directory = await shell.execute("cat /etc")
    assert directory.output == "cat: /etc: Is a directory\n"

    missing = await shell.execute("cat /no/file")
    assert missing.output == "cat: /no/file: No such file or directory\n"

    mixed = await shell.execute("cat /etc /etc/hostname /missing")
    assert "Is a directory" in mixed.output
    assert HOSTNAME in mixed.output
    assert "No such file or directory" in mixed.output

    no_operand = await shell.execute("cat")
    assert "missing file operand" in no_operand.output


async def test_empty_and_whitespace_input_is_noop(shell: Shell) -> None:
    assert await shell.execute("") == CommandResult()
    assert await shell.execute("   ") == CommandResult()
    assert await shell.execute("\t") == CommandResult()


async def test_unknown_command_message(shell: Shell) -> None:
    result = await shell.execute("nosuchcmd")
    assert result.output == "bash: nosuchcmd: command not found"
    assert not result.exit_session
    assert result.execution_path == "llm"


async def test_shlex_quote_handling(shell: Shell) -> None:
    quoted = await shell.execute("cat '/etc/hostname'")
    assert quoted.output == f"{HOSTNAME}\n"

    double = await shell.execute('ls "/etc"')
    assert "hostname" in double.output
    assert "os-release" in double.output

    unknown_quoted = await shell.execute('xyzzy "root"')
    assert unknown_quoted.output == "bash: xyzzy: command not found"


async def test_exit_and_logout(shell: Shell) -> None:
    assert (await shell.execute("exit")).exit_session is True
    assert (await shell.execute("logout")).exit_session is True


async def test_local_commands_do_not_call_llm(vfs: VirtualFileSystem) -> None:
    provider = RecordingLLMProvider()
    shell = Shell(vfs, llm_provider=provider)
    await shell.execute("pwd")
    await shell.execute("ls")
    await shell.execute("cd /tmp")
    await shell.execute("cat /etc/hostname")
    await shell.execute("touch /tmp/keep")
    assert provider.calls == []


async def test_static_recon_commands_bypass_llm(vfs: VirtualFileSystem) -> None:
    provider = RecordingLLMProvider()
    shell = Shell(vfs, llm_provider=provider)
    cases = (
        "ps aux",
        "ps -ef",
        "df -h",
        "free -m",
        "uptime",
    )
    for command in cases:
        result = await shell.execute(command)
        expected = lookup_static_output(command.split())
        assert expected is not None
        assert result.output == expected
        assert not result.exit_session
    assert provider.calls == []
    assert "USER" in (await shell.execute("ps aux")).output
    assert "/sbin/init" in (await shell.execute("ps -ef")).output
    assert "Filesystem" in (await shell.execute("df -h")).output
    assert "Mem:" in (await shell.execute("free -m")).output
    assert "load average" in (await shell.execute("uptime")).output


async def test_unknown_command_uses_injected_provider(vfs: VirtualFileSystem) -> None:
    provider = RecordingLLMProvider()
    shell = Shell(vfs, llm_provider=provider)
    result = await shell.execute("getenforce")
    assert result.output == "uid=0(root) gid=0(root) groups=0(root)"
    assert len(provider.calls) == 1
    command, cwd, context = provider.calls[0]
    assert command == "getenforce"
    assert cwd == "/root"
    assert context is not None
    assert context["hostname"] == HOSTNAME
    assert context["user"] == "root"
    assert ".bash_history" in context["listing"]


async def test_repeated_dynamic_command_uses_llm_cache(vfs: VirtualFileSystem) -> None:
    status = "● nginx.service - A high performance web server\n     Active: active (running)"
    provider = MagicMock()
    provider.generate_response = AsyncMock(return_value=status)
    shell = Shell(vfs, llm_provider=provider)

    first = await shell.execute("  systemctl status nginx  ")
    second = await shell.execute("systemctl status nginx")

    assert first.output == status
    assert second.output == first.output
    assert first.execution_path == "llm"
    assert second.execution_path == "cache"
    provider.generate_response.assert_called_once()


async def test_date_commands_are_not_llm_cached(vfs: VirtualFileSystem) -> None:
    provider = MagicMock()
    provider.generate_response = AsyncMock(
        side_effect=["Tue Sep  8 02:08:01 UTC 2026", "Tue Sep  8 02:08:02 UTC 2026"]
    )
    shell = Shell(vfs, llm_provider=provider)

    first = await shell.execute("date")
    second = await shell.execute("date")

    assert first.output != second.output
    assert provider.generate_response.call_count == 2


async def test_mkdir_creates_directory_visible_in_ls(shell: Shell) -> None:
    created = await shell.execute("mkdir /tmp/payloads")
    assert created.output == ""
    listing = await shell.execute("ls /tmp")
    assert "payloads" in listing.output.split("  ")
    nested = await shell.execute("mkdir -p /tmp/payloads/nested/bin")
    assert nested.output == ""
    nested_listing = await shell.execute("ls /tmp/payloads/nested")
    assert "bin" in nested_listing.output.split("  ")


async def test_echo_redirect_writes_file_readable_by_cat(shell: Shell) -> None:
    written = await shell.execute('echo "malware_test" > /tmp/payload.sh')
    assert written.output == ""
    contents = await shell.execute("cat /tmp/payload.sh")
    assert contents.output == "malware_test\n"


async def test_append_redirect_preserves_existing_content(shell: Shell) -> None:
    await shell.execute('echo "malware_test" > /tmp/payload.sh')
    appended = await shell.execute('echo "stage2" >> /tmp/payload.sh')
    assert appended.output == ""
    contents = await shell.execute("cat /tmp/payload.sh")
    assert contents.output == "malware_test\nstage2\n"


async def test_rm_and_rmdir_deletion_edge_cases(shell: Shell) -> None:
    await shell.execute("mkdir /tmp/stash")
    await shell.execute('echo "keep" > /tmp/stash/note.txt')
    await shell.execute('echo "gone" > /tmp/drop.txt')

    nonempty = await shell.execute("rmdir /tmp/stash")
    assert nonempty.output == "rmdir: failed to remove '/tmp/stash': Directory not empty\n"
    assert (await shell.execute("ls /tmp/stash")).output.split("  ") == ["note.txt"]

    is_dir = await shell.execute("rm /tmp/stash")
    assert is_dir.output == "rm: cannot remove '/tmp/stash': Is a directory\n"

    missing = await shell.execute("rm /tmp/nope.txt")
    assert missing.output == "rm: cannot remove '/tmp/nope.txt': No such file or directory\n"
    forced = await shell.execute("rm -f /tmp/nope.txt")
    assert forced.output == ""

    removed_file = await shell.execute("rm /tmp/drop.txt")
    assert removed_file.output == ""
    gone = await shell.execute("cat /tmp/drop.txt")
    assert gone.output == "cat: /tmp/drop.txt: No such file or directory\n"

    await shell.execute("rm /tmp/stash/note.txt")
    emptied = await shell.execute("rmdir /tmp/stash")
    assert emptied.output == ""
    listing = await shell.execute("ls /tmp")
    assert "stash" not in listing.output.split("  ")

    await shell.execute("mkdir -p /tmp/tree/leaf")
    recursive = await shell.execute("rm -rf /tmp/tree")
    assert recursive.output == ""
    missing_dir = await shell.execute("ls /tmp/tree")
    assert "No such file or directory" in missing_dir.output


async def test_command_chaining_and_semicolon(shell: Shell) -> None:
    result = await shell.execute(
        'mkdir /tmp/test && touch /tmp/test/payload.sh; echo "done"'
    )
    assert "done" in result.output
    assert result.exit_code == 0
    listing = await shell.execute("ls /tmp/test")
    assert "payload.sh" in listing.output.split("  ")
    contents = await shell.execute("cat /tmp/test/payload.sh")
    assert contents.output == ""


async def test_and_chain_stops_on_failure(shell: Shell) -> None:
    result = await shell.execute("mkdir /tmp/missing/nested && echo should-not")
    assert "should-not" not in result.output
    assert "No such file or directory" in result.output
    assert result.exit_code != 0


async def test_or_chain_runs_fallback(shell: Shell) -> None:
    result = await shell.execute("cd /nope || cd /tmp")
    assert shell.state.cwd == "/tmp"
    assert "No such file" in result.output
    assert result.exit_code == 0


async def test_quoted_operator_is_not_a_chain(shell: Shell) -> None:
    result = await shell.execute('echo "mkdir /tmp/x && touch f"')
    assert result.output == "mkdir /tmp/x && touch f\n"
    assert result.exit_code == 0
    listing = await shell.execute("ls /tmp")
    assert "x" not in listing.output.split("  ")


async def test_cat_proc_and_resolv_are_linux_formatted(shell: Shell) -> None:
    cpuinfo = await shell.execute("cat /proc/cpuinfo")
    assert cpuinfo.execution_path == "vfs"
    assert cpuinfo.exit_code == 0
    assert "processor\t: 0" in cpuinfo.output
    assert "processor\t: 1" in cpuinfo.output
    assert "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz" in cpuinfo.output
    assert "bogomips" in cpuinfo.output.lower()
    assert "cache size" in cpuinfo.output

    meminfo = await shell.execute("cat /proc/meminfo")
    assert meminfo.execution_path == "vfs"
    assert "MemTotal:" in meminfo.output
    assert "4016332 kB" in meminfo.output
    assert "MemFree:" in meminfo.output
    assert "MemAvailable:" in meminfo.output
    assert "SwapTotal:" in meminfo.output
    assert meminfo.output.splitlines()[0].endswith(" kB")

    resolv = await shell.execute("cat /etc/resolv.conf")
    assert resolv.execution_path == "vfs"
    assert resolv.output == (
        "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n"
    )


async def test_static_identity_and_recon_commands(vfs: VirtualFileSystem) -> None:
    provider = RecordingLLMProvider()
    shell = Shell(vfs, llm_provider=provider)
    cases = {
        "whoami": "root",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "hostname": HOSTNAME,
        "arch": "x86_64",
        "uname": "Linux",
        "uname -s": "Linux",
        "uname -r": KERNEL_RELEASE,
        "uname -m": "x86_64",
        "uname -a": UNAME_A,
        "which bash": "/bin/bash",
        "lscpu": None,
        "ip a": None,
    }
    for command, expected in cases.items():
        result = await shell.execute(command)
        assert result.execution_path == "static", command
        assert result.exit_code == 0, command
        if expected is not None:
            assert result.output == expected, command
        else:
            assert result.output
    lscpu = await shell.execute("lscpu")
    assert "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz" in lscpu.output
    assert "CPU(s):                          2" in lscpu.output
    ip_a = await shell.execute("ip a")
    assert "192.168.1.105/24" in ip_a.output
    assert "52:54:00:12:34:56" in ip_a.output
    assert "eth0" in ip_a.output
    assert provider.calls == []


async def test_which_unknown_tool_is_empty_static_failure(shell: Shell) -> None:
    result = await shell.execute("which unknown_tool")
    assert result.output == ""
    assert result.exit_code == 1
    assert result.execution_path == "static"


async def test_kernel_identity_is_consistent_across_proc_and_uname(
    shell: Shell,
) -> None:
    version = await shell.execute("cat /proc/version")
    uname_a = await shell.execute("uname -a")
    uname_r = await shell.execute("uname -r")
    assert version.execution_path == "vfs"
    assert uname_a.execution_path == "static"
    assert uname_r.execution_path == "static"
    assert version.output == PROC_VERSION
    assert uname_r.output == KERNEL_RELEASE
    assert KERNEL_RELEASE in version.output
    assert KERNEL_RELEASE in uname_a.output
    assert "#98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023" in version.output
    assert "#98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023" in uname_a.output
    assert uname_a.output == UNAME_A


async def test_proactive_recon_commands_are_static(vfs: VirtualFileSystem) -> None:
    provider = RecordingLLMProvider()
    shell = Shell(vfs, llm_provider=provider)

    env = await shell.execute("env")
    assert env.execution_path == "static"
    assert env.exit_code == 0
    assert "USER=root" in env.output
    assert f"HOSTNAME={HOSTNAME}" in env.output
    assert "HOME=/root" in env.output
    assert f"PWD={shell.state.cwd}" in env.output

    groups = await shell.execute("groups")
    assert groups.execution_path == "static"
    assert groups.output == "root"

    crontab = await shell.execute("crontab -l")
    assert crontab.execution_path == "static"
    assert crontab.exit_code == 1
    assert crontab.output == "no crontab for root"

    last = await shell.execute("last")
    assert last.execution_path == "static"
    assert "root" in last.output
    assert "pts/0" in last.output
    assert KERNEL_RELEASE in last.output

    nproc = await shell.execute("nproc")
    assert nproc.execution_path == "static"
    assert nproc.output == "2"
    assert provider.calls == []


async def test_network_and_firewall_static_variants(shell: Shell) -> None:
    ip_route = await shell.execute("ip route")
    assert ip_route.execution_path == "static"
    assert "default via 192.168.1.1 dev eth0" in ip_route.output

    route_n = await shell.execute("route -n")
    assert route_n.execution_path == "static"
    assert "192.168.1.1" in route_n.output

    ss = await shell.execute("ss -tulpn")
    assert ss.execution_path == "static"
    assert ":22" in ss.output
    assert "sshd" in ss.output

    netstat = await shell.execute("netstat -tuln")
    assert netstat.execution_path == "static"
    assert "0.0.0.0:22" in netstat.output

    iptables = await shell.execute("iptables -L")
    assert iptables.execution_path == "static"
    assert "policy ACCEPT" in iptables.output

    ufw = await shell.execute("ufw status")
    assert ufw.execution_path == "static"
    assert ufw.output == "Status: inactive"

    dmidecode = await shell.execute("dmidecode -s system-product-name")
    assert dmidecode.execution_path == "static"
    assert dmidecode.output == "Standard PC (Q35 + ICH9, 2009)"
