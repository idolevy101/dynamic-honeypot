from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from llm import NullLLMProvider
from shell import CommandResult, SessionState, Shell, format_uname, lookup_static_output
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
    create_default_vfs,
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
    assert no_operand.output == ""
    assert no_operand.exit_code == 0


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
    await shell.execute("mkdir /tmp/keepdir")
    await shell.execute("chmod +x /tmp/keep")
    await shell.execute("rm /tmp/keep")
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


async def test_uname_a_execute_path_exact_string(shell: Shell) -> None:
    expected = (
        "Linux ubuntu-srv 5.15.0-88-generic "
        "#98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 "
        "x86_64 x86_64 x86_64 GNU/Linux"
    )
    result = await shell.execute("uname -a")
    assert result.execution_path == "static"
    assert result.output == expected
    assert "2023 x86_64" in result.output
    assert "2023x86_64" not in result.output
    assert format_uname(["-a"]) == expected
    assert format_uname(["-snrvmpio"]) == expected
    combined = await shell.execute("uname -snrvmpio")
    assert combined.output == expected


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
    assert uname_a.output == (
        "Linux ubuntu-srv 5.15.0-88-generic "
        "#98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 "
        "x86_64 x86_64 x86_64 GNU/Linux"
    )
    assert KERNEL_RELEASE in version.output
    assert KERNEL_RELEASE in uname_a.output


async def test_echo_status_after_which_unknown(shell: Shell) -> None:
    missing = await shell.execute("which invalid_bin")
    assert missing.output == ""
    assert missing.exit_code == 1
    assert missing.execution_path == "static"
    status = await shell.execute("echo $?")
    assert status.output == "1\n"
    assert status.exit_code == 0


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


def test_vfs_clone_and_default_instances_are_isolated() -> None:
    base = create_default_vfs()
    first = base.clone()
    second = create_default_vfs()
    first.touch("/tmp/isolated.txt", "/")
    first.mkdir("/tmp/isolated-dir", "/")
    assert first.exists("/tmp/isolated.txt", "/")
    assert first.exists("/tmp/isolated-dir", "/")
    assert not second.exists("/tmp/isolated.txt", "/")
    assert not second.exists("/tmp/isolated-dir", "/")
    assert not base.exists("/tmp/isolated.txt", "/")


def test_vfs_chmod_octal_and_symbolic(vfs: VirtualFileSystem) -> None:
    vfs.touch("/tmp/script.sh", "/")
    node = vfs.get("/tmp/script.sh", "/")
    assert node.mode == 0o644
    vfs.chmod("/tmp/script.sh", "+x", "/")
    assert node.mode == 0o755
    vfs.chmod("/tmp/script.sh", "777", "/")
    assert node.mode == 0o777
    vfs.chmod("/tmp/script.sh", "-x", "/")
    assert node.mode == 0o666
    vfs.chmod("/tmp/script.sh", "644", "/")
    assert node.mode == 0o644


def test_vfs_remove_force_and_directory_guard(vfs: VirtualFileSystem) -> None:
    vfs.mkdir("/tmp/keep", "/")
    assert vfs.remove("/tmp/missing", "/", force=True) is True
    with pytest.raises(IsADirectoryError):
        vfs.remove("/tmp/keep", "/")
    assert vfs.remove("/tmp/keep", "/", recursive=True) is True
    assert not vfs.exists("/tmp/keep", "/")


async def test_mkdir_p_nested_existing_and_errors(shell: Shell) -> None:
    created = await shell.execute("mkdir /tmp/payloads")
    assert created.output == ""
    assert created.exit_code == 0

    exists = await shell.execute("mkdir /tmp/payloads")
    assert exists.output == "mkdir: cannot create directory '/tmp/payloads': File exists\n"
    assert exists.exit_code == 1
    status = await shell.execute("echo $?")
    assert status.output == "1\n"

    missing_parent = await shell.execute("mkdir /tmp/missing/nested")
    assert missing_parent.output == (
        "mkdir: cannot create directory '/tmp/missing/nested': No such file or directory\n"
    )
    assert missing_parent.exit_code == 1

    nested = await shell.execute("mkdir -p /tmp/a/b/c/d")
    assert nested.output == ""
    assert nested.exit_code == 0
    listing = await shell.execute("ls /tmp/a/b/c")
    assert "d" in listing.output.split("  ")

    long_opt = await shell.execute("mkdir --parents /tmp/a/b/c/d")
    assert long_opt.output == ""
    assert long_opt.exit_code == 0

    idempotent = await shell.execute("mkdir -p /tmp/payloads")
    assert idempotent.output == ""
    assert idempotent.exit_code == 0

    multi = await shell.execute("mkdir /tmp/one /tmp/two")
    assert multi.output == ""
    assert multi.exit_code == 0
    root_tmp = await shell.execute("ls /tmp")
    names = root_tmp.output.split("  ")
    assert "one" in names
    assert "two" in names


async def test_created_paths_are_navigable_and_listed(shell: Shell) -> None:
    await shell.execute("mkdir -p /tmp/work/bin")
    cd = await shell.execute("cd /tmp/work")
    assert cd.exit_code == 0
    assert shell.state.cwd == "/tmp/work"

    touched = await shell.execute("touch rel.txt")
    assert touched.output == ""
    assert touched.exit_code == 0

    listing = await shell.execute("ls")
    assert "bin" in listing.output.split("  ")
    assert "rel.txt" in listing.output.split("  ")

    long_listing = await shell.execute("ls -la")
    lines = long_listing.output.splitlines()
    names = [line.rsplit(" ", 1)[-1] for line in lines[1:]]
    assert "bin" in names
    assert "rel.txt" in names
    bin_line = next(line for line in lines[1:] if line.endswith(" bin"))
    assert bin_line.startswith("drwxr-xr-x")
    file_line = next(line for line in lines[1:] if line.endswith(" rel.txt"))
    assert file_line.startswith("-rw-r--r--")

    abs_touch = await shell.execute("touch /tmp/work/abs.txt")
    assert abs_touch.exit_code == 0
    assert "abs.txt" in (await shell.execute("ls /tmp/work")).output.split("  ")


async def test_touch_multi_arg_and_invalid_parent(shell: Shell) -> None:
    ok = await shell.execute("touch /tmp/alpha /tmp/beta /tmp/gamma")
    assert ok.output == ""
    assert ok.exit_code == 0
    listing = await shell.execute("ls /tmp")
    names = listing.output.split("  ")
    assert "alpha" in names
    assert "beta" in names
    assert "gamma" in names

    missing = await shell.execute("touch /no/such/file")
    assert missing.output == "touch: cannot touch '/no/such/file': No such file or directory\n"
    assert missing.exit_code == 1
    status = await shell.execute("echo $?")
    assert status.output == "1\n"


async def test_rm_multi_arg_directory_and_force(shell: Shell) -> None:
    await shell.execute("touch /tmp/file1 /tmp/file2 /tmp/file3")
    await shell.execute("mkdir /tmp/stash")

    is_dir = await shell.execute("rm /tmp/stash")
    assert is_dir.output == "rm: cannot remove '/tmp/stash': Is a directory\n"
    assert is_dir.exit_code == 1
    assert "stash" in (await shell.execute("ls /tmp")).output.split("  ")

    missing = await shell.execute("rm /tmp/nope.txt")
    assert missing.output == "rm: cannot remove '/tmp/nope.txt': No such file or directory\n"
    assert missing.exit_code == 1

    forced = await shell.execute("rm -f /tmp/nope.txt")
    assert forced.output == ""
    assert forced.exit_code == 0

    multi = await shell.execute("rm /tmp/file1 /tmp/file2")
    assert multi.output == ""
    assert multi.exit_code == 0
    leftover = (await shell.execute("ls /tmp")).output.split("  ")
    assert "file1" not in leftover
    assert "file2" not in leftover
    assert "file3" in leftover

    grouped = await shell.execute("rm -rf /tmp/stash /tmp/file3")
    assert grouped.output == ""
    assert grouped.exit_code == 0
    after = (await shell.execute("ls /tmp")).output.split("  ")
    assert "stash" not in after
    assert "file3" not in after

    fr = await shell.execute("rm -fr /tmp/still-missing")
    assert fr.output == ""
    assert fr.exit_code == 0
    status = await shell.execute("echo $?")
    assert status.output == "0\n"


async def test_chmod_updates_ls_permissions_and_errors(shell: Shell) -> None:
    await shell.execute("touch /tmp/script.sh /tmp/other.sh")
    before = await shell.execute("ls -l /tmp/script.sh")
    assert before.output.startswith("-rw-r--r--")
    assert before.exit_code == 0

    plus_x = await shell.execute("chmod +x /tmp/script.sh")
    assert plus_x.output == ""
    assert plus_x.exit_code == 0
    after_x = await shell.execute("ls -l /tmp/script.sh")
    assert after_x.output.startswith("-rwxr-xr-x")

    mode_777 = await shell.execute("chmod 777 /tmp/script.sh /tmp/other.sh")
    assert mode_777.output == ""
    assert mode_777.exit_code == 0
    both = await shell.execute("ls -l /tmp/script.sh")
    assert both.output.startswith("-rwxrwxrwx")
    other = await shell.execute("ls -l /tmp/other.sh")
    assert other.output.startswith("-rwxrwxrwx")

    missing = await shell.execute("chmod 755 /tmp/missing.sh")
    assert missing.output == (
        "chmod: cannot access '/tmp/missing.sh': No such file or directory\n"
    )
    assert missing.exit_code == 1
    status = await shell.execute("echo $?")
    assert status.output == "1\n"


async def test_file_mutations_do_not_touch_host_filesystem(
    shell: Shell, tmp_path: Path
) -> None:
    marker = "vfs_isolation_marker_9f3c"
    host_tmp = Path("/tmp") / marker
    await shell.execute(f"mkdir /tmp/{marker}")
    await shell.execute(f"touch /tmp/{marker}/file")
    await shell.execute(f"chmod 777 /tmp/{marker}/file")
    listing = await shell.execute(f"ls /tmp/{marker}")
    assert "file" in listing.output.split("  ")
    assert not (tmp_path / marker).exists()
    assert not host_tmp.exists()


async def test_semicolon_runs_both_and_last_status(shell: Shell) -> None:
    result = await shell.execute("echo a; echo b")
    assert result.output == "a\nb\n"
    assert result.exit_code == 0
    status = await shell.execute("echo $?")
    assert status.output == "0\n"


async def test_and_chain_mkdir_then_touch(shell: Shell) -> None:
    result = await shell.execute("mkdir /tmp/d && touch /tmp/d/f")
    assert result.output == ""
    assert result.exit_code == 0
    listing = await shell.execute("ls /tmp/d")
    assert "f" in listing.output.split("  ")


async def test_and_chain_short_circuits_on_rm_failure(shell: Shell) -> None:
    result = await shell.execute("rm /nonexistent && touch /tmp/fail")
    assert "No such file or directory" in result.output
    assert result.exit_code != 0
    listing = await shell.execute("ls /tmp")
    assert "fail" not in listing.output.split("  ")


async def test_or_chain_runs_fallback_touch(shell: Shell) -> None:
    result = await shell.execute("rm /nonexistent || touch /tmp/fallback")
    assert "No such file or directory" in result.output
    assert result.exit_code == 0
    listing = await shell.execute("ls /tmp")
    assert "fallback" in listing.output.split("  ")


async def test_mixed_conditionals_and_semicolon(shell: Shell) -> None:
    result = await shell.execute("false && echo no || echo yes; echo always")
    assert result.output == "yes\nalways\n"
    assert "no" not in result.output
    assert result.exit_code == 0
    status = await shell.execute("echo $?")
    assert status.output == "0\n"


async def test_echo_n_redirect_has_no_extra_newline(shell: Shell) -> None:
    written = await shell.execute('echo -n "hello" > /tmp/test.txt')
    assert written.output == ""
    assert written.exit_code == 0
    contents = await shell.execute("cat /tmp/test.txt")
    assert contents.output == "hello"


async def test_append_redirect_after_echo_n(shell: Shell) -> None:
    await shell.execute('echo -n "hello" > /tmp/test.txt')
    appended = await shell.execute('echo "world" >> /tmp/test.txt')
    assert appended.output == ""
    assert appended.exit_code == 0
    contents = await shell.execute("cat /tmp/test.txt")
    assert contents.output == "helloworld\n"


async def test_empty_redirect_creates_zero_byte_file(shell: Shell) -> None:
    result = await shell.execute("> /tmp/empty.txt")
    assert result.output == ""
    assert result.exit_code == 0
    contents = await shell.execute("cat /tmp/empty.txt")
    assert contents.output == ""
    listing = await shell.execute("ls /tmp")
    assert "empty.txt" in listing.output.split("  ")


async def test_redirect_missing_parent_directory(shell: Shell) -> None:
    result = await shell.execute("echo hi > /no/such/file.txt")
    assert result.exit_code == 1
    assert result.output == "bash: /no/such/file.txt: No such file or directory"


async def test_pipeline_echo_grep_matching_line(shell: Shell) -> None:
    result = await shell.execute('echo "line1\nline2" | grep line1')
    assert result.output == "line1\n"
    assert "line2" not in result.output
    assert result.exit_code == 0


async def test_pipeline_cat_issue_grep_ignore_case(shell: Shell) -> None:
    result = await shell.execute("cat /etc/issue | grep -i ubuntu")
    assert result.exit_code == 0
    assert "Ubuntu" in result.output


async def test_quoted_operators_are_literal_text(shell: Shell) -> None:
    result = await shell.execute('echo "hello && world; foo | bar > baz"')
    assert result.output == "hello && world; foo | bar > baz\n"
    assert result.exit_code == 0
    listing = await shell.execute("ls /tmp")
    assert "baz" not in listing.output.split("  ")


async def test_pipeline_unknown_command_receives_stdin(vfs: VirtualFileSystem) -> None:
    provider = RecordingLLMProvider()
    shell = Shell(vfs, llm_provider=provider)
    await shell.execute("echo hello | nosuch")
    assert len(provider.calls) == 1
    command, _cwd, context = provider.calls[0]
    assert command.startswith("nosuch")
    assert "hello" in command
    assert context is not None
    assert context["stdin"] == "hello\n"
