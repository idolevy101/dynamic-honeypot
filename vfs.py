"""In-memory virtual filesystem for simulated Linux shell sessions.

All nodes live in process memory. Path resolution never touches the host disk.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final

HOSTNAME: Final[str] = "ubuntu-srv"
DEFAULT_HOME: Final[str] = "/root"
KERNEL_RELEASE: Final[str] = "5.15.0-88-generic"
KERNEL_VERSION: Final[str] = "#98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023"
UNAME_A: Final[str] = " ".join(
    (
        "Linux",
        HOSTNAME,
        KERNEL_RELEASE,
        KERNEL_VERSION,
        "x86_64",
        "x86_64",
        "x86_64",
        "GNU/Linux",
    )
)
_DEFAULT_MTIME: Final[datetime] = datetime(2024, 4, 10, 9, 15, tzinfo=timezone.utc)

OS_RELEASE: Final[str] = """\
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""

ISSUE: Final[str] = "Ubuntu 22.04.3 LTS \\n \\l\n"

PROC_VERSION: Final[str] = (
    f"Linux version {KERNEL_RELEASE} (buildd@lcy02-amd64-044) "
    "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
    f"{KERNEL_VERSION}\n"
)

_CPUINFO_FLAGS: Final[str] = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
    "clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc "
    "rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 "
    "fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave "
    "avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single "
    "pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid "
    "mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl "
    "xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke"
)


def _cpuinfo_block(processor: int) -> str:
    return f"""\
processor	: {processor}
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
stepping	: 7
microcode	: 0x5003306
cpu MHz		: 2499.998
cache size	: 36608 KB
physical id	: 0
siblings	: 2
core id		: {processor}
cpu cores	: 2
apicid		: {processor}
initial apicid	: {processor}
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: {_CPUINFO_FLAGS}
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit mmio_stale_data
bogomips	: 4999.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:
"""


PROC_CPUINFO: Final[str] = _cpuinfo_block(0) + "\n" + _cpuinfo_block(1)

PROC_MEMINFO: Final[str] = """\
MemTotal:        4016332 kB
MemFree:         2891456 kB
MemAvailable:    3210340 kB
Buffers:          126844 kB
Cached:           412768 kB
SwapCached:            0 kB
Active:           524288 kB
Inactive:         312456 kB
Active(anon):     287104 kB
Inactive(anon):    10240 kB
Active(file):     237184 kB
Inactive(file):   302216 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                64 kB
Writeback:             0 kB
AnonPages:        289012 kB
Mapped:            89432 kB
Shmem:              2560 kB
KReclaimable:      98416 kB
Slab:             142336 kB
SReclaimable:      98416 kB
SUnreclaim:        43920 kB
KernelStack:        4096 kB
PageTables:         5120 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     2008164 kB
Committed_AS:     612448 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       12352 kB
VmallocChunk:          0 kB
Percpu:             1024 kB
HardwareCorrupted:     0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      122880 kB
DirectMap2M:     4063232 kB
DirectMap1G:           0 kB
"""

PROC_NET_DEV: Final[str] = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  152384     182    0    0    0     0          0         0   152384     182    0    0    0     0       0          0
  eth0: 8472192    6234    0    0    0     0          0         0  2156032    4102    0    0    0     0       0          0
"""

RESOLV_CONF: Final[str] = """\
nameserver 127.0.0.53
options edns0 trust-ad
search .
"""

PASSWD: Final[str] = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""

BASH_HISTORY: Final[str] = """\
apt-get update
apt-get install -y nginx
systemctl status nginx
vim /etc/nginx/sites-available/default
ss -tulpn
journalctl -u ssh
tail -n 50 /var/log/auth.log
chmod 600 /root/.ssh/authorized_keys
ufw allow OpenSSH
"""


@dataclass
class INode:
    """Base metadata for a virtual filesystem node."""

    name: str
    mode: int
    uid: int = 0
    gid: int = 0
    owner: str = "root"
    group: str = "root"
    mtime: datetime = _DEFAULT_MTIME

    @property
    def size(self) -> int:
        return 0

    @property
    def nlink(self) -> int:
        return 1


@dataclass
class VFSFile(INode):
    """Regular file whose contents live entirely in memory."""

    content: str = ""

    @property
    def size(self) -> int:
        return len(self.content.encode("utf-8"))


@dataclass
class VFSDirectory(INode):
    """Directory node holding named child inodes."""

    children: dict[str, INode] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return 4096

    @property
    def nlink(self) -> int:
        subdirs = sum(1 for child in self.children.values() if isinstance(child, VFSDirectory))
        return 2 + subdirs


def canonicalize(path: str, cwd: str, home: str = DEFAULT_HOME) -> str:
    """Resolve ``path`` against ``cwd`` and collapse ``.`` / ``..`` inside ``/``."""
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    elif path == "-":
        return path
    if not path.startswith("/"):
        base = cwd if cwd != "/" else ""
        path = f"{base}/{path}"
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def parent_path(abs_path: str) -> str:
    if abs_path == "/":
        return "/"
    parent, _sep, _name = abs_path.rstrip("/").rpartition("/")
    return parent if parent else "/"


def _directory(name: str, *children: INode, mode: int = 0o755) -> VFSDirectory:
    node = VFSDirectory(name=name, mode=mode)
    for child in children:
        node.children[child.name] = child
    return node


def _file(name: str, content: str, mode: int = 0o644) -> VFSFile:
    return VFSFile(name=name, content=content, mode=mode)


def build_honeypot_tree() -> VFSDirectory:
    """Populate the default Ubuntu-like honeypot tree (never touches the host disk)."""
    etc = _directory(
        "etc",
        _file("os-release", OS_RELEASE),
        _file("issue", ISSUE),
        _file("passwd", PASSWD),
        _file("hostname", f"{HOSTNAME}\n"),
        _file("resolv.conf", RESOLV_CONF),
    )
    proc = _directory(
        "proc",
        _file("version", PROC_VERSION),
        _file("cpuinfo", PROC_CPUINFO),
        _file("meminfo", PROC_MEMINFO),
        _directory("net", _file("dev", PROC_NET_DEV)),
    )
    root_home = _directory(
        "root",
        _file(".bash_history", BASH_HISTORY, mode=0o600),
        mode=0o700,
    )
    home = _directory("home", _directory("ubuntu", mode=0o755))
    return _directory(
        "",
        _directory("bin"),
        etc,
        home,
        proc,
        root_home,
        _directory("tmp", mode=0o1777),
        _directory("var", _directory("log")),
    )


def apply_chmod_mode(current: int, spec: str) -> int:
    """Return permission bits after applying octal or symbolic ``spec``."""
    stripped = spec.strip()
    if not stripped:
        raise ValueError(spec)
    if all(char in "01234567" for char in stripped):
        if len(stripped) > 4:
            raise ValueError(spec)
        return int(stripped, 8) & 0o7777
    result = current & 0o7777
    for clause in stripped.split(","):
        result = _apply_symbolic_clause(result, clause)
    return result


def _apply_symbolic_clause(current: int, clause: str) -> int:
    if not clause:
        raise ValueError(clause)
    index = 0
    who_chars: list[str] = []
    while index < len(clause) and clause[index] in "ugoa":
        who_chars.append(clause[index])
        index += 1
    if index >= len(clause) or clause[index] not in "+-=":
        raise ValueError(clause)
    op = clause[index]
    perms = clause[index + 1 :]
    if any(char not in "rwxst" for char in perms):
        raise ValueError(clause)
    subjects = {"u", "g", "o"} if (not who_chars or "a" in who_chars) else set(who_chars)
    bit_map = {
        ("u", "r"): 0o400,
        ("u", "w"): 0o200,
        ("u", "x"): 0o100,
        ("u", "s"): 0o4000,
        ("g", "r"): 0o040,
        ("g", "w"): 0o020,
        ("g", "x"): 0o010,
        ("g", "s"): 0o2000,
        ("o", "r"): 0o004,
        ("o", "w"): 0o002,
        ("o", "x"): 0o001,
        ("o", "t"): 0o1000,
    }
    delta = 0
    for subject in subjects:
        for perm in perms:
            key = ("o", "t") if perm == "t" else (subject, perm)
            delta |= bit_map.get(key, 0)
    who_mask = 0
    if "u" in subjects:
        who_mask |= 0o4700
    if "g" in subjects:
        who_mask |= 0o2070
    if "o" in subjects:
        who_mask |= 0o1007
    if op == "+":
        return current | delta
    if op == "-":
        return current & ~delta
    return (current & ~who_mask) | delta


def create_default_vfs() -> VirtualFileSystem:
    """Return an isolated default honeypot tree (no shared inode references)."""
    return VirtualFileSystem()


class VirtualFileSystem:
    """In-memory Linux-like filesystem with path resolution relative to a cwd."""

    def __init__(
        self,
        root: VFSDirectory | None = None,
        *,
        home: str = DEFAULT_HOME,
    ) -> None:
        self._root = root if root is not None else build_honeypot_tree()
        self.home = home

    def clone(self) -> VirtualFileSystem:
        """Deep-copy this tree so mutations never leak across sessions."""
        return VirtualFileSystem(deepcopy(self._root), home=self.home)

    def resolve(self, path: str, cwd: str) -> INode:
        """Return the inode at ``path``, raising POSIX-style errors on failure."""
        abs_path = canonicalize(path, cwd, self.home)
        if abs_path == "/":
            return self._root
        node: INode = self._root
        parts = abs_path.strip("/").split("/")
        for index, part in enumerate(parts):
            if not isinstance(node, VFSDirectory):
                raise NotADirectoryError("/" + "/".join(parts[:index]))
            child = node.children.get(part)
            if child is None:
                raise FileNotFoundError(abs_path)
            node = child
        return node

    def read_file(self, path: str, cwd: str) -> str:
        node = self.resolve(path, cwd)
        if isinstance(node, VFSDirectory):
            raise IsADirectoryError(canonicalize(path, cwd, self.home))
        if not isinstance(node, VFSFile):
            raise FileNotFoundError(canonicalize(path, cwd, self.home))
        return node.content

    def list_dir(self, path: str, cwd: str) -> list[str]:
        node = self.resolve(path, cwd)
        if not isinstance(node, VFSDirectory):
            raise NotADirectoryError(canonicalize(path, cwd, self.home))
        return sorted(node.children)

    def is_dir(self, path: str, cwd: str) -> bool:
        try:
            return isinstance(self.resolve(path, cwd), VFSDirectory)
        except (FileNotFoundError, NotADirectoryError):
            return False

    def exists(self, path: str, cwd: str) -> bool:
        try:
            self.resolve(path, cwd)
        except (FileNotFoundError, NotADirectoryError):
            return False
        return True

    def get(self, path: str, cwd: str) -> INode:
        return self.resolve(path, cwd)

    def touch(self, path: str, cwd: str) -> None:
        """Create an empty file if missing; update mtime when the node exists."""
        abs_path = canonicalize(path, cwd, self.home)
        if abs_path == "/":
            self._root.mtime = datetime.now(timezone.utc)
            return
        directory = self.resolve(parent_path(abs_path), "/")
        if not isinstance(directory, VFSDirectory):
            raise NotADirectoryError(parent_path(abs_path))
        name = abs_path.rsplit("/", 1)[-1]
        existing = directory.children.get(name)
        now = datetime.now(timezone.utc)
        if existing is None:
            directory.children[name] = VFSFile(name=name, content="", mode=0o644, mtime=now)
            return
        existing.mtime = now

    def touch_file(self, path: str, cwd: str) -> None:
        self.touch(path, cwd)

    def write_file(self, path: str, content: str, cwd: str, append: bool = False) -> None:
        abs_path = canonicalize(path, cwd, self.home)
        if abs_path == "/":
            raise IsADirectoryError("/")
        parent = parent_path(abs_path)
        directory = self.resolve(parent, "/")
        if not isinstance(directory, VFSDirectory):
            raise NotADirectoryError(parent)
        name = abs_path.rsplit("/", 1)[-1]
        existing = directory.children.get(name)
        now = datetime.now(timezone.utc)
        if existing is not None:
            if isinstance(existing, VFSDirectory):
                raise IsADirectoryError(abs_path)
            if not isinstance(existing, VFSFile):
                raise IsADirectoryError(abs_path)
            existing.content = existing.content + content if append else content
            existing.mtime = now
            return
        directory.children[name] = VFSFile(name=name, content=content, mode=0o644, mtime=now)

    def mkdir(self, path: str, cwd: str, parents: bool = False, mode: int = 0o755) -> bool:
        abs_path = canonicalize(path, cwd, self.home)
        if abs_path == "/":
            if parents:
                return True
            raise FileExistsError("/")
        now = datetime.now(timezone.utc)
        if parents:
            node: INode = self._root
            parts = abs_path.strip("/").split("/")
            for index, part in enumerate(parts):
                if not isinstance(node, VFSDirectory):
                    raise NotADirectoryError("/" + "/".join(parts[:index]))
                child = node.children.get(part)
                if child is None:
                    created = VFSDirectory(name=part, mode=mode, mtime=now)
                    node.children[part] = created
                    node = created
                    continue
                node = child
            if not isinstance(node, VFSDirectory):
                raise FileExistsError(abs_path)
            return True
        parent = parent_path(abs_path)
        try:
            directory = self.resolve(parent, "/")
        except FileNotFoundError as exc:
            raise FileNotFoundError(parent) from exc
        if not isinstance(directory, VFSDirectory):
            raise NotADirectoryError(parent)
        name = abs_path.rsplit("/", 1)[-1]
        if name in directory.children:
            raise FileExistsError(abs_path)
        directory.children[name] = VFSDirectory(name=name, mode=mode, mtime=now)
        return True

    def remove(
        self,
        path: str,
        cwd: str,
        recursive: bool = False,
        force: bool = False,
    ) -> bool:
        abs_path = canonicalize(path, cwd, self.home)
        if abs_path == "/":
            raise OSError("Directory not empty")
        parent = parent_path(abs_path)
        try:
            directory = self.resolve(parent, "/")
        except FileNotFoundError:
            if force:
                return True
            raise
        if not isinstance(directory, VFSDirectory):
            raise NotADirectoryError(parent)
        name = abs_path.rsplit("/", 1)[-1]
        node = directory.children.get(name)
        if node is None:
            if force:
                return True
            raise FileNotFoundError(abs_path)
        if isinstance(node, VFSDirectory) and not recursive:
            raise IsADirectoryError(abs_path)
        del directory.children[name]
        return True

    def rmdir(self, path: str, cwd: str) -> None:
        abs_path = canonicalize(path, cwd, self.home)
        if abs_path == "/":
            raise OSError("Directory not empty")
        parent = parent_path(abs_path)
        directory = self.resolve(parent, "/")
        if not isinstance(directory, VFSDirectory):
            raise NotADirectoryError(parent)
        name = abs_path.rsplit("/", 1)[-1]
        node = directory.children.get(name)
        if node is None:
            raise FileNotFoundError(abs_path)
        if not isinstance(node, VFSDirectory):
            raise NotADirectoryError(abs_path)
        if node.children:
            raise OSError("Directory not empty")
        del directory.children[name]

    def chmod(self, path: str, mode: str, cwd: str) -> None:
        node = self.resolve(path, cwd)
        node.mode = apply_chmod_mode(node.mode, mode)
