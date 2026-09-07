"""In-memory virtual filesystem for simulated Linux shell sessions.

All nodes live in process memory. Path resolution never touches the host disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final

HOSTNAME: Final[str] = "ubuntu-srv"
DEFAULT_HOME: Final[str] = "/root"
_DEFAULT_MTIME: Final[datetime] = datetime(2024, 4, 10, 9, 15, tzinfo=timezone.utc)

OS_RELEASE: Final[str] = """\
PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
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
        _file("passwd", PASSWD),
        _file("hostname", f"{HOSTNAME}\n"),
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
        root_home,
        _directory("tmp", mode=0o1777),
        _directory("var", _directory("log")),
    )


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
