"""File-system safety that differs by platform: owner-only permissions, links, cloud placeholders,
and names Windows can't store.

POSIX gets these from mode bits and `O_NOFOLLOW`; Windows needs ACLs and reparse-point attributes
(see `winapi`). The pure functions here take stat results or names, so they are tested everywhere.
"""

from __future__ import annotations

import errno
import ntpath
import os
import stat
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"

# Reparse tags with this bit redirect to another name (symlinks, junctions, mount points).
_NAME_SURROGATE = 0x20000000
# OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS: cloud or HSM placeholders whose data isn't local;
# reading one starts a download (or fails), so it is reported as not scanned instead.
_PLACEHOLDER_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000
# macOS SF_DATALESS: a File Provider placeholder (iCloud Drive and similar).
_SF_DATALESS = 0x40000000


def is_link_attributes(attributes: int, reparse_tag: int) -> bool:
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT) and bool(reparse_tag & _NAME_SURROGATE)


def is_link(st: os.stat_result) -> bool:
    """A symlink, or on Windows any name-surrogate reparse point (junctions included)."""
    if stat.S_ISLNK(st.st_mode):
        return True
    return is_link_attributes(getattr(st, "st_file_attributes", 0), getattr(st, "st_reparse_tag", 0))


def is_placeholder_attributes(attributes: int) -> bool:
    return bool(attributes & _PLACEHOLDER_ATTRIBUTES)


def is_placeholder(st: os.stat_result) -> bool:
    return is_placeholder_attributes(getattr(st, "st_file_attributes", 0)) or bool(
        getattr(st, "st_flags", 0) & _SF_DATALESS)


def make_private(path: str | Path, mode: int) -> None:
    """Owner-only access by name: `mode` on POSIX, a protected owner-and-SYSTEM ACL on Windows.

    For files and directories pii-scan has just created; prefer `make_private_fd` for open files.
    """
    if WINDOWS:
        from .winapi import make_private as protect

        protect(str(path), directory=os.path.isdir(path))
    else:
        os.chmod(path, mode)


def make_private_fd(fd: int, mode: int) -> None:
    """Owner-only access for an open regular file. Devices and pipes (/dev/null, NUL) are left alone."""
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        return
    if WINDOWS:
        from .winapi import make_private_fd as protect

        protect(fd)
    else:
        os.fchmod(fd, mode)


def create_private_file(path: str | Path, mode: int) -> int:
    """Create a new file, owner-only from its first moment, never following a link. Returns an fd.

    FileExistsError if anything is already there. On POSIX the umask can only remove bits from
    `mode`, so the file is never more open than requested before the fchmod.
    """
    if WINDOWS:
        from .winapi import create_private_file as create

        return create(str(path))
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def create_private_dir(path: str | Path, mode: int) -> None:
    """Create a directory, owner-only from its first moment. FileExistsError if anything is there."""
    if WINDOWS:
        from .winapi import create_private_dir as create

        create(str(path))
    else:
        os.mkdir(path, mode)
        os.chmod(path, mode)  # undo the umask; it can only have removed bits


# Windows ERROR_FILE_NOT_FOUND and ERROR_PATH_NOT_FOUND
_NOT_FOUND_WINERRORS = (2, 3)


def is_gone(exc: OSError) -> bool:
    """The file (or a parent directory) no longer exists. Any other error, such as access denied
    or a sharing violation, means the file is there but could not be examined."""
    return isinstance(exc, FileNotFoundError) or getattr(exc, "winerror", None) in _NOT_FOUND_WINERRORS


def make_private_dirs(path: Path) -> None:
    """Create every missing directory as owner-only (mkdir(parents=True) only applies a mode to the last)."""
    missing: list[Path] = []
    p = path
    while not p.exists():
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        try:
            create_private_dir(d, 0o700)
        except FileExistsError:
            # created concurrently, possibly by someone else: it must at least not be a link
            if is_link(os.lstat(d)):
                raise OSError(f"refusing to write through a symlink or junction: {d}") from None


def change_time_ns(path: str, st: os.stat_result) -> int:
    """When the file last changed: max(mtime, ctime) on POSIX, where ctime moves on every change.

    On Windows st_ctime is the creation time, so NTFS ChangeTime is read instead; otherwise a file
    edited and given back its old mtime would look unchanged to the resume cache.
    """
    if WINDOWS:
        from .winapi import change_time_ns as change_time

        return max(st.st_mtime_ns, change_time(path))
    return max(st.st_mtime_ns, st.st_ctime_ns)


def extended_path(path: str, cwd: str) -> str:
    r"""The `\\?\` form of a Windows path, which Win32 passes to the file system unchanged.

    Without it, `secret.` and `secret ` open `secret`, a file named `NUL` opens the device, and
    paths over MAX_PATH fail. The `\\?\` form takes `.` and `..` literally, so the path is made
    absolute (joined to `cwd`) and `.`/`..` are resolved first, lexically: `ntpath.normpath` keeps
    trailing dots and spaces, unlike `os.path.abspath` on Windows (GetFullPathName drops them).
    """
    path = path.replace("/", "\\")  # so "//?/C:/x" is recognized below, not taken for a UNC path
    if path.startswith(("\\\\?\\", "\\\\.\\")):  # already exact, or a device path
        return path
    cwd = strip_extended_prefix(cwd)
    drive, rest = ntpath.splitdrive(path)
    if not drive:  # relative, or rooted on the current drive (\data; isabs differs by version)
        path = ntpath.join(cwd, path)
    elif drive[1:] == ":" and not rest.startswith(("\\", "/")):  # "C:notes.txt": relative to C:'s cwd
        if ntpath.splitdrive(cwd)[0].upper() != drive.upper():
            raise OSError(errno.EINVAL, "drive-relative paths on another drive are not supported", path)
        path = ntpath.join(cwd, rest)
    path = ntpath.normpath(path)
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def strip_extended_prefix(path: str) -> str:
    r"""`\\?\C:\x` -> `C:\x`, `\\?\UNC\srv\share` -> `\\srv\share` (GetFinalPathNameByHandle output)."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def is_under(path: str, root: str) -> bool:
    """`path` is `root` or inside it, compared the way the platform compares names."""
    path, root = os.path.normcase(path), os.path.normcase(root).rstrip("\\/")
    return path == root or path.startswith(root + os.sep)


_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{dev}{n}" for dev in ("COM", "LPT") for n in (*"0123456789", "¹", "²", "³")}
)
_FORBIDDEN_CHARS = frozenset('<>:"|?*\\') | {chr(c) for c in range(32)}


def windows_name_problem(name: str) -> str:
    """Why Windows can't store a file or directory called `name`, or "" if it can.

    A colon would write an alternate data stream, a device name would open the device, and a
    trailing dot or space is silently dropped, so the copy would land under another name.
    """
    if name in ("", ".", ".."):
        return ""
    if set(name) & _FORBIDDEN_CHARS:
        return "contains a character Windows does not allow in file names"
    if name[-1] in ". ":
        return "ends with a dot or space"
    if name.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_NAMES:
        return "is a reserved Windows device name"
    return ""
