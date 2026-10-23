"""Local / mounted filesystem source: fast scandir walk and hardened, bounded reads."""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..private import (
    WINDOWS,
    change_time_ns,
    extended_path,
    is_link,
    is_placeholder,
    is_placeholder_attributes,
    is_under,
    strip_extended_prefix,
)
from .base import FileRef, ReadError

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


class Excludes:
    """Directory names, file-extension suffixes, and root-relative glob patterns."""

    def __init__(self, dir_names: Iterable[str] = (), extensions: Iterable[str] = (),
                 globs: Iterable[str] = (), file_names: Iterable[str] = ()) -> None:  # fmt: skip
        # case-insensitive: shares expose "$Recycle.Bin" and "$RECYCLE.BIN" alike
        self.dir_names = frozenset(d.strip().lower() for d in dir_names if d.strip())
        self.extensions = tuple(e.strip().lower() for e in extensions if e.strip())
        self.globs = tuple(g.strip() for g in globs if g.strip())
        self.file_names = frozenset(f.strip() for f in file_names if f.strip())

    def dir_excluded(self, name: str, relpath: str) -> bool:
        return name.lower() in self.dir_names or self._glob(relpath) or self._glob(relpath + "/")

    def file_excluded(self, name: str, relpath: str) -> str:
        lower = name.lower()
        if name in self.file_names:
            return "file name"
        if self.extensions and lower.endswith(self.extensions):
            return "extension"
        if self._glob(relpath):
            return "glob"
        return ""

    def _glob(self, relpath: str) -> bool:
        return any(fnmatch.fnmatchcase(relpath, g) for g in self.globs)


class FilesystemSource:
    def __init__(self, roots: Iterable[str | Path], excludes: Excludes, *,
                 max_file_size: int, same_filesystem: bool = False,
                 precise_change_time: bool = False) -> None:  # fmt: skip
        self.roots = [Path(r) for r in roots]
        self.excludes = excludes
        self.max_file_size = max_file_size
        self.same_filesystem = same_filesystem
        self.precise_change_time = precise_change_time

    def __iter__(self) -> Iterator[FileRef]:
        # With several roots, prefix relative paths with the root's name so output trees don't collide.
        multi = len(self.roots) > 1
        for i, root in enumerate(self.roots):
            prefix = f"{i + 1}-{root.resolve().name or 'root'}" if multi else ""
            yield from self._walk_root(root, prefix)

    def _walk_root(self, root: Path, prefix: str = "") -> Iterator[FileRef]:
        def joined(name: str) -> str:
            return f"{prefix}/{name}" if prefix else name

        try:
            st = os.lstat(root)
        except OSError as exc:
            yield FileRef(str(root), joined(root.name), error=f"stat: {exc.strerror or exc}")
            return
        if is_link(st):
            # An explicitly named root may be a symlink or junction (e.g. a mount alias); resolve it once.
            root = root.resolve()
            st = os.stat(root)
        if stat.S_ISREG(st.st_mode):
            real = os.path.realpath(root)
            path, rel = str(root.absolute()), joined(root.name)
            try:
                changed = change_marker(path, st, self.precise_change_time)
            except OSError as exc:
                yield FileRef(path, rel, st.st_size, error=f"stat: {exc.strerror or exc}")
                return
            if is_placeholder(st):
                yield FileRef(path, rel, st.st_size, changed, error="offline_placeholder: data is not stored locally")
            elif st.st_size > self.max_file_size:
                yield FileRef(path, rel, st.st_size, changed, error=f"too_large: {st.st_size} bytes")
            else:
                yield FileRef(path, rel, st.st_size, changed, root=real)
            return
        if not stat.S_ISDIR(st.st_mode):
            yield FileRef(str(root), joined(root.name), excluded="special file")
            return

        # Windows: normalized once here (the user typed it), because the names below the root are
        # opened in \\?\ form, which takes "..", "." and trailing dots literally.
        root_abs = os.path.abspath(root) if WINDOWS else str(root.absolute())
        root_real = os.path.realpath(root)
        root_dev = st.st_dev
        cwd = os.getcwd()
        seen: set[tuple[int, int]] = {(st.st_dev, st.st_ino)}
        stack: list[tuple[str, str]] = [(root_abs, prefix)]
        while stack:
            dir_path, dir_rel = stack.pop()
            try:
                # Windows: list the exact name. A plain path drops a trailing dot or space, so
                # "dir." would list its sibling "dir" and the files only in "dir." would be missed.
                it = os.scandir(extended_path(dir_path, cwd) if WINDOWS else dir_path)
            except OSError as exc:
                yield FileRef(dir_path, dir_rel or ".", error=f"list: {exc.strerror or exc}")
                continue
            subdirs: list[tuple[str, str]] = []
            with it:
                for entry in it:
                    # Windows: entry.path would carry the \\?\ prefix; keep plain paths in results
                    # (every open adds the prefix back, so the name is still used exactly).
                    path = os.path.join(dir_path, entry.name) if WINDOWS else entry.path
                    rel = f"{dir_rel}/{entry.name}" if dir_rel else entry.name
                    grel = rel[len(prefix) + 1:] if prefix else rel  # globs match relative to this root
                    try:
                        est = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        yield FileRef(path, rel, error=f"stat: {exc.strerror or exc}")
                        continue
                    if is_link(est):  # symlinks, and on Windows junctions and other name surrogates
                        yield FileRef(path, rel, excluded="symlink")
                        continue
                    mode = est.st_mode
                    if stat.S_ISDIR(mode):
                        if self.excludes.dir_excluded(entry.name, grel):
                            continue
                        if is_placeholder(est):  # listing a cloud folder placeholder would download it
                            yield FileRef(path, rel, error="offline_placeholder: data is not stored locally")
                            continue
                        # DirEntry.stat() reports st_dev as 0 on Windows; lstat has the volume
                        dev = est.st_dev
                        if WINDOWS and self.same_filesystem:
                            try:
                                dev = os.lstat(extended_path(path, cwd)).st_dev
                            except OSError as exc:
                                yield FileRef(path, rel, error=f"stat: {exc.strerror or exc}")
                                continue
                        if self.same_filesystem and dev != root_dev:
                            yield FileRef(path, rel, excluded="different filesystem")
                            continue
                        key = (est.st_dev, est.st_ino)
                        if est.st_ino and key in seen:
                            continue
                        seen.add(key)
                        subdirs.append((path, rel))
                    elif stat.S_ISREG(mode):
                        reason = self.excludes.file_excluded(entry.name, grel)
                        try:
                            # an excluded file is never read, so it isn't opened for its change time
                            changed = change_marker(path, est, self.precise_change_time and not reason)
                        except OSError as exc:
                            yield FileRef(path, rel, error=f"stat: {exc.strerror or exc}")
                            continue
                        if reason:
                            yield FileRef(path, rel, est.st_size, changed, excluded=reason)
                        elif is_placeholder(est):
                            yield FileRef(path, rel, est.st_size, changed,
                                          error="offline_placeholder: data is not stored locally")  # fmt: skip
                        elif est.st_size > self.max_file_size:
                            yield FileRef(path, rel, est.st_size, changed,
                                          error=f"too_large: {est.st_size} bytes")  # fmt: skip
                        else:
                            yield FileRef(path, rel, est.st_size, changed, root=root_real)
                    else:
                        yield FileRef(path, rel, excluded="special file")
            # Sorted, depth-first: deterministic order without holding the whole tree in memory.
            stack.extend(sorted(subdirs, reverse=True))

    def read(self, ref: FileRef, max_bytes: int) -> bytes:
        return read_regular_file(ref.path, max_bytes, root=ref.root)


def change_marker(path: str, st: os.stat_result, precise: bool) -> int:
    """Change marker for the resume cache: ctime also moves when someone restores an old mtime.

    On Windows st_ctime is the creation time, so `precise` (set when a cache will use the marker)
    reads NTFS ChangeTime instead, at the cost of one extra open per file.
    """
    if precise:
        return change_time_ns(path, st)
    return max(st.st_mtime_ns, st.st_ctime_ns)


def _fd_realpath(fd: int) -> str | None:
    """Real path of an open descriptor, or None where the platform can't tell us."""
    try:
        if sys.platform == "darwin":
            import fcntl

            buf = fcntl.fcntl(fd, 50, b"\0" * 1024)  # F_GETPATH
            return os.fsdecode(buf.split(b"\0", 1)[0])
        if sys.platform.startswith("linux"):
            return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None
    return None


def _open_posix(path: str, root: str) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC | _O_BINARY)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)):
            raise ReadError("symlink") from exc
        raise ReadError("open_failed", exc.strerror or str(exc)) from exc
    try:
        if root:
            real = _fd_realpath(fd)
            if real is not None and not is_under(real, root):
                raise ReadError("outside_root")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_windows(path: str, root: str) -> int:
    """Windows has no O_NOFOLLOW: open the path itself without following links (see winapi)."""
    from .. import winapi

    try:
        fd, final, is_disk, attributes = winapi.open_for_reading(path)
    except winapi.LinkRefused as exc:
        raise ReadError("symlink") from exc
    except OSError as exc:
        raise ReadError("open_failed", exc.strerror or str(exc)) from exc
    try:
        if is_placeholder_attributes(attributes):
            raise ReadError("offline_placeholder", "data is not stored locally")
        if attributes & stat.FILE_ATTRIBUTE_DIRECTORY or not is_disk:
            raise ReadError("not_regular_file")
        if root and not is_under(strip_extended_prefix(final), strip_extended_prefix(root)):
            raise ReadError("outside_root")
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_regular_file(path: str, max_bytes: int, *, root: str = "") -> bytes:
    """Open without following links or blocking on FIFOs; read at most `max_bytes`.

    With `root`, the opened file must really live under that directory (or be that file), which
    stops a parent directory swapped for a symlink or junction during the scan from redirecting
    the read.
    """
    fd = _open_windows(path, root) if WINDOWS else _open_posix(path, root)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReadError("not_regular_file")
        if is_placeholder(st):  # macOS dataless file: reading it would start a download
            raise ReadError("offline_placeholder", "data is not stored locally")
        if st.st_size > max_bytes:
            raise ReadError("too_large", f"{st.st_size} bytes")
        if _O_NONBLOCK:
            os.set_blocking(fd, True)
        parts: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            buf = os.read(fd, min(remaining, 1 << 20))
            if not buf:
                break
            parts.append(buf)
            remaining -= len(buf)
        data = b"".join(parts)
        if len(data) > max_bytes:
            raise ReadError("too_large", "file grew while reading")
        return data
    except OSError as exc:
        raise ReadError("read_failed", exc.strerror or str(exc)) from exc
    finally:
        os.close(fd)
