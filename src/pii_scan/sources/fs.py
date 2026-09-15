"""Local / mounted filesystem source: fast scandir walk and hardened, bounded reads."""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path

from .base import FileRef, ReadError

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


class Excludes:
    """Directory names, file-extension suffixes, and root-relative glob patterns."""

    def __init__(self, dir_names: Iterable[str] = (), extensions: Iterable[str] = (),
                 globs: Iterable[str] = (), file_names: Iterable[str] = ()) -> None:  # fmt: skip
        self.dir_names = frozenset(d.strip() for d in dir_names if d.strip())
        self.extensions = tuple(e.strip().lower() for e in extensions if e.strip())
        self.globs = tuple(g.strip() for g in globs if g.strip())
        self.file_names = frozenset(f.strip() for f in file_names if f.strip())

    def dir_excluded(self, name: str, relpath: str) -> bool:
        return name in self.dir_names or self._glob(relpath) or self._glob(relpath + "/")

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
                 max_file_size: int, same_filesystem: bool = False) -> None:  # fmt: skip
        self.roots = [Path(r) for r in roots]
        self.excludes = excludes
        self.max_file_size = max_file_size
        self.same_filesystem = same_filesystem

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
        if stat.S_ISLNK(st.st_mode):
            # An explicitly named root may be a symlink (e.g. a mount alias); resolve it once.
            root = root.resolve()
            st = os.stat(root)
        if stat.S_ISREG(st.st_mode):
            if st.st_size > self.max_file_size:
                yield FileRef(str(root.absolute()), joined(root.name), st.st_size, st.st_mtime_ns,
                              error=f"too_large: {st.st_size} bytes")  # fmt: skip
            else:
                yield FileRef(str(root.absolute()), joined(root.name), st.st_size, st.st_mtime_ns)
            return
        if not stat.S_ISDIR(st.st_mode):
            yield FileRef(str(root), joined(root.name), excluded="special file")
            return

        root_abs = str(root.absolute())
        root_dev = st.st_dev
        seen: set[tuple[int, int]] = {(st.st_dev, st.st_ino)}
        stack: list[tuple[str, str]] = [(root_abs, prefix)]
        while stack:
            dir_path, dir_rel = stack.pop()
            try:
                it = os.scandir(dir_path)
            except OSError as exc:
                yield FileRef(dir_path, dir_rel or ".", error=f"list: {exc.strerror or exc}")
                continue
            subdirs: list[tuple[str, str]] = []
            with it:
                for entry in it:
                    rel = f"{dir_rel}/{entry.name}" if dir_rel else entry.name
                    try:
                        if entry.is_symlink():
                            yield FileRef(entry.path, rel, excluded="symlink")
                            continue
                        est = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        yield FileRef(entry.path, rel, error=f"stat: {exc.strerror or exc}")
                        continue
                    mode = est.st_mode
                    if stat.S_ISDIR(mode):
                        if self.excludes.dir_excluded(entry.name, rel):
                            continue
                        if self.same_filesystem and est.st_dev != root_dev:
                            yield FileRef(entry.path, rel, excluded="different filesystem")
                            continue
                        key = (est.st_dev, est.st_ino)
                        if est.st_ino and key in seen:
                            continue
                        seen.add(key)
                        subdirs.append((entry.path, rel))
                    elif stat.S_ISREG(mode):
                        reason = self.excludes.file_excluded(entry.name, rel)
                        if reason:
                            yield FileRef(entry.path, rel, est.st_size, est.st_mtime_ns, excluded=reason)
                        elif est.st_size > self.max_file_size:
                            yield FileRef(entry.path, rel, est.st_size, est.st_mtime_ns,
                                          error=f"too_large: {est.st_size} bytes")  # fmt: skip
                        else:
                            yield FileRef(entry.path, rel, est.st_size, est.st_mtime_ns)
                    else:
                        yield FileRef(entry.path, rel, excluded="special file")
            # Sorted, depth-first: deterministic order without holding the whole tree in memory.
            stack.extend(sorted(subdirs, reverse=True))

    def read(self, ref: FileRef, max_bytes: int) -> bytes:
        return read_regular_file(ref.path, max_bytes)


def read_regular_file(path: str, max_bytes: int) -> bytes:
    """Open without following symlinks or blocking on FIFOs; read at most `max_bytes`."""
    if not _O_NOFOLLOW and os.path.islink(path):  # platforms without O_NOFOLLOW (Windows)
        raise ReadError("symlink")
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC | _O_BINARY)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)):
            raise ReadError("symlink") from exc
        raise ReadError("open_failed", exc.strerror or str(exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReadError("not_regular_file")
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
