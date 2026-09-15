"""Changed files from git, invoked defensively (the repository content is untrusted)."""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path

from .base import FileRef, ReadError
from .fs import Excludes, read_regular_file

_HARDENING = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.quotePath=false",
    "-c", "diff.external=",
    "-c", "protocol.allow=never",
    "--no-optional-locks",
]  # fmt: skip


class GitError(Exception):
    pass


def _git(cwd: Path, *args: str) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        proc = subprocess.run(
            ["git", *_HARDENING, *args], cwd=cwd, env=env, capture_output=True, timeout=120, check=False
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.decode("utf-8", "replace").strip() or f"git {args[0]} failed")
    return proc.stdout


def resolve_base(top: Path, base: str | None) -> str:
    """An explicit base wins; otherwise use the GitHub PR base, then origin's default branch."""
    candidates: list[str] = []
    if base:
        candidates.append(base)
    else:
        if os.environ.get("GITHUB_BASE_REF"):
            candidates.append(f"origin/{os.environ['GITHUB_BASE_REF']}")
        try:
            head = _git(top, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD").decode().strip()
            candidates.append(head.removeprefix("refs/remotes/"))
        except GitError:
            pass
        candidates += ["origin/main", "origin/master"]
    for ref in candidates:
        if ref.strip("0") == "":  # all-zero SHA from a new-branch push event
            continue
        try:
            return _git(top, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").decode().strip()
        except GitError:
            continue
    raise GitError(
        "cannot determine the git base to diff against. Fix: pass --base <ref> "
        "(in GitHub Actions use the PR base SHA or github.event.before), or use --all."
    )


_LFS_VALUES = {
    "filter.lfs.clean": "git-lfs clean -- %f", "filter.lfs.smudge": "git-lfs smudge -- %f",
    "filter.lfs.process": "git-lfs filter-process", "filter.lfs.required": "true",
}  # fmt: skip


def _risky_config_keys(top: Path) -> list[str]:
    """Repository-level git settings that could make `git diff` run commands.

    Global and system config are the operator's own; repository config on a share or in a
    downloaded repo is attacker-controlled. Config files are read with --file, which never follows
    includes or runs anything.
    """
    common = Path(_git(top, "rev-parse", "--git-common-dir").decode().strip())
    gitdir = common if common.is_absolute() else top / common
    risky: list[str] = []
    for cfg in (gitdir / "config", gitdir / "config.worktree"):
        if not cfg.is_file():
            continue
        out = _git(top, "config", "--file", str(cfg), "--null", "--list").decode("utf-8", "replace")
        for entry in filter(None, out.split("\0")):
            name, _, value = entry.partition("\n")
            key = name.lower()
            if key in _LFS_VALUES and value.strip() == _LFS_VALUES[key]:
                continue
            if (key.startswith(("filter.", "include.", "includeif.")) or key in {
                "core.fsmonitor", "core.worktree", "core.sshcommand", "core.askpass", "diff.external",
            } or (key.startswith("diff.") and key.endswith((".textconv", ".command")))):  # fmt: skip
                risky.append(name)
    return sorted(set(risky))


class GitChangedSource:
    def __init__(self, path: Path, base: str | None, excludes: Excludes, *, max_file_size: int,
                 trust_repo: bool = False) -> None:  # fmt: skip
        self.path = path.resolve()
        cwd = self.path if self.path.is_dir() else self.path.parent
        self.top = Path(_git(cwd, "rev-parse", "--show-toplevel").decode().strip()).resolve()
        if not trust_repo:
            risky = _risky_config_keys(self.top)
            if risky:
                raise GitError(
                    f"the repository's git config sets {', '.join(risky[:5])}, which could run commands during "
                    "the diff. Review .git/config and rerun with --trust-repo"
                )
        self.base = resolve_base(self.top, base)
        self.excludes = excludes
        self.max_file_size = max_file_size

    def changed_paths(self) -> list[str]:
        """Committed, staged, unstaged, and untracked changes relative to the merge base.

        In CI the working tree equals HEAD, so this is the same as `base...HEAD`; locally it also
        covers work that has not been committed yet.
        """
        merge_base = _git(self.top, "merge-base", self.base, "HEAD").decode().strip()
        tracked = _git(self.top, "diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT",
                       merge_base, "--")  # fmt: skip
        untracked = _git(self.top, "ls-files", "--others", "--exclude-standard", "-z", "--")
        names = [os.fsdecode(raw) for raw in (tracked + b"\0" + untracked).split(b"\0") if raw]
        return sorted(dict.fromkeys(names))

    def __iter__(self) -> Iterator[FileRef]:
        for rel in self.changed_paths():
            full = self.top / rel
            if self.path != self.top and self.path not in full.parents and full != self.path:
                continue
            name = full.name
            if any(part.lower() in self.excludes.dir_names for part in Path(rel).parts[:-1]):
                continue
            reason = self.excludes.file_excluded(name, rel)
            try:
                st = full.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                reason = "symlink"
            elif not stat.S_ISREG(st.st_mode):  # submodules, nested repositories, special files
                reason = "not a regular file"
            changed = max(st.st_mtime_ns, st.st_ctime_ns)
            if reason:
                yield FileRef(str(full), rel, st.st_size, changed, excluded=reason, source="git")
            elif st.st_size > self.max_file_size:
                yield FileRef(str(full), rel, st.st_size, changed,
                              error=f"too_large: {st.st_size} bytes", source="git")  # fmt: skip
            else:
                yield FileRef(str(full), rel, st.st_size, changed, source="git", root=str(self.top))

    def read(self, ref: FileRef, max_bytes: int) -> bytes:
        return read_regular_file(ref.path, max_bytes, root=ref.root)


__all__ = ["GitChangedSource", "GitError", "ReadError", "resolve_base"]
