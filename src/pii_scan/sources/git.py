"""Changed files from git, invoked defensively (the repository content is untrusted)."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from .base import FileRef, ReadError
from .fs import Excludes, read_regular_file

_HARDENING = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.quotePath=false",
    "-c", "diff.external=",
    # No network or transport, ever: repository config could otherwise allow "ext::" (which runs a
    # command) for an on-demand fetch of a missing object in a partial clone. Per-protocol settings
    # win over protocol.allow, so each is overridden here, where repository config can't undo it.
    "-c", "protocol.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.git.allow=never",
    "-c", "protocol.ssh.allow=never",
    "-c", "protocol.http.allow=never",
    "-c", "protocol.https.allow=never",
    # Only use the repository found through a .git entry, never a directory that merely looks like
    # a bare repository (git 2.38+; older git ignores it, and _check_layout covers the case).
    "-c", "safe.bareRepository=explicit",
    # Never look inside submodules: git would run itself there, reading the submodule's own config
    # (.git/modules/<name>/config), which the risky-config check doesn't see.
    "-c", "diff.ignoreSubmodules=all",
    "-c", "submodule.recurse=false",
    "--no-optional-locks",
]  # fmt: skip


class GitError(Exception):
    pass


def _git_executable(repo: Path) -> str:
    """Absolute path of git from the absolute PATH entries, never from the repository itself.

    Windows searches the current directory before PATH, so running a bare "git" from a checkout
    could run a git.exe committed to it. Relative PATH entries ("" or ".") are skipped for the
    same reason.
    """
    names = ("git.exe",) if sys.platform == "win32" else ("git",)
    inside = os.path.realpath(repo)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or not os.path.isabs(d):
            continue
        for name in names:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                real = os.path.realpath(candidate)
                if real == inside or real.startswith(inside.rstrip(os.sep) + os.sep):
                    continue
                return candidate
    raise GitError("git is not installed (no git executable on an absolute PATH entry)")


def _git(cwd: Path, *args: str) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_NO_LAZY_FETCH"] = "1"  # never fetch missing objects (git 2.44+)
    env["GIT_PROTOCOL_FROM_USER"] = "0"
    try:
        proc = subprocess.run(
            [_git_executable(cwd), *_HARDENING, *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=120, check=False,
        )  # fmt: skip
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


# Config scopes that live inside the repository (and so may be attacker-controlled). Global and
# system config are the operator's own; "command" is our own hardening flags.
_REPO_SCOPES = frozenset({"local", "worktree"})


def _risky_config_keys(top: Path) -> list[str]:
    """Repository-level git settings that could make `git diff` run commands.

    Asks git for the configuration it will actually use, with the scope of each entry, instead of
    guessing file locations: that also covers linked worktrees (whose `config.worktree` lives under
    `.git/worktrees/<name>/`) and `.git` files that point elsewhere. `--no-includes` lists include
    directives without following them, and listing config never runs anything.
    """
    out = _git(top, "config", "--no-includes", "--list", "--null", "--show-scope").decode("utf-8", "replace")
    fields = out.split("\0")
    risky: list[str] = []
    for scope, entry in zip(fields[0::2], fields[1::2], strict=False):
        if scope not in _REPO_SCOPES:
            continue
        name, _, value = entry.partition("\n")
        key = name.lower()
        if key in _LFS_VALUES and value.strip() == _LFS_VALUES[key]:
            continue
        if (key.startswith(("filter.", "include.", "includeif.", "protocol.")) or key in {
            "core.fsmonitor", "core.worktree", "core.sshcommand", "core.askpass", "core.gitproxy",
            "diff.external",
        } or (key.startswith("diff.") and key.endswith((".textconv", ".command")))
                or (key.startswith("remote.") and key.endswith((".uploadpack", ".receivepack")))):  # fmt: skip
            risky.append(name)
    return sorted(set(risky))


def _check_layout(top: Path) -> None:
    """The repository must be the usual `<top>/.git` (a directory, or a file as in linked worktrees).

    Anything else means git found its repository some other way, for example through a directory
    in the tree that is laid out like a bare repository, whose config this scan didn't vet.
    """
    gitdir = Path(_git(top, "rev-parse", "--absolute-git-dir").decode().strip()).resolve()
    dot_git = top / ".git"
    if dot_git.is_file() or gitdir == dot_git.resolve():
        return
    raise GitError(f"the repository's git directory {gitdir} is not {dot_git}. Review it and rerun with --trust-repo")


class GitChangedSource:
    def __init__(self, path: Path, base: str | None, excludes: Excludes, *, max_file_size: int,
                 trust_repo: bool = False) -> None:  # fmt: skip
        self.path = path.resolve()
        cwd = self.path if self.path.is_dir() else self.path.parent
        self.top = Path(_git(cwd, "rev-parse", "--show-toplevel").decode().strip()).resolve()
        if not trust_repo:
            _check_layout(self.top)
            risky = _risky_config_keys(self.top)
            if risky:
                raise GitError(
                    f"the repository's git config sets {', '.join(risky[:5])}, which could run commands during "
                    "the diff. Review it with 'git config --list --show-scope' and rerun with --trust-repo"
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
        tracked = _git(self.top, "diff", "--name-only", "-z", "--no-renames", "--ignore-submodules=all",
                       "--no-ext-diff", "--no-textconv",
                       "--diff-filter=ACMRT",
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
