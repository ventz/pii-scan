"""Win32 calls the os module doesn't expose: protected ACLs, reparse-point checks, final paths.

On Windows `os.chmod` only toggles the read-only flag, there is no `O_NOFOLLOW`, and a junction
is not a symlink to `os.path.islink`. Import this module only on Windows.
"""

from __future__ import annotations

import ctypes
import functools
import msvcrt
import os
from ctypes import wintypes

from .private import extended_path, is_link_attributes, is_placeholder_attributes

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_ALWAYS = 4
FILE_SHARE_ALL = 0x1 | 0x2 | 0x4  # read | write | delete: never block other users of the file
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a directory
FILE_TYPE_DISK = 0x1
_CREATE_NEW = 1
_FILE_READ_ATTRIBUTES = 0x80
_ERROR_ALREADY_EXISTS = 183
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87
_FILE_BASIC_INFO_CLASS = 0
_EPOCH_AS_FILETIME = 116444736000000000  # 1970-01-01 in 100 ns units since 1601-01-01
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_ID_INFO_CLASS = 18
_INVALID_HANDLE = wintypes.HANDLE(-1).value
_TOKEN_QUERY = 0x8
_TOKEN_USER = 1
_DACL_SECURITY_INFORMATION = 0x4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SECURITY_INFORMATION = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
_SE_FILE_OBJECT = 1
WRITE_DAC = 0x00040000
_SDDL_REVISION_1 = 1


class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [("CreationTime", ctypes.c_int64), ("LastAccessTime", ctypes.c_int64),
                ("LastWriteTime", ctypes.c_int64), ("ChangeTime", ctypes.c_int64),
                ("FileAttributes", wintypes.DWORD)]  # fmt: skip


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD)]  # fmt: skip


class _FileIdInfo(ctypes.Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_uint64), ("FileId", ctypes.c_ubyte * 16)]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


_kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]  # fmt: skip
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
_kernel32.CreateDirectoryW.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GetFileType.argtypes = [wintypes.HANDLE]
_kernel32.GetFileType.restype = wintypes.DWORD
_kernel32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
_kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
_kernel32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
_kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p
_advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]  # fmt: skip
_advapi32.GetTokenInformation.restype = wintypes.BOOL
_advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
_advapi32.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]  # fmt: skip
_advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
_advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
_advapi32.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_advapi32.SetSecurityInfo.restype = wintypes.DWORD
_advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
_advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL


def _error(what: str, path: str = "") -> OSError:
    code = ctypes.get_last_error()
    return OSError(None, f"{what}: {ctypes.FormatError(code).strip()}", path or None, code)


def _open(path: str, flags: int, *, access: int = GENERIC_READ, disposition: int = OPEN_EXISTING,
          security: object = None, exact: bool = True) -> int:  # fmt: skip
    """CreateFileW. `exact` (the default) passes the name through unchanged; user-given paths such
    as a report path use exact=False so Win32 meanings like the NUL device still apply."""
    name = extended_path(path, os.getcwd()) if exact else path
    handle = _kernel32.CreateFileW(name, access, FILE_SHARE_ALL, security, disposition, flags, None)
    if handle == _INVALID_HANDLE or handle is None:
        raise _error("open", path)
    return handle


def _attributes(handle: int) -> tuple[int, int]:
    info = _AttributeTagInfo()
    if not _kernel32.GetFileInformationByHandleEx(handle, _FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(info),
                                                  ctypes.sizeof(info)):  # fmt: skip
        raise _error("file attributes")
    return info.FileAttributes, info.ReparseTag


def _final_path(handle: int) -> str:
    size = 512
    while True:
        buf = ctypes.create_unicode_buffer(size)
        n = _kernel32.GetFinalPathNameByHandleW(handle, buf, size, 0)
        if n == 0:
            raise _error("final path")
        if n < size:
            return buf.value
        size = n + 1


class LinkRefused(OSError):
    """The path is a symlink, junction, or other name-surrogate reparse point."""


def _file_id(handle: int) -> tuple[int, bytes]:
    """Volume serial and file ID. The 128-bit ID (FileIdInfo) is unique on ReFS, where the 64-bit
    index from GetFileInformationByHandle may not be; file systems without it fall back to that."""
    info = _FileIdInfo()
    if _kernel32.GetFileInformationByHandleEx(handle, _FILE_ID_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)):
        return info.VolumeSerialNumber, bytes(info.FileId)
    legacy = _ByHandleFileInformation()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(legacy)):
        raise _error("file id")
    return legacy.dwVolumeSerialNumber, ((legacy.nFileIndexHigh << 32) | legacy.nFileIndexLow).to_bytes(16, "little")


def open_for_reading(path: str) -> tuple[int, str, bool, int]:
    """Open `path` itself for reading, never what a link there points to.

    Returns (CRT file descriptor, final path, is a disk file, attributes). Raises LinkRefused for
    links. The path is opened without reparse processing, and the attributes come from that same
    handle, so a link can't be swapped in between a check and the open. A reparse point that is
    not a link (Windows Server deduplication, for example) only yields its stub that way, so it is
    reopened normally and must still be the same file.
    """
    handle = _open(path, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
    try:
        attributes, tag = _attributes(handle)
        if is_link_attributes(attributes, tag):
            raise LinkRefused(None, "symlink or junction", path)
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT and not is_placeholder_attributes(attributes):
            data_handle = _open(path, FILE_FLAG_BACKUP_SEMANTICS)
            try:
                if _file_id(data_handle) != _file_id(handle):
                    raise LinkRefused(None, "file changed while opening", path)
            except BaseException:
                _kernel32.CloseHandle(data_handle)
                raise
            _kernel32.CloseHandle(handle)
            handle = data_handle
        final = _final_path(handle)
        is_disk = _kernel32.GetFileType(handle) == FILE_TYPE_DISK
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        _kernel32.CloseHandle(handle)
        raise
    return fd, final, is_disk, attributes


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]  # fmt: skip


def _with_private_security(create, *, directory: bool):  # noqa: ANN001, ANN202 - create(SECURITY_ATTRIBUTES)
    """Call `create` with SECURITY_ATTRIBUTES carrying the private ACL, so the object is born private."""
    result = []

    def apply(descriptor, _dacl):  # noqa: ANN001
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        result.append(create(ctypes.byref(sa)))

    _apply_private_dacl(apply, directory=directory)
    return result[0]


def create_private_file(path: str) -> int:
    """Create a new file (never an existing one) that is private from the start. Returns a CRT fd."""
    handle = _with_private_security(
        lambda sa: _open(path, 0, access=GENERIC_READ | GENERIC_WRITE, disposition=_CREATE_NEW, security=sa),
        directory=False,
    )
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        _kernel32.CloseHandle(handle)
        raise


def create_private_dir(path: str) -> None:
    """Create a directory that is private from the start (FileExistsError if anything is there)."""

    def create(sa):  # noqa: ANN001, ANN202
        if not _kernel32.CreateDirectoryW(extended_path(path, os.getcwd()), sa):
            code = ctypes.get_last_error()
            if code == _ERROR_ALREADY_EXISTS:
                raise FileExistsError(None, "already exists", path, code)
            raise OSError(None, f"create directory: {ctypes.FormatError(code).strip()}", path, code)

    _with_private_security(create, directory=True)


def change_time_ns(path: str) -> int:
    """NTFS ChangeTime (moves on every write, unlike st_ctime, which is the creation time on Windows)."""
    handle = _open(path, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, access=_FILE_READ_ATTRIBUTES)
    try:
        info = _FileBasicInfo()
        if not _kernel32.GetFileInformationByHandleEx(handle, _FILE_BASIC_INFO_CLASS, ctypes.byref(info),
                                                      ctypes.sizeof(info)):  # fmt: skip
            raise _error("file times", path)
        return (info.ChangeTime - _EPOCH_AS_FILETIME) * 100
    finally:
        _kernel32.CloseHandle(handle)


def open_for_writing(path: str) -> int:
    """Create or open `path` for writing without following a link there (Windows has no O_NOFOLLOW).

    Opens the name itself and refuses it if it is a link, so a link planted at `path` can't
    redirect the write. Nothing is truncated here: the caller makes the file private first, then
    empties it. Returns a CRT file descriptor.
    """
    try:
        handle = _with_private_security(
            lambda sa: _open(path, FILE_FLAG_OPEN_REPARSE_POINT, access=GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                             disposition=OPEN_ALWAYS, security=sa, exact=False),  # a new file is born private
            directory=False,
        )
    except OSError as exc:
        # Devices such as NUL may refuse WRITE_DAC. Retry without it for an existing device only: a
        # disk file must be made private, so for one the original error stands.
        if getattr(exc, "winerror", None) not in (_ERROR_ACCESS_DENIED, _ERROR_INVALID_PARAMETER):
            raise
        try:
            handle = _open(path, FILE_FLAG_OPEN_REPARSE_POINT, access=GENERIC_READ | GENERIC_WRITE, exact=False)
        except OSError:
            raise exc from None
        if _kernel32.GetFileType(handle) == FILE_TYPE_DISK:
            _kernel32.CloseHandle(handle)
            raise exc from None
    try:
        if _kernel32.GetFileType(handle) == FILE_TYPE_DISK:  # devices such as NUL can't be links
            attributes, tag = _attributes(handle)
            if is_link_attributes(attributes, tag):
                raise LinkRefused(None, "refusing to write through a symlink or junction", path)
            if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:  # cloud or dedup file: opened raw, so never write it
                raise OSError(None, "refusing to overwrite a cloud, deduplicated, or other reparse-point file", path)
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        _kernel32.CloseHandle(handle)
        raise
    return fd


@functools.cache
def _user_sid() -> str:
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise _error("process token")
    try:
        needed = wintypes.DWORD()
        _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not _advapi32.GetTokenInformation(token, _TOKEN_USER, buf, needed, ctypes.byref(needed)):
            raise _error("token user")
        sid = ctypes.cast(buf, ctypes.POINTER(_SidAndAttributes)).contents.Sid
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise _error("user SID")
        try:
            return text.value
        finally:
            _kernel32.LocalFree(text)
    finally:
        _kernel32.CloseHandle(token)


def private_sddl(*, directory: bool) -> str:
    """Full access for the current user and SYSTEM only, nothing inherited from the parent.

    The Windows equivalent of mode 0600 (files) or 0700 (directories, whose entries are also
    inherited by new children).
    """
    inherit = "OICI" if directory else ""
    return f"D:P(A;{inherit};FA;;;{_user_sid()})(A;{inherit};FA;;;SY)"


def _apply_private_dacl(apply, *, directory: bool) -> None:  # noqa: ANN001 - callable(descriptor, dacl)
    descriptor = ctypes.c_void_p()
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            private_sddl(directory=directory), _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise _error("security descriptor")
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not _advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                                   ctypes.byref(defaulted)):  # fmt: skip
            raise _error("security descriptor ACL")
        apply(descriptor, dacl)
    finally:
        _kernel32.LocalFree(descriptor)


def make_private(path: str, *, directory: bool) -> None:
    """Replace the ACL of `path` (by name) with the private ACL. For directories we just created."""

    def apply(_descriptor, dacl):  # noqa: ANN001
        # SetNamedSecurityInfoW, unlike SetFileSecurityW, documents PROTECTED_DACL_SECURITY_INFORMATION
        code = _advapi32.SetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _SECURITY_INFORMATION, None, None, dacl, None)
        if code:
            raise OSError(None, f"set ACL: {ctypes.FormatError(code).strip()}", path, code)

    _apply_private_dacl(apply, directory=directory)


def make_private_fd(fd: int) -> None:
    """Replace the ACL of an open file (needs WRITE_DAC, which the owner always has)."""
    handle = msvcrt.get_osfhandle(fd)

    def apply(_descriptor, dacl):  # noqa: ANN001
        code = _advapi32.SetSecurityInfo(handle, _SE_FILE_OBJECT, _SECURITY_INFORMATION, None, None, dacl, None)
        if code:
            raise OSError(None, f"set ACL: {ctypes.FormatError(code).strip()}", None, code)

    _apply_private_dacl(apply, directory=False)


def dacl_sddl(path: str) -> str:
    """The ACL of `path` in SDDL, for tests and diagnostics."""
    dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    code = _advapi32.GetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION, None, None,
                                           ctypes.byref(dacl), None, ctypes.byref(descriptor))  # fmt: skip
    if code:
        raise OSError(None, f"get ACL: {ctypes.FormatError(code).strip()}", path, code)
    try:
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(text), None):
            raise _error("ACL to SDDL", path)
        try:
            return text.value
        finally:
            _kernel32.LocalFree(text)
    finally:
        _kernel32.LocalFree(descriptor)
