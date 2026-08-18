"""
Windows EFS helpers for Explorer Advance — Cipher.

Detection uses the NTFS Encrypted file attribute (language-independent).
`cipher.exe` is used for certificate / file details, encrypt (`/E`),
decrypt (`/D`), and Explorer launch.
"""

from __future__ import annotations

import ctypes
import os
import string
import subprocess
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

# ---------------------------------------------------------------------------
# Win32 constants / APIs
# ---------------------------------------------------------------------------

FILE_ATTRIBUTE_READONLY = 0x0001
FILE_ATTRIBUTE_HIDDEN = 0x0002
FILE_ATTRIBUTE_SYSTEM = 0x0004
FILE_ATTRIBUTE_DIRECTORY = 0x0010
FILE_ATTRIBUTE_ENCRYPTED = 0x4000
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4

_kernel32 = ctypes.windll.kernel32

_GetFileAttributesW = _kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_GetFileAttributesW.restype = wintypes.DWORD

_GetLogicalDrives = _kernel32.GetLogicalDrives
_GetLogicalDrives.restype = wintypes.DWORD

_GetDriveTypeW = _kernel32.GetDriveTypeW
_GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
_GetDriveTypeW.restype = wintypes.UINT

_GetVolumeInformationW = _kernel32.GetVolumeInformationW
_GetVolumeInformationW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    wintypes.DWORD,
]
_GetVolumeInformationW.restype = wintypes.BOOL

_GetVolumePathNameW = _kernel32.GetVolumePathNameW
_GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_GetVolumePathNameW.restype = wintypes.BOOL

# Directory names skipped when "Skip Windows / system folders" is on.
# Compared case-insensitively against a single path segment.
SYSTEM_DIR_NAMES = {
    "$recycle.bin",
    "system volume information",
    "winsxs",
    "servicing",
    "windows.old",
    "$windows.~bt",
    "$windows.~ws",
    "recovery",
    "config.msi",
}

# Extra top-level folders skipped only when the scan root is a drive letter.
DRIVE_ROOT_SKIP_NAMES = {
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "$recycle.bin",
    "system volume information",
    "recovery",
    "documents and settings",
}


@dataclass(slots=True)
class DriveInfo:
    letter: str
    root: str
    kind: str
    filesystem: str
    ntfs: bool


@dataclass(slots=True)
class EncryptedItem:
    kind: str
    name: str
    path: str
    parent: str
    size: int
    size_label: str
    modified: str
    modified_ts: float


@dataclass
class ScanProgress:
    running: bool = False
    cancelled: bool = False
    done: bool = False
    scanned: int = 0
    found: int = 0
    errors: int = 0
    current: str = ""
    message: str = ""
    rows: list[dict] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    cancel_event: threading.Event = field(default_factory=threading.Event)


def is_windows() -> bool:
    return sys.platform == "win32"


def creationflags_no_window() -> int:
    if is_windows():
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return 0


def file_attributes(path: str) -> int:
    attrs = _GetFileAttributesW(path)
    if attrs == INVALID_FILE_ATTRIBUTES:
        return -1
    return int(attrs)


def is_encrypted_path(path: str) -> bool:
    attrs = file_attributes(path)
    return attrs >= 0 and bool(attrs & FILE_ATTRIBUTE_ENCRYPTED)


def is_readonly_path(path: str) -> bool:
    attrs = file_attributes(path)
    return attrs >= 0 and bool(attrs & FILE_ATTRIBUTE_READONLY)


def volume_root_for(path: str) -> str:
    """NTFS volume root that contains `path` (e.g. ``C:\\``)."""
    if not is_windows():
        return ""
    probe = path
    if not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent:
            probe = parent
    buf = ctypes.create_unicode_buffer(261)
    if probe and _GetVolumePathNameW(probe, buf, 261):
        return buf.value
    drive, _tail = os.path.splitdrive(os.path.abspath(path))
    if drive:
        return drive + "\\"
    return ""


def filesystem_for_path(path: str) -> str:
    root = volume_root_for(path)
    if not root:
        return ""
    vol_name = ctypes.create_unicode_buffer(261)
    fs_name = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    max_comp = wintypes.DWORD()
    flags = wintypes.DWORD()
    ok = _GetVolumeInformationW(
        root,
        vol_name,
        261,
        ctypes.byref(serial),
        ctypes.byref(max_comp),
        ctypes.byref(flags),
        fs_name,
        261,
    )
    return fs_name.value if ok else ""


def is_ntfs_path(path: str) -> bool:
    return filesystem_for_path(path).upper() == "NTFS"


def format_size(n: int) -> str:
    if n < 0:
        return "—"
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(n)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def format_modified(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return "—"


def pick_folder(start: str = "", title: str = "Select folder") -> Optional[str]:
    """Native Windows folder dialog (tkinter). Returns None if cancelled."""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        initial = start if start and Path(start).is_dir() else str(Path.home())
        path = filedialog.askdirectory(initialdir=initial, title=title)
        root.destroy()
        return path or None
    except Exception:
        return None


def list_local_drives(*, include_removable: bool = False, include_remote: bool = False) -> list[DriveInfo]:
    """Fixed (and optionally removable/remote) volumes with filesystem name."""
    if not is_windows():
        return []
    mask = _GetLogicalDrives()
    drives: list[DriveInfo] = []
    allowed = {DRIVE_FIXED}
    if include_removable:
        allowed.add(DRIVE_REMOVABLE)
    if include_remote:
        allowed.add(DRIVE_REMOTE)

    vol_name = ctypes.create_unicode_buffer(261)
    fs_name = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    max_comp = wintypes.DWORD()
    flags = wintypes.DWORD()

    for i, letter in enumerate(string.ascii_uppercase):
        if not (mask & (1 << i)):
            continue
        root = f"{letter}:\\"
        kind_code = int(_GetDriveTypeW(root))
        if kind_code not in allowed:
            continue
        ok = _GetVolumeInformationW(
            root,
            vol_name,
            261,
            ctypes.byref(serial),
            ctypes.byref(max_comp),
            ctypes.byref(flags),
            fs_name,
            261,
        )
        filesystem = fs_name.value if ok else ""
        kind = {DRIVE_FIXED: "Fixed", DRIVE_REMOVABLE: "Removable", DRIVE_REMOTE: "Network"}.get(
            kind_code, str(kind_code)
        )
        drives.append(
            DriveInfo(
                letter=letter,
                root=root,
                kind=kind,
                filesystem=filesystem or "unknown",
                ntfs=filesystem.upper() == "NTFS",
            )
        )
    return drives


def ntfs_scan_roots(*, include_removable: bool = False) -> list[str]:
    return [d.root for d in list_local_drives(include_removable=include_removable) if d.ntfs]


def _is_drive_root(path: str) -> bool:
    abs_path = os.path.abspath(path)
    _drive, tail = os.path.splitdrive(abs_path)
    return tail in {"\\", "/", ""}


def open_in_explorer(path: str) -> None:
    """Reveal `path` in Explorer. Folders open in place; files are selected."""
    if not path or not str(path).strip():
        raise ValueError("No path to open.")
    target = Path(str(path).strip())
    if not target.exists():
        parent = target.parent
        if parent.exists():
            os.startfile(str(parent))  # type: ignore[attr-defined]
            return
        raise FileNotFoundError(str(target))
    # /n forces a new window so Explorer does not just focus the last folder.
    # Do not pass CREATE_NO_WINDOW or the window may never appear.
    if target.is_dir():
        os.startfile(str(target))  # type: ignore[attr-defined]
        return
    subprocess.Popen(["explorer", "/n", "/select," + str(target)])


def open_folder(path: str) -> None:
    folder = Path(path)
    if folder.is_file():
        folder = folder.parent
    if not folder.exists():
        raise FileNotFoundError(str(folder))
    os.startfile(str(folder))  # type: ignore[attr-defined]


@dataclass(slots=True)
class CipherRun:
    args: list[str]
    returncode: int
    text: str
    timed_out: bool = False

    @property
    def command(self) -> str:
        return "cipher " + " ".join(self.args)


@dataclass(slots=True)
class DecryptPlanItem:
    path: str
    kind: str
    recursive: bool
    args: list[str]

    @property
    def command(self) -> str:
        return "cipher " + " ".join(self.args)


@dataclass(slots=True)
class DecryptResult:
    path: str
    kind: str
    recursive: bool
    ok: bool
    still_encrypted: bool
    command: str
    text: str
    timed_out: bool = False
    missing: bool = False


@dataclass
class DecryptProgress:
    current: str = ""
    done: int = 0
    total: int = 0
    message: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)


def is_drive_root(path: str) -> bool:
    return _is_drive_root(path)


def _is_under(path: str, root: str) -> bool:
    path_n = os.path.normcase(os.path.abspath(path))
    root_n = os.path.normcase(os.path.abspath(root)).rstrip("\\/")
    if path_n.rstrip("\\/") == root_n:
        return False
    prefix = root_n + os.sep
    return path_n.startswith(prefix)


def run_cipher_ex(args: list[str], *, timeout: Optional[float] = 45) -> CipherRun:
    """Run cipher.exe and return exit code plus combined OEM text."""
    try:
        completed = subprocess.run(
            ["cipher", *args],
            capture_output=True,
            timeout=timeout,
            creationflags=creationflags_no_window(),
        )
    except FileNotFoundError:
        return CipherRun(args=list(args), returncode=127, text="cipher.exe was not found.")
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or b"") + (exc.stderr or b"")
        text = raw.decode("oem", errors="replace").strip()
        if not text:
            text = f"cipher timed out after {timeout} seconds."
        return CipherRun(args=list(args), returncode=124, text=text, timed_out=True)
    raw = completed.stdout or b""
    if completed.stderr:
        raw = raw + (b"\n" if raw else b"") + completed.stderr
    return CipherRun(
        args=list(args),
        returncode=int(completed.returncode),
        text=raw.decode("oem", errors="replace").strip(),
    )


def run_cipher(args: list[str], *, timeout: Optional[float] = 45) -> str:
    """Run cipher.exe and return combined text (OEM console encoding)."""
    return run_cipher_ex(args, timeout=timeout).text


def plan_decrypt(
    paths: Iterable[str],
    *,
    recursive_folders: bool = True,
    include_hidden: bool = True,
) -> list[DecryptPlanItem]:
    """
    Build the cipher /D commands for the given paths.

    When recursive_folders is on, a selected folder is decrypted with /S
    and items inside that folder are skipped so cipher is not run twice.
    """
    unique: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        path = os.path.abspath(raw)
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)

    folders = [path for path in unique if os.path.isdir(path)]
    plan: list[DecryptPlanItem] = []
    for path in unique:
        if recursive_folders and any(_is_under(path, folder) for folder in folders):
            continue
        is_dir = os.path.isdir(path)
        recursive = bool(recursive_folders and is_dir)
        args = ["/d"]
        if include_hidden:
            args.append("/h")
        if recursive:
            args.append(f"/s:{path}")
        else:
            args.append(path)
        plan.append(
            DecryptPlanItem(
                path=path,
                kind="Folder" if is_dir else "File",
                recursive=recursive,
                args=args,
            )
        )
    return plan


def decrypt_path(
    item: DecryptPlanItem,
    *,
    timeout: Optional[float] = None,
) -> DecryptResult:
    if not os.path.exists(item.path):
        return DecryptResult(
            path=item.path,
            kind=item.kind,
            recursive=item.recursive,
            ok=False,
            still_encrypted=False,
            command=item.command,
            text="Path no longer exists.",
            missing=True,
        )
    if timeout is None:
        timeout = None if item.recursive else 180
    run = run_cipher_ex(item.args, timeout=timeout)
    still = is_encrypted_path(item.path)
    note = run.text
    if run.timed_out and not note:
        note = "cipher timed out."
    return DecryptResult(
        path=item.path,
        kind=item.kind,
        recursive=item.recursive,
        ok=not still and not run.timed_out,
        still_encrypted=still,
        command=item.command,
        text=note,
        timed_out=run.timed_out,
    )


def decrypt_paths(
    paths: Iterable[str],
    *,
    recursive_folders: bool = True,
    include_hidden: bool = True,
    progress: Optional[DecryptProgress] = None,
) -> list[DecryptResult]:
    """Decrypt each planned target with cipher /D. Safe to call from a worker thread."""
    plan = plan_decrypt(
        paths,
        recursive_folders=recursive_folders,
        include_hidden=include_hidden,
    )
    results: list[DecryptResult] = []
    prog = progress
    if prog is not None:
        with prog.lock:
            prog.total = len(plan)
            prog.done = 0
            prog.message = "Starting…"
    for item in plan:
        if prog is not None:
            with prog.lock:
                prog.current = item.path
                prog.message = item.command
        result = decrypt_path(item)
        results.append(result)
        if prog is not None:
            with prog.lock:
                prog.done += 1
                prog.current = item.path
    if prog is not None:
        ok = sum(1 for item in results if item.ok)
        with prog.lock:
            prog.message = f"Done. {ok} of {len(results)} target(s) decrypted."
            prog.current = ""
    return results


@dataclass(slots=True)
class PathInspect:
    path: str
    name: str
    exists: bool
    kind: str
    encrypted: bool
    readonly: bool
    ntfs: bool
    filesystem: str
    drive_root: bool

    @property
    def status_label(self) -> str:
        if not self.exists:
            return "Missing"
        if not self.ntfs:
            fs = self.filesystem or "unknown"
            return f"Not NTFS ({fs})"
        if self.encrypted:
            return "Already encrypted"
        return "Plaintext"

    @property
    def can_encrypt(self) -> bool:
        return self.exists and self.ntfs


def inspect_path(path: str) -> PathInspect:
    abs_path = os.path.abspath(path)
    name = Path(abs_path).name or abs_path
    exists = os.path.exists(abs_path)
    is_dir = exists and os.path.isdir(abs_path)
    kind = "Folder" if is_dir else ("File" if exists else "Missing")
    filesystem = filesystem_for_path(abs_path) if exists else ""
    return PathInspect(
        path=abs_path,
        name=name,
        exists=exists,
        kind=kind,
        encrypted=is_encrypted_path(abs_path) if exists else False,
        readonly=is_readonly_path(abs_path) if exists else False,
        ntfs=filesystem.upper() == "NTFS",
        filesystem=filesystem,
        drive_root=exists and _is_drive_root(abs_path),
    )


@dataclass(slots=True)
class EncryptPlanItem:
    path: str
    kind: str
    recursive: bool
    args: list[str]

    @property
    def command(self) -> str:
        return "cipher " + " ".join(self.args)


@dataclass(slots=True)
class EncryptResult:
    path: str
    kind: str
    recursive: bool
    ok: bool
    still_plain: bool
    command: str
    text: str
    timed_out: bool = False
    missing: bool = False
    not_ntfs: bool = False
    returncode: int = 0


@dataclass
class EncryptProgress:
    current: str = ""
    done: int = 0
    total: int = 0
    message: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)


def plan_encrypt(
    paths: Iterable[str],
    *,
    recursive_folders: bool = True,
    include_hidden: bool = True,
    stop_on_error: bool = False,
) -> list[EncryptPlanItem]:
    """
    Build the cipher /E commands for the given paths.

    When recursive_folders is on, a selected folder is encrypted with /S
    and items inside that folder are skipped so cipher is not run twice.
    """
    unique: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        path = os.path.abspath(raw)
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)

    folders = [path for path in unique if os.path.isdir(path)]
    plan: list[EncryptPlanItem] = []
    for path in unique:
        if recursive_folders and any(_is_under(path, folder) for folder in folders):
            continue
        is_dir = os.path.isdir(path)
        recursive = bool(recursive_folders and is_dir)
        args = ["/e"]
        if stop_on_error:
            args.append("/b")
        if include_hidden:
            args.append("/h")
        if recursive:
            args.append(f"/s:{path}")
        else:
            args.append(path)
        plan.append(
            EncryptPlanItem(
                path=path,
                kind="Folder" if is_dir else "File",
                recursive=recursive,
                args=args,
            )
        )
    return plan


def encrypt_path(
    item: EncryptPlanItem,
    *,
    timeout: Optional[float] = None,
) -> EncryptResult:
    if not os.path.exists(item.path):
        return EncryptResult(
            path=item.path,
            kind=item.kind,
            recursive=item.recursive,
            ok=False,
            still_plain=True,
            command=item.command,
            text="Path no longer exists.",
            missing=True,
        )
    filesystem = filesystem_for_path(item.path)
    if filesystem.upper() != "NTFS":
        label = filesystem or "unknown"
        return EncryptResult(
            path=item.path,
            kind=item.kind,
            recursive=item.recursive,
            ok=False,
            still_plain=True,
            command=item.command,
            text=f"EFS requires NTFS (this volume is {label}).",
            not_ntfs=True,
        )
    if timeout is None:
        timeout = None if item.recursive else 180
    run = run_cipher_ex(item.args, timeout=timeout)
    encrypted = is_encrypted_path(item.path)
    note = run.text
    if run.timed_out and not note:
        note = "cipher timed out."
    if encrypted and run.returncode not in (0, None) and note:
        note = note + "\n(Folder/file is encrypted, but cipher reported an error — some children may still be plaintext.)"
    return EncryptResult(
        path=item.path,
        kind=item.kind,
        recursive=item.recursive,
        ok=encrypted and not run.timed_out,
        still_plain=not encrypted,
        command=item.command,
        text=note,
        timed_out=run.timed_out,
        returncode=int(run.returncode),
    )


def encrypt_paths(
    paths: Iterable[str],
    *,
    recursive_folders: bool = True,
    include_hidden: bool = True,
    stop_on_error: bool = False,
    progress: Optional[EncryptProgress] = None,
) -> list[EncryptResult]:
    """Encrypt each planned target with cipher /E. Safe to call from a worker thread."""
    plan = plan_encrypt(
        paths,
        recursive_folders=recursive_folders,
        include_hidden=include_hidden,
        stop_on_error=stop_on_error,
    )
    results: list[EncryptResult] = []
    prog = progress
    if prog is not None:
        with prog.lock:
            prog.total = len(plan)
            prog.done = 0
            prog.message = "Starting…"
    for item in plan:
        if prog is not None:
            with prog.lock:
                prog.current = item.path
                prog.message = item.command
        result = encrypt_path(item)
        results.append(result)
        if stop_on_error and not result.ok:
            if prog is not None:
                with prog.lock:
                    prog.done += 1
                    prog.message = "Stopped on first error."
                    prog.current = item.path
            break
        if prog is not None:
            with prog.lock:
                prog.done += 1
                prog.current = item.path
    if prog is not None:
        ok = sum(1 for item in results if item.ok)
        with prog.lock:
            if "Stopped on first error" not in (prog.message or ""):
                prog.message = f"Done. {ok} of {len(results)} target(s) encrypted."
            prog.current = ""
    return results


def cipher_current_certificate() -> str:
    try:
        return run_cipher(["/y"], timeout=15)
    except Exception as exc:
        return f"Could not read the current EFS certificate:\n{exc}"


def cipher_file_info(path: str) -> str:
    try:
        return run_cipher(["/c", path], timeout=30)
    except Exception as exc:
        return f"Could not read cipher details:\n{exc}"


def cipher_listing(path: str) -> str:
    """`cipher` with no switch: E/U listing of a directory."""
    try:
        return run_cipher([path], timeout=30)
    except Exception as exc:
        return f"Could not list encryption status:\n{exc}"


def _should_skip_dir(name: str, *, at_drive_root: bool, skip_system: bool) -> bool:
    if not skip_system:
        return False
    key = name.lower()
    if key in SYSTEM_DIR_NAMES:
        return True
    if at_drive_root and key in DRIVE_ROOT_SKIP_NAMES:
        return True
    return False


def _item_from_entry(path: str, name: str, is_dir: bool, include_hidden: bool) -> Optional[EncryptedItem]:
    attrs = file_attributes(path)
    if attrs < 0:
        return None
    if not include_hidden and (attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)):
        return None
    if not (attrs & FILE_ATTRIBUTE_ENCRYPTED):
        return None

    size = 0
    mtime = 0.0
    try:
        st = os.stat(path, follow_symlinks=False)
        size = 0 if is_dir else int(st.st_size)
        mtime = float(st.st_mtime)
    except OSError:
        pass

    parent = str(Path(path).parent)
    return EncryptedItem(
        kind="Folder" if is_dir else "File",
        name=name,
        path=path,
        parent=parent,
        size=size,
        size_label="—" if is_dir else format_size(size),
        modified=format_modified(mtime) if mtime else "—",
        modified_ts=mtime,
    )


def item_to_row(item: EncryptedItem) -> dict:
    return {
        "kind": item.kind,
        "kind_rank": 0 if item.kind == "Folder" else 1,
        "name": item.name,
        "path": item.path,
        "parent": item.parent,
        "size": item.size,
        "size_label": item.size_label,
        "modified": item.modified,
        "modified_ts": item.modified_ts,
    }


def containing_folder_rows(rows: Iterable[dict]) -> list[dict]:
    """
    Unique parent folders of encrypted *files* in `rows`.

    A folder appears even if it is not marked Encrypted itself — that is the
    usual gap: you can only reach it from a file row. Size is the sum of those
    files. file_count is how many encrypted files sit directly in the folder.
    """
    buckets: dict[str, dict] = {}
    for row in rows:
        if (row.get("kind") or "") != "File":
            continue
        path = str(row.get("path") or "")
        if not path:
            continue
        parent = str(row.get("parent") or Path(path).parent)
        if not parent:
            continue
        abs_parent = os.path.abspath(parent)
        key = os.path.normcase(abs_parent)
        bucket = buckets.get(key)
        if bucket is None:
            name = Path(abs_parent).name or abs_parent
            buckets[key] = {
                "kind": "Folder",
                "kind_rank": 0,
                "name": name,
                "path": abs_parent,
                "parent": str(Path(abs_parent).parent),
                "size": 0,
                "size_label": "—",
                "modified": "—",
                "modified_ts": 0.0,
                "file_count": 0,
                "encrypted_folder": is_encrypted_path(abs_parent),
                "role": "container",
            }
            bucket = buckets[key]
        bucket["file_count"] = int(bucket["file_count"]) + 1
        try:
            bucket["size"] = int(bucket["size"]) + int(row.get("size") or 0)
        except (TypeError, ValueError):
            pass
        try:
            mts = float(row.get("modified_ts") or 0)
        except (TypeError, ValueError):
            mts = 0.0
        if mts >= float(bucket.get("modified_ts") or 0):
            bucket["modified_ts"] = mts
            if row.get("modified"):
                bucket["modified"] = row["modified"]
    result: list[dict] = []
    for bucket in buckets.values():
        n = int(bucket["file_count"])
        files = "1 file" if n == 1 else f"{n:,} files"
        size = format_size(int(bucket["size"])) if bucket["size"] else "—"
        bucket["size_label"] = f"{files} · {size}"
        result.append(bucket)
    result.sort(key=lambda row: str(row.get("path") or "").casefold())
    return result


def scan_encrypted(
    roots: Iterable[str],
    *,
    recursive: bool = True,
    include_hidden: bool = False,
    skip_system: bool = True,
    progress: Optional[ScanProgress] = None,
    on_item: Optional[Callable[[EncryptedItem], None]] = None,
    max_results: int = 20_000,
) -> list[EncryptedItem]:
    """
    Walk `roots` and collect items with the Encrypted NTFS attribute.

    Does not follow reparse points / junctions. Safe to call from a worker thread.
    """
    found: list[EncryptedItem] = []
    prog = progress or ScanProgress()
    cancel = prog.cancel_event

    def bump(current: str = "") -> None:
        with prog.lock:
            prog.current = current
            prog.found = len(found)
            if current:
                prog.message = current

    roots_list = [os.path.abspath(r) for r in roots if r]
    for root in roots_list:
        if cancel.is_set():
            break
        if not os.path.exists(root):
            with prog.lock:
                prog.errors += 1
            continue

        # Include the root itself if it is encrypted.
        root_path = Path(root)
        root_item = _item_from_entry(
            str(root_path),
            root_path.name or str(root_path),
            root_path.is_dir(),
            include_hidden=True,
        )
        if root_item:
            found.append(root_item)
            if on_item:
                on_item(root_item)
            with prog.lock:
                prog.rows.append(item_to_row(root_item))

        if not os.path.isdir(root):
            with prog.lock:
                prog.scanned += 1
            continue

        stack = [str(root_path)]
        while stack and not cancel.is_set():
            current = stack.pop()
            bump(current)
            try:
                with os.scandir(current) as it:
                    entries = list(it)
            except OSError:
                with prog.lock:
                    prog.errors += 1
                continue

            parent_is_drive_root = _is_drive_root(current)

            for entry in entries:
                if cancel.is_set():
                    break
                with prog.lock:
                    prog.scanned += 1
                try:
                    if entry.is_symlink():
                        continue
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    with prog.lock:
                        prog.errors += 1
                    continue

                if is_dir and _should_skip_dir(
                    entry.name,
                    at_drive_root=parent_is_drive_root,
                    skip_system=skip_system,
                ):
                    continue

                item = _item_from_entry(entry.path, entry.name, is_dir, include_hidden)
                if item:
                    found.append(item)
                    if on_item:
                        on_item(item)
                    with prog.lock:
                        prog.rows.append(item_to_row(item))
                    if len(found) >= max_results:
                        with prog.lock:
                            prog.message = f"Stopped at {max_results:,} results."
                        cancel.set()
                        break

                if is_dir and recursive:
                    # Do not descend into junctions / mount points.
                    try:
                        if not entry.is_junction():  # type: ignore[attr-defined]
                            stack.append(entry.path)
                    except (AttributeError, OSError):
                        # Python < 3.12 has no is_junction; skip reparse via attributes.
                        attrs = file_attributes(entry.path)
                        FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
                        if attrs < 0 or not (attrs & FILE_ATTRIBUTE_REPARSE_POINT):
                            stack.append(entry.path)

    with prog.lock:
        prog.found = len(found)
        hit_cap = "Stopped at" in (prog.message or "")
        prog.cancelled = cancel.is_set() and not hit_cap
        if prog.cancelled:
            prog.message = "Scan cancelled."
        elif not prog.message:
            prog.message = f"Done. {len(found):,} encrypted item(s)."
        prog.running = False
        prog.done = True
        prog.current = ""
    return found
