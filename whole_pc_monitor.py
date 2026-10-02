import ctypes
import os
import struct
import threading
import time
from ctypes import wintypes
from pathlib import Path


RISKY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".com",
    ".pif", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".py",
    ".lnk", ".reg", ".inf", ".iso", ".img", ".zip", ".rar", ".7z",
}
MAX_FILE_BYTES = 300 * 1024 * 1024
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_ALL = 0x7
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
NOTIFY_FILTER = 0x1 | 0x2 | 0x8 | 0x10 | 0x20
ACTIONS_OF_INTEREST = {1, 3, 5}
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.ReadDirectoryChangesW.argtypes = (
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p,
    )
    kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
    kernel32.CancelIoEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
    kernel32.CancelIoEx.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
else:
    kernel32 = None


def fixed_and_removable_drives():
    if kernel32 is None:
        return []
    roots = []
    bitmask = kernel32.GetLogicalDrives()
    for index in range(26):
        if bitmask & (1 << index):
            root = chr(ord("A") + index) + ":\\"
            if kernel32.GetDriveTypeW(root) in (2, 3):
                roots.append(root)
    return roots


def path_is_excluded(path, excluded_roots):
    candidate = os.path.normcase(os.path.abspath(path))
    for root in excluded_roots:
        normalized = os.path.normcase(os.path.abspath(root))
        try:
            if os.path.commonpath((candidate, normalized)) == normalized:
                return True
        except ValueError:
            continue
    return False


def eligible_risky_file(path, excluded_roots=(), max_bytes=MAX_FILE_BYTES):
    file_path = Path(path)
    if file_path.suffix.lower() not in RISKY_EXTENSIONS:
        return False
    if path_is_excluded(file_path, excluded_roots):
        return False
    try:
        return file_path.is_file() and file_path.stat().st_size <= max_bytes
    except OSError:
        return False


class WholePCMonitor:
    def __init__(self, callback, status_callback=None, excluded_roots=(),
                 roots=None, settle_seconds=2.0, max_bytes=MAX_FILE_BYTES):
        self.callback = callback
        self.status_callback = status_callback or (lambda _text: None)
        self.excluded_roots = tuple(str(Path(root).resolve()) for root in excluded_roots)
        self.roots = tuple(roots) if roots is not None else tuple(fixed_and_removable_drives())
        self.settle_seconds = settle_seconds
        self.max_bytes = max_bytes
        self.stop_event = threading.Event()
        self.pending = {}
        self.last_scanned = {}
        self.lock = threading.Lock()
        self.handles = set()
        self.threads = []

    def start(self):
        if kernel32 is None:
            self.status_callback("Whole-PC file monitoring requires Windows")
            return ()
        if self.threads:
            return self.roots
        settle_thread = threading.Thread(target=self._settle_loop, daemon=True)
        settle_thread.start()
        self.threads.append(settle_thread)
        for root in self.roots:
            thread = threading.Thread(target=self._watch_root, args=(root,), daemon=True)
            thread.start()
            self.threads.append(thread)
        self.status_callback(
            "Whole-PC passive research watching: " + ", ".join(self.roots))
        return self.roots

    def stop(self):
        self.stop_event.set()
        with self.lock:
            handles = tuple(self.handles)
            self.handles.clear()
        for handle in handles:
            try:
                kernel32.CancelIoEx(handle, None)
                kernel32.CloseHandle(handle)
            except (OSError, ValueError):
                pass

    def mark_changed(self, path):
        if Path(path).suffix.lower() not in RISKY_EXTENSIONS:
            return
        if path_is_excluded(path, self.excluded_roots):
            return
        with self.lock:
            self.pending[os.path.abspath(path)] = (None, 0)

    def settle_once(self):
        ready = []
        with self.lock:
            items = tuple(self.pending.items())
        for path, (previous_signature, stable_count) in items:
            try:
                stat = os.stat(path)
                if not os.path.isfile(path) or stat.st_size > self.max_bytes:
                    raise OSError
                signature = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                with self.lock:
                    self.pending.pop(path, None)
                continue
            count = stable_count + 1 if previous_signature == signature else 0
            if count < 1:
                with self.lock:
                    self.pending[path] = (signature, count)
                continue
            with self.lock:
                self.pending.pop(path, None)
                if self.last_scanned.get(path) == signature:
                    continue
                self.last_scanned[path] = signature
            if eligible_risky_file(path, self.excluded_roots, self.max_bytes):
                ready.append(path)
        for path in ready:
            self.callback(path)
        return tuple(ready)

    def _settle_loop(self):
        while not self.stop_event.wait(self.settle_seconds):
            try:
                self.settle_once()
            except Exception as exc:
                self.status_callback(f"Whole-PC settle check error: {exc}")

    def _watch_root(self, root):
        handle = kernel32.CreateFileW(
            root, FILE_LIST_DIRECTORY, FILE_SHARE_ALL, None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, None)
        if handle == INVALID_HANDLE_VALUE:
            self.status_callback(
                f"Could not watch {root}: Windows error {ctypes.get_last_error()}")
            return
        with self.lock:
            self.handles.add(handle)
        buffer = ctypes.create_string_buffer(65536)
        bytes_returned = wintypes.DWORD()
        try:
            while not self.stop_event.is_set():
                ok = kernel32.ReadDirectoryChangesW(
                    handle, buffer, len(buffer), True, NOTIFY_FILTER,
                    ctypes.byref(bytes_returned), None, None)
                if not ok:
                    if not self.stop_event.is_set():
                        self.status_callback(
                            f"Watch stopped on {root}: Windows error {ctypes.get_last_error()}")
                    break
                self._parse_events(root, buffer.raw[:bytes_returned.value])
        finally:
            with self.lock:
                should_close = handle in self.handles
                self.handles.discard(handle)
            if should_close:
                kernel32.CloseHandle(handle)

    def _parse_events(self, root, data):
        offset = 0
        while offset + 12 <= len(data):
            next_offset, action, name_length = struct.unpack_from("<III", data, offset)
            name = data[offset + 12:offset + 12 + name_length].decode(
                "utf-16-le", errors="ignore")
            if action in ACTIONS_OF_INTEREST and name:
                self.mark_changed(os.path.join(root, name))
            if next_offset == 0:
                break
            offset += next_offset
