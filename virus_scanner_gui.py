"""GUI virus scanner - wraps .devin/skills/virus-scan/scanner.py.

- Add files or folders manually, hit SCAN
- Passive whole-PC mode: uses ReadDirectoryChangesW on every fixed/removable
  drive to catch new/changed risky files in real time and auto-scan them.
  You get a popup if something comes back NOT SAFE or UNKNOWN.
"""
import contextlib
import ctypes
import io
import os
import queue
import struct
import sys
import threading
import time
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, messagebox, ttk

SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCANNER_DIR)
import scanner  # noqa: E402

VERDICT = {
    0: ("SAFE", "#3fb950"),
    1: ("NOT SAFE", "#f85149"),
    2: ("UNKNOWN", "#d29922"),
}
TAG = {0: "safe", 1: "bad", 2: "unknown"}

BG = "#0d1117"
PANEL = "#161b22"
FG = "#c9d1d9"
ACCENT = "#58a6ff"

# File types worth auto-scanning when they appear/change anywhere on disk.
RISKY_EXT = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".com", ".pif",
    ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".py", ".lnk", ".reg",
    ".inf", ".iso", ".img", ".zip", ".rar", ".7z",
}
MAX_AUTOSCAN_BYTES = 300 * 1024 * 1024  # skip huge files (hash cost)

# --- Win32 constants for ReadDirectoryChangesW ---
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_ALL = 0x7
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

NOTIFY_FILTER = (0x1 | 0x2 | 0x8 | 0x10 | 0x20)  # name|dir|size|last_write|creation
ACTIONS_OF_INTEREST = {1, 3, 5}  # added, modified, renamed-to
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Virus Scanner")
        self.geometry("980x680")
        self.configure(bg=BG)
        self.minsize(760, 480)

        self._msg_q = queue.Queue()
        self._scan_q = queue.Queue()
        self._busy = set()          # paths enqueued or being scanned
        self._rows = {}             # path -> tree item id
        self._logs = {}             # path -> full scan output
        self._scanned_count = 0

        self._watch_dirs = []       # manually watched folders (polled)
        self._watch_on = False      # master passive switch
        self._pc_watch = False      # whole-PC mode active
        self._drive_threads = []
        self._known = {}            # path -> (size, mtime) already-seen
        self._pending = {}          # path -> last seen size (stability check)

        self._build_ui()

        threading.Thread(target=self._scan_worker, daemon=True).start()
        threading.Thread(target=self._settle_worker, daemon=True).start()
        self.after(100, self._poll_queue)

    # ---------- UI ----------

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=PANEL, foreground=FG, fieldbackground=PANEL,
            rowheight=24, borderwidth=0,
        )
        style.configure("Treeview.Heading", background="#21262d", foreground=FG)
        style.map("Treeview", background=[("selected", "#1f6feb")])

        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=10, pady=(10, 2))

        self._mk_btn(top, "Add Files", self.add_files).pack(side="left")
        self._mk_btn(top, "Add Folder", self.add_folder).pack(
            side="left", padx=(8, 0))
        self._mk_btn(top, "Clear", self.clear_list).pack(side="left", padx=(8, 0))

        tk.Button(
            top, text="SCAN", command=self.scan_all,
            bg=ACCENT, fg="#0d1117", relief="flat", padx=20, pady=6,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="right")

        watch = tk.Frame(self, bg=BG)
        watch.pack(fill="x", padx=10, pady=(2, 4))

        self._mk_btn(watch, "Watch Whole PC", self.watch_whole_pc).pack(
            side="left")
        self._mk_btn(watch, "Watch Folder...", self.watch_folder).pack(
            side="left", padx=(8, 0))
        self._mk_btn(watch, "Stop Watching", self.stop_watching).pack(
            side="left", padx=(8, 0))

        self.watch_lbl = tk.Label(
            watch, text="Passive scan: OFF", bg=BG, fg="#8b949e", anchor="w")
        self.watch_lbl.pack(side="left", padx=12)

        self.status_lbl = tk.Label(
            watch, text="Add files or a folder, then hit SCAN",
            bg=BG, fg="#8b949e", anchor="e")
        self.status_lbl.pack(side="right")

        self.tree = ttk.Treeview(
            self, columns=("path", "source", "result"), show="headings",
            height=10)
        self.tree.heading("path", text="File")
        self.tree.heading("source", text="Source")
        self.tree.heading("result", text="Result")
        self.tree.column("path", width=640, anchor="w")
        self.tree.column("source", width=90, anchor="center")
        self.tree.column("result", width=130, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=4)
        self.tree.tag_configure("safe", foreground="#3fb950")
        self.tree.tag_configure("bad", foreground="#f85149")
        self.tree.tag_configure("unknown", foreground="#d29922")
        self.tree.tag_configure("pending", foreground="#8b949e")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.log = tk.Text(
            self, bg=PANEL, fg=FG, insertbackground=FG,
            relief="flat", wrap="word", font=("Consolas", 9),
            state="disabled", height=12)
        self.log.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self.log.tag_configure("safe", foreground="#3fb950")
        self.log.tag_configure("bad", foreground="#f85149")
        self.log.tag_configure("unknown", foreground="#d29922")
        self.log.tag_configure("header", foreground=ACCENT)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=(0, 10))

    def _mk_btn(self, parent, text, cmd):
        return tk.Button(
            parent, text=text, command=cmd,
            bg="#21262d", fg=FG, relief="flat", padx=12, pady=6)

    # ---------- manual queue ----------

    def add_files(self):
        for p in filedialog.askopenfilenames(title="Select files to scan"):
            self._add_path(p, "manual")

    def add_folder(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if not folder:
            return
        count = 0
        for root, _, files in os.walk(folder):
            for name in files:
                self._add_path(os.path.join(root, name), "manual")
                count += 1
        if count == 0:
            messagebox.showinfo("Empty folder", "No files found in that folder.")

    def _add_path(self, path, source):
        path = os.path.abspath(path)
        if path in self._rows:
            return
        item = self.tree.insert(
            "", "end", values=(path, source, "Queued"), tags=("pending",))
        self._rows[path] = item
        self.status_lbl.config(text=f"{len(self._rows)} file(s) in list")

    def clear_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._rows.clear()
        self._logs.clear()
        self._set_log("")
        self.status_lbl.config(text="Add files or a folder, then hit SCAN")

    def scan_all(self):
        queued = [
            p for p, item in self._rows.items()
            if self.tree.item(item, "values")[2] in ("Queued", "UNKNOWN")
        ]
        if not queued:
            messagebox.showinfo("Nothing to scan",
                                "Add files or a folder first.")
            return
        for p in queued:
            self._enqueue_scan(p, "manual")

    # ---------- passive watching ----------

    def watch_whole_pc(self):
        if self._pc_watch:
            return
        roots = self._enum_drives()
        if not roots:
            messagebox.showerror("No drives", "Could not find any drives.")
            return
        self._watch_on = True
        self._pc_watch = True
        for root in roots:
            t = threading.Thread(
                target=self._drive_watch_worker, args=(root,), daemon=True)
            t.start()
            self._drive_threads.append(t)
        self._update_watch_lbl()
        self._append_log(
            f">>> Whole-PC watch started on: {', '.join(roots)}\n"
            "    Auto-scanning new/changed risky file types.\n",
            "header")

    def watch_folder(self):
        folder = filedialog.askdirectory(title="Folder to watch")
        if not folder:
            return
        folder = os.path.abspath(folder)
        if folder not in self._watch_dirs:
            self._watch_dirs.append(folder)
            # Baseline: only NEW/CHANGED files after this point get scanned
            for root, _, files in os.walk(folder):
                for name in files:
                    p = os.path.join(root, name)
                    try:
                        st = os.stat(p)
                        self._known[p] = (st.st_size, st.st_mtime)
                    except OSError:
                        pass
        self._watch_on = True
        self._update_watch_lbl()
        self._append_log(f">>> Now watching: {folder}\n", "header")

    def stop_watching(self):
        self._watch_on = False
        self._pc_watch = False
        self._watch_dirs.clear()
        self._pending.clear()
        self._update_watch_lbl()
        self._append_log(">>> Passive watching stopped\n", "header")

    def _update_watch_lbl(self):
        if not self._watch_on:
            self.watch_lbl.config(text="Passive scan: OFF", fg="#8b949e")
        elif self._pc_watch:
            self.watch_lbl.config(
                text="Passive scan: WHOLE PC", fg="#3fb950")
        else:
            names = ", ".join(
                os.path.basename(d) or d for d in self._watch_dirs)
            self.watch_lbl.config(
                text=f"Passive scan: ON ({names})", fg="#3fb950")

    @staticmethod
    def _enum_drives():
        roots = []
        bitmask = kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                root = chr(ord("A") + i) + ":\\"
                # 2 = removable, 3 = fixed
                if kernel32.GetDriveTypeW(root) in (2, 3):
                    roots.append(root)
        return roots

    def _drive_watch_worker(self, root):
        """One thread per drive: blocks on ReadDirectoryChangesW and feeds
        changed risky-looking paths into the pending-stability queue."""
        h = kernel32.CreateFileW(
            root, FILE_LIST_DIRECTORY, FILE_SHARE_ALL, None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, None)
        if h == INVALID_HANDLE_VALUE:
            self._msg_q.put(("log",
                             f"Watch failed on {root}: "
                             f"error {ctypes.get_last_error()}"))
            return
        event = kernel32.CreateEventW(None, True, False, None)
        ol = OVERLAPPED()
        ol.hEvent = event
        buf = ctypes.create_string_buffer(65536)
        n = wintypes.DWORD()
        try:
            while self._pc_watch:
                kernel32.ResetEvent(event)
                ok = kernel32.ReadDirectoryChangesW(
                    h, buf, len(buf), True, NOTIFY_FILTER,
                    None, ctypes.byref(ol), None)
                if not ok and ctypes.get_last_error() != ERROR_IO_PENDING:
                    self._msg_q.put(
                        ("log", f"Watch stopped on {root}: "
                                f"error {ctypes.get_last_error()}"))
                    break
                rc = kernel32.WaitForSingleObject(event, 800)
                if rc == WAIT_TIMEOUT:
                    continue
                if rc != WAIT_OBJECT_0:
                    continue
                if not kernel32.GetOverlappedResult(
                        h, ctypes.byref(ol), ctypes.byref(n), False):
                    continue
                self._parse_events(root, buf.raw[:n.value])
        finally:
            kernel32.CloseHandle(event)
            kernel32.CloseHandle(h)

    def _parse_events(self, root, data):
        offset = 0
        while offset + 12 <= len(data):
            next_off, action, name_len = struct.unpack_from(
                "<III", data, offset)
            name = data[offset + 12:offset + 12 + name_len].decode(
                "utf-16-le", "ignore")
            if action in ACTIONS_OF_INTEREST and name:
                self._event_pending(os.path.join(root, name))
            if next_off == 0:
                break
            offset += next_off

    def _event_pending(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext not in RISKY_EXT:
            return
        if path in self._busy or path in self._pending:
            return
        self._pending[path] = None  # None = "changed, not yet size-checked"

    def _settle_worker(self):
        """Every few seconds: poll watched folders AND settle pending
        whole-PC events (scan a file once its size stops changing)."""
        while True:
            time.sleep(2.5)
            if not self._watch_on:
                continue
            try:
                if self._watch_dirs:
                    self._poll_dirs()
                self._settle_pending()
            except Exception:
                pass

    def _poll_dirs(self):
        for d in list(self._watch_dirs):
            for root, _, files in os.walk(d):
                for name in files:
                    p = os.path.join(root, name)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    sig = (st.st_size, st.st_mtime)
                    if self._known.get(p) == sig:
                        continue
                    prev = self._pending.get(p)
                    ticks = prev[1] + 1 if isinstance(prev, tuple) \
                        and prev[0] == sig else 0
                    if ticks >= 2:
                        self._pending.pop(p, None)
                        self._known[p] = sig
                        self._enqueue_scan(p, "watch")
                    else:
                        self._pending[p] = (sig, ticks)

    def _settle_pending(self):
        for p, last_size in list(self._pending.items()):
            if isinstance(last_size, tuple):
                continue  # belongs to folder-poll logic
            try:
                st = os.stat(p)
            except OSError:
                self._pending.pop(p, None)
                continue
            if not os.path.isfile(p):
                self._pending.pop(p, None)
                continue
            sig = (st.st_size, st.st_mtime)
            if self._known.get(p) == sig:
                self._pending.pop(p, None)
                continue
            if st.st_size == last_size:
                self._pending.pop(p, None)
                self._known[p] = sig
                if st.st_size > MAX_AUTOSCAN_BYTES:
                    self._msg_q.put(
                        ("log", f"Skipped (too large): {p}"))
                else:
                    self._enqueue_scan(p, "watch")
            else:
                self._pending[p] = st.st_size

    # ---------- scan engine ----------

    def _enqueue_scan(self, path, source):
        path = os.path.abspath(path)
        if path in self._busy:
            return
        self._busy.add(path)
        self._scan_q.put((path, source))

    def _scan_worker(self):
        while True:
            path, source = self._scan_q.get()
            self._msg_q.put(("scanning", path, source))
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    code = scanner.scan(path)
            except Exception as e:
                print(f"Scanner crashed: {e}", file=buf)
                code = 2
            self._logs[path] = buf.getvalue()
            self._busy.discard(path)
            self._msg_q.put(("result", path, code, source))
            if self._scan_q.empty() and not self._busy:
                self._msg_q.put(("idle",))

    def _poll_queue(self):
        try:
            while True:
                msg = self._msg_q.get_nowait()
                kind = msg[0]
                if kind == "scanning":
                    _, path, source = msg
                    self._upsert_row(path, source, "Scanning...", "pending")
                    self.progress.start(12)
                    self.status_lbl.config(
                        text=f"Scanning: {os.path.basename(path)}")
                    self._append_log(f"\n>>> Scanning {path}\n", "header")
                elif kind == "result":
                    _, path, code, source = msg
                    label, _ = VERDICT.get(code, VERDICT[2])
                    self._upsert_row(
                        path, source, label, TAG.get(code, "unknown"))
                    self._scanned_count += 1
                    self._append_log(
                        self._logs.get(path, "") + f"[{label}] {path}\n",
                        TAG.get(code, "unknown"))
                    self.status_lbl.config(
                        text=f"Scanned {self._scanned_count} "
                             "file(s) this session")
                    if source == "watch" and code == 1:
                        self.bell()
                        messagebox.showwarning(
                            "Threat detected!",
                            f"NOT SAFE: {path}\n\n"
                            "VirusTotal/heuristics flagged this file. "
                            "Do not run it.")
                    elif source == "watch" and code == 2:
                        self.bell()
                        messagebox.showinfo(
                            "Unknown file",
                            f"UNKNOWN: {path}\n\n"
                            "Not in VirusTotal's database. Use caution.")
                elif kind == "log":
                    self._append_log(f">>> {msg[1]}\n", "header")
                elif kind == "idle":
                    self.progress.stop()
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _upsert_row(self, path, source, result, tag):
        if path in self._rows:
            item = self._rows[path]
            self.tree.item(item, values=(path, source, result), tags=(tag,))
        else:
            item = self.tree.insert(
                "", "end", values=(path, source, result), tags=(tag,))
            self._rows[path] = item
            self.tree.see(item)

    # ---------- helpers ----------

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        path = self.tree.item(sel[0], "values")[0]
        text = self._logs.get(path)
        if text:
            self._set_log(f"===== {path} =====\n\n{text}")

    def _append_log(self, text, tag=None):
        self.log.config(state="normal")
        self.log.insert("end", text, tag or ())
        self.log.see("end")
        self.log.config(state="disabled")

    def _set_log(self, text):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", text)
        self.log.config(state="disabled")


if __name__ == "__main__":
    ScannerGUI().mainloop()
