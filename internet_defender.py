import ctypes
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from dataclasses import asdict, replace
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

from whole_pc_monitor import WholePCMonitor, path_is_excluded

from mission_control import (
    card_from_connection,
    card_from_file,
    card_from_local_finding,
    card_from_remote_access,
    contain_operation,
    investigate_operation,
)

from gmail_alerts import (
    audit_gmail_settings,
    connect_gmail,
    disconnect_gmail,
    gmail_connected,
    gmail_settings_authorized,
    scan_gmail_alerts,
)

from account_liberation import (
    CHECKLIST_STEPS,
    PROVIDER_PLANS,
    add_account,
    add_known_device,
    blast_radius,
    build_stolen_account_report,
    checklist_completion,
    checklist_for,
    discover_account_candidates,
    list_accounts,
    list_known_devices,
    post_recovery_result,
    prioritize_alert,
    provider_plan,
    remove_account,
    remove_known_device,
    save_checklist,
    save_encrypted_recovery_report,
)

from local_detective_core import (
    collect_startup_items as collect_local_startup_items,
    connection_program_name,
    data_root as local_data_root,
    describe_connection,
    describe_program,
    detect_remote_access,
    disconnect_remote_access,
    inspect_local_file,
    investigate_connection_processes,
    run_local_scan,
    save_remote_access_report,
    save_startup_baseline as save_local_startup_baseline,
)

from defender_core import (
    RISKY_EXTENSIONS,
    VirusTotalClient,
    active_connections,
    ad_block_enabled,
    active_network_quarantine_backup,
    block_ip,
    disable_ad_block,
    download_origin,
    enable_ad_block,
    inspect_file,
    list_quarantine_items,
    load_virustotal_key,
    normalize_indicator,
    quarantine_file,
    recent_risky_files,
    restore_emergency_network,
    restore_network_quarantine,
    restore_quarantine_item,
    running_executable_paths,
    save_origin_report,
    save_virustotal_key,
    should_auto_block_reputation,
    start_network_quarantine,
    startup_file_paths,
)


GOOGLE_ACCOUNT_PAGES = (
    ("Recover access", "https://accounts.google.com/signin/recovery"),
    ("Change password", "https://myaccount.google.com/signinoptions/password"),
    ("Sign out unknown devices", "https://myaccount.google.com/device-activity"),
    ("Review security", "https://myaccount.google.com/security-checkup"),
)

RECOVERY_PROVIDERS = {
    "Microsoft": "https://support.microsoft.com/en-us/account-billing/how-to-recover-a-hacked-or-compromised-microsoft-account-24ca907d-bcdf-a44b-4656-47f0cd89c245",
    "Google": "https://support.google.com/accounts/answer/6294825?hl=en",
    "Discord": "https://support.discord.com/hc/en-us/articles/24160905919511-My-Discord-Account-was-Hacked-or-Compromised",
    "Steam": "https://help.steampowered.com/en/wizard/HelpWithAccountStolen",
    "Any other account": None,
}


def mask_email_address(value):
    local, separator, domain = value.strip().partition("@")
    if not separator or not local or not domain:
        return "Connected Gmail account"
    return f"{local[0]}{'*' * max(3, len(local) - 1)}@{domain}"


def recovery_pages_for_alerts(alerts):
    pages = []
    seen = set()
    labels = {
        "recovery": "Recover access",
        "security": "Review security",
        "devices": "Sign out unknown devices",
        "connected_apps": "Review connected apps",
        "payments": "Review purchases and payments",
    }
    for alert in alerts:
        _service, plan = provider_plan(alert.service)
        candidates = list(GOOGLE_ACCOUNT_PAGES) if alert.service == "Google" else []
        if alert.recovery_url:
            candidates.append((f"{alert.service} account recovery", alert.recovery_url))
        candidates.extend((labels[key], url) for key, url in plan.items() if url)
        for name, url in candidates:
            if url and url not in seen:
                seen.add(url)
                pages.append((name, url))
    return tuple(pages)


BG = "#080907"
PANEL = "#151711"
FG = "#f2f0df"
MUTED = "#9b9d8d"
ACCENT = "#f4d03f"
DANGER = "#d63c32"
COLORS = {
    "LOW": "#78b84a",
    "MEDIUM": "#f4d03f",
    "HIGH": "#ef8b32",
    "CRITICAL": "#ef4035",
    "UNKNOWN": "#9b9d8d",
}


APPLICATION_SOURCE_FILES = (
    "account_liberation.py",
    "defender_core.py",
    "gmail_alerts.py",
    "internet_defender.py",
    "local_detective_core.py",
    "mission_control.py",
    "scanner.py",
    "virus_scanner_gui.py",
    "whole_pc_monitor.py",
)


def application_root():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def application_component_paths():
    if getattr(sys, "frozen", False):
        return (Path(sys.executable).resolve(),)
    return tuple(application_root() / name for name in APPLICATION_SOURCE_FILES)


def passive_scan_excluded_roots():
    return (
        Path(os.environ.get("LOCALAPPDATA", Path.home())) / "InternetDefender" / "quarantine",
        local_data_root() / "quarantine",
        *application_component_paths(),
    )


def combined_file_severity(inspection, local_assessment=None):
    levels = {"INFO": 0, "LOW": 1, "UNKNOWN": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    local_severity = local_assessment.severity if local_assessment else "INFO"
    return max((inspection.severity, local_severity), key=lambda value: levels.get(value, 0))


def passive_quarantine_confirmed(inspection):
    return bool(
        inspection.reputation and
        inspection.reputation.severity in {"HIGH", "CRITICAL"}
    )


def inspect_passive_file(path, vt_client, excluded_roots=()):
    if path_is_excluded(path, excluded_roots):
        return None
    try:
        if not Path(path).is_file():
            return None
        return inspect_file(path, vt_client), inspect_local_file(path)
    except (OSError, ValueError):
        return None


def connection_program_names(connections):
    names = tuple(dict.fromkeys(connection_program_name(connection) for connection in connections))
    return ", ".join(names) or "Unknown program"


def connection_program_details(connections):
    details = tuple(dict.fromkeys(describe_program(connection) for connection in connections))
    return "\n\n".join(details) or "Program: Unknown\nWhat it is: Windows could not identify it."


class InternetDefenderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Helldivers 2 - Super Earth Incident Response")
        self.geometry("1120x760")
        self.minsize(900, 620)
        self.configure(bg=BG)
        self.app_icon = tk.PhotoImage(width=32, height=32)
        self.app_icon.put(BG, to=(0, 0, 32, 32))
        self.app_icon.put(ACCENT, to=(4, 5, 28, 11))
        self.app_icon.put(ACCENT, to=(8, 11, 24, 17))
        self.app_icon.put(ACCENT, to=(12, 17, 20, 27))
        self.iconphoto(True, self.app_icon)
        self.protocol("WM_DELETE_WINDOW", self._close)
        stored_key = load_virustotal_key()
        self.vt = VirusTotalClient(api_key=stored_key or None)
        self.jobs = queue.Queue()
        self.messages = queue.Queue()
        self.stop_event = threading.Event()
        self.monitoring = True
        self.passive_file_protection = True
        self.emergency_active = False
        self.network_quarantine_active = False
        self.network_quarantine_backup = None
        self.network_restore_requested = False
        self.sweep_active = False
        self.sweep_round = 0
        self.sweep_prompted = set()
        self.sweep_reports = []
        self.sweep_errors = []
        self.seen_ips = set()
        self.reputations = {}
        self.connection_rows = {}
        self.connection_anomalies = {}
        self.anomaly_prompted = set()
        self.mission_cards = {}
        self.mission_card_keys = {}
        self.mission_investigations = {}
        self.blocked_ips = set()
        self.auto_block_critical = True
        self.ad_blocking_enabled = ad_block_enabled()
        self.current_file = None
        quarantine_items = list_quarantine_items()
        self.last_quarantine_item = quarantine_items[0] if quarantine_items else None
        self.current_indicator = None
        self.local_findings = {}
        self.local_scan_result = None
        self.remote_access_findings = {}
        self.remote_containment_actions = []
        self.remote_access_report = None
        self.gmail_alerts_connected = gmail_connected()
        self.gmail_settings_access = gmail_settings_authorized()
        self.gmail_account_display = ""
        self.gmail_settings_audit = None
        self.last_account_recovery_data = None
        self.last_recovery_report = None
        self.last_account_alerts = ()
        self.detected_account_candidates = ()
        self.confirmed_affected_account_ids = set()
        self.downloads_path = Path.home() / "Downloads"
        self.passive_scan_exclusions = passive_scan_excluded_roots()
        self.whole_pc_monitor = None
        self.whole_pc_roots = ()
        self.download_known = {}
        self.download_pending = {}
        self._build_ui()
        previous_backup = active_network_quarantine_backup()
        if previous_backup:
            self.network_quarantine_active = True
            self.network_quarantine_backup = previous_backup
            self.restore_button.configure(state="normal")
            self.protection_label.configure(text="PC NETWORK QUARANTINED", fg=DANGER)
            self._set_activity(
                "A previous emergency quarantine is still active. Click Restore Internet.", DANGER)
        threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._monitor_worker, daemon=True).start()
        self.whole_pc_monitor = WholePCMonitor(
            callback=lambda path: self.jobs.put(("passive_file", path)),
            status_callback=lambda text: self.messages.put(("whole_pc_status", text)),
            excluded_roots=self.passive_scan_exclusions,
        )
        self.whole_pc_roots = self.whole_pc_monitor.start()
        self.jobs.put(("connections",))
        self.after(100, self._poll_messages)
        if "--enable-ad-block" in sys.argv:
            self.after(700, lambda: self._apply_ad_block(True, skip_confirmation=True))
        elif "--disable-ad-block" in sys.argv:
            self.after(700, lambda: self._apply_ad_block(False, skip_confirmation=True))
        elif "--start-emergency" in sys.argv:
            self.after(700, lambda: self._start_emergency(skip_confirmation=True))

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#25271f", foreground=FG, padding=(15, 9))
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT)], foreground=[("selected", "#090a07")],
        )
        style.configure(
            "Treeview", background=PANEL, foreground=FG, fieldbackground=PANEL,
            rowheight=25, borderwidth=0,
        )
        style.configure("Treeview.Heading", background=ACCENT, foreground="#090a07")
        stripe = tk.Canvas(self, height=8, bg="#090a07", highlightthickness=0)
        stripe.pack(fill="x")
        for x in range(-20, 1200, 40):
            stripe.create_polygon(
                x, 0, x + 20, 0, x + 30, 8, x + 10, 8,
                fill=ACCENT, outline=ACCENT)
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=14, pady=(12, 6))
        branding = tk.Frame(header, bg=BG)
        branding.pack(side="left")
        tk.Label(
            branding, text="SUPER EARTH MINISTRY OF DEFENSE // CYBER WARFARE DIVISION", bg=BG, fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            branding, text="HELLDIVER DIGITAL WARFARE CONSOLE", bg=BG, fg=FG,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")
        self.protection_label = tk.Label(
            header, text="MISSION STATUS: PROTECTION ON", bg=BG, fg="#78b84a",
            font=("Consolas", 10, "bold"),
        )
        self.protection_label.pack(side="right")
        tk.Label(
            self,
            text=("UNOFFICIAL FAN-MADE TOOL — NOT AFFILIATED WITH ARROWHEAD OR SONY. "
                  "All containment requires authorization."),
            bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=1060,
        ).pack(fill="x", padx=14, pady=(0, 6))
        emergency = tk.Frame(self, bg=PANEL, highlightbackground=ACCENT, highlightthickness=1)
        emergency.pack(fill="x", padx=14, pady=(0, 8))
        self.emergency_button = tk.Button(
            emergency, text="DEPLOY 500 KG — 5-PASS EMERGENCY SCAN", command=self._start_emergency,
            bg=DANGER, fg="white", activebackground="#ef4035", relief="flat",
            padx=18, pady=9, font=("Segoe UI", 10, "bold"),
        )
        self.emergency_button.pack(side="left", padx=6, pady=6)
        self.restore_button = self._button(
            emergency, "Restore Internet Now", self._restore_emergency)
        self.restore_button.configure(state="disabled")
        self.restore_button.pack(side="left", padx=4)
        tk.Label(
            emergency, text="Takes normal programs offline, checks everything 5 times, then restores internet.",
            bg=PANEL, fg=MUTED,
        ).pack(side="left", padx=8)
        activity = tk.Frame(self, bg="#202217", highlightbackground=ACCENT, highlightthickness=1)
        activity.pack(fill="x", padx=14, pady=(0, 8))
        tk.Label(
            activity, text="MISSION FEED:", bg="#202217", fg=ACCENT,
            font=("Consolas", 9, "bold"),
        ).pack(side="left", padx=(9, 5), pady=6)
        self.activity_label = tk.Label(
            activity, text="Watching internet connections and new Downloads files",
            bg="#202217", fg=FG, anchor="w", font=("Segoe UI", 9),
        )
        self.activity_label.pack(side="left", fill="x", expand=True, padx=(0, 9), pady=6)
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.live_tab = tk.Frame(notebook, bg=BG)
        self.file_tab = tk.Frame(notebook, bg=BG)
        self.local_tab = tk.Frame(notebook, bg=BG)
        self.rescue_tab = tk.Frame(notebook, bg=BG)
        self.settings_tab = tk.Frame(notebook, bg=BG)
        self.help_tab = tk.Frame(notebook, bg=BG)
        notebook.add(self.live_tab, text="MISSION CONTROL")
        notebook.add(self.file_tab, text="SAMPLE LAB (Files)")
        notebook.add(self.local_tab, text="LOCAL DETECTIVE")
        notebook.add(self.rescue_tab, text="ACCOUNT LIBERATION")
        notebook.add(self.settings_tab, text="REQUISITIONS")
        notebook.add(self.help_tab, text="FIELD MANUAL")
        self._build_live_tab()
        self._build_file_tab()
        self._build_local_tab()
        self._build_rescue_tab()
        self._build_settings_tab()
        self._build_help_tab()

    def _button(self, parent, text, command, primary=False):
        return tk.Button(
            parent, text=text, command=command, relief="flat", padx=13, pady=7,
            bg=ACCENT if primary else "#292b21", fg="#090a07" if primary else FG,
            activebackground="#ffe86a" if primary else "#3a3d30",
            highlightbackground=ACCENT if primary else "#4a4d3d", highlightthickness=1,
            cursor="hand2", font=("Segoe UI", 9, "bold" if primary else "normal"),
        )

    def _build_live_tab(self):
        tk.Label(
            self.live_tab, text="MISSION CONTROL // COMBINED THREAT OPERATIONS",
            bg=BG, fg=ACCENT, font=("Segoe UI", 12, "bold"), anchor="w",
        ).pack(fill="x", pady=(10, 0))
        tk.Label(
            self.live_tab,
            text=("Mission Control collects important Internet Detective, Ministry of Science, and Local Detective "
                  "findings into operation cards. INVESTIGATE builds one timeline and verdict. Confirmed threats can "
                  "use confirmation-gated containment. Live internet activity remains visible below without raw IPs "
                  "or traffic contents."),
            bg=BG, fg=FG, anchor="w", wraplength=1000,
        ).pack(fill="x", pady=(10, 0))
        mission_controls = tk.Frame(self.live_tab, bg=BG)
        mission_controls.pack(fill="x", pady=(8, 5))
        tk.Label(
            mission_controls, text="ACTIVE OPERATIONS", bg=BG, fg=ACCENT,
            font=("Consolas", 10, "bold"),
        ).pack(side="left")
        self.investigate_button = self._button(
            mission_controls, "INVESTIGATE", self._investigate_mission_card, True)
        self.investigate_button.configure(state="disabled")
        self.investigate_button.pack(side="right")
        self.contain_button = self._button(
            mission_controls, "CONTAIN THREAT", self._contain_mission_card)
        self.contain_button.configure(state="disabled")
        self.contain_button.pack(side="right", padx=8)
        mission_columns = ("severity", "source", "operation", "status")
        self.mission_tree = ttk.Treeview(
            self.live_tab, columns=mission_columns, show="headings", height=5)
        mission_headings = {
            "severity": "Threat", "source": "Evidence Source",
            "operation": "Operation Card", "status": "Operation Status",
        }
        mission_widths = {"severity": 90, "source": 160, "operation": 570, "status": 150}
        for column in mission_columns:
            self.mission_tree.heading(column, text=mission_headings[column])
            self.mission_tree.column(column, width=mission_widths[column], anchor="w")
        for severity, color in {**COLORS, "INFO": MUTED}.items():
            self.mission_tree.tag_configure(severity, foreground=color)
        self.mission_tree.pack(fill="x")
        self.mission_tree.bind("<<TreeviewSelect>>", self._show_mission_card)
        self.mission_detail = tk.Text(
            self.live_tab, height=7, bg=PANEL, fg=FG, insertbackground=FG,
            relief="flat", state="disabled", wrap="word", font=("Consolas", 9))
        self.mission_detail.pack(fill="x", pady=(5, 5))
        self.live_detail = self.mission_detail
        controls = tk.Frame(self.live_tab, bg=BG)
        controls.pack(fill="x", pady=8)
        self.monitor_button = self._button(controls, "Pause Monitoring", self._toggle_monitor, True)
        self.monitor_button.pack(side="left")
        self._button(controls, "Refresh", self._request_connections).pack(side="left", padx=8)
        self._button(controls, "Check Selected", self._investigate_selected).pack(side="left")
        self._button(
            controls, "Block Selected Confirmed Threat", self._block_selected).pack(side="right")
        options = tk.Frame(self.live_tab, bg=BG)
        options.pack(fill="x", pady=(0, 8))
        self.auto_block_var = tk.BooleanVar(value=self.auto_block_critical)
        tk.Checkbutton(
            options, text="Auto-deploy Firewall Stratagem (CRITICAL only)", variable=self.auto_block_var,
            command=self._toggle_auto_block, bg=BG, fg=ACCENT, selectcolor=PANEL,
            activebackground=BG, activeforeground=FG,
        ).pack(side="left")
        self.ad_block_var = tk.BooleanVar(value=self.ad_blocking_enabled)
        tk.Checkbutton(
            options, text="Automaton Propaganda Jammer (block ads/trackers)", variable=self.ad_block_var,
            command=self._toggle_ad_block, bg=BG, fg=ACCENT, selectcolor=PANEL,
            activebackground=BG, activeforeground=FG,
        ).pack(side="left")
        self.ad_block_status = tk.Label(
            options,
            text=("ON — Windows hosts block active" if self.ad_blocking_enabled else
                  "OFF — turn on to block common ad/tracker domains"),
            bg=BG, fg="#78b84a" if self.ad_blocking_enabled else MUTED,
        )
        self.ad_block_status.pack(side="left", padx=10)
        columns = ("process", "activity", "state", "verdict", "detections")
        self.connection_tree = ttk.Treeview(self.live_tab, columns=columns, show="headings")
        headings = {
            "process": "Program", "activity": "What It Is Doing",
            "state": "Connection", "verdict": "Result", "detections": "VT Detections",
        }
        widths = {"process": 180, "activity": 440, "state": 100, "verdict": 130, "detections": 110}
        for column in columns:
            self.connection_tree.heading(column, text=headings[column])
            anchor = "w" if column in {"process", "activity"} else "center"
            self.connection_tree.column(column, width=widths[column], anchor=anchor)
        self.connection_tree.pack(fill="both", expand=True)
        for severity, color in COLORS.items():
            self.connection_tree.tag_configure(severity, foreground=color)
        self.connection_tree.bind("<<TreeviewSelect>>", self._show_connection_detail)

    def _build_lookup_tab(self):
        tk.Label(
            self.lookup_tab,
            text="Paste a website, domain, or IP address to check its VirusTotal reputation.",
            bg=BG, fg=FG, anchor="w",
        ).pack(fill="x", pady=(12, 0))
        row = tk.Frame(self.lookup_tab, bg=BG)
        row.pack(fill="x", pady=(8, 8))
        tk.Label(row, text="Check this", bg=BG, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(side="left")
        self.lookup_kind = ttk.Combobox(row, values=("url", "domain", "ip"), state="readonly", width=10)
        self.lookup_kind.set("url")
        self.lookup_kind.pack(side="left", padx=8)
        self.lookup_value = tk.Entry(row, bg=PANEL, fg=FG, insertbackground=FG, relief="flat")
        self.lookup_value.pack(side="left", fill="x", expand=True, ipady=7)
        self._button(row, "Check It", self._lookup_indicator, True).pack(side="left", padx=(8, 0))
        self.lookup_result = tk.Text(
            self.lookup_tab, bg=PANEL, fg=FG, insertbackground=FG,
            relief="flat", state="disabled", wrap="word", font=("Consolas", 10),
        )
        self.lookup_result.pack(fill="both", expand=True, pady=(4, 8))
        self._button(self.lookup_tab, "Block This IP If Confirmed Bad", self._block_lookup).pack(anchor="e")

    def _build_file_tab(self):
        tk.Label(
            self.file_tab, text="MINISTRY OF SCIENCE // SAMPLE LAB",
            bg=BG, fg=ACCENT, font=("Segoe UI", 12, "bold"), anchor="w",
        ).pack(fill="x", pady=(10, 0))
        self.download_status = tk.Label(
            self.file_tab,
            text="MINISTRY PASSIVE RESEARCH: STARTING WHOLE-PC WATCH",
            bg=BG, fg="#78b84a", anchor="w", font=("Consolas", 9, "bold"),
        )
        self.download_status.pack(fill="x", pady=(12, 0))
        tk.Label(
            self.file_tab,
            text=("Ministry of Science watches every fixed/removable drive for new or changed risky files while "
                  "this app is open. It waits for each sample to finish writing, then runs local behavior/signature "
                  "analysis and VirusTotal reputation when available. Existing unchanged files are not repeatedly read."),
            bg=BG, fg=FG, anchor="w", wraplength=1000,
        ).pack(fill="x", pady=(3, 0))
        controls = tk.Frame(self.file_tab, bg=BG)
        controls.pack(fill="x", pady=(8, 8))
        self.file_path = tk.Entry(controls, bg=PANEL, fg=FG, insertbackground=FG, relief="flat")
        self.file_path.pack(side="left", fill="x", expand=True, ipady=7)
        self._button(controls, "Select File", self._browse_file).pack(side="left", padx=8)
        self._button(controls, "Scan File", self._scan_file, True).pack(side="left")
        self.file_result = tk.Text(
            self.file_tab, bg=PANEL, fg=FG, insertbackground=FG,
            relief="flat", state="disabled", wrap="word", font=("Consolas", 10),
        )
        self.file_result.pack(fill="both", expand=True, pady=(4, 8))
        sample_actions = tk.Frame(self.file_tab, bg=BG)
        sample_actions.pack(fill="x")
        self.restore_sample_button = self._button(
            sample_actions, "RESTORE LAST BRAIN + BODY SAMPLE", self._restore_last_sample)
        self.restore_sample_button.configure(
            state="normal" if self.last_quarantine_item else "disabled")
        self.restore_sample_button.pack(side="left")
        self.quarantine_button = self._button(
            sample_actions, "EXTERMINATE DISSIDENT (Quarantine)", self._quarantine_current)
        self.quarantine_button.configure(state="disabled")
        self.quarantine_button.pack(side="right")

    def _build_local_tab(self):
        tk.Label(
            self.local_tab, text="SEAF INTERNAL SECURITY // LOCAL PC DETECTIVE",
            bg=BG, fg=ACCENT, font=("Segoe UI", 12, "bold"), anchor="w",
        ).pack(fill="x", pady=(10, 0))
        tk.Label(
            self.local_tab,
            text=("This scan stays on your PC and does not use VirusTotal or any online reputation service. "
                  "It checks running programs, startup changes, recent risky files, Windows login events, "
                  "and whether a locally suspicious program is using the internet."),
            bg=BG, fg=FG, anchor="w", justify="left", wraplength=1000,
        ).pack(fill="x", pady=(10, 6))
        controls = tk.Frame(self.local_tab, bg=BG)
        controls.pack(fill="x", pady=(0, 8))
        self.local_scan_button = self._button(
            controls, "RUN INTERNAL SECURITY SWEEP (Local Scan)", self._start_local_scan, True)
        self.local_scan_button.pack(side="left")
        self._button(
            controls, "Trust Current Startup List", self._save_local_startup_baseline
        ).pack(side="left", padx=8)
        self.local_quarantine_button = self._button(
            controls, "Quarantine Selected Bad File", self._quarantine_local_finding)
        self.local_quarantine_button.configure(state="disabled")
        self.local_quarantine_button.pack(side="right")
        columns = ("severity", "category", "finding", "subject")
        self.local_tree = ttk.Treeview(
            self.local_tab, columns=columns, show="headings", height=9)
        headings = {
            "severity": "Risk", "category": "Checked Area",
            "finding": "What It Found", "subject": "Program / File / Account",
        }
        widths = {"severity": 85, "category": 130, "finding": 300, "subject": 450}
        for column in columns:
            self.local_tree.heading(column, text=headings[column])
            self.local_tree.column(column, width=widths[column], anchor="w")
        for severity, color in {**COLORS, "INFO": MUTED}.items():
            self.local_tree.tag_configure(severity, foreground=color)
        self.local_tree.pack(fill="both", expand=True)
        self.local_tree.bind("<<TreeviewSelect>>", self._show_local_finding)
        self.local_detail = tk.Text(
            self.local_tab, height=7, bg=PANEL, fg=FG, relief="flat",
            state="disabled", wrap="word", font=("Segoe UI", 9),
        )
        self.local_detail.pack(fill="x", pady=(8, 0))
        self.local_status = tk.Label(
            self.local_tab, text="No local scan run yet.", bg=BG, fg=MUTED, anchor="w")
        self.local_status.pack(fill="x", pady=(4, 0))

    def _build_rescue_tab(self):
        panel = tk.Frame(self.rescue_tab, bg=PANEL, padx=20, pady=20)
        panel.pack(fill="both", expand=True, pady=18)
        tk.Label(
            panel, text="ACCOUNT LIBERATION // FIND, CONTAIN, RECOVER", bg=PANEL, fg=ACCENT,
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w")
        tk.Label(
            panel,
            text=("Account Liberation checks official security-alert email information to find which service may be "
                  "under attack, then combines Local Detective and Mission Control evidence. It can disconnect "
                  "unapproved remote control on this PC and block confirmed malicious connections after you agree. "
                  "It never asks for or stores an account password or verification code."),
            bg=PANEL, fg=FG, justify="left", wraplength=900,
        ).pack(anchor="w", pady=(6, 10))
        gmail_controls = tk.Frame(panel, bg=PANEL)
        gmail_controls.pack(fill="x")
        self.gmail_connection_status = tk.Label(
            gmail_controls,
            text=("Gmail alert discovery: CONNECTED" if self.gmail_alerts_connected else
                  "Gmail alert discovery: NOT CONNECTED"),
            bg=PANEL, fg="#78b84a" if self.gmail_alerts_connected else "#f4d03f",
            anchor="w", font=("Consolas", 9, "bold"),
        )
        self.gmail_connection_status.pack(side="left", fill="x", expand=True)
        self.gmail_connect_button = self._button(
            gmail_controls, "CONNECT GMAIL ALERTS", self._connect_gmail_alerts)
        self.gmail_connect_button.configure(
            state="disabled" if self.gmail_alerts_connected else "normal")
        self.gmail_connect_button.pack(side="right")
        self.gmail_disconnect_button = self._button(
            gmail_controls, "DISCONNECT", self._disconnect_gmail_alerts)
        self.gmail_disconnect_button.configure(
            state="normal" if self.gmail_alerts_connected else "disabled")
        self.gmail_disconnect_button.pack(side="right", padx=8)
        tk.Label(
            panel,
            text=("Gmail permission is read-only metadata: sender, subject, date, and Google's anti-spoofing result. "
                  "Message bodies are not read. First-time connection requires a Google Desktop OAuth JSON file."),
            bg=PANEL, fg=MUTED, justify="left", wraplength=900,
        ).pack(anchor="w", pady=(5, 6))
        audit_controls = tk.Frame(panel, bg=PANEL)
        audit_controls.pack(fill="x", pady=(0, 8))
        self.gmail_audit_button = self._button(
            audit_controls, "AUDIT GMAIL FILTERS / FORWARDING", self._audit_gmail_settings)
        self.gmail_audit_button.pack(side="left")
        self.gmail_audit_status = tk.Label(
            audit_controls,
            text=("Settings audit permission ready" if self.gmail_settings_access else
                  "Optional separate permission required; audit is GET-only"),
            bg=PANEL, fg="#78b84a" if self.gmail_settings_access else MUTED)
        self.gmail_audit_status.pack(side="left", padx=8)
        self._button(
            audit_controls, "GMAIL SETUP HELP", self._show_gmail_setup_help
        ).pack(side="right")
        account_controls = tk.Frame(panel, bg=PANEL)
        account_controls.pack(fill="x")
        self.account_recovery_button = self._button(
            account_controls, "BEGIN ACCOUNT LIBERATION", self._start_account_recovery, True)
        self.account_recovery_button.pack(side="left")
        self._button(
            account_controls, "Open Local Evidence Folder", self._open_local_report_folder
        ).pack(side="left", padx=8)
        feature_controls = tk.Frame(panel, bg=PANEL)
        feature_controls.pack(fill="x", pady=(7, 0))
        self._button(feature_controls, "Accounts", self._manage_accounts).pack(side="left")
        self._button(feature_controls, "Known Devices", self._manage_known_devices).pack(side="left", padx=5)
        self._button(feature_controls, "Recovery Checklist", self._open_recovery_checklist).pack(side="left")
        self._button(feature_controls, "Provider Pages", self._open_provider_pages).pack(side="left", padx=5)
        self._button(feature_controls, "Post-Recovery Verify", self._post_recovery_verify).pack(side="left")
        self._button(feature_controls, "Save Encrypted Report", self._save_recovery_report).pack(side="right")
        report_controls = tk.Frame(panel, bg=PANEL)
        report_controls.pack(fill="x", pady=(7, 0))
        self.review_detected_accounts_button = self._button(
            report_controls, "REVIEW DETECTED ACCOUNTS", self._review_detected_accounts)
        self.review_detected_accounts_button.configure(state="disabled")
        self.review_detected_accounts_button.pack(side="left")
        self.prepare_account_report_button = self._button(
            report_controls, "PREPARE STOLEN-ACCOUNT REPORT", self._prepare_stolen_account_report)
        self.prepare_account_report_button.configure(state="disabled")
        self.prepare_account_report_button.pack(side="left", padx=8)
        tk.Label(
            report_controls,
            text="Reports are drafted locally. You review and press the provider's final submit button.",
            bg=PANEL, fg=MUTED,
        ).pack(side="left")
        self.account_recovery_status = tk.Label(
            panel,
            text=("Ready. Gmail alert discovery is connected; begin Account Liberation when ready." if
                  self.gmail_alerts_connected else
                  "Ready. Connect Gmail alerts to find affected services automatically."),
            bg=PANEL, fg=MUTED, anchor="w")
        self.account_recovery_status.pack(fill="x", pady=(8, 6))
        self.account_recovery_result = tk.Text(
            panel, bg=BG, fg=FG, relief="flat", wrap="word", state="disabled",
            font=("Segoe UI", 10), height=14, padx=10, pady=10)
        self.account_recovery_result.pack(fill="both", expand=True)
        self._set_text(
            self.account_recovery_result,
            "WHAT ACCOUNT LIBERATION DOES\n\n"
            "1. Finds recent official account-security alerts in connected Gmail metadata.\n"
            "2. Checks this PC for malware clues, dangerous connections, and remote control.\n"
            "3. Asks before disconnecting remote tools or blocking confirmed malicious addresses.\n"
            "4. Matches alerts to every account label in the encrypted inventory and asks when several could match.\n"
            "5. Opens the real recovery page for each service found, but only when this PC looks safe enough.\n"
            "6. Prepares a report draft that you review, copy, and submit on the official provider page.\n\n"
            "Only the account company can remove its cloud sessions. The app never submits a report without you."
        )

    def _build_settings_tab(self):
        panel = tk.Frame(self.settings_tab, bg=PANEL, padx=20, pady=20)
        panel.pack(fill="x", pady=18)
        tk.Label(
            panel, text="VIRUSTOTAL API KEY", bg=PANEL, fg=ACCENT,
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        tk.Label(
            panel,
            text=("VirusTotal is an online safety database. The key lets this app ask VirusTotal about file "
                  "fingerprints and internet addresses. It is not your password, and this app does not upload "
                  "the file itself. The rest of the app still works without a key, but online results say UNKNOWN."),
            bg=PANEL, fg=MUTED, justify="left", wraplength=900,
        ).pack(anchor="w", pady=(4, 8))
        tk.Label(
            panel,
            text=("HOW TO GET A FREE KEY\n"
                  "1. Click the button below.\n"
                  "2. Sign in or make a free VirusTotal Community account.\n"
                  "3. Copy the API key from VirusTotal.\n"
                  "4. Paste it into the box below and click Save Key Securely.\n"
                  "Keep the key private. Do not send it in a message or screenshot."),
            bg=PANEL, fg=FG, justify="left", wraplength=900,
        ).pack(anchor="w", pady=(0, 8))
        self._button(
            panel, "CREATE ACCOUNT / GET FREE VIRUSTOTAL KEY",
            lambda: webbrowser.open("https://www.virustotal.com/gui/my-apikey", new=2),
        ).pack(anchor="w", pady=(0, 10))
        tk.Label(
            panel, text="Opens the official virustotal.com website in your browser.",
            bg=PANEL, fg=MUTED,
        ).pack(anchor="w", pady=(0, 10))
        key_row = tk.Frame(panel, bg=PANEL)
        key_row.pack(fill="x")
        self.api_key_entry = tk.Entry(key_row, show="*", bg=BG, fg=FG, insertbackground=FG, relief="flat")
        if self.vt.api_key:
            self.api_key_entry.insert(0, self.vt.api_key)
        self.api_key_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self._button(key_row, "Save Key Securely", self._set_api_key, True).pack(side="left", padx=(8, 0))
        self.key_status = tk.Label(
            panel,
            text="Encrypted API key loaded" if self.vt.api_key else "No API key saved: online verdicts will be UNKNOWN",
            bg=PANEL, fg="#78b84a" if self.vt.api_key else "#f4d03f",
        )
        self.key_status.pack(anchor="w", pady=(10, 0))

    def _build_help_tab(self):
        panel = tk.Frame(self.help_tab, bg=PANEL, padx=20, pady=16)
        panel.pack(fill="both", expand=True, pady=12)
        tk.Label(
            panel, text="FIELD MANUAL — WHAT EVERYTHING DOES", bg=PANEL, fg=ACCENT,
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w")
        explanations = (
            "MISSION CONTROL\n"
            "This is the main warning screen. It brings together important findings from the internet watch, "
            "Sample Lab, and Local Detective. Select a warning and click INVESTIGATE to learn what happened. "
            "The CONTAIN THREAT button stays locked until the app finds strong proof.\n\n"
            "INTERNET WATCH\n"
            "Every 10 seconds, the app asks Windows which programs are using the internet. It explains the likely "
            "kind of activity and asks VirusTotal about the destination. It does not read your messages, passwords, "
            "web pages, or the information being sent.\n\n"
            "AD AND TRACKER BLOCKER\n"
            "When you turn this on, the app adds known advertising and tracking websites to a Windows block list. "
            "Turn it off to remove only the entries added by this app. It cannot block every kind of advertisement.\n\n"
            "SAMPLE LAB\n"
            "While the app is open, Ministry passive research watches every fixed/removable drive for new or changed "
            "risky files. A risky type can be an app, script, shortcut, installer, archive, or disk image. It waits "
            "for writing to finish, checks local clues, and sends only the file fingerprint to VirusTotal. Existing "
            "unchanged files are not repeatedly scanned, and the full file is never uploaded automatically.\n\n"
            "LOCAL DETECTIVE\n"
            "This scan stays on your PC. It looks for unusual running programs, startup changes, risky recent files, "
            "failed Windows sign-ins, remote access, and suspicious programs using the internet. It saves its report "
            "on this PC and does not send the report online.\n\n"
            "EMERGENCY SCAN\n"
            "This temporarily cuts most programs off from the internet while the app checks connections, files, "
            "running programs, and startup items five times. It saves your old Windows Firewall setup and restores "
            "it afterward. Windows will ask for Administrator permission.\n\n"
            "WHAT WINDOWS FIREWALL DOES\n"
            "A firewall is like a security gate between this PC and a network. Its rules decide which programs and "
            "internet addresses may communicate with the PC. An incoming rule controls traffic trying to enter; an "
            "outgoing rule controls programs trying to connect outward. Internet Defender uses Windows Firewall, "
            "asks before normal containment actions, and keeps its rules separate so they can be removed. A firewall "
            "does not remove malware, read messages, hide your identity, or guarantee safety.\n\n"
            "BLOCKING A BAD CONNECTION\n"
            "If VirusTotal strongly confirms a dangerous destination, the app can add a Windows Firewall rule that "
            "stops this PC from contacting it. The app asks before taking action unless critical auto-block is on.\n\n"
            "500 KG QUARANTINE\n"
            "Quarantine stops matching running copies, splits the dangerous file into two pieces that cannot work "
            "alone, checks that the pieces are correct, and removes the working original. Restore puts the exact "
            "file back only if both pieces are unchanged and match the saved fingerprints.\n\n"
            "WHAT THE RESULT WORDS MEAN\n"
            "LOW means VirusTotal did not report a threat. MEDIUM means the app found something worth checking. "
            "HIGH means at least one VirusTotal scanner called it harmful. CRITICAL means at least three did. "
            "UNKNOWN means the app could not get a clear answer. UNKNOWN does not mean safe.\n\n"
            "ACCOUNT LIBERATION\n"
            "With permission, this checks recent Gmail security-alert information to find affected services. It also "
            "checks the PC for malware, remote control, and dangerous connections. It compares every alert with the "
            "encrypted account inventory, selects one clear match automatically, and asks you when several accounts "
            "could match. You approve any local disconnect or firewall action. It can prepare a report draft and open "
            "the official provider page, but you must review and submit it. It never reads email bodies or stores "
            "passwords.\n\n"
            "HOW THE GMAIL CONNECTION IS PROTECTED\n"
            "The app accepts only official Google HTTPS sign-in and token addresses. It uses a one-time random state "
            "and PKCE code so another page cannot easily fake Google's answer. Google returns to a temporary address "
            "on this PC only. Windows encrypts the saved token for your Windows account. Disconnect removes the "
            "local encrypted files and asks Google to revoke access. These protections lower risk, but no app can "
            "promise that it is impossible to hack—Windows and your Google account still need strong protection.\n\n"
            "VIRUSTOTAL KEY\n"
            "VirusTotal is a separate website. Open REQUISITIONS and use the account button to get a free personal "
            "key. Keep it secret. Windows encrypts the saved copy for your Windows account.\n\n"
            "IMPORTANT\n"
            "No scanner can promise that every file is safe. This app cannot identify a hacker, read private account "
            "activity, or replace Windows Security and good passwords. Read each warning before approving an action."
        )
        help_text = tk.Text(
            panel, bg=PANEL, fg=FG, relief="flat", wrap="word",
            font=("Segoe UI", 10), padx=2, pady=10,
        )
        help_text.pack(fill="both", expand=True)
        help_text.insert("1.0", explanations)
        help_text.configure(state="disabled")

    def _upsert_mission_card(self, key, card):
        existing_id = self.mission_card_keys.get(key)
        if existing_id:
            existing = self.mission_cards[existing_id]
            order = {"INFO": 0, "LOW": 1, "UNKNOWN": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            severity = card.severity if order.get(card.severity, 0) > order.get(existing.severity, 0) else existing.severity
            card = replace(card, id=existing.id, severity=severity, status=existing.status)
            self.mission_cards[existing_id] = card
            self.mission_tree.item(
                existing_id,
                values=(card.severity, card.source, card.title, card.status),
                tags=(card.severity,),
            )
            return existing_id
        self.mission_cards[card.id] = card
        self.mission_card_keys[key] = card.id
        self.mission_tree.insert(
            "", "end", iid=card.id,
            values=(card.severity, card.source, card.title, card.status),
            tags=(card.severity,),
        )
        return card.id

    def _selected_mission_card(self):
        selected = self.mission_tree.selection()
        return self.mission_cards.get(selected[0]) if selected else None

    def _show_mission_card(self, _event=None):
        card = self._selected_mission_card()
        if not card:
            self.investigate_button.configure(state="disabled")
            self.contain_button.configure(state="disabled")
            return
        investigation = self.mission_investigations.get(card.id)
        lines = [
            f"OPERATION: {card.title}",
            f"SOURCE: {card.source}",
            f"THREAT: {card.severity}",
            f"STATUS: {card.status}",
            f"SUBJECT: {card.subject}",
            "",
            f"INITIAL EVIDENCE: {card.explanation}",
        ]
        if investigation:
            lines.extend(["", "THREAT TIMELINE"])
            for event in investigation.timeline:
                lines.append(f"{event.stage} -> {event.state}: {event.details}")
            lines.extend([
                "",
                f"VERDICT: {investigation.verdict}",
                investigation.verdict_explanation,
            ])
        self._set_text(self.mission_detail, "\n".join(lines))
        self.investigate_button.configure(state="normal")
        self.contain_button.configure(
            state="normal" if investigation and investigation.confirmed else "disabled")

    def _investigate_mission_card(self):
        card = self._selected_mission_card()
        if not card:
            return
        self.investigate_button.configure(state="disabled")
        self.contain_button.configure(state="disabled")
        updated = replace(card, status="INVESTIGATING")
        self.mission_cards[card.id] = updated
        self.mission_tree.item(
            card.id, values=(updated.severity, updated.source, updated.title, updated.status),
            tags=(updated.severity,))
        self._set_activity(f"Mission Control investigating: {card.title}", ACCENT)
        self.jobs.put(("investigate_operation", updated))

    def _display_mission_investigation(self, investigation):
        card = replace(
            investigation.card,
            status="CONFIRMED" if investigation.confirmed else "REVIEW REQUIRED")
        investigation = replace(investigation, card=card)
        self.mission_cards[card.id] = card
        self.mission_investigations[card.id] = investigation
        self.mission_tree.item(
            card.id, values=(card.severity, card.source, card.title, card.status),
            tags=(card.severity,))
        self.mission_tree.selection_set(card.id)
        self.investigate_button.configure(state="normal")
        self.contain_button.configure(state="normal" if investigation.confirmed else "disabled")
        self._show_mission_card()
        self._set_activity(
            f"Mission verdict: {investigation.verdict}",
            DANGER if investigation.confirmed else ACCENT)

    def _contain_mission_card(self):
        card = self._selected_mission_card()
        investigation = self.mission_investigations.get(card.id) if card else None
        if not investigation or not investigation.confirmed:
            messagebox.showwarning(
                "Containment unavailable",
                "Mission Control only enables containment for a confirmed threat. Unknown is never treated as clean.")
            return
        block_destination = False
        disconnect_program = False
        quarantine_sample = False
        if investigation.destination_confirmed:
            block_destination = messagebox.askyesno(
                "Block malicious destination?",
                f"Block the confirmed malicious destination used by "
                f"{investigation.card.program_name or 'the investigated program'}?\n\n"
                "This adds a Windows Firewall rule.")
        if investigation.program_running or investigation.remote_access_findings:
            disconnect_program = messagebox.askyesno(
                "Disconnect suspicious program?",
                "Terminate/log off the identified program or remote-access session and block its executable route?"
            )
        if investigation.file_confirmed and investigation.executable_path:
            details = (
                f"Mission verdict: {investigation.verdict}\n"
                f"{investigation.verdict_explanation}\n\n"
                "Brain/body fragments will be verified before the functioning original path is removed."
            )
            quarantine_sample = self._ask_500kg(investigation.executable_path, details)
        if not any((block_destination, disconnect_program, quarantine_sample)):
            messagebox.showinfo("No actions approved", "Mission Control made no containment changes.")
            return
        self.investigate_button.configure(state="disabled")
        self.contain_button.configure(state="disabled")
        card = replace(card, status="CONTAINING")
        investigation = replace(investigation, card=card)
        self.mission_cards[card.id] = card
        self.mission_investigations[card.id] = investigation
        self.mission_tree.item(
            card.id, values=(card.severity, card.source, card.title, card.status),
            tags=(card.severity,))
        self._set_activity("DEPLOYING 500 KG — Mission Control containment in progress", ACCENT)
        self.jobs.put((
            "contain_operation", investigation, block_destination,
            disconnect_program, quarantine_sample,
        ))

    def _display_mission_containment(self, result):
        card = self.mission_cards.get(result.card_id)
        investigation = self.mission_investigations.get(result.card_id)
        if not card or not investigation:
            return
        status = "AREA SECURED" if result.area_secured else "CONTAINMENT INCOMPLETE"
        card = replace(card, status=status)
        self.mission_cards[card.id] = card
        self.mission_tree.item(
            card.id, values=(card.severity, card.source, card.title, card.status),
            tags=("LOW" if result.area_secured else "HIGH",))
        if result.quarantine_metadata:
            self._record_quarantine(result.quarantine_metadata)
        lines = [
            f"OPERATION: {card.title}",
            f"STATUS: {status}",
            "",
            "CONTAINMENT ACTIONS",
        ]
        lines.extend(f"- {action}" for action in result.actions)
        lines.extend([
            "",
            "POST-CONTAINMENT VERIFICATION",
            f"Program gone: {result.verification['program_gone']}",
            f"Connection gone: {result.verification['connection_gone']}",
            f"Original file gone: {result.verification['original_file_gone']}",
            "",
            f"Evidence report: {result.report_path}",
        ])
        self._set_text(self.mission_detail, "\n".join(lines))
        self.investigate_button.configure(state="normal")
        self.contain_button.configure(state="disabled")
        if result.area_secured:
            self._set_activity("AREA SECURED — threat no longer active", "#78b84a")
            messagebox.showinfo("AREA SECURED", f"Containment verified.\n\nReport: {result.report_path}")
        else:
            self._set_activity("CONTAINMENT INCOMPLETE — review Mission Control evidence", DANGER)
            messagebox.showwarning(
                "Containment incomplete",
                f"One or more verification checks failed. Review Mission Control.\n\nReport: {result.report_path}")

    def _set_gmail_connection_state(self, connected, email_address=""):
        self.gmail_alerts_connected = connected
        self.gmail_account_display = mask_email_address(email_address) if email_address else ""
        if connected:
            detail = f" ({self.gmail_account_display})" if self.gmail_account_display else ""
            self.gmail_connection_status.configure(
                text=f"Gmail alert discovery: CONNECTED{detail}", fg="#78b84a")
        else:
            self.gmail_connection_status.configure(
                text="Gmail alert discovery: NOT CONNECTED", fg="#f4d03f")
        self.gmail_connect_button.configure(state="disabled" if connected else "normal")
        self.gmail_disconnect_button.configure(state="normal" if connected else "disabled")

    def _show_gmail_setup_help(self):
        self._set_text(
            self.account_recovery_result,
            "GMAIL SETUP HELP\n\n"
            "WHAT THE TWO FEATURES DO\n"
            "CONNECT GMAIL ALERTS checks official security-alert senders, subjects, dates, and authentication "
            "headers. It cannot read email bodies.\n\n"
            "AUDIT GMAIL FILTERS / FORWARDING checks for rules that secretly forward email, hide alerts from the "
            "Inbox, or send alerts to Trash. It reports findings and does not change or remove Gmail settings.\n\n"
            "SET UP GMAIL ALERTS\n"
            "1. In Google Cloud, create an External app in Testing mode and add yourself as a test user.\n"
            "2. Enable Gmail API.\n"
            "3. Under Data Access, add only https://www.googleapis.com/auth/gmail.metadata.\n"
            "4. Create a Desktop app OAuth client and download its JSON file.\n"
            "5. Click CONNECT GMAIL ALERTS, choose that JSON file, and approve metadata access on accounts.google.com.\n\n"
            "SET UP FILTER / FORWARDING AUDIT\n"
            "1. In Google Cloud Data Access, also add "
            "https://www.googleapis.com/auth/gmail.settings.basic.\n"
            "2. Click AUDIT GMAIL FILTERS / FORWARDING.\n"
            "3. Approve the warning, choose the same OAuth JSON file, and approve the separate settings permission.\n"
            "4. The audit starts automatically after Google returns to the app.\n\n"
            "IMPORTANT\n"
            "gmail.settings.basic is a broader Google permission that can manage settings in principle. This app "
            "uses it only for GET requests. Leave the optional audit disconnected if you do not want to grant it. "
            "Never share the JSON file, saved tokens, passwords, or verification codes."
        )
        self.account_recovery_status.configure(
            text="Showing setup instructions for both Gmail features", fg=ACCENT)

    def _run_gmail_job(self, kind, path=""):
        try:
            if kind == "connect_gmail":
                self.messages.put(("gmail_connected", connect_gmail(path)))
            elif kind == "connect_gmail_settings":
                self.messages.put((
                    "gmail_settings_connected", connect_gmail(path, include_settings=True)))
            elif kind == "gmail_settings_audit":
                self.messages.put(("gmail_settings_audit", audit_gmail_settings()))
        except Exception as exc:
            self.messages.put(("error", kind, str(exc)))

    def _start_gmail_job(self, kind, path=""):
        threading.Thread(
            target=self._run_gmail_job, args=(kind, path), daemon=True).start()

    def _connect_gmail_alerts(self):
        if not messagebox.askyesno(
            "Connect Gmail security alerts?",
            "Choose a Google Desktop OAuth JSON file from a Google Cloud project you control.\n\n"
            "Google will open in your browser and ask for read-only Gmail metadata permission. "
            "This app can read sender, subject, date, and email-authentication results, but not message bodies.\n\n"
            "Continue?",
        ):
            return
        path = filedialog.askopenfilename(
            title="Choose Google Desktop OAuth JSON",
            filetypes=(("Google OAuth JSON", "*.json"), ("All files", "*.*")),
        )
        if not path:
            return
        self.gmail_connect_button.configure(state="disabled")
        self.gmail_disconnect_button.configure(state="disabled")
        self.gmail_connection_status.configure(
            text="Gmail alert discovery: WAITING FOR GOOGLE SIGN-IN", fg=ACCENT)
        self._start_gmail_job("connect_gmail", path)

    def _disconnect_gmail_alerts(self):
        if not messagebox.askyesno(
            "Disconnect Gmail alerts?",
            "Remove the encrypted Gmail token and OAuth client saved on this PC?\n\n"
            "The app will also ask Google to revoke the saved permission. If Google cannot be reached, remove "
            "Internet Defender from your Google Account permissions manually. This does not change your password.",
        ):
            return
        self.gmail_connect_button.configure(state="disabled")
        self.gmail_disconnect_button.configure(state="disabled")
        self.jobs.put(("disconnect_gmail",))

    def _audit_gmail_settings(self):
        if not self.gmail_alerts_connected:
            messagebox.showinfo(
                "Connect Gmail first",
                "Connect Gmail alert metadata before requesting the separate filter/forwarding audit permission.")
            return
        if not self.gmail_settings_access:
            if not messagebox.askyesno(
                "Authorize Gmail settings audit?",
                "Google's gmail.settings.basic scope can manage filters/settings in principle. Internet Defender "
                "will perform GET-only reads of filters, forwarding addresses, and auto-forwarding. Message bodies "
                "remain unavailable. Reauthorize using your Google Desktop OAuth JSON?",
            ):
                return
            path = filedialog.askopenfilename(
                title="Choose Google Desktop OAuth JSON",
                filetypes=(("Google OAuth JSON", "*.json"), ("All files", "*.*")),
            )
            if not path:
                return
            self.gmail_audit_button.configure(state="disabled")
            self.gmail_audit_status.configure(text="Waiting for Google settings permission", fg=ACCENT)
            self._start_gmail_job("connect_gmail_settings", path)
            return
        self.gmail_audit_button.configure(state="disabled")
        self.gmail_audit_status.configure(text="Auditing filters and forwarding with GET requests", fg=ACCENT)
        self._start_gmail_job("gmail_settings_audit")

    def _display_gmail_settings_audit(self, audit):
        self.gmail_settings_audit = audit
        self.gmail_audit_button.configure(state="normal")
        serious = [item for item in audit.findings if item.severity in {"HIGH", "CRITICAL"}]
        self.gmail_audit_status.configure(
            text=(f"Audit complete: {audit.filters_checked} filters, "
                  f"{audit.forwarding_addresses_checked} forwarding addresses, "
                  f"{len(serious)} serious finding(s)"),
            fg=DANGER if serious else "#78b84a",
        )
        lines = [
            "GMAIL FILTER / FORWARDING AUDIT",
            f"Filters checked: {audit.filters_checked}",
            f"Forwarding addresses checked: {audit.forwarding_addresses_checked}",
            "",
        ]
        if audit.findings:
            for item in audit.findings:
                lines.append(f"- {item.severity}: {item.title} — {item.details}")
        else:
            lines.append("No forwarding or hide/trash filter warning was found.")
        self._set_text(self.account_recovery_result, "\n".join(lines))
        self._set_activity(
            f"Gmail settings audit complete — {len(serious)} serious finding(s)",
            DANGER if serious else "#78b84a",
        )

    def _review_detected_accounts(self):
        candidates = tuple(self.detected_account_candidates)
        if not candidates:
            messagebox.showinfo(
                "No account candidates",
                "No saved account matched an alert or local account-theft clue. Add non-secret account labels under Accounts.")
            return
        accounts = {account.id: account for account in list_accounts()}
        selected = set()
        unknown_services = []
        for candidate in candidates:
            if not candidate.account_id:
                if messagebox.askyesno(
                    "Alerted account is not in inventory",
                    f"An official {candidate.service} security alert was found, but no saved account label matched.\n\n"
                    "Add a non-secret username or masked email label now?",
                ):
                    label = simpledialog.askstring(
                        "Account label",
                        f"Enter a {candidate.service} username or masked email label. Never enter a password:",
                        parent=self,
                    )
                    if label:
                        try:
                            account = add_account(candidate.service, label, "Gmail", "Added from security alert")
                            accounts[account.id] = account
                            selected.add(account.id)
                            continue
                        except ValueError as exc:
                            messagebox.showerror("Could not add account", str(exc))
                unknown_services.append(candidate.service)
                continue
            if candidate.certainty == "LIKELY MATCH":
                selected.add(candidate.account_id)
                continue
            account = accounts.get(candidate.account_id)
            if not account:
                continue
            if messagebox.askyesno(
                "Could this account be affected?",
                f"Service: {account.service}\nAccount label: {account.account_label}\n"
                f"Reason: {candidate.reason}\n\nInclude this account in recovery and report preparation?",
            ):
                selected.add(account.id)
        self.confirmed_affected_account_ids = selected
        self.prepare_account_report_button.configure(
            state="normal" if selected else "disabled")
        lines = ["DETECTED ACCOUNT REVIEW", ""]
        if selected:
            lines.append("Accounts selected for recovery/report preparation:")
            for account_id in selected:
                account = accounts[account_id]
                lines.append(f"- {account.service}: {account.account_label}")
        else:
            lines.append("No saved account was confirmed as affected.")
        if unknown_services:
            lines.extend([
                "",
                "Alerted services missing from encrypted inventory:",
                *[f"- {service}" for service in dict.fromkeys(unknown_services)],
                "Open Accounts to add a non-secret label, then run Account Liberation again.",
            ])
        self._set_text(self.account_recovery_result, "\n".join(lines))
        self.account_recovery_status.configure(
            text=f"Account review complete: {len(selected)} account(s) selected", fg=ACCENT)

    def _prepare_stolen_account_report(self):
        accounts = [
            account for account in list_accounts()
            if account.id in self.confirmed_affected_account_ids
        ]
        if not accounts:
            messagebox.showinfo(
                "Review accounts first",
                "Run Account Liberation and review the detected account candidates before preparing a report.")
            return
        window = tk.Toplevel(self)
        window.title("Review Stolen-Account Report Draft")
        window.geometry("860x650")
        window.configure(bg=BG)
        labels = {f"{account.service}: {account.account_label}": account for account in accounts}
        selector = ttk.Combobox(window, values=tuple(labels), state="readonly", width=65)
        selector.set(next(iter(labels)))
        selector.pack(anchor="w", padx=14, pady=(14, 8))
        tk.Label(
            window,
            text=("This is a local draft. Read and edit it before copying. The app never presses a provider's "
                  "final submit button."),
            bg=BG, fg=MUTED, justify="left", wraplength=810,
        ).pack(anchor="w", padx=14, pady=(0, 8))
        text = tk.Text(
            window, bg=PANEL, fg=FG, insertbackground=FG, wrap="word",
            font=("Consolas", 9), padx=10, pady=10)
        text.pack(fill="both", expand=True, padx=14)
        status = tk.Label(window, text="", bg=BG, fg=MUTED)
        status.pack(anchor="w", padx=14, pady=6)
        current = {"draft": None}

        def load(_event=None):
            account = labels[selector.get()]
            draft = build_stolen_account_report(
                account, self.last_account_alerts, self.last_account_recovery_data or {})
            current["draft"] = draft
            text.delete("1.0", "end")
            text.insert("1.0", f"Subject: {draft.title}\n\n{draft.body}")
            status.configure(
                text=("Official provider page ready" if draft.submission_url else
                      "No built-in official submission page for this provider"),
                fg="#78b84a" if draft.submission_url else ACCENT)

        def copy_and_open():
            draft = current["draft"]
            if not draft:
                return
            reviewed_text = text.get("1.0", "end").strip()
            if not messagebox.askyesno(
                    "Copy draft and open official page?",
                    "Copy the report draft to the clipboard and open the provider's official recovery/report page?\n\n"
                    "You must review the page and press its final submit button yourself.", parent=window):
                return
            self.clipboard_clear()
            self.clipboard_append(reviewed_text)
            self.update_idletasks()
            if draft.submission_url:
                webbrowser.open(draft.submission_url, new=2)
            status.configure(
                text="Draft copied. Paste it only into the official provider page after reviewing it.",
                fg="#78b84a")

        def save_draft():
            draft = current["draft"]
            if not draft:
                return
            path = save_encrypted_recovery_report({
                "stolen_account_report_draft": {
                    "service": draft.service,
                    "account_label": draft.account_label,
                    "title": draft.title,
                    "body": text.get("1.0", "end").strip(),
                    "submission_url": draft.submission_url,
                }
            })
            status.configure(text=f"Encrypted draft saved: {path}", fg="#78b84a")

        selector.bind("<<ComboboxSelected>>", load)
        controls = tk.Frame(window, bg=BG)
        controls.pack(fill="x", padx=14, pady=(0, 14))
        self._button(
            controls, "COPY DRAFT + OPEN OFFICIAL PAGE", copy_and_open, True
        ).pack(side="left")
        self._button(controls, "Save Encrypted Draft", save_draft).pack(side="left", padx=8)
        load()

    def _manage_accounts(self):
        window = tk.Toplevel(self)
        window.title("Encrypted Account Inventory")
        window.geometry("780x430")
        window.configure(bg=BG)
        tree = ttk.Treeview(
            window, columns=("service", "account", "recovery", "notes"), show="headings")
        for column, heading, width in (
                ("service", "Service", 130), ("account", "Account label", 210),
                ("recovery", "Recovery channel", 170), ("notes", "Notes", 240)):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            for account in list_accounts():
                tree.insert("", "end", iid=account.id, values=(
                    account.service, account.account_label, account.recovery_channel, account.notes))

        def add():
            service = simpledialog.askstring("Service", "Service name (for example Discord or Steam):", parent=window)
            if not service:
                return
            label = simpledialog.askstring(
                "Account label", "Username or masked email label — never enter a password:", parent=window)
            if not label:
                return
            recovery = simpledialog.askstring(
                "Recovery channel", "Recovery channel (for example Gmail):", parent=window) or ""
            notes = simpledialog.askstring("Notes", "Optional non-secret notes:", parent=window) or ""
            try:
                add_account(service, label, recovery, notes)
                refresh()
            except ValueError as exc:
                messagebox.showerror("Could not add account", str(exc), parent=window)

        def remove():
            selected = tree.selection()
            if selected and messagebox.askyesno(
                    "Remove account?", "Remove this record from encrypted inventory?", parent=window):
                remove_account(selected[0])
                refresh()

        controls = tk.Frame(window, bg=BG)
        controls.pack(fill="x", padx=10, pady=(0, 10))
        self._button(controls, "Add Account", add, True).pack(side="left")
        self._button(controls, "Remove Selected", remove).pack(side="left", padx=8)
        refresh()

    def _manage_known_devices(self):
        window = tk.Toplevel(self)
        window.title("Encrypted Known Devices")
        window.geometry("700x400")
        window.configure(bg=BG)
        tree = ttk.Treeview(
            window, columns=("service", "device", "notes"), show="headings")
        for column, heading, width in (
                ("service", "Service", 150), ("device", "Known device", 240),
                ("notes", "Notes", 280)):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            for device in list_known_devices():
                tree.insert("", "end", iid=device.id, values=(
                    device.service, device.device_name, device.notes))

        def add():
            service = simpledialog.askstring("Service", "Service name:", parent=window)
            device = simpledialog.askstring("Device", "Device name you recognize:", parent=window)
            if not service or not device:
                return
            notes = simpledialog.askstring("Notes", "Optional non-secret notes:", parent=window) or ""
            add_known_device(service, device, notes)
            refresh()

        def remove():
            selected = tree.selection()
            if selected and messagebox.askyesno(
                    "Remove device?", "Remove this device from the known list?", parent=window):
                remove_known_device(selected[0])
                refresh()

        controls = tk.Frame(window, bg=BG)
        controls.pack(fill="x", padx=10, pady=(0, 10))
        self._button(controls, "Add Known Device", add, True).pack(side="left")
        self._button(controls, "Remove Selected", remove).pack(side="left", padx=8)
        refresh()

    def _open_recovery_checklist(self):
        accounts = list_accounts()
        if not accounts:
            messagebox.showinfo("Add an account first", "Open Accounts and add a non-secret account label first.")
            return
        window = tk.Toplevel(self)
        window.title("Recovery Progress Checklist")
        window.geometry("620x500")
        window.configure(bg=BG)
        labels = {f"{account.service}: {account.account_label}": account for account in accounts}
        selected = ttk.Combobox(window, values=tuple(labels), state="readonly", width=55)
        selected.set(next(iter(labels)))
        selected.pack(anchor="w", padx=14, pady=(14, 8))
        names = {
            "password_changed": "Password changed",
            "sessions_removed": "Unknown sessions/devices removed",
            "recovery_details_checked": "Recovery email/phone/passkeys checked",
            "connected_apps_reviewed": "Connected apps reviewed",
            "mfa_enabled": "MFA / 2-Step Verification enabled",
            "payments_reviewed": "Purchases and payments reviewed",
            "post_recovery_verified": "Post-recovery detective verification passed",
        }
        variables = {step: tk.BooleanVar() for step in CHECKLIST_STEPS}
        checks = tk.Frame(window, bg=BG)
        checks.pack(fill="both", expand=True, padx=14)
        for step in CHECKLIST_STEPS:
            tk.Checkbutton(
                checks, text=names[step], variable=variables[step], bg=BG, fg=FG,
                selectcolor=PANEL, activebackground=BG, activeforeground=FG,
            ).pack(anchor="w", pady=3)
        status = tk.Label(window, text="", bg=BG, fg=MUTED)
        status.pack(anchor="w", padx=14)

        def load(_event=None):
            progress = checklist_for(labels[selected.get()].id)
            for step, value in progress.steps.items():
                variables[step].set(value)
            completed, total = checklist_completion(progress)
            status.configure(text=f"{completed}/{total} recovery steps complete")

        def save():
            account = labels[selected.get()]
            progress = save_checklist(
                account.id, {step: variable.get() for step, variable in variables.items()})
            completed, total = checklist_completion(progress)
            status.configure(text=f"Saved securely: {completed}/{total} complete", fg="#78b84a")

        selected.bind("<<ComboboxSelected>>", load)
        self._button(window, "Save Checklist Securely", save, True).pack(anchor="w", padx=14, pady=14)
        load()

    def _open_provider_pages(self):
        accounts = list_accounts()
        choices = sorted({account.service for account in accounts}) or sorted(PROVIDER_PLANS)
        service = simpledialog.askstring(
            "Provider recovery pages",
            "Enter a service name from your inventory:\n" + ", ".join(choices),
            parent=self,
        )
        if not service:
            return
        name, plan = provider_plan(service)
        pages = [(label, url) for label, url in plan.items() if url]
        if not pages:
            messagebox.showinfo(
                "No verified plan", f"No built-in official recovery links are stored for {name}.")
            return
        if not messagebox.askyesno(
                "Open official provider pages?",
                f"Open {len(pages)} official {name} recovery/security pages?\n\n"
                "Includes recovery, devices, connected apps, and payments when available."):
            return
        for _label, url in pages:
            webbrowser.open(url, new=2)

    def _post_recovery_verify(self):
        self.account_recovery_status.configure(
            text="Running post-recovery Local + Internet + remote-access verification...", fg=ACCENT)
        self._set_activity("Post-recovery verification in progress", ACCENT)
        self.jobs.put(("post_recovery_verify", self._account_network_clues()))

    def _display_post_recovery_result(self, local_result, network_clues, remote_findings):
        result = post_recovery_result(
            local_result.findings, network_clues, remote_findings, list_accounts())
        status = "ACCOUNT AREA SECURED" if result.secured else "RECOVERY STILL INCOMPLETE"
        color = "#78b84a" if result.secured else DANGER
        lines = [
            status,
            "",
            f"Serious local findings: {result.serious_local_findings}",
            f"Serious network findings: {result.serious_network_findings}",
            f"Unrecognized remote access: {result.unrecognized_remote_access}",
            f"Incomplete account checklists: {result.incomplete_checklists}",
            f"Local verification report: {local_result.report_path}",
        ]
        self._set_text(self.account_recovery_result, "\n".join(lines))
        self.account_recovery_status.configure(text=status, fg=color)
        self._set_activity(status, color)
        if result.secured:
            for account in list_accounts():
                progress = checklist_for(account.id)
                steps = dict(progress.steps)
                steps["post_recovery_verified"] = True
                save_checklist(account.id, steps)

    def _save_recovery_report(self):
        accounts = list_accounts()
        devices = list_known_devices()
        data = {
            "accounts": [asdict(item) for item in accounts],
            "known_devices": [asdict(item) for item in devices],
            "checklists": [asdict(checklist_for(account.id)) for account in accounts],
            "last_account_recovery": self.last_account_recovery_data or {},
            "gmail_settings_audit": (
                {"findings": [asdict(item) for item in self.gmail_settings_audit.findings],
                 "filters_checked": self.gmail_settings_audit.filters_checked,
                 "forwarding_addresses_checked": self.gmail_settings_audit.forwarding_addresses_checked}
                if self.gmail_settings_audit else {}),
            "remote_access_report": self.remote_access_report or "",
        }
        path = save_encrypted_recovery_report(data)
        self.last_recovery_report = path
        messagebox.showinfo(
            "Encrypted recovery report saved",
            f"Saved with Windows user encryption:\n{path}\n\nNo passwords or verification codes were included.")

    def _open_local_report_folder(self):
        folder = local_data_root() / "reports"
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(folder)

    def _account_network_clues(self):
        clues = []
        for row_id, connection in self.connection_rows.items():
            reputation = self.reputations.get(connection.remote_ip)
            anomaly = self.connection_anomalies.get(row_id)
            if reputation and reputation.severity in {"HIGH", "CRITICAL"}:
                clues.append({
                    "severity": reputation.severity,
                    "program": connection_program_name(connection),
                    "activity": describe_connection(connection),
                    "reason": reputation.explanation,
                    "remote_ip": connection.remote_ip,
                    "confirmed": True,
                })
            if anomaly and anomaly.severity in {"HIGH", "CRITICAL"}:
                clues.append({
                    "severity": anomaly.severity,
                    "program": connection_program_name(connection),
                    "activity": describe_connection(connection),
                    "reason": anomaly.explanation,
                    "remote_ip": connection.remote_ip,
                    "confirmed": False,
                })
        return tuple(clues)

    def _start_account_recovery(self):
        self.account_recovery_button.configure(state="disabled")
        discovery = "Gmail alerts, " if self.gmail_alerts_connected else ""
        self.account_recovery_status.configure(
            text=f"Checking {discovery}this PC, and active connections for account-theft clues...",
            fg=ACCENT,
        )
        self._set_activity("Account Liberation is finding accounts and checking this PC", ACCENT)
        self.jobs.put(("account_recovery", self._account_network_clues()))

    def _finish_account_recovery(
            self, local_result, network_clues, remote_findings, remote_report,
            gmail_result=None, gmail_error="", settings_audit=None, settings_error=""):
        self.account_recovery_button.configure(state="normal")
        self._display_local_result(local_result)
        alerts = tuple(gmail_result.alerts) if gmail_result else ()
        if gmail_result:
            self._set_gmail_connection_state(True, gmail_result.email_address)
        elif gmail_error:
            self.gmail_connection_status.configure(
                text="Gmail alert discovery: CONNECTED — CHECK FAILED", fg=DANGER)
        self.remote_access_findings = {
            f"{finding.kind}:{finding.identifier}": finding for finding in remote_findings
        }
        for finding in remote_findings:
            self._upsert_mission_card(
                f"remote:{finding.kind}:{finding.identifier}",
                card_from_remote_access(finding))
        unrecognized_remote = []
        for finding in remote_findings:
            activity = "\n".join(finding.activities) or "No active public connection was visible."
            recognized = messagebox.askyesno(
                "Remote-control access found",
                f"Found: {finding.tool}\n"
                f"User/session: {finding.username or 'Not shown'}\n"
                f"Activity: {activity}\n\n"
                f"{finding.explanation}\n\n"
                "Do you recognize and approve this remote-access tool or session?\n\n"
                "Yes = leave it running. No = disconnect and block/disable it.",
            )
            if recognized:
                continue
            unrecognized_remote.append(finding)
            self._set_activity(
                f"EXTERMINATING A DISSIDENT — disconnecting {finding.tool}", ACCENT)
            self.jobs.put(("disconnect_remote_access", finding, tuple(remote_findings)))
        confirmed_ips = tuple(dict.fromkeys(
            clue["remote_ip"] for clue in network_clues
            if clue.get("confirmed") and clue.get("remote_ip")
        ))
        for remote_ip in confirmed_ips:
            self._confirm_block(remote_ip)
        serious_local = [
            finding for finding in local_result.findings
            if finding.severity in {"HIGH", "CRITICAL"}
        ]
        if settings_audit:
            self.gmail_settings_audit = settings_audit
            self.gmail_settings_access = True
        settings_findings = tuple(settings_audit.findings) if settings_audit else ()
        serious_settings = [
            finding for finding in settings_findings
            if finding.severity in {"HIGH", "CRITICAL"}
        ]
        accounts = list_accounts()
        devices = list_known_devices()
        radius = blast_radius(accounts, alerts)
        prioritized_alerts = sorted(
            ((prioritize_alert(alert), alert) for alert in alerts),
            key=lambda item: item[0][1], reverse=True)
        incomplete_checklists = sum(
            checklist_completion(checklist_for(account.id))[0] < len(CHECKLIST_STEPS)
            for account in accounts)
        serious_count = (
            len(serious_local) + len(network_clues) + len(unrecognized_remote) +
            len(serious_settings))
        broad_local_risk = bool(
            serious_local or network_clues or unrecognized_remote or serious_settings)
        candidates = discover_account_candidates(accounts, alerts, broad_local_risk)
        self.last_account_alerts = alerts
        self.detected_account_candidates = candidates
        self.confirmed_affected_account_ids = {
            candidate.account_id for candidate in candidates
            if candidate.account_id and candidate.certainty == "LIKELY MATCH"
        }
        self.review_detected_accounts_button.configure(
            state="normal" if candidates else "disabled")
        self.prepare_account_report_button.configure(
            state="normal" if self.confirmed_affected_account_ids else "disabled")
        recovery_pages = recovery_pages_for_alerts(alerts)
        lines = [
            "ACCOUNT LIBERATION CHECK FINISHED",
            "",
            f"Alert mailbox: {mask_email_address(gmail_result.email_address) if gmail_result else 'Not identified'}",
            f"Official security alerts found: {len(alerts)}",
            f"Encrypted account inventory: {len(accounts)} account(s)",
            f"Known devices: {len(devices)}",
            f"Incomplete recovery checklists: {incomplete_checklists}",
            f"Directly alerted inventory/services: {len(radius)}",
            f"Potential account candidates: {len(candidates)}",
            f"Serious Gmail filter/forwarding findings: {len(serious_settings)}",
            f"Serious local findings: {len(serious_local)}",
            f"Serious connection findings: {len(network_clues)}",
            f"Unrecognized remote-control findings: {len(unrecognized_remote)}",
            f"Local scan report: {local_result.report_path}",
            f"Remote-access report: {remote_report or 'No remote-access software/session found'}",
            "",
        ]
        if gmail_result:
            lines.append(f"Gmail metadata messages checked: {gmail_result.checked_messages}")
        elif gmail_error:
            lines.append(f"Gmail alert check unavailable: {gmail_error}")
        else:
            lines.append("Gmail alert discovery was not connected, so no affected service was identified automatically.")
        if alerts:
            lines.extend(["", "PRIORITIZED OFFICIAL SECURITY ALERTS"])
            for (category, priority), alert in prioritized_alerts[:10]:
                lines.append(
                    f"- PRIORITY {priority} {category}: {alert.service} — "
                    f"{alert.subject} ({alert.date or 'date not shown'})")
        if radius:
            lines.extend(["", "BLAST-RADIUS REVIEW — DIRECTLY ALERTED SERVICES"])
            for item in radius:
                lines.append(
                    f"- {item['service']}: {item['account_label']} — {item['reason']}")
        if settings_findings:
            lines.extend(["", "GMAIL FILTER / FORWARDING AUDIT"])
            for item in settings_findings[:10]:
                lines.append(f"- {item.severity}: {item.title} — {item.details}")
        elif settings_error:
            lines.extend(["", f"Gmail settings audit unavailable: {settings_error}"])
        if serious_count:
            lines.extend([
                "",
                "SAFETY STOP",
                "This PC has evidence that could put passwords or login sessions at risk. "
                "Approved local disconnection and firewall actions are being started.",
            ])
            for finding in serious_local[:5]:
                lines.append(f"- {finding.severity}: {finding.title}")
            for clue in network_clues[:5]:
                lines.append(
                    f"- {clue['severity']}: {clue['program']} — {clue['activity']}")
            for finding in unrecognized_remote[:5]:
                lines.append(f"- REMOTE ACCESS: {finding.tool} is being disconnected")
            lines.extend([
                "",
                "Official account pages were not opened on this PC while serious local clues remain.",
                "After containment finishes, run ACCOUNT LIBERATION again or use a different safe device.",
            ])
            status = f"Safety stop: {serious_count} serious clue(s); containment/review required"
            color = DANGER
        elif recovery_pages:
            services = ", ".join(dict.fromkeys(alert.service for alert in alerts))
            lines.extend([
                "",
                "OPENING OFFICIAL ACCOUNT PAGES",
                f"Detected service(s): {services}",
                "Use those pages to change the password, remove unknown devices and recovery methods, "
                "and enable two-step verification.",
                "The account company—not this app—removes its cloud sessions.",
            ])
            status = f"Opening official recovery pages for: {services}"
            color = "#78b84a"
        elif gmail_result:
            lines.extend([
                "",
                "No recent official security alert identified an affected service. No recovery page was opened.",
            ])
            status = "No affected account was identified from recent Gmail alert metadata"
            color = ACCENT
        elif gmail_error:
            lines.extend([
                "",
                "Fix or reconnect Gmail alert access, then run ACCOUNT LIBERATION again.",
            ])
            status = "Gmail alert discovery failed; local safety checks completed"
            color = DANGER
        else:
            lines.extend([
                "",
                "Connect Gmail alerts and run ACCOUNT LIBERATION again to identify affected services automatically.",
            ])
            status = "Local safety checks completed; connect Gmail alerts for account discovery"
            color = ACCENT
        self.last_account_recovery_data = {
            "gmail_account": mask_email_address(gmail_result.email_address) if gmail_result else "",
            "alerts": [asdict(alert) for alert in alerts],
            "alert_priorities": [
                {"category": category, "priority": priority, "service": alert.service}
                for (category, priority), alert in prioritized_alerts],
            "blast_radius": list(radius),
            "account_candidates": [asdict(candidate) for candidate in candidates],
            "accounts": [asdict(account) for account in accounts],
            "known_devices": [asdict(device) for device in devices],
            "checklists": [asdict(checklist_for(account.id)) for account in accounts],
            "gmail_settings_findings": [asdict(item) for item in settings_findings],
            "local_report": local_result.report_path,
            "remote_access_report": remote_report or "",
            "serious_local_count": len(serious_local),
            "serious_network_count": len(network_clues),
            "unrecognized_remote_count": len(unrecognized_remote),
            "serious_settings_count": len(serious_settings),
        }
        self.last_recovery_report = save_encrypted_recovery_report(
            self.last_account_recovery_data)
        lines.extend(["", f"Encrypted recovery report: {self.last_recovery_report}"])
        self._set_text(self.account_recovery_result, "\n".join(lines))
        self.account_recovery_status.configure(text=status, fg=color)
        self._set_activity(status, color)
        if not serious_count:
            for _name, url in recovery_pages:
                webbrowser.open(url, new=2)
        if candidates and any(
                candidate.certainty != "LIKELY MATCH" for candidate in candidates):
            self.after(500, self._review_detected_accounts)

    def _start_local_scan(self):
        self.local_scan_button.configure(state="disabled")
        self.local_quarantine_button.configure(state="disabled")
        self.local_status.configure(text="Starting local-only scan...", fg=ACCENT)
        self._set_activity("Local PC detective: starting scan", ACCENT)
        self.jobs.put(("local_scan",))

    def _save_local_startup_baseline(self):
        if not messagebox.askyesno(
            "Trust current startup list",
            "Save the programs that currently start with Windows as trusted?\n\n"
            "Only do this if you recognize them. Future scans will flag additions and changes.",
        ):
            return
        self._set_activity("Saving the trusted Windows startup list", ACCENT)
        self.jobs.put(("save_local_baseline",))

    def _display_local_result(self, result):
        self.local_scan_result = result
        self.local_scan_button.configure(state="normal")
        self.local_quarantine_button.configure(state="disabled")
        for item in self.local_tree.get_children():
            self.local_tree.delete(item)
        self.local_findings.clear()
        for index, finding in enumerate(result.findings):
            item_id = f"local-{index}"
            self.local_findings[item_id] = finding
            self.local_tree.insert(
                "", "end", iid=item_id,
                values=(finding.severity, finding.category, finding.title, finding.subject),
                tags=(finding.severity,),
            )
            if finding.severity in {"HIGH", "CRITICAL"}:
                card = card_from_local_finding(finding)
                self._upsert_mission_card(
                    f"local:{finding.category}:{finding.title}:{finding.subject}", card)
        serious = sum(
            finding.severity in {"HIGH", "CRITICAL"} for finding in result.findings)
        self.local_status.configure(
            text=(f"Scan complete: {len(result.findings)} finding(s), {serious} serious. "
                  f"Local report: {result.report_path}"),
            fg=DANGER if serious else "#78b84a",
        )
        self._set_activity(
            f"Local PC scan complete — {serious} serious finding(s)",
            DANGER if serious else "#78b84a",
        )
        if self.local_tree.get_children():
            first = self.local_tree.get_children()[0]
            self.local_tree.selection_set(first)
            self.local_tree.see(first)
            self._show_local_finding()

    def _selected_local_finding(self):
        selected = self.local_tree.selection()
        return self.local_findings.get(selected[0]) if selected else None

    def _show_local_finding(self, _event=None):
        finding = self._selected_local_finding()
        if not finding:
            return
        text = (
            f"RISK: {finding.severity}\n"
            f"CHECKED AREA: {finding.category}\n"
            f"WHAT IT FOUND: {finding.title}\n\n"
            f"WHY IT WAS FLAGGED:\n{finding.explanation}\n\n"
            f"PROGRAM / FILE / ACCOUNT:\n{finding.subject}\n\n"
            f"WHAT TO DO:\n{finding.recommendation}"
        )
        self._set_text(self.local_detail, text)
        can_quarantine = (
            finding.category == "FILE" and
            finding.severity in {"HIGH", "CRITICAL"} and
            Path(finding.subject).is_file()
        )
        self.local_quarantine_button.configure(
            state="normal" if can_quarantine else "disabled")

    def _quarantine_local_finding(self):
        finding = self._selected_local_finding()
        if not finding or finding.category != "FILE" or not Path(finding.subject).is_file():
            return
        details = (
            f"Local result: {finding.severity}\n{finding.explanation}\n\n"
            "This detector uses behavior rules, so false positives are possible. Brain/body fragments "
            "will be verified before the functioning original path is removed."
        )
        if not self._ask_500kg(finding.subject, details):
            return
        self.local_quarantine_button.configure(state="disabled")
        self._set_activity(
            f"DEPLOYING 500 KG — exterminating dissident {Path(finding.subject).name}", ACCENT)
        self.jobs.put(("local_quarantine", finding.subject))

    def _set_activity(self, text, color=FG):
        self.activity_label.configure(text=text, fg=color)

    def _toggle_ad_block(self):
        requested = bool(self.ad_block_var.get())
        if not self._is_admin():
            self.ad_block_var.set(self.ad_blocking_enabled)
            action = "enable" if requested else "disable"
            if messagebox.askyesno(
                "Administrator permission required",
                f"Administrator permission is needed to {action} the Windows ad block. "
                "Restart as Administrator and do it automatically?",
            ):
                flag = "--enable-ad-block" if requested else "--disable-ad-block"
                self._relaunch_as_admin(flag)
            return
        self._apply_ad_block(requested)

    def _apply_ad_block(self, enabled, skip_confirmation=False):
        if not skip_confirmation:
            action = "enable" if enabled else "disable"
            details = (
                "This adds a managed list of common ad and tracker domains to the Windows hosts file. "
                "A backup is created. Some websites may require the blocker to be turned off. "
                "It cannot block every first-party video ad."
            ) if enabled else (
                "This removes only Internet Defender's managed ad-block section and keeps other hosts entries."
            )
            if not messagebox.askyesno(
                f"{action.title()} ad blocking?", f"{details}\n\nContinue?"):
                self.ad_block_var.set(self.ad_blocking_enabled)
                return
        self.ad_block_status.configure(
            text="Updating Windows ad blocking...", fg=ACCENT)
        self._set_activity(
            "Enabling common ad and tracker blocking" if enabled else
            "Disabling Internet Defender ad blocking",
            ACCENT,
        )
        self.jobs.put(("enable_ad_block" if enabled else "disable_ad_block",))

    def _toggle_auto_block(self):
        self.auto_block_critical = bool(self.auto_block_var.get())
        state = "ON" if self.auto_block_critical else "OFF"
        self._set_activity(
            f"Automatic blocking of CRITICAL confirmed connections is {state}",
            ACCENT if self.auto_block_critical else MUTED,
        )

    def _toggle_monitor(self):
        self.monitoring = not self.monitoring
        if self.monitoring:
            self.monitor_button.configure(text="Pause Monitoring")
            self.protection_label.configure(text="PROTECTION ON", fg="#78b84a")
            self._set_activity("Monitoring internet connections and new Downloads files")
            self._request_connections()
        else:
            self.monitor_button.configure(text="Resume Monitoring")
            self.protection_label.configure(text="DOWNLOAD WATCH ONLY", fg=ACCENT)
            self._set_activity("Internet monitoring paused; new Downloads are still watched", ACCENT)

    def _request_connections(self):
        self.jobs.put(("connections",))

    def _prime_downloads(self):
        if not self.downloads_path.is_dir():
            return
        try:
            for path in self.downloads_path.rglob("*"):
                if (path.is_file() and path.suffix.lower() in RISKY_EXTENSIONS and
                        not path_is_excluded(path, self.passive_scan_exclusions)):
                    stat = path.stat()
                    self.download_known[str(path)] = (stat.st_size, stat.st_mtime_ns)
        except OSError:
            pass

    def _download_monitor_worker(self):
        while not self.stop_event.wait(3):
            if not self.passive_file_protection or not self.downloads_path.is_dir():
                continue
            try:
                paths = list(self.downloads_path.rglob("*"))
            except OSError:
                continue
            for path in paths:
                try:
                    if (not path.is_file() or path.suffix.lower() not in RISKY_EXTENSIONS or
                            path_is_excluded(path, self.passive_scan_exclusions)):
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                key = str(path)
                signature = (stat.st_size, stat.st_mtime_ns)
                if self.download_known.get(key) == signature:
                    continue
                previous = self.download_pending.get(key)
                stable_polls = previous[1] + 1 if previous and previous[0] == signature else 0
                if stable_polls >= 1:
                    self.download_pending.pop(key, None)
                    self.download_known[key] = signature
                    if stat.st_size <= 300 * 1024 * 1024:
                        self.jobs.put(("passive_file", key))
                else:
                    self.download_pending[key] = (signature, stable_polls)

    def _monitor_worker(self):
        while not self.stop_event.wait(10):
            if self.monitoring:
                self.jobs.put(("connections",))

    def _run_sweep_pass(self, round_number):
        result = {
            "round": round_number, "connections": [], "files": [],
            "local_scan": None, "errors": [],
        }
        try:
            connections = active_connections()
        except Exception as exc:
            connections = []
            result["errors"].append(f"Connections: {exc}")
        unique_ips = []
        for connection in connections:
            if connection.remote_ip not in unique_ips:
                unique_ips.append(connection.remote_ip)
        for index, ip in enumerate(unique_ips, 1):
            programs = connection_program_names(
                connection for connection in connections if connection.remote_ip == ip)
            self.messages.put(("sweep_progress", round_number,
                               f"Checking connection {index}/{len(unique_ips)} used by {programs}"))
            try:
                result["connections"].append((ip, self.vt.lookup(ip, "ip")))
            except Exception as exc:
                result["errors"].append(f"IP {ip}: {exc}")
        roots = (self.downloads_path, Path.home() / "Desktop")
        paths = []
        for root in roots:
            paths.extend(recent_risky_files(root, limit=10))
        try:
            paths.extend(running_executable_paths(limit=10))
        except Exception as exc:
            result["errors"].append(f"Running programs: {exc}")
        paths.extend(startup_file_paths(limit=10))
        paths = list(dict.fromkeys(paths))
        for index, path in enumerate(paths, 1):
            self.messages.put(("sweep_progress", round_number,
                               f"Checking file {index}/{len(paths)}: {Path(path).name}"))
            try:
                inspection = inspect_file(path, self.vt)
                origin = download_origin(path)
                report = ""
                if inspection.reputation.severity in {"HIGH", "CRITICAL"}:
                    report = save_origin_report(inspection, origin)
                result["files"].append((inspection, origin, report))
            except Exception as exc:
                result["errors"].append(f"File {path}: {exc}")
        try:
            result["local_scan"] = run_local_scan(
                progress=lambda text: self.messages.put((
                    "sweep_progress", round_number, f"Local detective: {text}")))
        except Exception as exc:
            result["errors"].append(f"Local detective: {exc}")
        return result

    def _worker(self):
        while not self.stop_event.is_set():
            try:
                job = self.jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            kind = job[0]
            try:
                if kind == "connections":
                    self.messages.put(("connections", active_connections()))
                elif kind == "lookup":
                    _, indicator, indicator_kind, context = job
                    result = self.vt.lookup(indicator, indicator_kind)
                    self.messages.put(("reputation", result, context))
                elif kind == "file":
                    self.messages.put(("file", inspect_file(job[1], self.vt)))
                elif kind == "passive_file":
                    result = inspect_passive_file(
                        job[1], self.vt, self.passive_scan_exclusions)
                    if result is None:
                        self.messages.put(("passive_file_skipped", job[1]))
                    else:
                        self.messages.put(("passive_file", result[0], result[1]))
                elif kind == "local_scan":
                    result = run_local_scan(
                        progress=lambda text: self.messages.put(("local_progress", text)))
                    self.messages.put(("local_result", result))
                elif kind == "connect_gmail":
                    self.messages.put(("gmail_connected", connect_gmail(job[1])))
                elif kind == "connect_gmail_settings":
                    email = connect_gmail(job[1], include_settings=True)
                    self.messages.put(("gmail_settings_connected", email))
                elif kind == "gmail_settings_audit":
                    self.messages.put(("gmail_settings_audit", audit_gmail_settings()))
                elif kind == "disconnect_gmail":
                    self.messages.put(("gmail_disconnected", disconnect_gmail()))
                elif kind == "post_recovery_verify":
                    result = run_local_scan(
                        progress=lambda text: self.messages.put(("account_recovery_progress", text)))
                    remote_findings = tuple(detect_remote_access())
                    self.messages.put(("post_recovery_result", result, job[1], remote_findings))
                elif kind == "account_recovery":
                    result = run_local_scan(
                        progress=lambda text: self.messages.put(("account_recovery_progress", text)))
                    self.messages.put((
                        "account_recovery_progress", "Checking direct remote-control connections"))
                    remote_findings = tuple(detect_remote_access())
                    report = save_remote_access_report(remote_findings) if remote_findings else None
                    gmail_result = None
                    gmail_error = ""
                    settings_audit = None
                    settings_error = ""
                    if gmail_connected():
                        self.messages.put((
                            "account_recovery_progress",
                            "Finding affected accounts from official Gmail security-alert metadata"))
                        try:
                            gmail_result = scan_gmail_alerts()
                        except Exception as exc:
                            gmail_error = str(exc)
                        if gmail_settings_authorized():
                            self.messages.put((
                                "account_recovery_progress",
                                "Auditing Gmail filters and forwarding with GET-only requests"))
                            try:
                                settings_audit = audit_gmail_settings()
                            except Exception as exc:
                                settings_error = str(exc)
                    self.messages.put((
                        "account_recovery_result", result, job[1], remote_findings, report,
                        gmail_result, gmail_error, settings_audit, settings_error))
                elif kind == "investigate_operation":
                    card = job[1]
                    result = investigate_operation(
                        card, self.vt,
                        progress=lambda text: self.messages.put((
                            "mission_progress", card.id, text)))
                    self.messages.put(("mission_investigated", result))
                elif kind == "contain_operation":
                    result = contain_operation(
                        job[1], block_destination=job[2], disconnect_program=job[3],
                        quarantine_sample=job[4])
                    self.messages.put(("mission_contained", result))
                elif kind == "investigate_connections":
                    try:
                        findings = investigate_connection_processes(job[1])
                        self.messages.put(("connection_anomalies", job[1], findings))
                    except Exception as exc:
                        self.messages.put(("connection_investigation_error", str(exc)))
                elif kind == "local_quarantine":
                    self.messages.put(("local_quarantined", quarantine_file(job[1])))
                elif kind == "restore_sample":
                    self.messages.put(("sample_restored", restore_quarantine_item(job[1])))
                elif kind == "disconnect_remote_access":
                    actions = disconnect_remote_access(job[1])
                    report = save_remote_access_report(job[2], actions)
                    self.messages.put(("remote_access_disconnected", job[1], actions, report))
                elif kind == "save_local_baseline":
                    path = save_local_startup_baseline(collect_local_startup_items())
                    self.messages.put(("local_baseline_saved", path))
                elif kind == "enable_ad_block":
                    self.messages.put(("ad_block_enabled", enable_ad_block()))
                elif kind == "disable_ad_block":
                    disable_ad_block()
                    self.messages.put(("ad_block_disabled",))
                elif kind == "block":
                    try:
                        self.messages.put(("blocked", job[1], block_ip(job[1])))
                    except Exception as exc:
                        self.messages.put(("block_failed", job[1], str(exc)))
                elif kind == "quarantine":
                    self.messages.put(("quarantined", quarantine_file(job[1])))
                elif kind == "begin_network_quarantine":
                    result = start_network_quarantine(
                        sys.executable, launch_watchdog=True)
                    self.messages.put(("network_quarantined", result))
                elif kind == "restore_network_quarantine":
                    restore_network_quarantine(job[1])
                    summary = job[2] if len(job) > 2 else None
                    self.messages.put(("network_quarantine_restored", summary))
                elif kind == "sweep":
                    self.messages.put(("sweep_complete", self._run_sweep_pass(job[1])))
                elif kind == "restore":
                    restore_emergency_network()
                    self.messages.put(("emergency_restored",))
            except Exception as exc:
                self.messages.put(("error", kind, str(exc)))

    def _record_quarantine(self, metadata):
        self.last_quarantine_item = metadata
        self.restore_sample_button.configure(state="normal")

    def _restore_after_containment(self, reason):
        if (not self.network_quarantine_active or not self.network_quarantine_backup or
                self.network_restore_requested):
            return
        self.network_restore_requested = True
        self._set_activity(
            f"Threat contained — automatically restoring internet after {reason}", ACCENT)
        self.jobs.put((
            "restore_network_quarantine", self.network_quarantine_backup,
            {"continue_scan": self.sweep_active, "reason": reason},
        ))

    def _poll_messages(self):
        try:
            while True:
                message = self.messages.get_nowait()
                kind = message[0]
                if kind == "whole_pc_status":
                    self.download_status.configure(text=f"MINISTRY PASSIVE RESEARCH: {message[1]}")
                    if not self.sweep_active:
                        self._set_activity(message[1], ACCENT)
                elif kind == "connections":
                    self._update_connections(message[1])
                    if not self.sweep_active:
                        self._set_activity(
                            f"Monitoring internet connections — {len(message[1])} active public connection(s)")
                elif kind == "reputation":
                    self._show_reputation(message[1], message[2])
                elif kind == "file":
                    self._show_file_result(message[1])
                    self._set_activity(f"File check finished — result: {message[1].severity}")
                elif kind == "passive_file":
                    self._show_passive_file_result(message[1], message[2])
                elif kind == "passive_file_skipped":
                    name = Path(message[1]).name or "file"
                    text = f"Skipped {name}; it was moved, deleted, protected, or belongs to Internet Defender"
                    self.download_status.configure(text=f"MINISTRY PASSIVE RESEARCH: {text}", fg=MUTED)
                    if not self.sweep_active:
                        self._set_activity(text, MUTED)
                elif kind == "local_progress":
                    self.local_status.configure(text=message[1], fg=ACCENT)
                    self._set_activity(f"Local PC detective: {message[1]}", ACCENT)
                elif kind == "local_result":
                    self._display_local_result(message[1])
                elif kind == "gmail_connected":
                    self._set_gmail_connection_state(True, message[1])
                    self.account_recovery_status.configure(
                        text="Gmail alert discovery connected. Begin Account Liberation when ready.",
                        fg="#78b84a")
                    self._set_activity("Gmail security-alert metadata connected", "#78b84a")
                    messagebox.showinfo(
                        "Gmail alerts connected",
                        f"Connected: {mask_email_address(message[1])}\n\n"
                        "Only Gmail metadata permission was saved with Windows encryption. Message bodies are not read.")
                elif kind == "gmail_settings_connected":
                    self._set_gmail_connection_state(True, message[1])
                    self.gmail_settings_access = True
                    self.gmail_audit_status.configure(
                        text="Settings audit permission ready; running GET-only audit", fg="#78b84a")
                    self._start_gmail_job("gmail_settings_audit")
                elif kind == "gmail_settings_audit":
                    self._display_gmail_settings_audit(message[1])
                elif kind == "gmail_disconnected":
                    revoked = bool(message[1])
                    self._set_gmail_connection_state(False)
                    self.gmail_settings_access = False
                    self.gmail_audit_status.configure(
                        text="Optional separate permission required; audit is GET-only", fg=MUTED)
                    status = (
                        "Gmail disconnected locally and Google permission revoked." if revoked else
                        "Gmail disconnected locally; revoke Internet Defender in Google Account permissions."
                    )
                    self.account_recovery_status.configure(
                        text=status, fg=MUTED if revoked else DANGER)
                    self._set_activity(status, MUTED if revoked else DANGER)
                    if not revoked:
                        messagebox.showwarning(
                            "Google permission may still be active",
                            "The encrypted local token was removed, but Google could not be reached to revoke it. "
                            "Remove Internet Defender from your Google Account permissions manually.")
                elif kind == "post_recovery_result":
                    self._display_post_recovery_result(message[1], message[2], message[3])
                elif kind == "account_recovery_progress":
                    self.account_recovery_status.configure(text=message[1], fg=ACCENT)
                    self._set_activity(f"Account Liberation: {message[1]}", ACCENT)
                elif kind == "account_recovery_result":
                    self._finish_account_recovery(
                        message[1], message[2], message[3], message[4],
                        message[5], message[6], message[7], message[8])
                elif kind == "mission_progress":
                    self._set_activity(f"Mission Control: {message[2]}", ACCENT)
                    self._set_text(self.mission_detail, f"INVESTIGATING OPERATION\n\n{message[2]}")
                elif kind == "mission_investigated":
                    self._display_mission_investigation(message[1])
                elif kind == "mission_contained":
                    self._display_mission_containment(message[1])
                elif kind == "remote_access_disconnected":
                    self.remote_containment_actions.extend(message[2])
                    self.remote_access_report = message[3]
                    self._set_activity(
                        f"500 KG STRIKE COMPLETE — disconnected {message[1].tool}", ACCENT)
                    messagebox.showinfo(
                        "Remote access disconnected",
                        "\n".join(message[2]) + f"\n\nLocal evidence report: {message[3]}")
                elif kind == "connection_anomalies":
                    self._handle_connection_anomalies(message[2])
                elif kind == "connection_investigation_error":
                    self._set_activity(
                        f"Internet connection behavior check unavailable: {message[1]}", MUTED)
                elif kind == "local_quarantined":
                    self.local_quarantine_button.configure(state="disabled")
                    self._record_quarantine(message[1])
                    self._set_activity(
                        "500 KG IMPACT CONFIRMED — local dissident split into brain/body quarantine",
                        ACCENT)
                    messagebox.showinfo(
                        "Brain/body quarantine complete",
                        f"Brain: {message[1]['brain_path']}\nBody: {message[1]['body_path']}\n\n"
                        "The functioning original path was removed after hash verification.")
                    self._restore_after_containment("local virus quarantine")
                elif kind == "sample_restored":
                    items = list_quarantine_items()
                    self.last_quarantine_item = items[0] if items else None
                    self.restore_sample_button.configure(
                        state="normal" if self.last_quarantine_item else "disabled")
                    self._set_activity("Ministry of Science restored the verified sample", "#78b84a")
                    messagebox.showinfo(
                        "Sample restored",
                        f"Restored to: {message[1]['restored_path']}\nSHA-256: {message[1]['sha256']}")
                elif kind == "local_baseline_saved":
                    self._set_activity("Saved the trusted Windows startup list", "#78b84a")
                    messagebox.showinfo(
                        "Startup list saved",
                        f"Future local scans will compare startup changes against:\n{message[1]}")
                elif kind == "ad_block_enabled":
                    self.ad_blocking_enabled = True
                    self.ad_block_var.set(True)
                    self.ad_block_status.configure(
                        text=f"ON — blocking {message[1]['domains']} common ad/tracker domains",
                        fg="#78b84a")
                    self._set_activity("Common ad and tracker blocking is ON", "#78b84a")
                    messagebox.showinfo(
                        "Ad blocking enabled",
                        f"Blocked {message[1]['domains']} common domains.\n"
                        f"Hosts backup: {message[1]['backup_path']}")
                elif kind == "ad_block_disabled":
                    self.ad_blocking_enabled = False
                    self.ad_block_var.set(False)
                    self.ad_block_status.configure(
                        text="OFF — common ad/tracker hosts block removed", fg=MUTED)
                    self._set_activity("Internet Defender ad blocking is OFF", MUTED)
                    messagebox.showinfo(
                        "Ad blocking disabled",
                        "Internet Defender's managed hosts entries were removed.")
                elif kind == "blocked":
                    self.blocked_ips.add(message[1])
                    self._set_activity(
                        "500 KG STRIKE COMPLETE — blocked a confirmed malicious connection", ACCENT)
                    messagebox.showinfo(
                        "Malicious connection blocked",
                        "Windows Firewall is now blocking the confirmed malicious connection.")
                    self._restore_after_containment("malicious connection block")
                elif kind == "block_failed":
                    self.blocked_ips.discard(message[1])
                    self._set_activity(
                        f"Could not block the malicious connection: {message[2]}", DANGER)
                    messagebox.showerror("Could not block connection", message[2])
                elif kind == "quarantined":
                    self.current_file = None
                    self.quarantine_button.configure(state="disabled")
                    self._record_quarantine(message[1])
                    self._set_activity(
                        "500 KG IMPACT CONFIRMED — dissident split into brain/body quarantine", ACCENT)
                    messagebox.showinfo(
                        "Brain/body quarantine complete",
                        f"Brain: {message[1]['brain_path']}\nBody: {message[1]['body_path']}\n\n"
                        "The functioning original path was removed after hash verification.")
                    self._restore_after_containment("virus quarantine")
                elif kind == "network_quarantined":
                    self.network_quarantine_active = True
                    self.network_quarantine_backup = message[1]["backup_path"]
                    self.network_restore_requested = False
                    self.restore_button.configure(state="normal")
                    self.protection_label.configure(text="PC NETWORK QUARANTINED", fg=DANGER)
                    self._set_activity(
                        f"PC quarantined — blocked {message[1]['blocked_programs']} running program(s); "
                        "VirusTotal access remains available", DANGER)
                    self.jobs.put(("sweep", 1))
                elif kind == "network_quarantine_restored":
                    self.network_quarantine_active = False
                    self.network_quarantine_backup = None
                    self.network_restore_requested = False
                    self.restore_button.configure(state="disabled")
                    payload = message[1]
                    if isinstance(payload, dict) and payload.get("continue_scan"):
                        self.protection_label.configure(text="EMERGENCY CHECK CONTINUING", fg="#f0883e")
                        self._set_activity(
                            f"Internet restored automatically after {payload['reason']}; remaining checks continue",
                            "#78b84a",
                        )
                    else:
                        self._finish_sweep(payload)
                elif kind == "sweep_progress":
                    self.protection_label.configure(
                        text=f"EMERGENCY CHECK {message[1]}/5", fg="#f0883e")
                    self._set_activity(message[2], "#f0883e")
                    self._set_text(self.live_detail, message[2])
                elif kind == "sweep_complete":
                    self._handle_sweep_complete(message[1])
                elif kind == "emergency_restored":
                    self.emergency_active = False
                    self.emergency_button.configure(state="normal")
                    self.restore_button.configure(state="disabled")
                    self.protection_label.configure(
                        text="PROTECTION ON" if self.monitoring else "DOWNLOAD WATCH ONLY",
                        fg="#78b84a" if self.monitoring else "#f4d03f")
                    self._set_activity("Internet restored after old lockdown")
                    messagebox.showinfo("Network restored", "The app's emergency firewall rules were removed.")
                elif kind == "error":
                    needs_restore = (
                        self.network_quarantine_active and self.network_quarantine_backup and
                        not self.network_restore_requested and
                        message[1] != "restore_network_quarantine"
                    )
                    if message[1] in {
                            "sweep", "restore", "begin_network_quarantine",
                            "restore_network_quarantine"}:
                        self.sweep_active = False
                        if not needs_restore:
                            self.emergency_button.configure(state="normal")
                    if message[1] == "restore_network_quarantine":
                        self.network_restore_requested = False
                        self.restore_button.configure(state="normal")
                        self.protection_label.configure(text="PC NETWORK QUARANTINED", fg=DANGER)
                    if message[1] == "local_scan":
                        self.local_scan_button.configure(state="normal")
                        self.local_status.configure(text=f"Scan failed: {message[2]}", fg=DANGER)
                    if message[1] == "restore_sample":
                        self.restore_sample_button.configure(
                            state="normal" if self.last_quarantine_item else "disabled")
                    if message[1] == "connect_gmail":
                        self._set_gmail_connection_state(False)
                        self.gmail_connection_status.configure(
                            text=f"Gmail alert connection failed: {message[2]}", fg=DANGER)
                    if message[1] == "disconnect_gmail":
                        self._set_gmail_connection_state(True)
                        self.gmail_connection_status.configure(
                            text=f"Gmail alert disconnect failed: {message[2]}", fg=DANGER)
                    if message[1] in {"connect_gmail_settings", "gmail_settings_audit"}:
                        self.gmail_audit_button.configure(state="normal")
                        self.gmail_audit_status.configure(
                            text=f"Gmail settings audit failed: {message[2]}", fg=DANGER)
                    if message[1] == "post_recovery_verify":
                        self.account_recovery_status.configure(
                            text=f"Post-recovery verification failed: {message[2]}", fg=DANGER)
                    if message[1] == "account_recovery":
                        self.account_recovery_button.configure(state="normal")
                        self.account_recovery_status.configure(
                            text=f"Account Liberation failed: {message[2]}", fg=DANGER)
                    if message[1] == "investigate_operation":
                        self.investigate_button.configure(state="normal")
                    if message[1] == "contain_operation":
                        self.contain_button.configure(state="normal")
                    if message[1] in {"enable_ad_block", "disable_ad_block"}:
                        self.ad_blocking_enabled = ad_block_enabled()
                        self.ad_block_var.set(self.ad_blocking_enabled)
                        self.ad_block_status.configure(
                            text="Ad block update failed; previous state kept", fg=DANGER)
                    self._set_activity(f"Could not finish {message[1]}: {message[2]}", DANGER)
                    messagebox.showerror("Operation failed", f"{message[1]}: {message[2]}")
                    if needs_restore:
                        self.network_restore_requested = True
                        self._set_activity(
                            "Scan error — automatically restoring normal internet now", ACCENT)
                        self.jobs.put((
                            "restore_network_quarantine", self.network_quarantine_backup, None))
        except queue.Empty:
            pass
        if not self.stop_event.is_set():
            self.after(100, self._poll_messages)

    def _finish_sweep(self, summary=None):
        self.sweep_active = False
        self.emergency_button.configure(state="normal")
        self.protection_label.configure(
            text="PROTECTION ON" if self.monitoring else "DOWNLOAD WATCH ONLY",
            fg="#78b84a" if self.monitoring else "#f4d03f")
        if not summary:
            self._set_activity("Normal internet access restored", "#78b84a")
            return
        if summary["threats"]:
            self._set_activity(
                "500 KG STRIKE COMPLETE — threats handled and normal internet restored", ACCENT)
        else:
            self._set_activity(
                "ALL 5 CHECKS COMPLETE — no confirmed threat found; normal internet restored",
                "#78b84a")
        messagebox.showinfo(
            "Emergency scan complete",
            f"Completed all checks five times.\n"
            f"Confirmed threats reviewed: {summary['threats']}\n"
            f"Local origin reports saved: {summary['reports']}\n"
            f"Non-fatal check errors: {summary['errors']}\n\n"
            "Normal internet access has been restored.",
        )

    def _handle_sweep_complete(self, result):
        round_number = result["round"]
        self.sweep_round = round_number
        self.sweep_errors.extend(result["errors"])
        for ip, reputation in result["connections"]:
            self.reputations[ip] = reputation
            self._refresh_connection_verdicts(ip)
            key = f"ip:{ip}"
            if reputation.severity not in {"HIGH", "CRITICAL"} or key in self.sweep_prompted:
                continue
            self.sweep_prompted.add(key)
            matches = [
                connection for connection in self.connection_rows.values()
                if connection.remote_ip == ip
            ]
            programs = connection_program_names(matches)
            program_details = connection_program_details(matches)
            activity = describe_connection(matches[0]) if matches else "Unknown internet activity"
            if (should_auto_block_reputation(reputation, self.auto_block_critical) and
                    ip not in self.blocked_ips):
                self.blocked_ips.add(ip)
                self._set_activity(
                    f"Calling in a 500 KG strike on a CRITICAL connection used by {programs}", ACCENT)
                self.jobs.put(("block", ip))
                continue
            self._set_activity(
                f"VirusTotal warning for a connection used by {programs} — review required", DANGER)
            if messagebox.askyesno(
                "VirusTotal connection warning",
                f"Emergency pass {round_number}/5 found a {reputation.severity} connection.\n\n"
                f"{program_details}\n\nConnection activity: {activity}\n\n"
                f"{reputation.explanation}\n\nBlock it with Windows Firewall?",
            ):
                self.blocked_ips.add(ip)
                self._set_activity("Calling in a 500 KG strike on the malicious connection", ACCENT)
                self.jobs.put(("block", ip))
        for inspection, origin, report in result["files"]:
            if report and report not in self.sweep_reports:
                self.sweep_reports.append(report)
            key = f"file:{inspection.sha256}"
            if inspection.reputation.severity not in {"HIGH", "CRITICAL"} or key in self.sweep_prompted:
                continue
            self.sweep_prompted.add(key)
            self.current_file = inspection
            self._show_file_result(inspection)
            self._upsert_mission_card(key, card_from_file(inspection))
            source = origin.get("host_url") or origin.get("referrer_url") or "Origin metadata unavailable"
            report_text = f"\nEvidence report: {report}" if report else ""
            self._set_activity(
                f"Virus found: {Path(inspection.path).name} — waiting for your permission", DANGER)
            details = (
                f"Emergency pass {round_number}/5 result: {inspection.reputation.severity}\n"
                f"{inspection.reputation.explanation}\nSource: {source}{report_text}\n\n"
                "Brain/body fragments will be hash-verified before the functioning original path is removed."
            )
            if self._ask_500kg(inspection.path, details):
                self._set_activity(
                    f"DEPLOYING 500 KG — exterminating dissident {Path(inspection.path).name}", ACCENT)
                self.jobs.put(("quarantine", inspection.path))
        local_result = result.get("local_scan")
        if local_result:
            self._display_local_result(local_result)
            for finding in local_result.findings:
                if finding.severity not in {"HIGH", "CRITICAL"}:
                    continue
                key = f"local:{finding.category}:{finding.title}:{finding.subject}"
                if key in self.sweep_prompted:
                    continue
                self.sweep_prompted.add(key)
                self._set_activity(
                    f"Local detective found: {finding.title} — waiting for your decision", DANGER)
                if finding.category == "FILE" and Path(finding.subject).is_file():
                    details = (
                        f"{finding.title}\n{finding.explanation}\n\n"
                        "Brain/body fragments will be hash-verified before the functioning original path is removed."
                    )
                    if self._ask_500kg(finding.subject, details):
                        self._set_activity(
                            f"DEPLOYING 500 KG — exterminating dissident {Path(finding.subject).name}",
                            ACCENT,
                        )
                        self.jobs.put(("local_quarantine", finding.subject))
                else:
                    messagebox.showwarning(
                        "Serious local finding",
                        f"{finding.title}\n\n{finding.explanation}\n\n"
                        f"Affected: {finding.subject}\n\nWhat to do:\n{finding.recommendation}",
                    )
        if round_number < 5:
            self.protection_label.configure(
                text=f"EMERGENCY CHECK {round_number}/5 COMPLETE", fg="#f0883e")
            self.after(3000, lambda: self.jobs.put(("sweep", round_number + 1)))
            return
        summary = {
            "threats": len(self.sweep_prompted),
            "reports": len(self.sweep_reports),
            "errors": len(self.sweep_errors),
        }
        if self.network_quarantine_active and self.network_quarantine_backup:
            self.network_restore_requested = True
            self._set_activity("Restoring normal internet access from the firewall backup", ACCENT)
            self.jobs.put((
                "restore_network_quarantine", self.network_quarantine_backup, summary))
        else:
            self._finish_sweep(summary)

    def _handle_connection_anomalies(self, anomalies):
        for connection, finding in anomalies:
            row_id = f"{connection.pid}:{connection.remote_address}"
            self.connection_anomalies[row_id] = finding
            reputation = self.reputations.get(connection.remote_ip)
            card = card_from_connection(connection, reputation, finding)
            card = replace(card, activity=describe_connection(connection))
            self._upsert_mission_card(
                f"connection:{connection.pid}:{connection.remote_ip}", card)
            if self.connection_tree.exists(row_id):
                values = list(self.connection_tree.item(row_id, "values"))
                reputation = self.reputations.get(connection.remote_ip)
                if not reputation or reputation.severity in {"LOW", "UNKNOWN"}:
                    values[3] = f"WEIRD {finding.severity}"
                    self.connection_tree.item(
                        row_id, values=values, tags=(finding.severity,))
            prompt_key = f"{connection.pid}:{connection.remote_address}:{finding.title}"
            if finding.severity not in {"HIGH", "CRITICAL"} or prompt_key in self.anomaly_prompted:
                continue
            self.anomaly_prompted.add(prompt_key)
            program_name = connection_program_name(connection)
            self._set_activity(
                f"Investigating unusual behavior from {program_name}", DANGER)
            messagebox.showwarning(
                "Unusual internet behavior found",
                f"{describe_program(connection)}\n"
                f"Connection activity: {describe_connection(connection)}\n\n"
                f"Why it looks unusual:\n{finding.explanation}\n\n"
                f"What to do:\n{finding.recommendation}\n\n"
                "It was not blocked automatically because local behavior rules can have false alarms.",
            )

    def _update_connections(self, connections):
        active_ids = set()
        new_connections = []
        for connection in connections:
            row_id = f"{connection.pid}:{connection.remote_address}"
            active_ids.add(row_id)
            reputation = self.reputations.get(connection.remote_ip)
            severity = reputation.severity if reputation else "UNKNOWN"
            detections = "-" if not reputation else str(reputation.malicious + reputation.suspicious)
            activity = describe_connection(connection)
            values = (
                connection_program_name(connection), activity, connection.state, severity, detections,
            )
            if self.connection_tree.exists(row_id):
                self.connection_tree.item(row_id, values=values, tags=(severity,))
            else:
                self.connection_tree.insert("", "end", iid=row_id, values=values, tags=(severity,))
                new_connections.append(connection)
            self.connection_rows[row_id] = connection
            if connection.remote_ip not in self.seen_ips:
                self.seen_ips.add(connection.remote_ip)
                self.jobs.put(("lookup", connection.remote_ip, "ip", "connection"))
        for row_id in self.connection_tree.get_children():
            if row_id not in active_ids:
                self.connection_tree.delete(row_id)
                self.connection_rows.pop(row_id, None)
                self.connection_anomalies.pop(row_id, None)
        if new_connections:
            self.jobs.put(("investigate_connections", tuple(new_connections)))

    def _selected_connection(self):
        selected = self.connection_tree.selection()
        return self.connection_rows.get(selected[0]) if selected else None

    def _investigate_selected(self):
        connection = self._selected_connection()
        if not connection:
            messagebox.showinfo("Select a connection", "Select a connection first.")
            return
        self.jobs.put(("lookup", connection.remote_ip, "ip", "connection"))

    def _show_connection_detail(self, _event=None):
        selected = self.connection_tree.selection()
        if not selected:
            return
        row_id = selected[0]
        connection = self.connection_rows.get(row_id)
        if not connection:
            return
        reputation = self.reputations.get(connection.remote_ip)
        text = (
            f"{describe_program(connection)}\n"
            f"What it is doing: {describe_connection(connection)}\n"
            f"Connection state: {connection.state}\n"
        )
        if connection.process_path:
            text += f"Program location: {connection.process_path}\n"
        if reputation:
            text += f"VIRUSTOTAL RESULT: {reputation.severity}\n{reputation.explanation}"
        else:
            text += "VIRUSTOTAL RESULT: UNKNOWN\nWaiting for the reputation check."
        anomaly = self.connection_anomalies.get(row_id)
        if anomaly:
            text += (
                f"\n\nLOCAL DETECTIVE WARNING: {anomaly.title}\n"
                f"WHY: {anomaly.explanation}\nWHAT TO DO: {anomaly.recommendation}"
            )
        self._set_text(self.live_detail, text)

    def _show_reputation(self, reputation, context):
        self.reputations[reputation.indicator] = reputation
        if context == "connection":
            self._refresh_connection_verdicts(reputation.indicator)
            matches = [
                connection for connection in self.connection_rows.values()
                if connection.remote_ip == reputation.indicator
            ]
            programs = connection_program_names(matches)
            program_details = connection_program_details(matches)
            activity = describe_connection(matches[0]) if matches else "Unknown internet activity"
            if reputation.severity in {"MEDIUM", "HIGH", "CRITICAL"}:
                for connection in matches:
                    row_id = f"{connection.pid}:{connection.remote_address}"
                    card = card_from_connection(
                        connection, reputation, self.connection_anomalies.get(row_id))
                    card = replace(card, activity=describe_connection(connection))
                    self._upsert_mission_card(
                        f"connection:{connection.pid}:{connection.remote_ip}", card)
            if (should_auto_block_reputation(reputation, self.auto_block_critical) and
                    reputation.indicator not in self.blocked_ips):
                self.blocked_ips.add(reputation.indicator)
                self._set_activity(
                    f"Automatically blocking a CRITICAL connection used by {programs}", DANGER)
                self.bell()
                self.jobs.put(("block", reputation.indicator))
                messagebox.showwarning(
                    "CRITICAL connection automatically blocked",
                    f"{program_details}\n\nConnection activity: {activity}\n"
                    f"VirusTotal risk: {reputation.severity}\n\n{reputation.explanation}\n\n"
                    "A Windows Firewall block was requested automatically.",
                )
            elif reputation.severity in {"HIGH", "CRITICAL"}:
                self._set_activity(
                    f"VirusTotal warning for a connection used by {programs} — review required", DANGER)
                self.bell()
                messagebox.showwarning(
                    "VirusTotal connection warning",
                    f"{program_details}\n\nConnection activity: {activity}\n"
                    f"VirusTotal risk: {reputation.severity}\n\n{reputation.explanation}\n\n"
                    "Nothing was blocked automatically. Select the connection if you want to block it.",
                )
        else:
            self.current_indicator = reputation
            self._set_text(self.lookup_result, self._format_reputation(reputation))
            self._set_activity(
                f"VirusTotal check finished — result: {reputation.severity}")

    def _refresh_connection_verdicts(self, remote_ip):
        reputation = self.reputations[remote_ip]
        for row_id, connection in self.connection_rows.items():
            if connection.remote_ip != remote_ip or not self.connection_tree.exists(row_id):
                continue
            values = list(self.connection_tree.item(row_id, "values"))
            values[3] = reputation.severity
            values[4] = reputation.malicious + reputation.suspicious
            self.connection_tree.item(row_id, values=values, tags=(reputation.severity,))

    def _lookup_indicator(self):
        value = self.lookup_value.get().strip()
        kind = self.lookup_kind.get()
        try:
            value = normalize_indicator(value, kind)
        except ValueError as exc:
            messagebox.showerror("Invalid indicator", str(exc))
            return
        self._set_text(self.lookup_result, "Investigating with VirusTotal...")
        self._set_activity(f"Checking {kind}: {value}", ACCENT)
        self.jobs.put(("lookup", value, kind, "manual"))

    @staticmethod
    def _format_reputation(reputation):
        return (
            f"Indicator: {reputation.indicator}\n"
            f"Type: {reputation.kind}\n"
            f"Verdict: {reputation.severity}\n"
            f"Malicious: {reputation.malicious}\n"
            f"Suspicious: {reputation.suspicious}\n"
            f"Harmless: {reputation.harmless}\n"
            f"Undetected: {reputation.undetected}\n\n"
            f"Detective explanation:\n{reputation.explanation}\n\n"
            "A clean reputation result is not a guarantee of safety."
        )

    def _block_selected(self):
        connection = self._selected_connection()
        if not connection:
            messagebox.showinfo("Select a connection", "Select a connection first.")
            return
        self._confirm_block(connection.remote_ip)

    def _block_lookup(self):
        if not self.current_indicator or self.current_indicator.kind != "ip":
            messagebox.showinfo("Investigate an IP", "Investigate an IP address first.")
            return
        self._confirm_block(self.current_indicator.indicator)

    def _confirm_block(self, ip):
        reputation = self.reputations.get(ip)
        if not reputation or reputation.severity not in {"HIGH", "CRITICAL"}:
            messagebox.showwarning(
                "Blocking refused",
                "The app only enables firewall blocking when VirusTotal reports a HIGH or CRITICAL threat.",
            )
            return
        if ip in self.blocked_ips:
            messagebox.showinfo("Already blocked", "This VirusTotal-flagged connection is already blocked.")
            return
        matches = [
            connection for connection in self.connection_rows.values()
            if connection.remote_ip == ip
        ]
        program_details = connection_program_details(matches)
        activity = describe_connection(matches[0]) if matches else "Unknown internet activity"
        if messagebox.askyesno(
            "Confirm firewall block",
            f"Block this VirusTotal-flagged connection?\n\n"
            f"{program_details}\n\nConnection activity: {activity}\n"
            f"VirusTotal risk: {reputation.severity}\n\n{reputation.explanation}\n\n"
            "Administrator permission may be required.",
        ):
            self.blocked_ips.add(ip)
            self.jobs.put(("block", ip))

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Choose a file to inspect")
        if path:
            self.file_path.delete(0, "end")
            self.file_path.insert(0, path)

    def _scan_file(self):
        path = self.file_path.get().strip()
        if not path:
            messagebox.showinfo("Choose a file", "Choose a file first.")
            return
        self.current_file = None
        self.quarantine_button.configure(state="disabled")
        self._set_text(self.file_result, "Hashing and investigating the file...")
        self._set_activity(f"Checking file: {Path(path).name}", ACCENT)
        self.jobs.put(("file", path))

    def _show_file_result(self, inspection):
        self.current_file = inspection
        findings = "\n".join(f"- {item}" for item in inspection.findings) or "- None"
        origin = download_origin(inspection.path)
        source = origin.get("host_url") or origin.get("referrer_url") or "Origin metadata unavailable"
        text = (
            f"File: {inspection.path}\n"
            f"Size: {inspection.size:,} bytes\n"
            f"SHA-256: {inspection.sha256}\n"
            f"Downloaded from: {source}\n"
            f"Verdict: {inspection.severity}\n\n"
            f"Local findings:\n{findings}\n\n"
            f"VirusTotal:\n{inspection.reputation.explanation}\n\n"
            "Files are checked by hash only and are not uploaded. Heuristics alone never enable quarantine."
        )
        self._set_text(self.file_result, text)
        if inspection.reputation.severity in {"HIGH", "CRITICAL"}:
            self.quarantine_button.configure(state="normal")
            self.bell()
        else:
            self.quarantine_button.configure(state="disabled")

    def _ask_500kg(self, file_path, details):
        dialog = tk.Toplevel(self)
        dialog.title("Internet Defender — Review Possible Threat")
        dialog.configure(bg=BG)
        dialog.geometry("860x620")
        dialog.minsize(720, 520)
        dialog.resizable(True, True)
        dialog.transient(self)
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(2, weight=1)
        answer = {"deploy": False}

        heading = tk.Frame(dialog, bg=BG)
        heading.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 10))
        tk.Label(
            heading, text="POSSIBLE THREAT FOUND", bg=BG, fg=DANGER,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")
        tk.Label(
            heading,
            text="Review the evidence before deciding. A serious warning can still be a false alarm.",
            bg=BG, fg=FG, font=("Segoe UI", 11), justify="left",
        ).pack(anchor="w", pady=(5, 0))

        file_panel = tk.Frame(
            dialog, bg=PANEL, highlightbackground="#3b3e31", highlightthickness=1)
        file_panel.grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 12))
        tk.Label(
            file_panel, text="FILE TO QUARANTINE", bg=PANEL, fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(
            file_panel, text=str(Path(file_path).resolve()), bg=PANEL, fg=FG,
            font=("Consolas", 10), justify="left", anchor="w", wraplength=790,
        ).pack(fill="x", padx=12, pady=(0, 10))

        evidence_panel = tk.Frame(dialog, bg=BG)
        evidence_panel.grid(row=2, column=0, sticky="nsew", padx=22)
        evidence_panel.columnconfigure(0, weight=1)
        evidence_panel.rowconfigure(1, weight=1)
        tk.Label(
            evidence_panel, text="WHY IT WAS FLAGGED", bg=BG, fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))
        evidence = tk.Text(
            evidence_panel, bg="#0f100c", fg=FG, insertbackground=FG,
            selectbackground="#4d4822", selectforeground=FG, wrap="word",
            font=("Consolas", 10), relief="flat", padx=12, pady=10,
            highlightbackground="#3b3e31", highlightthickness=1,
        )
        evidence_scroll = tk.Scrollbar(evidence_panel, command=evidence.yview)
        evidence.configure(yscrollcommand=evidence_scroll.set)
        evidence.grid(row=1, column=0, sticky="nsew")
        evidence_scroll.grid(row=1, column=1, sticky="ns")
        evidence.insert("1.0", details)
        evidence.configure(state="disabled")

        action_panel = tk.Frame(
            dialog, bg="#211915", highlightbackground=DANGER, highlightthickness=1)
        action_panel.grid(row=3, column=0, sticky="ew", padx=22, pady=12)
        tk.Label(
            action_panel, text="WHAT QUARANTINE DOES", bg="#211915", fg="#ff8279",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=12, pady=(9, 2))
        tk.Label(
            action_panel,
            text=("Stops matching processes, stores verified recovery fragments, and removes the original "
                  "file so it cannot run. Restore Sample can rebuild it later if the fragments remain valid."),
            bg="#211915", fg=FG, justify="left", anchor="w", wraplength=790,
            font=("Segoe UI", 10),
        ).pack(fill="x", padx=12, pady=(0, 9))

        def finish(deploy):
            answer["deploy"] = deploy
            dialog.destroy()

        buttons = tk.Frame(dialog, bg=BG)
        buttons.grid(row=4, column=0, sticky="ew", padx=22, pady=(0, 20))
        tk.Button(
            buttons, text="AUTHORIZE 500 KG — QUARANTINE FILE", command=lambda: finish(True),
            bg=DANGER, fg="white", activebackground="#ef4035", relief="flat",
            padx=18, pady=10, font=("Segoe UI", 10, "bold"),
        ).pack(side="left")
        hold_fire = tk.Button(
            buttons, text="HOLD FIRE — KEEP FILE", command=lambda: finish(False),
            bg="#292b21", fg=FG, activebackground="#3a3d30", relief="flat",
            padx=18, pady=10, font=("Segoe UI", 10, "bold"),
        )
        hold_fire.pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        dialog.bind("<Escape>", lambda _event: finish(False))
        dialog.update_idletasks()
        x = max(0, self.winfo_rootx() + (self.winfo_width() - 860) // 2)
        y = max(0, self.winfo_rooty() + (self.winfo_height() - 620) // 2)
        dialog.geometry(f"860x620+{x}+{y}")
        dialog.grab_set()
        hold_fire.focus_set()
        self.wait_window(dialog)
        return answer["deploy"]

    def _show_passive_file_result(self, inspection, local_assessment=None):
        self.file_path.delete(0, "end")
        self.file_path.insert(0, inspection.path)
        self._show_file_result(inspection)
        result_severity = combined_file_severity(inspection, local_assessment)
        color = COLORS.get(result_severity, MUTED)
        name = Path(inspection.path).name
        self.download_status.configure(
            text=f"MINISTRY PASSIVE RESEARCH: {name} — {result_severity}",
            fg=color,
        )
        online_serious = passive_quarantine_confirmed(inspection)
        local_serious = bool(
            local_assessment and local_assessment.severity in {"HIGH", "CRITICAL"})
        if not online_serious and not local_serious:
            self._set_activity(f"Ministry research finished — {name}: {result_severity}")
            return
        card = card_from_file(inspection, local_assessment)
        self._upsert_mission_card(f"file:{inspection.sha256}", card)
        origin = download_origin(inspection.path)
        report = save_origin_report(inspection, origin)
        source = origin.get("host_url") or origin.get("referrer_url") or "Origin metadata unavailable"
        if report not in self.sweep_reports:
            self.sweep_reports.append(report)
        if not online_serious:
            self.download_status.configure(
                text=f"MINISTRY PASSIVE RESEARCH: {name} — {result_severity} LOCAL WARNING",
                fg=color,
            )
            self._set_activity(
                f"Review {name} in Mission Control; local rules alone will not offer quarantine",
                ACCENT,
            )
            return
        if not Path(inspection.path).is_file():
            self._set_activity(f"Skipped {name}; it was moved or deleted after scanning", MUTED)
            return
        local_details = (
            "; ".join(local_assessment.reasons) if local_assessment and local_assessment.reasons
            else "No serious local behavior rule fired."
        )
        details = (
            f"Combined result: {result_severity}\n"
            f"VirusTotal: {inspection.reputation.explanation}\n"
            f"Local research: {local_details}\n"
            f"Downloaded from: {source}\n"
            f"Evidence report: {report}\n\n"
            "Serious detections can still be false positives. Review before authorizing containment."
        )
        if self._ask_500kg(inspection.path, details):
            self._set_activity(
                f"DEPLOYING 500 KG — quarantining {name}", ACCENT)
            self.jobs.put(("quarantine", inspection.path))
        else:
            self._set_activity(f"Quarantine canceled — {name} was left in place", MUTED)

    def _restore_last_sample(self):
        item = self.last_quarantine_item
        if not item:
            messagebox.showinfo("No sample", "There is no recoverable brain/body sample in quarantine.")
            return
        if not messagebox.askyesno(
            "Restore quarantined sample?",
            f"Reassemble the verified brain and body fragments?\n\n"
            f"Original path: {item['original_path']}\nSHA-256: {item['sha256']}\n\n"
            "Restoration stops if the original path is occupied or any hash fails.",
        ):
            return
        self.restore_sample_button.configure(state="disabled")
        self._set_activity("Ministry of Science is reassembling brain + body fragments", ACCENT)
        self.jobs.put(("restore_sample", item))

    def _quarantine_current(self):
        inspection = self.current_file
        if not inspection or inspection.reputation.severity not in {"HIGH", "CRITICAL"}:
            return
        details = (
            f"Result: {inspection.reputation.severity}\n"
            f"{inspection.reputation.explanation}\n\n"
            "A verified brain/body recovery copy will be created, then the functioning original path will be removed."
        )
        if self._ask_500kg(inspection.path, details):
            self._set_activity(
                f"DEPLOYING 500 KG — exterminating dissident {Path(inspection.path).name}", ACCENT)
            self.jobs.put(("quarantine", inspection.path))

    @staticmethod
    def _is_admin():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _relaunch_as_admin(self, action_flag="--start-emergency"):
        if getattr(sys, "frozen", False):
            executable = sys.executable
            parameters = action_flag
            working_directory = str(Path(sys.executable).resolve().parent)
        else:
            script = str(Path(__file__).resolve())
            executable = sys.executable
            parameters = f'"{script}" {action_flag}'
            working_directory = str(Path(script).parent)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, parameters, working_directory, 1)
        if result <= 32:
            messagebox.showerror(
                "Administrator restart failed",
                "Windows did not start the elevated copy. You can right-click the launcher and choose Run as administrator.",
            )
            return
        self.stop_event.set()
        self.destroy()

    def _start_emergency(self, skip_confirmation=False):
        if self.sweep_active:
            return
        if not self._is_admin():
            if messagebox.askyesno(
                "Administrator permission required",
                "Emergency network quarantine needs Administrator permission. Restart this app as Administrator now?\n\n"
                "Windows will show a UAC confirmation. A securely saved VirusTotal key loads automatically.",
            ):
                self._relaunch_as_admin()
            return
        online_status = (
            "VirusTotal online checks are enabled." if self.vt.api_key else
            "No VirusTotal key is saved, so local checks will run and online results will be UNKNOWN."
        )
        if not skip_confirmation and not messagebox.askyesno(
            "Start Emergency Scan",
            "Temporarily quarantine this PC's network and run every check five times?\n\n"
            "Most running programs will be blocked from the internet. This app keeps HTTPS and Windows DNS "
            "access so VirusTotal can work. The previous firewall setup is backed up and restored afterward.\n\n"
            "Administrator permission is required. Confirmed threats still require your approval before "
            "firewall blocking or file quarantine.\n\n"
            f"{online_status}",
        ):
            return
        self.sweep_active = True
        self.sweep_round = 0
        self.sweep_prompted.clear()
        self.sweep_reports.clear()
        self.sweep_errors.clear()
        self.emergency_button.configure(state="disabled")
        if self.network_quarantine_active and self.network_quarantine_backup:
            self.protection_label.configure(text="PC NETWORK QUARANTINED", fg=DANGER)
            self._set_activity("Starting emergency check 1 of 5", "#f0883e")
            self.jobs.put(("sweep", 1))
        else:
            self.protection_label.configure(text="QUARANTINING PC NETWORK", fg=DANGER)
            self._set_activity(
                "Saving the firewall setup, then taking normal programs offline", DANGER)
            self.jobs.put(("begin_network_quarantine",))

    def _restore_emergency(self):
        if not messagebox.askyesno(
            "Restore internet",
            "Restore the firewall setup saved before Internet Defender quarantined this PC?",
        ):
            return
        self.restore_button.configure(state="disabled")
        if self.network_quarantine_active and self.network_quarantine_backup:
            self.network_restore_requested = True
            self._set_activity("Restoring the previous firewall setup", ACCENT)
            self.jobs.put((
                "restore_network_quarantine", self.network_quarantine_backup, None))
        else:
            self.jobs.put(("restore",))

    def _open_recovery(self):
        webbrowser.open("https://myaccount.google.com/security-checkup", new=2)

    def _set_api_key(self):
        key = self.api_key_entry.get().strip()
        try:
            save_virustotal_key(key)
        except Exception as exc:
            messagebox.showerror(
                "Could not save key securely",
                f"Windows could not encrypt and save the key. Nothing was saved.\n\n{exc}",
            )
            return
        self.vt.set_api_key(key)
        if key:
            self.key_status.configure(
                text="Key saved with Windows encryption — you should not need to enter it again",
                fg="#78b84a")
            self.seen_ips.clear()
            messagebox.showinfo(
                "Key saved securely",
                "Windows encrypted the key for this Windows account. Administrator restarts will load it automatically.",
            )
        else:
            self.key_status.configure(
                text="No API key saved: online verdicts will be UNKNOWN", fg="#f4d03f")

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _close(self):
        if self.network_quarantine_active and self.network_quarantine_backup:
            if not messagebox.askyesno(
                "Restore internet before closing",
                "The PC network is still quarantined. Restore the previous firewall setup and close?",
            ):
                return
            self._set_activity("Restoring internet before closing", ACCENT)
            try:
                restore_network_quarantine(self.network_quarantine_backup)
            except Exception as exc:
                messagebox.showerror(
                    "Could not restore internet",
                    f"The app will stay open so you can try Restore Internet again.\n\n{exc}",
                )
                return
        self.stop_event.set()
        if self.whole_pc_monitor:
            self.whole_pc_monitor.stop()
        self.destroy()


if __name__ == "__main__":
    InternetDefenderApp().mainloop()
