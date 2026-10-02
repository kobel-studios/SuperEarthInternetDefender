import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None


RISKY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".py",
    ".lnk", ".reg", ".iso", ".img", ".zip", ".rar", ".7z",
}
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
REMOTE_ACCESS_TOOLS = {
    "anydesk.exe": "AnyDesk",
    "teamviewer.exe": "TeamViewer",
    "teamviewer_service.exe": "TeamViewer",
    "rustdesk.exe": "RustDesk",
    "screenconnect.clientservice.exe": "ScreenConnect",
    "screenconnect.windowsclient.exe": "ScreenConnect",
    "remoting_host.exe": "Chrome Remote Desktop",
    "chromoting_host.exe": "Chrome Remote Desktop",
    "winvnc.exe": "VNC",
    "vncserver.exe": "VNC",
    "tvnserver.exe": "TightVNC",
    "splashtopremote.exe": "Splashtop",
    "srserver.exe": "Splashtop",
    "logmein.exe": "LogMeIn",
    "lmi_rescue.exe": "LogMeIn Rescue",
    "parsecd.exe": "Parsec",
    "parsec.exe": "Parsec",
    "dwrcs.exe": "Dameware",
}


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    parent_pid: int
    name: str
    path: str
    command_line: str


@dataclass(frozen=True)
class ConnectionRecord:
    protocol: str
    local_address: str
    remote_address: str
    remote_ip: str
    state: str
    pid: int


@dataclass(frozen=True)
class StartupItem:
    location: str
    name: str
    command: str


@dataclass(frozen=True)
class SecurityEvent:
    event_id: int
    timestamp: str
    username: str
    ip_address: str
    logon_type: str
    status: str


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    explanation: str
    subject: str
    recommendation: str
    score: int = 0


@dataclass(frozen=True)
class FileAssessment:
    path: str
    sha256: str
    signature: str
    origin: str
    reasons: tuple
    score: int
    severity: str


@dataclass(frozen=True)
class ScanResult:
    findings: tuple
    process_count: int
    connection_count: int
    startup_count: int
    file_count: int
    report_path: str
    startup_baseline_created: bool


@dataclass(frozen=True)
class LocalScanContext:
    processes: tuple
    connections: tuple
    startup_items: tuple
    security_events: tuple


@dataclass(frozen=True)
class RemoteAccessFinding:
    kind: str
    tool: str
    identifier: int
    process_path: str
    username: str
    activities: tuple
    explanation: str


def data_root():
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LocalSecurityDetective"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def severity_for_score(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def is_user_writable_path(path):
    if not path:
        return False
    normalized = os.path.normcase(os.path.abspath(path))
    candidates = [
        os.environ.get("USERPROFILE", ""),
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
    ]
    return any(root and normalized.startswith(os.path.normcase(os.path.abspath(root)))
               for root in candidates)


def parse_process_csv(text):
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    records = []
    for row in csv.DictReader(lines):
        try:
            pid = int((row.get("ProcessId") or "").strip())
            parent_pid = int((row.get("ParentProcessId") or "0").strip() or 0)
        except ValueError:
            continue
        records.append(ProcessRecord(
            pid,
            parent_pid,
            (row.get("Name") or "Unknown").strip(),
            (row.get("ExecutablePath") or "").strip(),
            (row.get("CommandLine") or "").strip(),
        ))
    return records


def running_processes(runner=subprocess.run):
    result = runner(
        ["wmic", "process", "get",
         "Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine", "/format:csv"],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not list running programs")
    return parse_process_csv(result.stdout)


def signature_status(path, runner=subprocess.run):
    environment = os.environ.copy()
    environment["LOCAL_DETECTIVE_PATH"] = os.path.abspath(path)
    result = runner(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$s=Get-AuthenticodeSignature -LiteralPath $env:LOCAL_DETECTIVE_PATH; $s.Status"],
        capture_output=True, text=True, timeout=15, env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        return "Unknown"
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else "Unknown"


def assess_process(record, signature="Unknown"):
    reasons = []
    score = 0
    path_lower = record.path.lower()
    command = record.command_line.lower()
    suspicious_roots = [
        os.path.join(os.environ.get("USERPROFILE", ""), "Downloads").lower(),
        os.environ.get("TEMP", "").lower(),
        os.environ.get("TMP", "").lower(),
    ]
    if record.path and any(root and path_lower.startswith(root) for root in suspicious_roots):
        score += 45
        reasons.append("Running from Downloads or a temporary folder")
    elif record.path and is_user_writable_path(record.path):
        score += 15
        reasons.append("Running from a user-writable folder")
    command_patterns = {
        " -enc ": "Encoded command-line content",
        "-encodedcommand": "Encoded PowerShell command",
        "invoke-expression": "Dynamic PowerShell execution",
        "downloadstring": "Command downloads executable content",
        "frombase64string": "Command decodes embedded content",
        "mshta http": "MSHTA launched remote content",
        "regsvr32 /s /n /u /i:http": "Regsvr32 remote-content technique",
    }
    for token, reason in command_patterns.items():
        if token in command:
            score += 40
            reasons.append(reason)
    if signature in {"HashMismatch", "NotTrusted", "UnknownError"}:
        score += 50
        reasons.append(f"Executable signature status is {signature}")
    elif signature == "NotSigned" and is_user_writable_path(record.path):
        score += 20
        reasons.append("Unsigned executable in a user-writable folder")
    return score, tuple(dict.fromkeys(reasons))


def split_endpoint(endpoint):
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        close = endpoint.rfind("]")
        return endpoint[1:close], endpoint[close + 2:]
    host, separator, port = endpoint.rpartition(":")
    return (host, port) if separator else (endpoint, "")


PROCESS_DISPLAY_INFO = {
    "applicationframehost.exe": ("Windows Application Frame Host", "Displays windows for some Microsoft Store apps."),
    "chrome.exe": ("Google Chrome", "Google's web browser."),
    "code.exe": ("Visual Studio Code", "Microsoft's code editor."),
    "discord.exe": ("Discord", "The Discord chat, voice, and streaming app."),
    "epicgameslauncher.exe": ("Epic Games Launcher", "The Epic Games store and game launcher."),
    "explorer.exe": ("Windows File Explorer", "The Windows desktop and file manager."),
    "filecoauth.exe": ("Microsoft File Co-Authoring", "A Microsoft 365 and OneDrive file-sync helper."),
    "firefox.exe": ("Mozilla Firefox", "Mozilla's web browser."),
    "gamingservices.exe": ("Microsoft Gaming Services", "A Windows component used by Xbox and Microsoft Store games."),
    "msedge.exe": ("Microsoft Edge", "Microsoft's web browser."),
    "msedgewebview2.exe": ("Microsoft Edge WebView2", "A Microsoft browser engine that apps use for sign-in pages and web content inside their own windows."),
    "ms-teams.exe": ("Microsoft Teams", "Microsoft's chat and meeting app."),
    "onedrive.exe": ("Microsoft OneDrive", "Microsoft's cloud file-sync app."),
    "opera.exe": ("Opera / Opera GX", "The Opera web browser."),
    "python.exe": ("Python Program", "A program or script running with Python."),
    "pythonw.exe": ("Python Desktop App", "A windowed program or script running with Python."),
    "runtimebroker.exe": ("Windows Runtime Broker", "Controls permissions for Microsoft Store apps."),
    "searchhost.exe": ("Windows Search", "The Windows search interface."),
    "steam.exe": ("Steam", "The Steam game store and launcher."),
    "steamwebhelper.exe": ("Steam Web Helper", "Steam's built-in browser for the store, library, and community pages."),
    "svchost.exe": ("Windows Service Host", "Runs one or more Windows background services."),
    "system": ("Windows System", "Core Windows operating-system activity."),
    "teams.exe": ("Microsoft Teams", "Microsoft's chat and meeting app."),
    "widgets.exe": ("Windows Widgets", "The Windows news, weather, and widgets panel."),
}


def process_display_name(process_name):
    raw_name = (process_name or "Unknown program").strip()
    return PROCESS_DISPLAY_INFO.get(raw_name.lower(), (raw_name, ""))[0]


def process_description(process_name):
    raw_name = (process_name or "Unknown program").strip()
    known = PROCESS_DISPLAY_INFO.get(raw_name.lower())
    if known:
        return known[1]
    if raw_name.lower() in {"unknown", "unknown program"}:
        return "Windows could not identify the program that owns this connection."
    return f"Windows executable named {raw_name}; its product name is not in the app's local name list."


def connection_program_name(connection):
    process_name = getattr(connection, "process_name", "") or "Unknown program"
    display_name = process_display_name(process_name)
    owner_name = getattr(connection, "owner_process_name", "") or ""
    if owner_name and owner_name.lower() != process_name.lower():
        return f"{display_name} (used by {process_display_name(owner_name)})"
    return display_name


def describe_program(connection):
    process_name = getattr(connection, "process_name", "") or "Unknown program"
    display_name = process_display_name(process_name)
    lines = [f"Program: {display_name}"]
    owner_name = getattr(connection, "owner_process_name", "") or ""
    if owner_name and owner_name.lower() != process_name.lower():
        owner_display = process_display_name(owner_name)
        owner_technical = f" ({owner_name})" if owner_display.lower() != owner_name.lower() else ""
        lines.append(f"Used by: {owner_display}{owner_technical}")
    if display_name.lower() != process_name.lower():
        lines.append(f"Technical file: {process_name}")
    lines.append(f"What it is: {process_description(process_name)}")
    return "\n".join(lines)


def describe_connection(connection):
    _, port_text = split_endpoint(connection.remote_address)
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    if port == 443:
        action = "making an encrypted internet connection, usually HTTPS"
    elif port == 80:
        action = "making an unencrypted web connection"
    elif port == 53:
        action = "looking up an internet name with DNS"
    elif port in {3478, 3479, 3480}:
        action = "setting up game, voice, or video traffic"
    elif 27000 <= port <= 27100:
        action = "communicating with Steam or a game service"
    elif port in {5222, 5223}:
        action = "using a messaging or push-notification service"
    elif port:
        action = f"using internet service port {port}"
    else:
        action = "using an internet service"
    return f"{connection_program_name(connection)} is {action}"


def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def parse_netstat(text):
    records = []
    seen = set()
    for line in text.splitlines():
        columns = line.split()
        if len(columns) < 4 or columns[0].upper() not in {"TCP", "UDP"}:
            continue
        protocol = columns[0].upper()
        if protocol == "TCP":
            if len(columns) < 5 or columns[3].upper() != "ESTABLISHED":
                continue
            local, remote, state, pid_text = columns[1:5]
        else:
            local, remote, state, pid_text = columns[1], columns[2], "ACTIVE", columns[3]
        remote_ip, _ = split_endpoint(remote)
        if not is_public_ip(remote_ip):
            continue
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        key = (protocol, local, remote, pid)
        if key in seen:
            continue
        seen.add(key)
        records.append(ConnectionRecord(protocol, local, remote, remote_ip, state, pid))
    return records


def active_connections(runner=subprocess.run):
    result = runner(
        ["netstat", "-ano"], capture_output=True, text=True, timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not list internet connections")
    return parse_netstat(result.stdout)


def parse_qwinsta(text):
    sessions = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("sessionname"):
            continue
        if line.startswith(">"):
            line = line[1:]
        tokens = line.split()
        index = next((i for i, token in enumerate(tokens) if token.isdigit()), None)
        if index is None or index + 1 >= len(tokens):
            continue
        session_name = tokens[0]
        username = " ".join(tokens[1:index])
        session_id = int(tokens[index])
        state = tokens[index + 1]
        sessions.append((session_name, username, session_id, state))
    return sessions


def remote_desktop_sessions(runner=subprocess.run):
    result = runner(
        ["qwinsta"], capture_output=True, text=True, timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode not in {0, 1}:
        return []
    findings = []
    for session_name, username, session_id, state in parse_qwinsta(result.stdout):
        if not session_name.lower().startswith("rdp-") or state.lower() != "active":
            continue
        findings.append(RemoteAccessFinding(
            "rdp_session", "Windows Remote Desktop", session_id, "", username, (),
            "An active Windows Remote Desktop session can control this PC.",
        ))
    return findings


def detect_remote_access(processes=None, connections=None, runner=subprocess.run):
    process_list = list(processes) if processes is not None else running_processes(runner)
    connection_list = list(connections) if connections is not None else active_connections(runner)
    findings = []
    seen = set()
    for process in process_list:
        tool = REMOTE_ACCESS_TOOLS.get(process.name.lower())
        if not tool or process.pid in seen:
            continue
        seen.add(process.pid)
        activities = tuple(
            describe_connection(connection) for connection in connection_list
            if connection.pid == process.pid
        )
        findings.append(RemoteAccessFinding(
            "process", tool, process.pid, process.path, "", activities,
            f"{tool} can provide another person with remote control of this PC. Its presence is not proof of hacking.",
        ))
    try:
        findings.extend(remote_desktop_sessions(runner))
    except (OSError, subprocess.SubprocessError):
        pass
    return findings


def disconnect_remote_access(finding, disable_rdp=True, runner=subprocess.run):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    def run(command):
        result = runner(
            command, capture_output=True, text=True, timeout=30, creationflags=flags)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                               "Remote-access containment command failed")
        return result

    actions = []
    if finding.kind == "process":
        run(["taskkill", "/PID", str(finding.identifier), "/T", "/F"])
        actions.append(f"Terminated {finding.tool} process {finding.identifier}")
        if finding.process_path and Path(finding.process_path).is_file():
            rule_id = hashlib.sha256(
                os.path.normcase(finding.process_path).encode()).hexdigest()[:12]
            for direction in ("in", "out"):
                rule_name = f"Internet Defender Remote Tool {rule_id} {direction.upper()}"
                runner(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={rule_name}"],
                    capture_output=True, text=True, timeout=30, creationflags=flags,
                )
                run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", f"dir={direction}", "action=block",
                    f"program={finding.process_path}", "enable=yes", "profile=any",
                ])
            actions.append(f"Blocked {finding.tool} executable in Windows Firewall")
    elif finding.kind == "rdp_session":
        run(["logoff", str(finding.identifier)])
        actions.append(f"Logged off Remote Desktop session {finding.identifier}")
        if disable_rdp:
            run([
                "reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f",
            ])
            actions.append("Disabled new Windows Remote Desktop connections")
    else:
        raise ValueError("Unsupported remote-access finding type")
    return tuple(actions)


def save_remote_access_report(findings, actions=(), root=None):
    report_root = Path(root or data_root() / "reports")
    report_root.mkdir(parents=True, exist_ok=True)
    report = {
        "created_at": time.time(),
        "notice": (
            "Local evidence only. Remote-access software may be legitimate, and this report does not identify a hacker. "
            "Nothing was submitted automatically."
        ),
        "remote_access_findings": [asdict(finding) for finding in findings],
        "containment_actions": list(actions),
    }
    path = report_root / f"remote_access_{int(report['created_at'])}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(path)


def investigate_connection_processes(connections, runner=subprocess.run):
    processes = running_processes(runner)
    process_map = {process.pid: process for process in processes}
    signature_cache = {}
    findings = []
    for connection in connections:
        process = process_map.get(connection.pid)
        if not process:
            continue
        signature = "Unknown"
        if process.path and is_user_writable_path(process.path) and Path(process.path).is_file():
            if process.path not in signature_cache:
                signature_cache[process.path] = signature_status(process.path, runner)
            signature = signature_cache[process.path]
        score, reasons = assess_process(process, signature)
        if score < 25:
            continue
        combined_score = min(100, score + 20)
        findings.append((connection, Finding(
            severity_for_score(combined_score),
            "INTERNET CONNECTION",
            f"Unusual program is using the internet: {process.name}",
            "; ".join(reasons),
            f"{process.path or process.command_line} -> remote service",
            "Review the program path and signature. Block the connection only if separate evidence confirms it is malicious.",
            combined_score,
        )))
    return findings


def parse_zone_identifier(text):
    values = {}
    active = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            active = line.lower() == "[zonetransfer]"
            continue
        if active and "=" in line:
            key, value = line.split("=", 1)
            if key.lower() in {"hosturl", "referrerurl", "zoneid"}:
                values[key.lower()] = value.strip()
    return values


def download_origin(path):
    try:
        text = Path(str(Path(path).resolve()) + ":Zone.Identifier").read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return parse_zone_identifier(text)


def inspect_local_file(path, runner=subprocess.run):
    file_path = Path(path).resolve()
    if not file_path.is_file():
        raise ValueError("Choose an existing file.")
    reasons = []
    score = 0
    extension = file_path.suffix.lower()
    with file_path.open("rb") as handle:
        header = handle.read(1024)
    is_executable = header[:2] == b"MZ"
    if "\u202e" in file_path.name:
        score += 80
        reasons.append("Filename contains a right-to-left override character")
    suffixes = [suffix.lower() for suffix in file_path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in {".exe", ".scr", ".com", ".bat", ".cmd"}:
        score += 35
        reasons.append("Double-extension filename may disguise an executable")
    if is_executable and extension not in {".exe", ".dll", ".sys", ".scr", ".com", ".cpl"}:
        score += 70
        reasons.append("File contents are executable but the extension hides that")
    script_extensions = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py"}
    if extension in script_extensions:
        text = file_path.read_text(errors="ignore")[:250_000].lower()
        patterns = {
            "invoke-expression": (35, "Script dynamically executes constructed commands"),
            "downloadstring": (40, "Script downloads executable content"),
            "frombase64string": (25, "Script decodes embedded content"),
            "currentversion\\run": (35, "Script may add startup persistence"),
            "-encodedcommand": (40, "Script launches encoded PowerShell"),
            "wscript.shell": (20, "Script controls Windows programs or settings"),
        }
        for token, (points, reason) in patterns.items():
            if token in text:
                score += points
                reasons.append(reason)
    signature = "NotApplicable"
    if is_executable:
        signature = signature_status(file_path, runner)
        if signature == "HashMismatch":
            score += 90
            reasons.append("Digital signature does not match the file")
        elif signature in {"NotTrusted", "UnknownError"}:
            score += 45
            reasons.append(f"Digital signature status is {signature}")
        elif signature == "NotSigned" and is_user_writable_path(file_path):
            score += 20
            reasons.append("Unsigned executable in a user-writable folder")
    origin_data = download_origin(file_path)
    origin = origin_data.get("hosturl") or origin_data.get("referrerurl") or "Unknown"
    return FileAssessment(
        str(file_path), sha256_file(file_path), signature, origin,
        tuple(dict.fromkeys(reasons)), score, severity_for_score(score),
    )


def _registry_startup_items():
    if winreg is None:
        return []
    locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Current user Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "All users Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "32-bit Run"),
    ]
    items = []
    for hive, key_name, label in locations:
        try:
            with winreg.OpenKey(hive, key_name) as key:
                index = 0
                while True:
                    try:
                        name, command, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    items.append(StartupItem(label, name, str(command)))
                    index += 1
        except OSError:
            continue
    return items


def collect_startup_items():
    items = _registry_startup_items()
    folders = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    for folder in folders:
        if not folder.is_dir():
            continue
        try:
            for path in folder.iterdir():
                if path.is_file():
                    items.append(StartupItem(str(folder), path.name, str(path.resolve())))
        except OSError:
            continue
    return sorted(items, key=lambda item: (item.location.lower(), item.name.lower()))


def startup_snapshot(items):
    return {f"{item.location}|{item.name}": item.command for item in items}


def load_startup_baseline(path=None):
    baseline_path = Path(path or data_root() / "startup_baseline.json")
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_startup_baseline(items, path=None):
    baseline_path = Path(path or data_root() / "startup_baseline.json")
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(startup_snapshot(items), indent=2), encoding="utf-8")
    return str(baseline_path)


def compare_startup_items(items, baseline):
    current = startup_snapshot(items)
    if baseline is None:
        return [], []
    added = [key for key in current if key not in baseline]
    changed = [key for key in current if key in baseline and current[key] != baseline[key]]
    return added, changed


def parse_security_events(xml_text):
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", xml_text).strip()
    if not cleaned:
        return []
    try:
        root = ET.fromstring(cleaned if cleaned.startswith("<Events") else f"<Events>{cleaned}</Events>")
    except ET.ParseError:
        return []
    event_nodes = [root] if root.tag.endswith("Event") else root.findall(".//{*}Event")
    events = []
    for event in event_nodes:
        event_id_node = event.find("./{*}System/{*}EventID")
        time_node = event.find("./{*}System/{*}TimeCreated")
        if event_id_node is None or not event_id_node.text:
            continue
        data = {}
        for item in event.findall("./{*}EventData/{*}Data"):
            data[item.attrib.get("Name", "")] = item.text or ""
        try:
            event_id = int(event_id_node.text)
        except ValueError:
            continue
        events.append(SecurityEvent(
            event_id,
            time_node.attrib.get("SystemTime", "") if time_node is not None else "",
            data.get("TargetUserName", ""),
            data.get("IpAddress", ""),
            data.get("LogonType", ""),
            data.get("Status", ""),
        ))
    return events


def security_events(runner=subprocess.run):
    query = "*[System[(EventID=4624 or EventID=4625)]]"
    result = runner(
        ["wevtutil", "qe", "Security", f"/q:{query}", "/f:xml", "/c:100", "/rd:true"],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise PermissionError(result.stderr.strip() or "Windows denied access to the Security event log")
    return parse_security_events(result.stdout)


def findings_from_security_events(events):
    findings = []
    failures = {}
    for event in events:
        if event.event_id == 4625:
            key = (event.username or "Unknown user", event.ip_address or "Unknown source")
            failures[key] = failures.get(key, 0) + 1
        elif event.event_id == 4624 and event.logon_type == "10" and is_public_ip(event.ip_address):
            findings.append(Finding(
                "HIGH", "WINDOWS LOGIN", "Remote desktop login from a public IP",
                "Windows recorded a successful Remote Desktop-style login from a public internet address.",
                f"{event.username} from {event.ip_address}",
                "If this was not you, disconnect the PC and change the Windows account password from a safe device.",
                60,
            ))
    for (username, source), count in failures.items():
        if count < 5:
            continue
        score = 80 if count >= 10 else 50
        findings.append(Finding(
            severity_for_score(score), "WINDOWS LOGIN", f"{count} failed login attempts",
            "Repeated failed Windows logins can mean someone or something is guessing a password.",
            f"{username} from {source}",
            "Review the source and change the password if the attempts were not yours.",
            score,
        ))
    return findings


def recent_risky_files(roots, limit=30, max_bytes=300 * 1024 * 1024):
    candidates = []
    for root in roots:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        try:
            for path in root_path.rglob("*"):
                try:
                    if path.is_file() and path.suffix.lower() in RISKY_EXTENSIONS:
                        stat = path.stat()
                        if stat.st_size <= max_bytes:
                            candidates.append((stat.st_mtime_ns, str(path.resolve())))
                except OSError:
                    continue
        except OSError:
            continue
    candidates.sort(reverse=True)
    return [path for _, path in candidates[:limit]]


def quarantine_file(path, root=None):
    source = Path(path).resolve()
    if not source.is_file():
        raise ValueError("The file no longer exists.")
    quarantine_root = Path(root or data_root() / "quarantine")
    quarantine_root.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(source)
    destination = quarantine_root / f"{int(time.time())}_{digest[:16]}.quarantine"
    shutil.move(str(source), destination)
    metadata = {
        "original_path": str(source),
        "quarantined_path": str(destination),
        "sha256": digest,
        "timestamp": time.time(),
    }
    Path(str(destination) + ".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def save_scan_report(findings, context, root=None):
    report_root = Path(root or data_root() / "reports")
    report_root.mkdir(parents=True, exist_ok=True)
    created_at = time.time()
    report = {
        "created_at": created_at,
        "notice": (
            "Local observations only. A finding is not proof that an online account or person was hacked. "
            "No report was sent anywhere."
        ),
        "summary": {
            "processes": len(context.processes),
            "connections": len(context.connections),
            "startup_items": len(context.startup_items),
            "security_events": len(context.security_events),
        },
        "findings": [asdict(finding) for finding in findings],
    }
    path = report_root / f"local_scan_{int(created_at)}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(path)


def run_local_scan(progress=None, runner=subprocess.run, baseline_path=None, report_root=None):
    notify = progress or (lambda _message: None)
    findings = []
    notify("Listing running programs")
    try:
        processes = running_processes(runner)
    except Exception as exc:
        processes = []
        findings.append(Finding(
            "MEDIUM", "SCAN ERROR", "Could not list running programs", str(exc), "Windows process list",
            "Try running the app as Administrator.", 25,
        ))
    process_scores = {}
    for index, process in enumerate(processes, 1):
        signature = "Unknown"
        if process.path and is_user_writable_path(process.path) and Path(process.path).is_file():
            notify(f"Checking running program {index}/{len(processes)}: {process.name}")
            signature = signature_status(process.path, runner)
        score, reasons = assess_process(process, signature)
        process_scores[process.pid] = score
        if score >= 25:
            findings.append(Finding(
                severity_for_score(score), "RUNNING PROGRAM", f"Suspicious running program: {process.name}",
                "; ".join(reasons), process.path or process.command_line,
                "Do not end it unless you recognize the evidence. Investigate the path and signature first.", score,
            ))
    notify("Checking active internet connections")
    try:
        connections = active_connections(runner)
    except Exception as exc:
        connections = []
        findings.append(Finding(
            "LOW", "SCAN ERROR", "Could not list internet connections", str(exc), "Windows network list",
            "Retry the scan.", 10,
        ))
    process_map = {process.pid: process for process in processes}
    for connection in connections:
        process_score = process_scores.get(connection.pid, 0)
        if process_score < 25:
            continue
        process = process_map.get(connection.pid)
        score = min(100, process_score + 20)
        findings.append(Finding(
            severity_for_score(score), "INTERNET CONNECTION", "Suspicious program is using the internet",
            "A locally suspicious program also has an active public internet connection.",
            f"{process.name if process else 'Unknown'} -> {connection.remote_address}",
            "Pause the connection and investigate the program before blocking or quarantining it.", score,
        ))
    notify("Checking programs that start with Windows")
    startup_items = tuple(collect_startup_items())
    baseline = load_startup_baseline(baseline_path)
    baseline_created = baseline is None
    if baseline_created:
        save_startup_baseline(startup_items, baseline_path)
        findings.append(Finding(
            "INFO", "STARTUP", "Startup baseline created",
            "This first scan saved the current startup list. Future scans can detect additions or changes.",
            "Windows startup locations", "Review the startup list before choosing to trust it.", 0,
        ))
    else:
        added, changed = compare_startup_items(startup_items, baseline)
        current = startup_snapshot(startup_items)
        for key in added:
            findings.append(Finding(
                "MEDIUM", "STARTUP", "New program starts with Windows",
                "This startup entry was not present in the saved baseline.", current[key],
                "Confirm that you installed or enabled this program.", 35,
            ))
        for key in changed:
            findings.append(Finding(
                "HIGH", "STARTUP", "Startup command changed",
                "A known startup entry now launches a different command.", current[key],
                "Investigate the changed command before trusting the new baseline.", 50,
            ))
    notify("Checking recent risky files")
    roots = [Path.home() / "Downloads", Path.home() / "Desktop", Path(os.environ.get("TEMP", ""))]
    files = recent_risky_files(roots)
    for index, path in enumerate(files, 1):
        notify(f"Checking recent file {index}/{len(files)}: {Path(path).name}")
        try:
            assessment = inspect_local_file(path, runner)
        except Exception as exc:
            findings.append(Finding(
                "LOW", "FILE", "Could not inspect a recent file", str(exc), path,
                "Check whether the file was deleted, locked, or requires Administrator access.", 10,
            ))
            continue
        if assessment.score >= 25:
            findings.append(Finding(
                assessment.severity, "FILE", f"Suspicious file: {Path(path).name}",
                "; ".join(assessment.reasons), assessment.path,
                "Review the source and evidence. Quarantine only if you confirm it is unwanted.", assessment.score,
            ))
    notify("Checking recent Windows login activity")
    try:
        events = tuple(security_events(runner))
        findings.extend(findings_from_security_events(events))
    except Exception as exc:
        events = ()
        findings.append(Finding(
            "INFO", "WINDOWS LOGIN", "Login history could not be read",
            str(exc), "Windows Security event log",
            "Run as Administrator if you want Windows login-event checks.", 0,
        ))
    if any(finding.severity in {"HIGH", "CRITICAL"} and
           finding.category in {"RUNNING PROGRAM", "FILE", "WINDOWS LOGIN"}
           for finding in findings):
        findings.append(Finding(
            "MEDIUM", "ACCOUNT CLUE", "Online accounts may need a security review",
            "A serious local finding can expose passwords or sessions, but this app cannot see private cloud-account activity.",
            "Your important online accounts",
            "From a different safe device, change passwords, sign out other sessions, and enable MFA.", 30,
        ))
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], -item.score, item.category, item.title))
    context = LocalScanContext(tuple(processes), tuple(connections), startup_items, events)
    report_path = save_scan_report(findings, context, report_root)
    notify("Local scan complete")
    return ScanResult(
        tuple(findings), len(processes), len(connections), len(startup_items), len(files),
        report_path, baseline_created,
    )
