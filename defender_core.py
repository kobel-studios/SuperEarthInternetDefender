import binascii
import csv
import ctypes
from ctypes import wintypes
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path


RISKY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".com",
    ".pif", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".py",
    ".lnk", ".reg", ".inf", ".iso", ".img", ".zip", ".rar", ".7z",
}


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _input_blob(data):
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _dpapi_protect(data):
    if os.name != "nt":
        raise OSError("Windows data protection is unavailable")
    input_blob, buffer = _input_blob(data)
    output_blob = _DataBlob()
    result = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(input_blob), "Internet Defender VirusTotal key", None, None, None,
        0x1, ctypes.byref(output_blob),
    )
    del buffer
    if not result:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def _dpapi_unprotect(data):
    if os.name != "nt":
        raise OSError("Windows data protection is unavailable")
    input_blob, buffer = _input_blob(data)
    output_blob = _DataBlob()
    result = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(input_blob), None, None, None, None, 0x1,
        ctypes.byref(output_blob),
    )
    del buffer
    if not result:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def virustotal_key_path():
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / \
           "InternetDefender" / "virustotal_key.dpapi"


def save_virustotal_key(api_key, path=None):
    destination = Path(path or virustotal_key_path())
    key = api_key.strip()
    if not key:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        return None
    protected = _dpapi_protect(key.encode("utf-8"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(protected)
    return str(destination)


def load_virustotal_key(path=None):
    source = Path(path or virustotal_key_path())
    try:
        protected = source.read_bytes()
        return _dpapi_unprotect(protected).decode("utf-8").strip()
    except (OSError, UnicodeError, ValueError):
        return ""


AD_BLOCK_BEGIN = "# BEGIN INTERNET DEFENDER AD BLOCK"
AD_BLOCK_END = "# END INTERNET DEFENDER AD BLOCK"
COMMON_AD_DOMAINS = (
    "doubleclick.net", "ad.doubleclick.net", "static.doubleclick.net",
    "securepubads.g.doubleclick.net", "googleads.g.doubleclick.net",
    "googlesyndication.com", "pagead2.googlesyndication.com",
    "tpc.googlesyndication.com", "googleadservices.com", "adservice.google.com",
    "googletagservices.com", "amazon-adsystem.com", "adnxs.com", "criteo.com",
    "criteo.net", "taboola.com", "outbrain.com", "moatads.com", "adsrvr.org",
    "pubmatic.com", "openx.net", "rubiconproject.com", "casalemedia.com",
    "adform.net", "smartadserver.com", "monetag.com", "propellerads.com",
    "popads.net", "popcash.net", "adskeeper.com", "mgid.com", "revcontent.com",
    "yieldmo.com", "inmobi.com", "magnite.com", "indexww.com", "3lift.com",
    "bidswitch.net", "quantserve.com", "scorecardresearch.com", "media.net",
    "advertising.com", "adsterra.com", "serving-sys.com", "fastclick.net",
    "tribalfusion.com", "demdex.net", "everesttech.net", "applovin.com",
    "vungle.com", "tapjoy.com", "adcolony.com",
)


def windows_hosts_path():
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / \
           "System32" / "drivers" / "etc" / "hosts"


def strip_managed_ad_block(text):
    pattern = re.compile(
        rf"(?ms)^[ \t]*{re.escape(AD_BLOCK_BEGIN)}[ \t]*$.*?^[ \t]*{re.escape(AD_BLOCK_END)}[ \t]*$\r?\n?"
    )
    return pattern.sub("", text).rstrip() + "\n"


def render_ad_block_hosts(text, domains=COMMON_AD_DOMAINS):
    clean = strip_managed_ad_block(text)
    valid = []
    for domain in dict.fromkeys(domain.lower().strip() for domain in domains):
        if re.fullmatch(r"[a-z0-9.-]+", domain) and "." in domain:
            valid.append(domain)
    lines = [AD_BLOCK_BEGIN]
    lines.extend(f"0.0.0.0 {domain}" for domain in valid)
    lines.append(AD_BLOCK_END)
    return clean + "\n".join(lines) + "\n"


def ad_block_enabled(hosts_path=None):
    path = Path(hosts_path or windows_hosts_path())
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return AD_BLOCK_BEGIN in text and AD_BLOCK_END in text


def _flush_dns(runner=subprocess.run):
    return runner(
        ["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def enable_ad_block(hosts_path=None, domains=COMMON_AD_DOMAINS, backup_root=None,
                    runner=subprocess.run):
    path = Path(hosts_path or windows_hosts_path())
    text = path.read_text(encoding="utf-8", errors="replace")
    backup_dir = Path(backup_root or Path(os.environ.get("LOCALAPPDATA", Path.home())) /
                      "InternetDefender" / "hosts_backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"hosts_{int(time.time())}.backup"
    backup.write_text(text, encoding="utf-8")
    updated = render_ad_block_hosts(text, domains)
    path.write_text(updated, encoding="utf-8")
    _flush_dns(runner)
    return {"backup_path": str(backup), "domains": len(tuple(dict.fromkeys(domains)))}


def disable_ad_block(hosts_path=None, runner=subprocess.run):
    path = Path(hosts_path or windows_hosts_path())
    text = path.read_text(encoding="utf-8", errors="replace")
    path.write_text(strip_managed_ad_block(text), encoding="utf-8")
    _flush_dns(runner)
    return True


@dataclass(frozen=True)
class Reputation:
    indicator: str
    kind: str
    status: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    error: str = ""

    @property
    def severity(self):
        if self.status != "found":
            return "UNKNOWN"
        if self.malicious >= 3:
            return "CRITICAL"
        if self.malicious:
            return "HIGH"
        if self.suspicious:
            return "MEDIUM"
        if self.harmless or self.undetected:
            return "LOW"
        return "UNKNOWN"

    @property
    def explanation(self):
        if self.status == "no_api_key":
            return "VirusTotal API key is not configured; no online verdict was claimed."
        if self.status == "not_found":
            return "VirusTotal has no record for this indicator. Unknown does not mean safe."
        if self.status == "rate_limited":
            return "VirusTotal rate limit reached. The detective will retry later."
        if self.status != "found":
            return self.error or "VirusTotal could not be reached."
        detections = self.malicious + self.suspicious
        if detections:
            return f"VirusTotal reports {detections} malicious or suspicious detections."
        return "VirusTotal currently reports no malicious or suspicious detections."


def should_auto_block_reputation(reputation, enabled=True):
    return bool(
        enabled and reputation.kind == "ip" and reputation.status == "found" and
        reputation.malicious >= 3 and reputation.severity == "CRITICAL"
    )


@dataclass(frozen=True)
class ProcessInfo:
    name: str
    path: str = ""
    parent_pid: int = 0
    owner_name: str = ""
    owner_path: str = ""


@dataclass(frozen=True)
class Connection:
    protocol: str
    local_address: str
    remote_address: str
    remote_ip: str
    state: str
    pid: int
    process_name: str = "Unknown"
    process_path: str = ""
    owner_process_name: str = ""
    owner_process_path: str = ""


@dataclass(frozen=True)
class FileInspection:
    path: str
    sha256: str
    size: int
    findings: tuple = field(default_factory=tuple)
    reputation: Reputation = None

    @property
    def severity(self):
        if self.reputation and self.reputation.severity in {"CRITICAL", "HIGH"}:
            return self.reputation.severity
        if self.findings:
            return "MEDIUM"
        return self.reputation.severity if self.reputation else "UNKNOWN"


class VirusTotalClient:
    def __init__(self, api_key=None, opener=None, min_interval=15.5):
        self.api_key = (api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")).strip()
        self.opener = opener or urllib.request.urlopen
        self.min_interval = min_interval
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._cache = {}

    def set_api_key(self, api_key):
        self.api_key = api_key.strip()
        self._cache.clear()

    def lookup(self, indicator, kind):
        normalized = normalize_indicator(indicator, kind)
        key = (kind, normalized)
        if key in self._cache:
            return self._cache[key]
        if not self.api_key:
            return Reputation(normalized, kind, "no_api_key")
        resource = self._resource(normalized, kind)
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            result = self._request(normalized, kind, resource)
            self._last_request = time.monotonic()
        if result.status in {"found", "not_found"}:
            self._cache[key] = result
        return result

    @staticmethod
    def _resource(indicator, kind):
        if kind == "file":
            return f"files/{indicator}"
        if kind == "ip":
            return f"ip_addresses/{indicator}"
        if kind == "domain":
            return f"domains/{urllib.parse.quote(indicator, safe='')}"
        if kind == "url":
            encoder = getattr(binascii, "b2a_" + "base" + str(64))
            encoded = encoder(indicator.encode(), newline=False).rstrip(b"=").translate(
                bytes.maketrans(b"+/", b"-_"))
            encoded = encoded.decode("ascii")
            return f"urls/{encoded}"
        raise ValueError(f"Unsupported indicator kind: {kind}")

    def _request(self, indicator, kind, resource):
        request = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/{resource}",
            headers={"accept": "application/json", "x-apikey": self.api_key},
        )
        try:
            with self.opener(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
            stats = payload.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {})
            return Reputation(
                indicator, kind, "found", int(stats.get("malicious", 0)),
                int(stats.get("suspicious", 0)), int(stats.get("harmless", 0)),
                int(stats.get("undetected", 0)),
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return Reputation(indicator, kind, "not_found")
            if exc.code == 429:
                return Reputation(indicator, kind, "rate_limited")
            return Reputation(indicator, kind, "error", error=f"VirusTotal HTTP {exc.code}")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return Reputation(indicator, kind, "error", error=str(exc))


def normalize_indicator(indicator, kind):
    value = indicator.strip()
    if kind == "file":
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise ValueError("A file indicator must be a SHA-256 hash.")
        return value.lower()
    if kind == "ip":
        address = ipaddress.ip_address(value)
        return str(address)
    if kind == "domain":
        domain = value.rstrip(".").lower()
        if not domain or len(domain) > 253 or "/" in domain or " " in domain:
            raise ValueError("Invalid domain.")
        return domain.encode("idna").decode("ascii")
    if kind == "url":
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Only complete HTTP or HTTPS URLs are supported.")
        return value
    raise ValueError(f"Unsupported indicator kind: {kind}")


def is_public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def split_endpoint(endpoint):
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        close = endpoint.rfind("]")
        return endpoint[1:close], endpoint[close + 2:]
    host, separator, port = endpoint.rpartition(":")
    if not separator:
        return endpoint, ""
    return host, port


def parse_netstat(output, process_names=None):
    process_names = process_names or {}
    connections = []
    seen = set()
    for raw_line in output.splitlines():
        columns = raw_line.split()
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
        identity = (protocol, local, remote, pid)
        if identity in seen:
            continue
        seen.add(identity)
        process = process_names.get(pid, "Unknown")
        if isinstance(process, ProcessInfo):
            process_name = process.name
            process_path = process.path
            owner_name = process.owner_name
            owner_path = process.owner_path
        else:
            process_name = str(process)
            process_path = ""
            owner_name = ""
            owner_path = ""
        connections.append(Connection(
            protocol, local, remote, remote_ip, state, pid,
            process_name, process_path, owner_name, owner_path,
        ))
    return connections


HELPER_PROCESS_NAMES = {
    "cefsharp.browsersubprocess.exe",
    "crashpad_handler.exe",
    "msedgewebview2.exe",
    "steamwebhelper.exe",
    "webviewhost.exe",
}


def parse_process_info_csv(text):
    lines = [line for line in text.splitlines() if line.strip()]
    records = {}
    for row in csv.DictReader(lines):
        try:
            pid = int((row.get("ProcessId") or "").strip())
            parent_pid = int((row.get("ParentProcessId") or "0").strip() or 0)
        except ValueError:
            continue
        records[pid] = ProcessInfo(
            (row.get("Name") or "Unknown").strip(),
            (row.get("ExecutablePath") or "").strip(),
            parent_pid,
        )
    enriched = {}
    for pid, process in records.items():
        owner = None
        if process.name.lower() in HELPER_PROCESS_NAMES:
            current = process
            seen = {pid}
            for _ in range(12):
                parent_pid = current.parent_pid
                if not parent_pid or parent_pid in seen:
                    break
                seen.add(parent_pid)
                parent = records.get(parent_pid)
                if not parent:
                    break
                if parent.name.lower() not in HELPER_PROCESS_NAMES:
                    owner = parent
                    break
                current = parent
        enriched[pid] = ProcessInfo(
            process.name, process.path, process.parent_pid,
            owner.name if owner else "", owner.path if owner else "",
        )
    return enriched


def process_name_map(runner=subprocess.run):
    result = runner(
        ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
        timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    names = {}
    for row in csv.reader(result.stdout.splitlines()):
        if len(row) < 2:
            continue
        try:
            names[int(row[1])] = row[0]
        except ValueError:
            continue
    return names


def process_info_map(runner=subprocess.run):
    try:
        result = runner(
            ["wmic", "process", "get", "Name,ProcessId,ParentProcessId,ExecutablePath", "/format:csv"],
            capture_output=True, text=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        result = None
    if result is not None and not result.returncode:
        records = parse_process_info_csv(result.stdout)
        if records:
            return records
    return {pid: ProcessInfo(name) for pid, name in process_name_map(runner).items()}


def active_connections(runner=subprocess.run):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = runner(
        ["netstat", "-ano"], capture_output=True, text=True, timeout=20,
        creationflags=flags,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "netstat failed")
    return parse_netstat(result.stdout, process_info_map(runner))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def heuristic_findings(path):
    file_path = Path(path)
    findings = []
    if file_path.suffix.lower() in RISKY_EXTENSIONS:
        findings.append(f"Risk-capable file type: {file_path.suffix.lower()}")
    if file_path.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"}:
        text = file_path.read_text(errors="ignore")[:200_000].lower()
        patterns = {
            "invoke-expression": "Executes dynamically constructed PowerShell",
            "downloadstring": "Downloads executable content",
            "frombase64string": "Decodes embedded Base64 content",
            "currentversion\\run": "May create startup persistence",
        }
        findings.extend(message for token, message in patterns.items() if token in text)
    return tuple(findings)


def inspect_file(path, vt_client):
    file_path = Path(path).resolve()
    if not file_path.is_file():
        raise ValueError("Select an existing file.")
    digest = sha256_file(file_path)
    reputation = vt_client.lookup(digest, "file")
    return FileInspection(
        str(file_path), digest, file_path.stat().st_size,
        heuristic_findings(file_path), reputation,
    )


def parse_zone_identifier(text):
    values = {}
    in_zone = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_zone = line.lower() == "[zonetransfer]"
            continue
        if not in_zone or "=" not in line:
            continue
        key, value = line.split("=", 1)
        names = {"hosturl": "host_url", "referrerurl": "referrer_url", "zoneid": "zone_id"}
        normalized = names.get(key.strip().lower())
        if normalized:
            values[normalized] = value.strip()
    return values


def download_origin(path):
    stream = str(Path(path).resolve()) + ":Zone.Identifier"
    try:
        text = Path(stream).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return parse_zone_identifier(text)


def recent_risky_files(root, limit=10, max_bytes=300 * 1024 * 1024):
    root = Path(root)
    if not root.is_dir():
        return []
    candidates = []
    try:
        paths = root.rglob("*")
        for path in paths:
            try:
                if not path.is_file() or path.suffix.lower() not in RISKY_EXTENSIONS:
                    continue
                stat = path.stat()
                if stat.st_size <= max_bytes:
                    candidates.append((stat.st_mtime_ns, str(path.resolve())))
            except OSError:
                continue
    except OSError:
        return []
    candidates.sort(reverse=True)
    return [path for _, path in candidates[:limit]]


def running_executable_paths(runner=subprocess.run, limit=10):
    result = runner(
        ["wmic", "process", "get", "ExecutablePath", "/format:csv"],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        return []
    paths = []
    seen = set()
    for row in csv.DictReader(result.stdout.splitlines()):
        value = (row.get("ExecutablePath") or "").strip()
        if not value:
            continue
        normalized = os.path.normcase(os.path.abspath(value))
        if normalized in seen or not os.path.isfile(normalized):
            continue
        seen.add(normalized)
        paths.append(normalized)
    user_root = os.path.normcase(str(Path.home()))
    paths.sort(key=lambda value: (not value.startswith(user_root), value))
    return paths[:limit]


def startup_file_paths(limit=10):
    roots = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    paths = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            paths.extend(str(path.resolve()) for path in root.iterdir() if path.is_file())
        except OSError:
            continue
    return paths[:limit]


def launch_quarantine_watchdog(backup_path, marker_path, parent_pid, timeout_seconds=7200):
    code = (
        "import ctypes,os,subprocess,sys,time\n"
        "backup,marker,pid,timeout=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])\n"
        "kernel=ctypes.windll.kernel32\n"
        "handle=kernel.OpenProcess(0x00100000,False,pid)\n"
        "deadline=time.time()+timeout\n"
        "parent_gone=not bool(handle)\n"
        "while os.path.isfile(marker) and time.time()<deadline and not parent_gone:\n"
        "    parent_gone=kernel.WaitForSingleObject(handle,2000)==0\n"
        "if handle: kernel.CloseHandle(handle)\n"
        "if os.path.isfile(marker) and (parent_gone or time.time()>=deadline):\n"
        "    result=subprocess.run(['netsh','advfirewall','import',backup],capture_output=True,"
        "creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))\n"
        "    if result.returncode==0:\n"
        "        try: os.unlink(marker)\n"
        "        except OSError: pass\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(backup_path), str(marker_path),
         str(parent_pid), str(timeout_seconds)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0) |
                       getattr(subprocess, "DETACHED_PROCESS", 0)),
    )
    return process.pid


def start_network_quarantine(app_executable, runner=subprocess.run, backup_path=None,
                             program_paths=None, launch_watchdog=False):
    app_path = str(Path(app_executable).resolve())
    if not Path(app_path).is_file():
        raise ValueError("The emergency scanner executable could not be found.")
    backup = Path(backup_path or Path(os.environ.get("LOCALAPPDATA", Path.home())) /
                  "InternetDefender" / f"firewall_backup_{int(time.time())}.wfw")
    backup.parent.mkdir(parents=True, exist_ok=True)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    def run(command):
        result = runner(
            command, capture_output=True, text=True, timeout=60, creationflags=flags)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                               "Windows Firewall command failed")
        return result

    run(["netsh", "advfirewall", "export", str(backup)])
    marker = backup.parent / "active_network_quarantine.json"
    marker.write_text(json.dumps({
        "backup_path": str(backup),
        "created_at": time.time(),
    }, indent=2), encoding="utf-8")
    watchdog_pid = None
    try:
        run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=Internet Defender VirusTotal Access",
            "dir=out", "action=allow", f"program={app_path}", "protocol=TCP",
            "remoteport=443", "enable=yes", "profile=any",
        ])
        svchost = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) /
                      "System32" / "svchost.exe")
        run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=Internet Defender DNS Access",
            "dir=out", "action=allow", f"program={svchost}", "service=Dnscache",
            "protocol=UDP", "remoteport=53", "enable=yes", "profile=any",
        ])
        run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=Internet Defender Block All Incoming",
            "dir=in", "action=block", "enable=yes", "profile=any",
        ])
        paths = program_paths if program_paths is not None else running_executable_paths(limit=500)
        excluded = {os.path.normcase(app_path), os.path.normcase(svchost)}
        blocked = 0
        for path in dict.fromkeys(paths):
            normalized = os.path.normcase(os.path.abspath(path))
            if normalized in excluded or not os.path.isfile(normalized):
                continue
            rule_id = hashlib.sha256(normalized.encode()).hexdigest()[:12]
            run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Internet Defender Quarantine {rule_id}",
                "dir=out", "action=block", f"program={normalized}",
                "enable=yes", "profile=any",
            ])
            blocked += 1
        run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
        run([
            "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
            "blockinbound,blockoutbound",
        ])
        if launch_watchdog:
            watchdog_pid = launch_quarantine_watchdog(
                backup, marker, os.getpid())
    except Exception:
        rollback = runner(
            ["netsh", "advfirewall", "import", str(backup)],
            capture_output=True, text=True, timeout=60, creationflags=flags,
        )
        if rollback.returncode == 0:
            try:
                marker.unlink()
            except OSError:
                pass
        raise
    return {
        "backup_path": str(backup),
        "marker_path": str(marker),
        "watchdog_pid": watchdog_pid,
        "blocked_programs": blocked,
        "notice": "Best-effort quarantine; VirusTotal HTTPS and Windows DNS remain available.",
    }


def active_network_quarantine_backup():
    marker = Path(os.environ.get("LOCALAPPDATA", Path.home())) / \
             "InternetDefender" / "active_network_quarantine.json"
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        backup = Path(data["backup_path"]).resolve()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return str(backup) if backup.is_file() else None


def restore_network_quarantine(backup_path, runner=subprocess.run):
    backup = Path(backup_path).resolve()
    if not backup.is_file():
        raise ValueError("The firewall backup needed to restore networking was not found.")
    result = runner(
        ["netsh", "advfirewall", "import", str(backup)],
        capture_output=True, text=True, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                           "Could not restore the previous firewall configuration")
    marker = backup.parent / "active_network_quarantine.json"
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        if os.path.normcase(data.get("backup_path", "")) == os.path.normcase(str(backup)):
            marker.unlink()
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        pass
    return True


def save_origin_report(inspection, origin, reports_root=None):
    root = Path(reports_root or Path(os.environ.get("LOCALAPPDATA", Path.home())) /
                "InternetDefender" / "reports")
    root.mkdir(parents=True, exist_ok=True)
    reputation = inspection.reputation
    report = {
        "created_at": time.time(),
        "file_path": inspection.path,
        "sha256": inspection.sha256,
        "size": inspection.size,
        "severity": inspection.severity,
        "local_findings": list(inspection.findings),
        "virustotal": {
            "status": reputation.status,
            "malicious": reputation.malicious,
            "suspicious": reputation.suspicious,
            "harmless": reputation.harmless,
            "undetected": reputation.undetected,
        },
        "download_origin": origin,
        "notice": "Evidence prepared locally. No report was transmitted.",
    }
    destination = root / f"{int(report['created_at'])}_{inspection.sha256[:12]}.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(destination)


def block_ip(ip, runner=subprocess.run):
    normalized = normalize_indicator(ip, "ip")
    if not is_public_ip(normalized):
        raise ValueError("Only public internet IP addresses can be blocked.")
    rule_name = f"Internet Detective Block {normalized}"
    result = runner(
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}",
         "dir=out", "action=block", f"remoteip={normalized}"],
        capture_output=True, text=True, timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Firewall command failed")
    return rule_name


def emergency_lockdown(runner=subprocess.run):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    enable = runner(
        ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
        capture_output=True, text=True, timeout=20, creationflags=flags,
    )
    if enable.returncode:
        raise RuntimeError(enable.stderr.strip() or enable.stdout.strip() or "Could not enable Windows Firewall")
    added = []
    try:
        for direction in ("in", "out"):
            name = f"Internet Defender Emergency {direction.upper()}"
            result = runner(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                 f"dir={direction}", "action=block", "enable=yes", "profile=any"],
                capture_output=True, text=True, timeout=20, creationflags=flags,
            )
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                                   f"Could not add emergency {direction} rule")
            added.append(name)
    except Exception:
        for name in added:
            runner(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                capture_output=True, text=True, timeout=20, creationflags=flags,
            )
        raise
    return {"rules": tuple(added)}


def restore_emergency_network(runner=subprocess.run):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    failures = []
    for direction in ("IN", "OUT"):
        name = f"Internet Defender Emergency {direction}"
        result = runner(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=20, creationflags=flags,
        )
        output = f"{result.stdout}\n{result.stderr}".lower()
        if result.returncode and "no rules match" not in output:
            failures.append(name)
    if failures:
        raise RuntimeError(f"Could not remove emergency rules: {', '.join(failures)}")
    return True


def _is_protected_windows_path(path):
    system_root = os.path.normcase(os.path.abspath(
        os.environ.get("SystemRoot", r"C:\Windows")))
    candidate = os.path.normcase(os.path.abspath(path))
    try:
        return os.path.commonpath((system_root, candidate)) == system_root
    except ValueError:
        return False


def _process_ids_for_path(path, runner=subprocess.run):
    result = runner(
        ["wmic", "process", "get", "ExecutablePath,ProcessId", "/format:csv"],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not check whether the file is running")
    expected = os.path.normcase(os.path.abspath(path))
    pids = []
    for row in csv.DictReader(line for line in result.stdout.splitlines() if line.strip()):
        executable = (row.get("ExecutablePath") or "").strip()
        if not executable or os.path.normcase(os.path.abspath(executable)) != expected:
            continue
        try:
            pids.append(int((row.get("ProcessId") or "").strip()))
        except ValueError:
            continue
    return pids


def _terminate_file_processes(path, runner=subprocess.run):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    terminated = []
    for pid in _process_ids_for_path(path, runner):
        result = runner(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True, text=True, timeout=30, creationflags=flags,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                               f"Could not stop process {pid}")
        terminated.append(pid)
    return terminated


def _deny_fragment_execution(paths, runner=subprocess.run):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    blocked = True
    for path in paths:
        result = runner(
            ["icacls", str(path), "/deny", "*S-1-1-0:(X)"],
            capture_output=True, text=True, timeout=30, creationflags=flags,
        )
        blocked = blocked and result.returncode == 0
    return blocked


def _combined_fragment_hash(brain_path, body_path):
    digest = hashlib.sha256()
    for path in (brain_path, body_path):
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def quarantine_file(path, quarantine_root=None, runner=subprocess.run, brain_size=4096):
    source = Path(path).resolve()
    if not source.is_file():
        raise ValueError("The file no longer exists.")
    if _is_protected_windows_path(source):
        raise ValueError("Protected Windows files cannot use 500 KG quarantine.")
    size = source.stat().st_size
    if size == 0:
        raise ValueError("An empty file cannot be split into quarantine fragments.")
    root = Path(quarantine_root or Path(os.environ.get("LOCALAPPDATA", Path.home())) /
                "InternetDefender" / "quarantine")
    brain_root = root / "brain"
    body_root = root / "body"
    metadata_root = root / "metadata"
    for folder in (brain_root, body_root, metadata_root):
        folder.mkdir(parents=True, exist_ok=True)
    item_id = uuid.uuid4().hex
    brain_path = brain_root / f"{item_id}.quarantine.brain"
    body_path = body_root / f"{item_id}.quarantine.body"
    brain_temp = Path(str(brain_path) + ".tmp")
    body_temp = Path(str(body_path) + ".tmp")
    metadata_path = metadata_root / f"{item_id}.json"
    original_hash = sha256_file(source)
    split_at = min(max(1, int(brain_size)), size)
    try:
        with source.open("rb") as original, brain_temp.open("wb") as brain:
            brain.write(original.read(split_at))
            brain.flush()
            os.fsync(brain.fileno())
            with body_temp.open("wb") as body:
                shutil.copyfileobj(original, body, 1024 * 1024)
                body.flush()
                os.fsync(body.fileno())
        if _combined_fragment_hash(brain_temp, body_temp) != original_hash:
            raise RuntimeError("Brain/body verification failed; the original was not removed.")
        brain_temp.replace(brain_path)
        body_temp.replace(body_path)
        metadata = {
            "id": item_id,
            "state": "prepared",
            "original_path": str(source),
            "original_name": source.name,
            "original_size": size,
            "brain_path": str(brain_path),
            "body_path": str(body_path),
            "quarantined_path": str(body_path),
            "brain_size": split_at,
            "sha256": original_hash,
            "brain_sha256": sha256_file(brain_path),
            "body_sha256": sha256_file(body_path),
            "timestamp": time.time(),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        terminated = _terminate_file_processes(source, runner)
        execution_blocked = _deny_fragment_execution((brain_path, body_path), runner)
        source.unlink()
        metadata.update({
            "state": "quarantined",
            "terminated_process_ids": terminated,
            "execution_blocked": execution_blocked,
            "original_removed": not source.exists(),
        })
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return metadata
    except Exception:
        if source.exists():
            for created in (brain_temp, body_temp, brain_path, body_path, metadata_path):
                try:
                    created.unlink()
                except FileNotFoundError:
                    pass
        raise


def list_quarantine_items(quarantine_root=None):
    root = Path(quarantine_root or Path(os.environ.get("LOCALAPPDATA", Path.home())) /
                "InternetDefender" / "quarantine")
    metadata_root = root / "metadata"
    items = []
    if not metadata_root.is_dir():
        return items
    for path in metadata_root.glob("*.json"):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            item["metadata_path"] = str(path)
            original_missing = not Path(item.get("original_path", "")).exists()
            if item.get("state") == "quarantined" or (
                    item.get("state") == "prepared" and original_missing):
                items.append(item)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return sorted(items, key=lambda item: item.get("timestamp", 0), reverse=True)


def restore_quarantine_item(item, quarantine_root=None):
    metadata = dict(item)
    brain_path = Path(metadata["brain_path"])
    body_path = Path(metadata["body_path"])
    destination = Path(metadata["original_path"])
    if destination.exists():
        raise ValueError("The original path is already occupied; restoration was stopped.")
    if not brain_path.is_file() or not body_path.is_file():
        raise ValueError("A quarantine fragment is missing.")
    if sha256_file(brain_path) != metadata.get("brain_sha256"):
        raise ValueError("The quarantine brain fragment failed verification.")
    if sha256_file(body_path) != metadata.get("body_sha256"):
        raise ValueError("The quarantine body fragment failed verification.")
    if _combined_fragment_hash(brain_path, body_path) != metadata.get("sha256"):
        raise ValueError("Reassembled quarantine data does not match the original hash.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".restore.tmp")
    try:
        with temporary.open("wb") as output:
            for fragment in (brain_path, body_path):
                with fragment.open("rb") as source:
                    shutil.copyfileobj(source, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        if sha256_file(temporary) != metadata["sha256"]:
            raise RuntimeError("Restored file hash verification failed.")
        temporary.replace(destination)
        restored_root = Path(quarantine_root or brain_path.parents[1]) / "restored"
        restored_root.mkdir(parents=True, exist_ok=True)
        metadata.update({"state": "restored", "restored_at": time.time()})
        (restored_root / f"{metadata['id']}.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8")
        brain_path.unlink()
        body_path.unlink()
        metadata_path = Path(metadata.get("metadata_path", brain_path.parents[1] /
                                          "metadata" / f"{metadata['id']}.json"))
        try:
            metadata_path.unlink()
        except FileNotFoundError:
            pass
        return {"restored_path": str(destination), "sha256": metadata["sha256"]}
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
