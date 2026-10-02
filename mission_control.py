import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defender_core import block_ip, download_origin, inspect_file, quarantine_file
from local_detective_core import (
    Finding,
    RemoteAccessFinding,
    active_connections,
    connection_program_name,
    collect_startup_items,
    detect_remote_access,
    disconnect_remote_access,
    findings_from_security_events,
    inspect_local_file,
    running_processes,
    security_events,
)


@dataclass(frozen=True)
class OperationCard:
    id: str
    source: str
    severity: str
    title: str
    subject: str
    program_name: str = ""
    pid: int = 0
    file_path: str = ""
    remote_ip: str = ""
    remote_address: str = ""
    activity: str = ""
    explanation: str = ""
    status: str = "NEW"


@dataclass(frozen=True)
class TimelineEvent:
    stage: str
    state: str
    details: str


@dataclass(frozen=True)
class InvestigationResult:
    card: OperationCard
    executable_path: str
    program_running: bool
    startup_matches: tuple
    download_source: str
    online_file_severity: str
    online_file_explanation: str
    local_file_severity: str
    local_file_reasons: tuple
    remote_access_findings: tuple
    account_clues: tuple
    timeline: tuple
    verdict: str
    verdict_explanation: str
    confirmed: bool
    destination_confirmed: bool
    file_confirmed: bool


@dataclass(frozen=True)
class ContainmentResult:
    card_id: str
    actions: tuple
    verification: dict
    area_secured: bool
    report_path: str
    quarantine_metadata: dict


def card_from_connection(connection, reputation=None, anomaly=None):
    severity = "UNKNOWN"
    explanations = []
    display_name = connection_program_name(connection)
    if reputation:
        severity = reputation.severity
        explanations.append(reputation.explanation)
    if anomaly:
        order = {"INFO": 0, "LOW": 1, "UNKNOWN": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(anomaly.severity, 0) > order.get(severity, 0):
            severity = anomaly.severity
        explanations.append(anomaly.explanation)
    return OperationCard(
        uuid.uuid4().hex,
        "INTERNET DETECTIVE",
        severity,
        f"Investigate internet activity from {display_name}",
        display_name,
        connection.process_name,
        connection.pid,
        getattr(connection, "process_path", ""),
        connection.remote_ip,
        connection.remote_address,
        getattr(connection, "activity", "") or "Active internet connection",
        "; ".join(explanations) or "New public internet connection observed.",
    )


def card_from_file(inspection, local_assessment=None):
    order = {"INFO": 0, "LOW": 1, "UNKNOWN": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    severities = [inspection.severity]
    explanations = [inspection.reputation.explanation]
    if local_assessment:
        severities.append(local_assessment.severity)
        explanations.extend(local_assessment.reasons)
    severity = max(severities, key=lambda value: order.get(value, 0))
    return OperationCard(
        uuid.uuid4().hex,
        "MINISTRY OF SCIENCE",
        severity,
        f"Investigate sample {Path(inspection.path).name}",
        inspection.path,
        file_path=inspection.path,
        explanation="; ".join(explanations),
    )


def card_from_local_finding(finding):
    path = finding.subject if finding.category in {"FILE", "RUNNING PROGRAM"} else ""
    return OperationCard(
        uuid.uuid4().hex,
        "LOCAL DETECTIVE",
        finding.severity,
        finding.title,
        finding.subject,
        file_path=path if Path(path).is_file() else "",
        explanation=finding.explanation,
    )


def card_from_remote_access(finding):
    subject = finding.process_path or finding.username or finding.tool
    return OperationCard(
        uuid.uuid4().hex,
        "REMOTE ACCESS CHECK",
        "MEDIUM",
        f"Review remote access: {finding.tool}",
        subject,
        finding.tool,
        finding.identifier if finding.kind == "process" else 0,
        finding.process_path,
        explanation=finding.explanation,
    )


def _find_process(card, processes):
    if card.pid:
        match = next((process for process in processes if process.pid == card.pid), None)
        if match:
            return match
    if card.file_path:
        expected = os.path.normcase(os.path.abspath(card.file_path))
        return next((
            process for process in processes
            if process.path and os.path.normcase(os.path.abspath(process.path)) == expected
        ), None)
    if card.program_name:
        return next((
            process for process in processes
            if process.name.lower() == card.program_name.lower()
        ), None)
    return None


def _startup_matches(path, startup_items):
    if not path:
        return ()
    normalized = os.path.normcase(os.path.abspath(path))
    name = Path(path).name.lower()
    matches = []
    for item in startup_items:
        command = os.path.normcase(item.command)
        if normalized in command or (name and name in command.lower()):
            matches.append(f"{item.location}: {item.name} -> {item.command}")
    return tuple(matches)


def investigate_operation(card, vt_client, progress=None, runner=None):
    notify = progress or (lambda _text: None)
    kwargs = {"runner": runner} if runner else {}
    notify("Identifying the program behind the operation")
    processes = running_processes(**kwargs)
    process = _find_process(card, processes)
    executable_path = card.file_path or (process.path if process else "")
    program_running = bool(process)
    notify("Inspecting the executable through Sample Lab")
    online_inspection = None
    local_assessment = None
    if executable_path and Path(executable_path).is_file():
        online_inspection = inspect_file(executable_path, vt_client)
        local_assessment = inspect_local_file(executable_path, **kwargs)
    notify("Checking whether it starts with Windows")
    startup_items = collect_startup_items()
    startup_matches = _startup_matches(executable_path, startup_items)
    notify("Finding the original download source")
    origin = download_origin(executable_path) if executable_path else {}
    download_source = origin.get("host_url") or origin.get("referrer_url") or "Origin metadata unavailable"
    notify("Checking related remote-access clues")
    connections = active_connections(**kwargs)
    remote_findings = tuple(
        finding for finding in detect_remote_access(processes, connections, **kwargs)
        if ((process and finding.kind == "process" and finding.identifier == process.pid) or
            (card.source == "REMOTE ACCESS CHECK" and finding.kind == "rdp_session" and
             (finding.username == card.subject or finding.tool in card.title)))
    )
    notify("Checking account-theft and Windows login clues")
    try:
        account_clues = tuple(
            finding for finding in findings_from_security_events(security_events(**kwargs))
            if finding.severity in {"HIGH", "CRITICAL"}
        )
    except Exception:
        account_clues = ()
    timeline = []
    if executable_path:
        if Path(executable_path).is_file():
            created = time.ctime(Path(executable_path).stat().st_ctime)
            timeline.append(TimelineEvent("Downloaded file", "OBSERVED", f"{download_source} | Created {created}"))
        else:
            timeline.append(TimelineEvent("Downloaded file", "MISSING", download_source))
    else:
        timeline.append(TimelineEvent("Downloaded file", "UNKNOWN", "No executable path was identified"))
    timeline.append(TimelineEvent(
        "Program started", "OBSERVED" if program_running else "NOT CURRENTLY RUNNING",
        process.name if process else card.program_name or "Program not identified",
    ))
    timeline.append(TimelineEvent(
        "Startup change", "OBSERVED" if startup_matches else "NOT OBSERVED",
        " | ".join(startup_matches) if startup_matches else "No matching startup entry found",
    ))
    timeline.append(TimelineEvent(
        "Internet connection", "OBSERVED" if card.remote_ip else "NOT OBSERVED",
        card.activity or ("An active destination was observed" if card.remote_ip else "No related destination recorded"),
    ))
    online_severity = online_inspection.reputation.severity if online_inspection else "UNKNOWN"
    online_explanation = (
        online_inspection.reputation.explanation if online_inspection
        else "No file was available for online hash reputation."
    )
    local_severity = local_assessment.severity if local_assessment else "UNKNOWN"
    local_reasons = local_assessment.reasons if local_assessment else ()
    destination_confirmed = card.severity in {"HIGH", "CRITICAL"} and bool(card.remote_ip)
    file_confirmed = bool(
        online_inspection and online_inspection.reputation.severity in {"HIGH", "CRITICAL"})
    signature_invalid = bool(
        local_assessment and local_assessment.signature in {"HashMismatch", "NotTrusted"})
    file_confirmed = file_confirmed or signature_invalid
    confirmed = destination_confirmed or file_confirmed
    suspicious = bool(
        local_assessment and local_assessment.severity in {"MEDIUM", "HIGH", "CRITICAL"}) or \
        bool(startup_matches) or bool(remote_findings) or bool(account_clues)
    if confirmed:
        verdict = "CONFIRMED THREAT"
        reasons = []
        if destination_confirmed:
            reasons.append("The destination has a HIGH or CRITICAL reputation result")
        if file_confirmed:
            reasons.append("The file has confirmed malicious reputation or an invalid signature")
        verdict_explanation = "; ".join(reasons) + "."
    elif suspicious:
        verdict = "SUSPICIOUS — NOT CONFIRMED"
        verdict_explanation = (
            "Local behavior, startup, remote-access, or login clues need review, but confirmation is insufficient."
        )
    else:
        verdict = "UNKNOWN / LOW EVIDENCE"
        verdict_explanation = (
            "No confirming evidence was found. Unknown results are not treated as clean or safe."
        )
    investigated_card = replace(
        card, status="INVESTIGATED",
        pid=process.pid if process else card.pid,
        program_name=process.name if process else card.program_name,
        file_path=executable_path,
    )
    return InvestigationResult(
        investigated_card, executable_path, program_running,
        startup_matches, download_source, online_severity, online_explanation,
        local_severity, local_reasons, remote_findings, account_clues,
        tuple(timeline), verdict, verdict_explanation, confirmed,
        destination_confirmed, file_confirmed,
    )


def _mission_report_root(root=None):
    return Path(root or Path(os.environ.get("LOCALAPPDATA", Path.home())) /
                "InternetDefender" / "mission_reports")


def save_mission_report(investigation, actions, verification, root=None):
    report_root = _mission_report_root(root)
    report_root.mkdir(parents=True, exist_ok=True)
    report = {
        "created_at": time.time(),
        "notice": (
            "Local evidence only. This report does not identify a person and was not submitted automatically."
        ),
        "operation": asdict(investigation.card),
        "timeline": [asdict(event) for event in investigation.timeline],
        "verdict": investigation.verdict,
        "verdict_explanation": investigation.verdict_explanation,
        "evidence": {
            "executable_path": investigation.executable_path,
            "program_running": investigation.program_running,
            "startup_matches": list(investigation.startup_matches),
            "download_source": investigation.download_source,
            "online_file_severity": investigation.online_file_severity,
            "online_file_explanation": investigation.online_file_explanation,
            "local_file_severity": investigation.local_file_severity,
            "local_file_reasons": list(investigation.local_file_reasons),
            "remote_access_findings": [asdict(item) for item in investigation.remote_access_findings],
            "account_clues": [asdict(item) for item in investigation.account_clues],
        },
        "containment_actions": list(actions),
        "verification": verification,
    }
    path = report_root / f"mission_{int(report['created_at'])}_{investigation.card.id[:8]}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(path)


def contain_operation(investigation, block_destination=False, disconnect_program=False,
                      quarantine_sample=False, runner=None, report_root=None, verify_delay=1):
    if not investigation.confirmed:
        raise ValueError("Containment is disabled because the threat is not confirmed.")
    kwargs = {"runner": runner} if runner else {}
    actions = []
    quarantine_metadata = {}
    if block_destination:
        if not investigation.destination_confirmed or not investigation.card.remote_ip:
            raise ValueError("The destination is not confirmed for blocking.")
        block_ip(investigation.card.remote_ip, **kwargs)
        actions.append("Blocked confirmed malicious destination with Windows Firewall")
    if disconnect_program:
        finding = next(iter(investigation.remote_access_findings), None)
        if not finding and investigation.card.pid:
            finding = RemoteAccessFinding(
                "process", investigation.card.program_name or "Suspicious program",
                investigation.card.pid, investigation.executable_path, "", (),
                "Mission Control containment request",
            )
        if not finding:
            raise ValueError("No running program or remote-access session was identified.")
        actions.extend(disconnect_remote_access(finding, **kwargs))
    if quarantine_sample:
        if not investigation.file_confirmed or not investigation.executable_path:
            raise ValueError("The file is not confirmed for quarantine.")
        quarantine_metadata = quarantine_file(investigation.executable_path, **kwargs)
        actions.append("Created verified brain/body quarantine and removed original path")
    if verify_delay:
        time.sleep(verify_delay)
    processes = running_processes(**kwargs)
    connections = active_connections(**kwargs)
    process_gone = not any(
        (investigation.card.pid and process.pid == investigation.card.pid) or
        (investigation.executable_path and process.path and
         os.path.normcase(os.path.abspath(process.path)) ==
         os.path.normcase(os.path.abspath(investigation.executable_path)))
        for process in processes
    ) if disconnect_program or quarantine_sample else True
    connection_gone = not any(
        connection.remote_ip == investigation.card.remote_ip for connection in connections
    ) if block_destination else True
    original_gone = not Path(investigation.executable_path).exists() if quarantine_sample else True
    verification = {
        "program_gone": process_gone,
        "connection_gone": connection_gone,
        "original_file_gone": original_gone,
    }
    area_secured = all(verification.values()) and bool(actions)
    report_path = save_mission_report(investigation, actions, verification, report_root)
    return ContainmentResult(
        investigation.card.id, tuple(actions), verification, area_secured,
        report_path, quarantine_metadata,
    )
