import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from local_detective_core import (
    ConnectionRecord,
    ProcessRecord,
    SecurityEvent,
    StartupItem,
    active_connections,
    assess_process,
    compare_startup_items,
    connection_program_name,
    RemoteAccessFinding,
    describe_connection,
    describe_program,
    detect_remote_access,
    disconnect_remote_access,
    findings_from_security_events,
    inspect_local_file,
    investigate_connection_processes,
    parse_netstat,
    parse_process_csv,
    parse_qwinsta,
    parse_security_events,
    quarantine_file,
    run_local_scan,
    save_remote_access_report,
    save_scan_report,
    severity_for_score,
    startup_snapshot,
)


class LocalScoringTests(unittest.TestCase):
    def test_score_severity_boundaries(self):
        self.assertEqual(severity_for_score(0), "INFO")
        self.assertEqual(severity_for_score(25), "MEDIUM")
        self.assertEqual(severity_for_score(50), "HIGH")
        self.assertEqual(severity_for_score(80), "CRITICAL")

    def test_encoded_command_is_high_risk(self):
        process = ProcessRecord(
            123, 1, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -encodedcommand AAAA",
        )
        score, reasons = assess_process(process, "Valid")
        self.assertGreaterEqual(score, 40)
        self.assertIn("Encoded PowerShell command", reasons)

    def test_parse_process_csv(self):
        text = (
            "Node,CommandLine,ExecutablePath,Name,ParentProcessId,ProcessId\n"
            "PC,example.exe --test,C:\\Tools\\example.exe,example.exe,10,20\n"
        )
        records = parse_process_csv(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].pid, 20)
        self.assertEqual(records[0].parent_pid, 10)


class LocalConnectionTests(unittest.TestCase):
    def test_netstat_keeps_established_public_connections(self):
        output = """
          TCP    10.0.0.2:50000       8.8.8.8:443          ESTABLISHED     1234
          TCP    10.0.0.2:50001       192.168.1.1:80       ESTABLISHED     1234
          TCP    10.0.0.2:50002       1.1.1.1:443          TIME_WAIT       0
        """
        records = parse_netstat(output)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].remote_ip, "8.8.8.8")

    def test_active_connections_uses_no_shell(self):
        result = Mock(returncode=0, stdout="", stderr="")
        runner = Mock(return_value=result)
        self.assertEqual(active_connections(runner), [])
        self.assertEqual(runner.call_args.args[0], ["netstat", "-ano"])

    def test_connection_description_hides_raw_ip(self):
        connection = Mock(
            remote_address="8.8.8.8:443", process_name="opera.exe",
            owner_process_name="")
        description = describe_connection(connection)
        self.assertIn("Opera / Opera GX", description)
        self.assertIn("encrypted", description)
        self.assertNotIn("8.8.8.8", description)

    def test_webview_connection_shows_friendly_name_and_owner(self):
        connection = Mock(
            remote_address="8.8.8.8:443", process_name="msedgewebview2.exe",
            owner_process_name="Discord.exe")
        self.assertEqual(
            connection_program_name(connection),
            "Microsoft Edge WebView2 (used by Discord)")
        details = describe_program(connection)
        self.assertIn("Program: Microsoft Edge WebView2", details)
        self.assertIn("Used by: Discord", details)
        self.assertIn("Technical file: msedgewebview2.exe", details)

    def test_weird_connected_process_is_investigated(self):
        process = ProcessRecord(
            123, 1, "powershell.exe", r"C:\Windows\powershell.exe",
            "powershell.exe -encodedcommand AAAA",
        )
        connection = ConnectionRecord(
            "TCP", "10.0.0.2:50000", "8.8.8.8:443", "8.8.8.8", "ESTABLISHED", 123)
        with patch("local_detective_core.running_processes", return_value=[process]):
            anomalies = investigate_connection_processes([connection])
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0][1].severity, "HIGH")
        self.assertNotIn("8.8.8.8", anomalies[0][1].subject)


class RemoteAccessTests(unittest.TestCase):
    def test_parse_active_rdp_session(self):
        text = """
         SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
        >console           player                    1  Active
         rdp-tcp#5         unknown-user               3  Active
        """
        sessions = parse_qwinsta(text)
        self.assertIn(("rdp-tcp#5", "unknown-user", 3, "Active"), sessions)

    def test_detects_known_remote_control_process(self):
        process = ProcessRecord(77, 1, "AnyDesk.exe", r"C:\Tools\AnyDesk.exe", "AnyDesk.exe")
        connection = ConnectionRecord(
            "TCP", "10.0.0.2:50000", "8.8.8.8:443", "8.8.8.8", "ESTABLISHED", 77)
        runner = Mock(return_value=Mock(returncode=1, stdout="", stderr=""))
        findings = detect_remote_access([process], [connection], runner)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tool, "AnyDesk")
        self.assertIn("not proof", findings[0].explanation)

    def test_disconnect_process_terminates_and_blocks_program(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "AnyDesk.exe"
            executable.write_bytes(b"test")
            finding = RemoteAccessFinding(
                "process", "AnyDesk", 77, str(executable), "", (), "test")
            runner = Mock(return_value=Mock(returncode=0, stdout="Ok", stderr=""))
            actions = disconnect_remote_access(finding, runner=runner)
            commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(commands[0][:2], ["taskkill", "/PID"])
        self.assertEqual(sum("add" in command for command in commands), 2)
        self.assertTrue(any("Terminated AnyDesk" in action for action in actions))

    def test_disconnect_rdp_logs_off_and_disables_new_rdp(self):
        finding = RemoteAccessFinding(
            "rdp_session", "Windows Remote Desktop", 3, "", "unknown-user", (), "test")
        runner = Mock(return_value=Mock(returncode=0, stdout="Ok", stderr=""))
        actions = disconnect_remote_access(finding, runner=runner)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(commands[0], ["logoff", "3"])
        self.assertEqual(commands[1][:2], ["reg", "add"])
        self.assertEqual(len(actions), 2)

    def test_remote_report_is_local_and_does_not_claim_identity(self):
        finding = RemoteAccessFinding(
            "process", "AnyDesk", 77, "AnyDesk.exe", "", (), "test")
        with tempfile.TemporaryDirectory() as folder:
            path = save_remote_access_report([finding], ["Terminated process"], folder)
            report = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertIn("does not identify a hacker", report["notice"])
        self.assertIn("Nothing was submitted", report["notice"])


class LocalFileTests(unittest.TestCase):
    def test_script_behavior_is_explained(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.ps1"
            sample = "Invoke" + "-Expression (" + "Download" + "String($url))"
            path.write_text(sample, encoding="utf-8")
            assessment = inspect_local_file(path)
        self.assertGreaterEqual(assessment.score, 50)
        self.assertIn("Script dynamically executes constructed commands", assessment.reasons)
        self.assertIn("Script downloads executable content", assessment.reasons)

    def test_quarantine_moves_file_and_saves_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sample.bin"
            destination = root / "quarantine"
            source.write_bytes(b"local test")
            metadata = quarantine_file(source, destination)
            self.assertFalse(source.exists())
            self.assertTrue(Path(metadata["quarantined_path"]).is_file())
            self.assertTrue(Path(metadata["quarantined_path"] + ".json").is_file())


class StartupTests(unittest.TestCase):
    def test_added_and_changed_startup_entries(self):
        items = [
            StartupItem("Run", "Existing", "new.exe"),
            StartupItem("Run", "Added", "added.exe"),
        ]
        baseline = {"Run|Existing": "old.exe"}
        added, changed = compare_startup_items(items, baseline)
        self.assertEqual(added, ["Run|Added"])
        self.assertEqual(changed, ["Run|Existing"])
        self.assertEqual(startup_snapshot(items)["Run|Added"], "added.exe")


class SecurityEventTests(unittest.TestCase):
    def test_remote_login_event_is_detected(self):
        xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>4624</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z" /></System>
          <EventData>
            <Data Name="TargetUserName">player</Data>
            <Data Name="IpAddress">8.8.8.8</Data>
            <Data Name="LogonType">10</Data>
          </EventData>
        </Event>
        """
        events = parse_security_events(xml)
        findings = findings_from_security_events(events)
        self.assertEqual(len(events), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_repeated_failed_logins_are_detected(self):
        events = tuple(SecurityEvent(4625, "", "player", "8.8.8.8", "3", "") for _ in range(10))
        findings = findings_from_security_events(events)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("10 failed", findings[0].title)


class FullLocalScanTests(unittest.TestCase):
    def test_scan_creates_local_report_without_online_service(self):
        process = ProcessRecord(1, 0, "system.exe", r"C:\Windows\system.exe", "system.exe")
        connection = ConnectionRecord("TCP", "10.0.0.2:1", "8.8.8.8:443", "8.8.8.8", "ESTABLISHED", 1)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline = root / "baseline.json"
            baseline.write_text("{}", encoding="utf-8")
            with patch("local_detective_core.running_processes", return_value=[process]), \
                    patch("local_detective_core.active_connections", return_value=[connection]), \
                    patch("local_detective_core.collect_startup_items", return_value=[]), \
                    patch("local_detective_core.recent_risky_files", return_value=[]), \
                    patch("local_detective_core.security_events", return_value=[]):
                result = run_local_scan(baseline_path=baseline, report_root=root / "reports")
            report = json.loads(Path(result.report_path).read_text(encoding="utf-8"))
        self.assertIn("No report was sent anywhere", report["notice"])
        self.assertEqual(report["summary"]["connections"], 1)

    def test_source_has_no_online_reputation_dependency(self):
        source = Path(__file__).with_name("local_detective_core.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("virustotal", source)
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)


if __name__ == "__main__":
    unittest.main()
