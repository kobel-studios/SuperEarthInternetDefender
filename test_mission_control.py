import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defender_core import Connection, FileInspection, Reputation
from local_detective_core import FileAssessment, ProcessRecord, StartupItem
from mission_control import (
    InvestigationResult,
    OperationCard,
    TimelineEvent,
    card_from_connection,
    contain_operation,
    investigate_operation,
    save_mission_report,
)


class MissionCardTests(unittest.TestCase):
    def test_connection_card_combines_reputation_and_program(self):
        connection = Connection(
            "TCP", "10.0.0.2:50000", "8.8.8.8:443", "8.8.8.8",
            "ESTABLISHED", 42, "sample.exe")
        reputation = Reputation("8.8.8.8", "ip", "found", malicious=3)
        card = card_from_connection(connection, reputation)
        self.assertEqual(card.source, "INTERNET DETECTIVE")
        self.assertEqual(card.severity, "CRITICAL")
        self.assertEqual(card.program_name, "sample.exe")
        self.assertEqual(card.pid, 42)


class MissionInvestigationTests(unittest.TestCase):
    def test_investigation_builds_ordered_timeline_and_confirmed_verdict(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "sample.exe"
            executable.write_bytes(b"MZ" + b"A" * 100)
            card = OperationCard(
                "card-1", "INTERNET DETECTIVE", "CRITICAL", "test", "sample.exe",
                "sample.exe", 42, str(executable), "8.8.8.8", "8.8.8.8:443",
                "sample.exe is using an encrypted web service", "test")
            process = ProcessRecord(42, 1, "sample.exe", str(executable), "sample.exe")
            online = FileInspection(
                str(executable), "a" * 64, executable.stat().st_size, (),
                Reputation("a" * 64, "file", "found", malicious=4))
            local = FileAssessment(
                str(executable), "a" * 64, "NotTrusted", "https://example.invalid/file",
                ("Digital signature status is NotTrusted",), 60, "HIGH")
            with patch("mission_control.running_processes", return_value=[process]), \
                    patch("mission_control.inspect_file", return_value=online), \
                    patch("mission_control.inspect_local_file", return_value=local), \
                    patch("mission_control.collect_startup_items", return_value=[
                        StartupItem("Run", "Sample", str(executable))]), \
                    patch("mission_control.download_origin", return_value={
                        "host_url": "https://example.invalid/file"}), \
                    patch("mission_control.active_connections", return_value=[]), \
                    patch("mission_control.detect_remote_access", return_value=[]), \
                    patch("mission_control.security_events", return_value=[]):
                result = investigate_operation(card, Mock())
        self.assertEqual(
            [event.stage for event in result.timeline],
            ["Downloaded file", "Program started", "Startup change", "Internet connection"])
        self.assertEqual(result.verdict, "CONFIRMED THREAT")
        self.assertTrue(result.confirmed)
        self.assertTrue(result.destination_confirmed)
        self.assertTrue(result.file_confirmed)

    def test_unknown_result_is_not_called_clean(self):
        card = OperationCard("card-2", "LOCAL DETECTIVE", "UNKNOWN", "test", "unknown")
        with patch("mission_control.running_processes", return_value=[]), \
                patch("mission_control.collect_startup_items", return_value=[]), \
                patch("mission_control.active_connections", return_value=[]), \
                patch("mission_control.detect_remote_access", return_value=[]), \
                patch("mission_control.security_events", return_value=[]):
            result = investigate_operation(card, Mock())
        self.assertEqual(result.verdict, "UNKNOWN / LOW EVIDENCE")
        self.assertFalse(result.confirmed)
        self.assertIn("not treated as clean", result.verdict_explanation)


class MissionContainmentTests(unittest.TestCase):
    @staticmethod
    def _investigation(file_path=""):
        card = OperationCard(
            "card-3", "INTERNET DETECTIVE", "CRITICAL", "test", "sample.exe",
            "sample.exe", 42, file_path, "8.8.8.8", "8.8.8.8:443",
            "encrypted web service", "confirmed")
        return InvestigationResult(
            card, file_path, True, ("Run: Sample",), "https://example.invalid/file",
            "CRITICAL", "four detections", "HIGH", ("unsigned",), (), (),
            (
                TimelineEvent("Downloaded file", "OBSERVED", "source"),
                TimelineEvent("Program started", "OBSERVED", "sample.exe"),
                TimelineEvent("Startup change", "OBSERVED", "Run"),
                TimelineEvent("Internet connection", "OBSERVED", "web"),
            ),
            "CONFIRMED THREAT", "confirmed evidence", True, True, bool(file_path),
        )

    def test_unconfirmed_operation_cannot_contain(self):
        investigation = self._investigation()
        investigation = InvestigationResult(
            investigation.card, investigation.executable_path, investigation.program_running,
            investigation.startup_matches, investigation.download_source,
            investigation.online_file_severity, investigation.online_file_explanation,
            investigation.local_file_severity, investigation.local_file_reasons,
            investigation.remote_access_findings, investigation.account_clues,
            investigation.timeline, "UNKNOWN / LOW EVIDENCE", "unknown", False, False, False)
        with self.assertRaises(ValueError):
            contain_operation(investigation, block_destination=True, verify_delay=0)

    def test_containment_blocks_quarantines_reports_and_verifies(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "sample.exe"
            executable.write_bytes(b"MZ test")
            investigation = self._investigation(str(executable))
            quarantine = {
                "id": "q1", "brain_path": "brain", "body_path": "body",
                "original_path": str(executable), "sha256": "a" * 64,
            }
            with patch("mission_control.block_ip") as block, \
                    patch("mission_control.quarantine_file", return_value=quarantine) as quarantine_call, \
                    patch("mission_control.running_processes", return_value=[]), \
                    patch("mission_control.active_connections", return_value=[]), \
                    patch("mission_control.save_mission_report", return_value=str(Path(folder) / "report.json")):
                executable.unlink()
                result = contain_operation(
                    investigation, block_destination=True, quarantine_sample=True,
                    report_root=folder, verify_delay=0)
        block.assert_called_once()
        quarantine_call.assert_called_once()
        self.assertTrue(result.area_secured)
        self.assertTrue(result.verification["connection_gone"])
        self.assertTrue(result.verification["original_file_gone"])

    def test_report_records_timeline_and_scope_notice(self):
        with tempfile.TemporaryDirectory() as folder:
            investigation = self._investigation()
            path = save_mission_report(
                investigation, ["Blocked destination"], {"connection_gone": True}, folder)
            report = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertEqual(len(report["timeline"]), 4)
        self.assertIn("does not identify a person", report["notice"])
        self.assertIn("not submitted", report["notice"])


if __name__ == "__main__":
    unittest.main()
