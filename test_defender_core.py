import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from internet_defender import (
    application_component_paths,
    application_root,
    combined_file_severity,
    inspect_passive_file,
    passive_quarantine_confirmed,
    passive_scan_excluded_roots,
)
from local_detective_core import FileAssessment
from whole_pc_monitor import path_is_excluded

from defender_core import (
    AD_BLOCK_BEGIN,
    AD_BLOCK_END,
    FileInspection,
    ProcessInfo,
    Reputation,
    VirusTotalClient,
    ad_block_enabled,
    block_ip,
    disable_ad_block,
    emergency_lockdown,
    enable_ad_block,
    heuristic_findings,
    launch_quarantine_watchdog,
    list_quarantine_items,
    load_virustotal_key,
    normalize_indicator,
    parse_netstat,
    parse_process_info_csv,
    parse_zone_identifier,
    quarantine_file,
    recent_risky_files,
    restore_emergency_network,
    render_ad_block_hosts,
    restore_network_quarantine,
    restore_quarantine_item,
    save_origin_report,
    save_virustotal_key,
    should_auto_block_reputation,
    start_network_quarantine,
    strip_managed_ad_block,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


class PassiveProtectionTests(unittest.TestCase):
    @staticmethod
    def _inspection(reputation):
        return FileInspection("sample.py", "a" * 64, 10, (), reputation)

    def test_internet_defender_components_are_excluded_without_hiding_its_folder(self):
        roots = passive_scan_excluded_roots()
        components = application_component_paths()
        sample = application_root() / "local_detective_core.py"
        self.assertIn(sample, components)
        self.assertTrue(path_is_excluded(sample, roots))
        self.assertFalse(path_is_excluded(application_root() / "unknown-new-file.py", roots))
        self.assertIsNone(inspect_passive_file(sample, Mock(), roots))

    def test_missing_passive_file_is_skipped_without_online_lookup(self):
        client = Mock()
        result = inspect_passive_file(Path("missing-passive-file.py"), client)
        self.assertIsNone(result)
        client.lookup.assert_not_called()

    def test_unknown_script_outside_app_is_still_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.ps1"
            sample.write_text("Invoke-Expression (DownloadString($url))", encoding="utf-8")
            client = Mock()
            client.lookup.return_value = Reputation("a" * 64, "file", "not_found")
            result = inspect_passive_file(sample, client, passive_scan_excluded_roots())
        self.assertIsNotNone(result)
        self.assertEqual(result[1].severity, "HIGH")
        client.lookup.assert_called_once()

    def test_local_rules_alone_require_review_instead_of_quarantine_prompt(self):
        inspection = self._inspection(Reputation("a" * 64, "file", "not_found"))
        local = FileAssessment(
            "sample.py", "a" * 64, "NotApplicable", "Unknown",
            ("Local behavior warning",), 100, "CRITICAL")
        self.assertEqual(combined_file_severity(inspection, local), "CRITICAL")
        self.assertFalse(passive_quarantine_confirmed(inspection))

    def test_virustotal_serious_result_can_offer_quarantine(self):
        inspection = self._inspection(Reputation("a" * 64, "file", "found", malicious=1))
        self.assertTrue(passive_quarantine_confirmed(inspection))


class ReputationTests(unittest.TestCase):
    def test_severity_thresholds(self):
        self.assertEqual(Reputation("x", "ip", "found", malicious=3).severity, "CRITICAL")
        self.assertEqual(Reputation("x", "ip", "found", malicious=1).severity, "HIGH")
        self.assertEqual(Reputation("x", "ip", "found", suspicious=1).severity, "MEDIUM")
        self.assertEqual(Reputation("x", "ip", "found", harmless=10).severity, "LOW")
        self.assertEqual(Reputation("x", "ip", "not_found").severity, "UNKNOWN")

    def test_missing_key_never_claims_clean(self):
        result = VirusTotalClient(api_key="").lookup("8.8.8.8", "ip")
        self.assertEqual(result.status, "no_api_key")
        self.assertEqual(result.severity, "UNKNOWN")

    def test_auto_block_requires_three_malicious_ip_detections(self):
        critical_ip = Reputation("8.8.8.8", "ip", "found", malicious=3)
        one_detection = Reputation("8.8.8.8", "ip", "found", malicious=1)
        critical_file = Reputation("a" * 64, "file", "found", malicious=5)
        self.assertTrue(should_auto_block_reputation(critical_ip))
        self.assertFalse(should_auto_block_reputation(one_detection))
        self.assertFalse(should_auto_block_reputation(critical_file))
        self.assertFalse(should_auto_block_reputation(critical_ip, enabled=False))

    def test_api_key_is_saved_only_as_protected_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.dpapi"
            with patch("defender_core._dpapi_protect", return_value=b"protected-bytes"):
                save_virustotal_key("test-key", path)
            self.assertEqual(path.read_bytes(), b"protected-bytes")
            self.assertNotIn(b"test-key", path.read_bytes())
            with patch("defender_core._dpapi_unprotect", return_value=b"test-key"):
                self.assertEqual(load_virustotal_key(path), "test-key")
            save_virustotal_key("", path)
            self.assertFalse(path.exists())

    def test_official_api_response_is_scored(self):
        payload = {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 4, "suspicious": 1, "harmless": 30, "undetected": 20,
            }}}
        }
        client = VirusTotalClient(
            api_key="test-key", opener=lambda *_args, **_kwargs: FakeResponse(payload),
            min_interval=0,
        )
        result = client.lookup("8.8.8.8", "ip")
        self.assertEqual(result.severity, "CRITICAL")
        self.assertEqual(result.malicious, 4)
        self.assertEqual(result.suspicious, 1)

    def test_not_found_stays_unknown(self):
        def missing(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

        client = VirusTotalClient(api_key="test-key", opener=missing, min_interval=0)
        self.assertEqual(client.lookup("8.8.8.8", "ip").status, "not_found")


class IndicatorTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_indicator("Example.COM.", "domain"), "example.com")
        self.assertEqual(normalize_indicator("8.8.8.8", "ip"), "8.8.8.8")
        self.assertEqual(
            normalize_indicator("A" * 64, "file"),
            "a" * 64,
        )

    def test_invalid_url_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_indicator("javascript:alert(1)", "url")

    def test_private_ip_cannot_be_blocked(self):
        runner = Mock()
        with self.assertRaises(ValueError):
            block_ip("192.168.1.2", runner=runner)
        runner.assert_not_called()

    def test_public_ip_uses_argument_list(self):
        result = Mock(returncode=0, stdout="Ok", stderr="")
        runner = Mock(return_value=result)
        rule = block_ip("8.8.8.8", runner=runner)
        command = runner.call_args.args[0]
        self.assertEqual(command[0], "netsh")
        self.assertIn("remoteip=8.8.8.8", command)
        self.assertEqual(rule, "Internet Detective Block 8.8.8.8")


class ConnectionTests(unittest.TestCase):
    def test_parse_established_public_connections_only(self):
        output = """
          TCP    10.0.0.2:50000       8.8.8.8:443          ESTABLISHED     1234
          TCP    10.0.0.2:50001       192.168.1.1:80       ESTABLISHED     1234
          TCP    10.0.0.2:50002       1.1.1.1:443          TIME_WAIT       0
          UDP    0.0.0.0:5353         8.8.4.4:53                           77
        """
        connections = parse_netstat(output, {1234: "browser.exe", 77: "dns.exe"})
        self.assertEqual(len(connections), 2)
        self.assertEqual(connections[0].remote_ip, "8.8.8.8")
        self.assertEqual(connections[0].process_name, "browser.exe")
        self.assertEqual(connections[1].remote_ip, "8.8.4.4")

    def test_connection_keeps_program_path_and_owner(self):
        output = "TCP 10.0.0.2:50000 8.8.8.8:443 ESTABLISHED 1234"
        process = ProcessInfo(
            "msedgewebview2.exe", "C:/Edge/msedgewebview2.exe", 100,
            "Discord.exe", "C:/Apps/Discord.exe")
        connection = parse_netstat(output, {1234: process})[0]
        self.assertEqual(connection.process_path, "C:/Edge/msedgewebview2.exe")
        self.assertEqual(connection.owner_process_name, "Discord.exe")

    def test_process_parser_finds_owner_behind_webview_helpers(self):
        output = (
            "Node,ExecutablePath,Name,ParentProcessId,ProcessId\n"
            "PC,C:/Apps/Discord.exe,Discord.exe,1,100\n"
            "PC,C:/Edge/msedgewebview2.exe,msedgewebview2.exe,100,200\n"
            "PC,C:/Edge/msedgewebview2.exe,msedgewebview2.exe,200,300\n"
        )
        records = parse_process_info_csv(output)
        self.assertEqual(records[300].owner_name, "Discord.exe")
        self.assertEqual(records[300].owner_path, "C:/Apps/Discord.exe")


class AdBlockTests(unittest.TestCase):
    def test_managed_hosts_block_is_reversible_and_idempotent(self):
        original = "127.0.0.1 localhost\n10.0.0.2 internal.example\n"
        first = render_ad_block_hosts(original, ("ads.example", "tracker.example"))
        second = render_ad_block_hosts(first, ("ads.example", "tracker.example"))
        self.assertEqual(first, second)
        self.assertEqual(first.count(AD_BLOCK_BEGIN), 1)
        self.assertEqual(first.count(AD_BLOCK_END), 1)
        restored = strip_managed_ad_block(first)
        self.assertIn("127.0.0.1 localhost", restored)
        self.assertIn("10.0.0.2 internal.example", restored)
        self.assertNotIn("ads.example", restored)

    def test_enable_and_disable_touch_only_test_hosts_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            hosts = root / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            runner = Mock(return_value=Mock(returncode=0, stdout="", stderr=""))
            result = enable_ad_block(
                hosts, domains=("ads.example",), backup_root=root / "backups", runner=runner)
            self.assertTrue(Path(result["backup_path"]).is_file())
            self.assertTrue(ad_block_enabled(hosts))
            self.assertIn("0.0.0.0 ads.example", hosts.read_text(encoding="utf-8"))
            self.assertTrue(disable_ad_block(hosts, runner=runner))
            self.assertFalse(ad_block_enabled(hosts))
            self.assertEqual(hosts.read_text(encoding="utf-8").strip(), "127.0.0.1 localhost")
            self.assertEqual(runner.call_args.args[0], ["ipconfig", "/flushdns"])


class EmergencyTests(unittest.TestCase):
    @staticmethod
    def _result(returncode=0, stdout="Ok", stderr=""):
        return Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_lockdown_adds_only_named_rules_without_defender(self):
        runner = Mock(side_effect=[self._result(), self._result(), self._result()])
        result = emergency_lockdown(runner=runner)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(commands[0][:4], ["netsh", "advfirewall", "set", "allprofiles"])
        self.assertIn("name=Internet Defender Emergency IN", commands[1])
        self.assertIn("name=Internet Defender Emergency OUT", commands[2])
        self.assertEqual(len(commands), 3)
        self.assertEqual(len(result["rules"]), 2)

    def test_partial_lockdown_rolls_back_added_rule(self):
        runner = Mock(side_effect=[
            self._result(), self._result(), self._result(returncode=1, stderr="denied"),
            self._result(),
        ])
        with self.assertRaises(RuntimeError):
            emergency_lockdown(runner=runner)
        rollback = runner.call_args_list[-1].args[0]
        self.assertIn("delete", rollback)
        self.assertIn("name=Internet Defender Emergency IN", rollback)

    def test_restore_removes_only_emergency_rules(self):
        runner = Mock(side_effect=[self._result(), self._result()])
        self.assertTrue(restore_emergency_network(runner=runner))
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertIn("name=Internet Defender Emergency IN", commands[0])
        self.assertIn("name=Internet Defender Emergency OUT", commands[1])
        self.assertTrue(all("delete" in command for command in commands))

    def test_watchdog_is_launched_as_hidden_helper(self):
        with patch("defender_core.subprocess.Popen") as popen:
            popen.return_value.pid = 4321
            pid = launch_quarantine_watchdog("backup.wfw", "active.json", 1234, 60)
        self.assertEqual(pid, 4321)
        command = popen.call_args.args[0]
        self.assertIn("-c", command)
        self.assertIn("backup.wfw", command)
        self.assertIn("active.json", command)

    def test_selective_quarantine_rolls_back_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            app = root / "scanner.exe"
            backup = root / "firewall.wfw"
            app.write_bytes(b"scanner")
            backup.write_bytes(b"backup")
            runner = Mock(side_effect=[
                self._result(), self._result(returncode=1, stderr="denied"),
                self._result(),
            ])
            with self.assertRaises(RuntimeError):
                start_network_quarantine(
                    app, runner=runner, backup_path=backup, program_paths=[])
            self.assertIn("import", runner.call_args_list[-1].args[0])
            self.assertFalse((root / "active_network_quarantine.json").exists())

    def test_selective_quarantine_keeps_scanner_and_dns_access(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            app = root / "scanner.exe"
            other = root / "browser.exe"
            backup = root / "firewall.wfw"
            app.write_bytes(b"scanner")
            other.write_bytes(b"browser")
            backup.write_bytes(b"backup")
            runner = Mock(return_value=self._result())
            state = start_network_quarantine(
                app, runner=runner, backup_path=backup, program_paths=[other])
            commands = [call.args[0] for call in runner.call_args_list]
            self.assertTrue(any("action=allow" in command for command in commands))
            self.assertTrue(any("action=block" in command for command in commands))
            self.assertTrue(any("dir=in" in command and "action=block" in command
                                for command in commands))
            self.assertTrue(any("blockinbound,blockoutbound" in command for command in commands))
            self.assertEqual(state["blocked_programs"], 1)
            self.assertTrue(Path(state["marker_path"]).is_file())
            restore_runner = Mock(return_value=self._result())
            self.assertTrue(restore_network_quarantine(backup, runner=restore_runner))
            self.assertIn("import", restore_runner.call_args.args[0])
            self.assertFalse(Path(state["marker_path"]).exists())


class FileSafetyTests(unittest.TestCase):
    def test_script_heuristics_are_advisory(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.ps1"
            path.write_text("Invoke-Expression $value", encoding="utf-8")
            findings = heuristic_findings(path)
        self.assertIn("Risk-capable file type: .ps1", findings)
        self.assertIn("Executes dynamically constructed PowerShell", findings)

    def test_zone_identifier_extracts_download_origin(self):
        origin = parse_zone_identifier(
            "[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://example.com/page\n"
            "HostUrl=https://cdn.example.com/file.exe\n"
        )
        self.assertEqual(origin["zone_id"], "3")
        self.assertEqual(origin["referrer_url"], "https://example.com/page")
        self.assertEqual(origin["host_url"], "https://cdn.example.com/file.exe")

    def test_recent_risky_files_excludes_normal_documents(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            risky = root / "download.exe"
            risky.write_bytes(b"MZ test")
            (root / "notes.txt").write_text("normal", encoding="utf-8")
            self.assertEqual(recent_risky_files(root), [str(risky.resolve())])

    def test_origin_report_is_local_evidence_only(self):
        inspection = FileInspection(
            "sample.exe", "a" * 64, 10, ("Risk-capable file type: .exe",),
            Reputation("a" * 64, "file", "found", malicious=3),
        )
        with tempfile.TemporaryDirectory() as folder:
            report_path = save_origin_report(
                inspection, {"host_url": "https://example.com/sample.exe"}, folder)
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
        self.assertEqual(report["download_origin"]["host_url"], "https://example.com/sample.exe")
        self.assertEqual(report["severity"], "CRITICAL")
        self.assertIn("No report was transmitted", report["notice"])

    def test_brain_body_quarantine_and_restore_are_hash_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sample.exe"
            quarantine = root / "quarantine"
            original = b"MZ" + bytes(range(256)) * 30
            source.write_bytes(original)
            runner = Mock(return_value=Mock(
                returncode=0, stdout="Node,ExecutablePath,ProcessId\n", stderr=""))
            metadata = quarantine_file(source, quarantine, runner=runner, brain_size=4096)
            self.assertFalse(source.exists())
            brain = Path(metadata["brain_path"])
            body = Path(metadata["body_path"])
            self.assertTrue(brain.is_file())
            self.assertTrue(body.is_file())
            self.assertTrue(brain.name.endswith(".quarantine.brain"))
            self.assertTrue(body.name.endswith(".quarantine.body"))
            self.assertEqual(brain.read_bytes() + body.read_bytes(), original)
            self.assertEqual(len(list_quarantine_items(quarantine)), 1)
            restored = restore_quarantine_item(metadata, quarantine)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(restored["sha256"], metadata["sha256"])
            self.assertFalse(brain.exists())
            self.assertFalse(body.exists())

    def test_tampered_brain_fragment_cannot_be_restored(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sample.exe"
            quarantine = root / "quarantine"
            source.write_bytes(b"MZ" + b"A" * 5000)
            runner = Mock(return_value=Mock(
                returncode=0, stdout="Node,ExecutablePath,ProcessId\n", stderr=""))
            metadata = quarantine_file(source, quarantine, runner=runner)
            Path(metadata["brain_path"]).write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                restore_quarantine_item(metadata, quarantine)
            self.assertFalse(source.exists())

    def test_protected_windows_path_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            windows = Path(folder) / "Windows"
            windows.mkdir()
            source = windows / "system.exe"
            source.write_bytes(b"MZ test")
            with patch.dict("os.environ", {"SystemRoot": str(windows)}):
                with self.assertRaises(ValueError):
                    quarantine_file(source, Path(folder) / "quarantine")
            self.assertTrue(source.exists())


if __name__ == "__main__":
    unittest.main()
