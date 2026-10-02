import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from whole_pc_monitor import WholePCMonitor, eligible_risky_file, path_is_excluded


class EligibilityTests(unittest.TestCase):
    def test_only_risky_existing_files_are_eligible(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            risky = root / "sample.exe"
            normal = root / "notes.txt"
            risky.write_bytes(b"MZ")
            normal.write_text("notes", encoding="utf-8")
            self.assertTrue(eligible_risky_file(risky))
            self.assertFalse(eligible_risky_file(normal))

    def test_excluded_quarantine_folder_is_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            quarantine = root / "quarantine"
            quarantine.mkdir()
            sample = quarantine / "sample.exe"
            sample.write_bytes(b"MZ")
            self.assertTrue(path_is_excluded(sample, (quarantine,)))
            self.assertFalse(eligible_risky_file(sample, (quarantine,)))

    def test_oversized_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "large.exe"
            sample.write_bytes(b"MZ" + b"A" * 100)
            self.assertFalse(eligible_risky_file(sample, max_bytes=10))


class StabilityTests(unittest.TestCase):
    def test_changed_file_waits_until_size_is_stable_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.exe"
            sample.write_bytes(b"MZ")
            detected = []
            monitor = WholePCMonitor(
                detected.append, roots=(), settle_seconds=0, max_bytes=1000)
            monitor.mark_changed(sample)
            self.assertEqual(monitor.settle_once(), ())
            self.assertEqual(monitor.settle_once(), (str(sample.resolve()),))
            self.assertEqual(detected, [str(sample.resolve())])
            monitor.mark_changed(sample)
            monitor.settle_once()
            self.assertEqual(monitor.settle_once(), ())
            sample.write_bytes(b"MZ changed")
            monitor.mark_changed(sample)
            monitor.settle_once()
            self.assertEqual(monitor.settle_once(), (str(sample.resolve()),))

    def test_removed_pending_file_is_dropped(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.ps1"
            sample.write_text("test", encoding="utf-8")
            monitor = WholePCMonitor(lambda _path: None, roots=())
            monitor.mark_changed(sample)
            sample.unlink()
            self.assertEqual(monitor.settle_once(), ())
            self.assertEqual(monitor.pending, {})


class EventParsingTests(unittest.TestCase):
    def test_added_event_marks_risky_path(self):
        monitor = WholePCMonitor(lambda _path: None, roots=())
        name = "folder\\sample.exe".encode("utf-16-le")
        event = struct.pack("<III", 0, 1, len(name)) + name
        monitor._parse_events("C:\\", event)
        expected = os.path.abspath("C:\\folder\\sample.exe")
        self.assertIn(expected, monitor.pending)

    def test_normal_file_event_is_ignored(self):
        monitor = WholePCMonitor(lambda _path: None, roots=())
        name = "folder\\notes.txt".encode("utf-16-le")
        event = struct.pack("<III", 0, 1, len(name)) + name
        monitor._parse_events("C:\\", event)
        self.assertEqual(monitor.pending, {})


if __name__ == "__main__":
    unittest.main()
