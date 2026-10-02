import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import account_liberation as liberation


class EncryptedLiberationTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = (
            patch("account_liberation.liberation_root", return_value=self.root),
            patch("account_liberation._dpapi_protect", side_effect=lambda data: b"protected:" + data),
            patch("account_liberation._dpapi_unprotect", side_effect=lambda data: data.removeprefix(b"protected:")),
        )
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()


class InventoryTests(EncryptedLiberationTestCase):
    def test_account_inventory_is_encrypted_and_removable(self):
        account = liberation.add_account("Discord", "player", "Gmail", "main account")
        self.assertEqual(liberation.list_accounts()[0].service, "Discord")
        stored = (self.root / "accounts.dpapi").read_bytes()
        self.assertTrue(stored.startswith(b"protected:"))
        self.assertTrue(liberation.remove_account(account.id))
        self.assertEqual(liberation.list_accounts(), ())

    def test_known_devices_are_encrypted_and_removable(self):
        device = liberation.add_known_device("Google", "Gaming PC", "Windows")
        self.assertEqual(liberation.list_known_devices()[0].device_name, "Gaming PC")
        self.assertTrue(liberation.remove_known_device(device.id))
        self.assertEqual(liberation.list_known_devices(), ())

    def test_password_fields_do_not_exist(self):
        fields = liberation.AccountRecord.__dataclass_fields__
        self.assertNotIn("password", fields)
        self.assertNotIn("verification_code", fields)


class ChecklistTests(EncryptedLiberationTestCase):
    def test_checklist_tracks_all_recovery_steps(self):
        account = liberation.add_account("Google", "player@gmail.com")
        steps = {step: True for step in liberation.CHECKLIST_STEPS}
        progress = liberation.save_checklist(account.id, steps)
        self.assertEqual(liberation.checklist_completion(progress), (7, 7))

    def test_incomplete_checklist_prevents_secured_result(self):
        account = liberation.add_account("Google", "player@gmail.com")
        result = liberation.post_recovery_result([], [], [], [account])
        self.assertFalse(result.secured)
        self.assertEqual(result.incomplete_checklists, 1)


class PlanningTests(unittest.TestCase):
    def test_provider_plan_has_recovery_devices_apps_and_payments(self):
        service, plan = liberation.provider_plan("Google")
        self.assertEqual(service, "Google")
        self.assertTrue(plan["recovery"])
        self.assertTrue(plan["devices"])
        self.assertTrue(plan["connected_apps"])
        self.assertTrue(plan["payments"])

    def test_recovery_change_alert_gets_highest_priority(self):
        alert = SimpleNamespace(subject="Your recovery email changed")
        category, priority = liberation.prioritize_alert(alert)
        self.assertEqual(category, "RECOVERY DETAILS CHANGED")
        self.assertEqual(priority, 100)

    def test_payment_alert_is_prioritized(self):
        alert = SimpleNamespace(subject="New purchase transaction")
        self.assertEqual(liberation.prioritize_alert(alert)[0], "PAYMENT WARNING")

    def test_blast_radius_lists_only_directly_alerted_services(self):
        accounts = (
            liberation.AccountRecord("1", "Discord", "player", "Gmail", "", 0),
            liberation.AccountRecord("2", "Steam", "player", "Gmail", "", 0),
        )
        alerts = (SimpleNamespace(service="Discord"),)
        radius = liberation.blast_radius(accounts, alerts)
        self.assertEqual(len(radius), 1)
        self.assertEqual(radius[0]["service"], "Discord")

    def test_multiple_matching_accounts_require_confirmation(self):
        accounts = (
            liberation.AccountRecord("1", "Discord", "first", "Gmail", "", 0),
            liberation.AccountRecord("2", "Discord", "second", "Gmail", "", 0),
        )
        candidates = liberation.discover_account_candidates(
            accounts, (SimpleNamespace(service="Discord"),))
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(item.certainty == "NEEDS CONFIRMATION" for item in candidates))

    def test_serious_local_risk_reviews_other_inventory_accounts(self):
        account = liberation.AccountRecord("1", "Steam", "player", "Gmail", "", 0)
        candidates = liberation.discover_account_candidates((account,), (), broad_local_risk=True)
        self.assertEqual(candidates[0].certainty, "POSSIBLE LOCAL RISK")


class ReportTests(EncryptedLiberationTestCase):
    def test_recovery_report_is_encrypted_and_contains_no_credentials(self):
        path = liberation.save_encrypted_recovery_report({"summary": "complete"})
        data = Path(path).read_bytes()
        self.assertTrue(data.startswith(b"protected:"))
        report = liberation.load_encrypted_recovery_report(path)
        self.assertEqual(report["data"]["summary"], "complete")
        self.assertIn("no passwords", report["notice"])
        self.assertIn("not submitted", report["notice"])

    def test_stolen_account_report_is_provider_specific_and_reviewable(self):
        account = liberation.AccountRecord("1", "Discord", "player", "Gmail", "", 0)
        alert = SimpleNamespace(
            service="Discord", subject="New login detected", date="today", severity="HIGH")
        draft = liberation.build_stolen_account_report(
            account, (alert,), {"serious_local_count": 1, "serious_network_count": 2})
        self.assertEqual(draft.service, "Discord")
        self.assertIn("support.discord.com", draft.submission_url)
        self.assertIn("New login detected", draft.body)
        self.assertIn("Serious network findings: 2", draft.body)
        self.assertIn("REVIEW BEFORE SUBMITTING", draft.body)


if __name__ == "__main__":
    unittest.main()
