import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gmail_alerts import (
    GMAIL_METADATA_SCOPE,
    GMAIL_SETTINGS_SCOPE,
    GmailAlert,
    GmailOAuthError,
    _authorized_json,
    _load_encrypted_json,
    _pkce_pair,
    _save_encrypted_json,
    audit_gmail_settings,
    classify_security_alert,
    disconnect_gmail,
    parse_oauth_client,
    scan_gmail_alerts,
)
from internet_defender import mask_email_address, recovery_pages_for_alerts


class FakeResponse:
    def __init__(self, payload=b"{}", status=200):
        self.payload = payload
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class OAuthConfigTests(unittest.TestCase):
    def test_accepts_google_desktop_client(self):
        client = parse_oauth_client({"installed": {
            "client_id": "example.apps.googleusercontent.com",
            "client_secret": "test-secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }})
        self.assertEqual(client["client_id"], "example.apps.googleusercontent.com")

    def test_rejects_non_google_endpoints(self):
        with self.assertRaises(GmailOAuthError):
            parse_oauth_client({"installed": {
                "client_id": "x", "auth_uri": "https://example.invalid/auth",
                "token_uri": "https://example.invalid/token",
            }})

    def test_rejects_lookalike_google_endpoint(self):
        with self.assertRaises(GmailOAuthError):
            parse_oauth_client({"installed": {
                "client_id": "example.apps.googleusercontent.com",
                "auth_uri": "https://accounts.google.com.example.invalid/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }})

    def test_empty_gmail_response_is_an_empty_result(self):
        result = _authorized_json(
            "https://gmail.googleapis.com/gmail/v1/users/me/settings/filters", "token",
            opener=lambda *_args, **_kwargs: FakeResponse(b"", 204),
        )
        self.assertEqual(result, {})

    def test_pkce_values_are_unique(self):
        first = _pkce_pair()
        second = _pkce_pair()
        self.assertNotEqual(first, second)
        self.assertGreater(len(first[0]), 40)
        self.assertGreater(len(first[1]), 40)

    def test_json_is_saved_only_as_protected_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "token.dpapi"
            with patch("gmail_alerts._dpapi_protect", return_value=b"protected"):
                _save_encrypted_json({"access_token": "secret-token"}, path)
            self.assertEqual(path.read_bytes(), b"protected")
            self.assertNotIn(b"secret-token", path.read_bytes())
            with patch(
                    "gmail_alerts._dpapi_unprotect",
                    return_value=b'{"access_token":"secret-token"}'):
                self.assertEqual(_load_encrypted_json(path)["access_token"], "secret-token")

    def test_disconnect_revokes_google_access_and_removes_local_files(self):
        with tempfile.TemporaryDirectory() as folder:
            token_path = Path(folder) / "token.dpapi"
            client_path = Path(folder) / "client.dpapi"
            token_path.write_bytes(b"encrypted-token")
            client_path.write_bytes(b"encrypted-client")
            requests = []

            def opener(request, timeout):
                requests.append((request, timeout))
                return FakeResponse(b"", 200)

            with patch("gmail_alerts.load_oauth_token", return_value={"refresh_token": "token"}), \
                    patch("gmail_alerts._token_path", return_value=token_path), \
                    patch("gmail_alerts._client_path", return_value=client_path):
                self.assertTrue(disconnect_gmail(opener))
            self.assertFalse(token_path.exists())
            self.assertFalse(client_path.exists())
            self.assertEqual(requests[0][0].full_url, "https://oauth2.googleapis.com/revoke")
            self.assertEqual(requests[0][0].method, "POST")


class AlertClassificationTests(unittest.TestCase):
    @staticmethod
    def _message(sender, subject, authentication="dkim=pass header.i=@accounts.google.com"):
        return {
            "id": "message-1",
            "internalDate": "9999999999999",
            "payload": {"headers": [
                {"name": "From", "value": sender},
                {"name": "Subject", "value": subject},
                {"name": "Date", "value": "today"},
                {"name": "Authentication-Results", "value": authentication},
            ]},
        }

    def test_authenticated_password_change_is_critical(self):
        alert = classify_security_alert(self._message(
            "Google <no-reply@accounts.google.com>", "Your password changed"))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.service, "Google")
        self.assertEqual(alert.severity, "CRITICAL")

    def test_unconfirmed_authentication_is_medium(self):
        alert = classify_security_alert(self._message(
            "Google <no-reply@accounts.google.com>", "New sign-in", ""))
        self.assertEqual(alert.severity, "MEDIUM")

    def test_lookalike_sender_is_rejected(self):
        alert = classify_security_alert(self._message(
            "Fake <no-reply@accounts.google.com.example.invalid>", "Security alert"))
        self.assertIsNone(alert)

    def test_normal_official_email_is_ignored(self):
        alert = classify_security_alert(self._message(
            "Google <no-reply@accounts.google.com>", "Your monthly summary"))
        self.assertIsNone(alert)


class GmailScanTests(unittest.TestCase):
    def test_scan_requests_metadata_and_returns_alert(self):
        profile = {"emailAddress": "player@gmail.com"}
        listing = {"messages": [{"id": "message-1"}]}
        message = AlertClassificationTests._message(
            "Discord <noreply@discord.com>", "New login detected",
            "dmarc=pass header.from=discord.com")
        with patch("gmail_alerts._access_token", return_value="access"), \
                patch("gmail_alerts._authorized_json", side_effect=[profile, listing, message]) as request:
            result = scan_gmail_alerts()
        self.assertEqual(result.email_address, "player@gmail.com")
        self.assertEqual(len(result.alerts), 1)
        self.assertEqual(result.alerts[0].service, "Discord")
        requested_url = request.call_args_list[-1].args[0]
        self.assertIn("format=metadata", requested_url)
        self.assertIn("metadataHeaders=Subject", requested_url)

    def test_scope_is_metadata_only(self):
        self.assertEqual(GMAIL_METADATA_SCOPE, "https://www.googleapis.com/auth/gmail.metadata")
        source = Path(__file__).with_name("gmail_alerts.py").read_text(encoding="utf-8")
        self.assertNotIn("gmail.readonly", source)
        self.assertNotIn("gmail.modify", source)


class GmailSettingsAuditTests(unittest.TestCase):
    def test_filter_and_forwarding_audit_is_get_only_and_flags_risk(self):
        filters = {"filter": [
            {"criteria": {"query": "security alert"},
             "action": {"forward": "unknown@example.com"}},
            {"criteria": {"from": "accounts.google.com"},
             "action": {"removeLabelIds": ["INBOX"], "addLabelIds": ["TRASH"]}},
        ]}
        auto = {"enabled": True, "emailAddress": "unknown@example.com"}
        addresses = {"forwardingAddresses": [
            {"forwardingEmail": "unknown@example.com", "verificationStatus": "accepted"}
        ]}
        with patch("gmail_alerts.gmail_settings_authorized", return_value=True), \
                patch("gmail_alerts._access_token", return_value="access"), \
                patch("gmail_alerts._authorized_json", side_effect=[filters, auto, addresses]) as request:
            result = audit_gmail_settings()
        self.assertEqual(result.filters_checked, 2)
        self.assertEqual(result.forwarding_addresses_checked, 1)
        self.assertTrue(any(item.severity == "CRITICAL" for item in result.findings))
        self.assertTrue(all(call.args[0].startswith("https://gmail.googleapis.com/")
                            for call in request.call_args_list))

    def test_settings_scope_is_separate_and_does_not_allow_mail_body_reading(self):
        self.assertEqual(
            GMAIL_SETTINGS_SCOPE,
            "https://www.googleapis.com/auth/gmail.settings.basic")
        self.assertNotEqual(GMAIL_SETTINGS_SCOPE, GMAIL_METADATA_SCOPE)


class AccountLiberationTests(unittest.TestCase):
    @staticmethod
    def _alert(service, recovery_url):
        return GmailAlert(
            "message", service, "HIGH", "New login detected", "official@example.com",
            "today", "authenticated", recovery_url,
        )

    def test_email_address_is_masked_before_display(self):
        self.assertEqual(mask_email_address("player@gmail.com"), "p*****@gmail.com")
        self.assertEqual(mask_email_address("invalid"), "Connected Gmail account")

    def test_google_alert_expands_to_full_recovery_sequence(self):
        pages = recovery_pages_for_alerts((
            self._alert("Google", "https://myaccount.google.com/security"),
        ))
        self.assertGreaterEqual(len(pages), 6)
        self.assertIn(
            ("Sign out unknown devices", "https://myaccount.google.com/device-activity"), pages)
        self.assertTrue(any(name == "Review connected apps" for name, _url in pages))
        self.assertTrue(any(name == "Review purchases and payments" for name, _url in pages))

    def test_duplicate_service_recovery_pages_are_opened_once(self):
        url = "https://support.discord.com/account-recovery"
        alert = self._alert("Discord", url)
        pages = recovery_pages_for_alerts((alert, alert))
        urls = [page_url for _name, page_url in pages]
        self.assertEqual(urls.count(url), 1)
        self.assertEqual(len(urls), len(set(urls)))


if __name__ == "__main__":
    unittest.main()
