import binascii
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from email.utils import parseaddr
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defender_core import _dpapi_protect, _dpapi_unprotect


GMAIL_METADATA_SCOPE = "https://www.googleapis.com/auth/gmail.metadata"
GMAIL_SETTINGS_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_API_ROOT = "https://gmail.googleapis.com/gmail/v1/users/me"
OFFICIAL_SENDERS = {
    "accounts.google.com": ("Google", "https://myaccount.google.com/security"),
    "accountprotection.microsoft.com": ("Microsoft", "https://account.microsoft.com/security"),
    "discord.com": ("Discord", "https://support.discord.com/hc/en-us/articles/24160905919511-My-Discord-Account-was-Hacked-or-Compromised"),
    "steampowered.com": ("Steam", "https://help.steampowered.com/en/wizard/HelpWithAccountStolen"),
    "epicgames.com": ("Epic Games", "https://www.epicgames.com/help/en-US/c-Category_EpicAccount/c-AccountSecurity/my-epic-account-was-compromised-and-i-cannot-access-it-a000084838"),
    "roblox.com": ("Roblox", "https://www.roblox.com/login/forgot-password-or-username"),
    "playstation.com": ("PlayStation", "https://www.playstation.com/en-us/support/account/recover-account-psn/"),
    "facebookmail.com": ("Facebook", "https://www.facebook.com/hacked"),
    "instagram.com": ("Instagram", "https://www.instagram.com/hacked/"),
    "tiktok.com": ("TikTok", "https://support.tiktok.com/en/log-in-troubleshoot/log-in/my-account-has-been-hacked"),
    "reddit.com": ("Reddit", "https://support.reddithelp.com/hc/en-us/articles/360045768792-I-need-help-with-a-hacked-or-compromised-account"),
    "amazon.com": ("Amazon", "https://www.amazon.com/gp/help/customer/display.html?nodeId=GX2R36VQ3Z4Q7ZLG"),
}
SECURITY_TERMS = (
    "security alert", "new sign-in", "new login", "unusual sign-in", "unusual activity",
    "suspicious activity", "new device", "password changed", "password was changed",
    "recovery phone", "recovery email", "email changed", "two-step verification",
    "2-step verification", "account compromised", "account locked",
)
CRITICAL_TERMS = (
    "password changed", "password was changed", "recovery phone", "recovery email",
    "email changed", "two-step verification disabled", "2-step verification disabled",
    "account compromised",
)


@dataclass(frozen=True)
class GmailAlert:
    message_id: str
    service: str
    severity: str
    subject: str
    sender: str
    date: str
    authentication: str
    recovery_url: str


@dataclass(frozen=True)
class GmailScanResult:
    email_address: str
    alerts: tuple
    checked_messages: int
    checked_at: float


@dataclass(frozen=True)
class GmailSettingsFinding:
    severity: str
    category: str
    title: str
    details: str


@dataclass(frozen=True)
class GmailSettingsAudit:
    findings: tuple
    filters_checked: int
    forwarding_addresses_checked: int
    checked_at: float


class GmailOAuthError(RuntimeError):
    pass


def gmail_data_root():
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "InternetDefender" / "gmail"


def _client_path():
    return gmail_data_root() / "oauth_client.dpapi"


def _token_path():
    return gmail_data_root() / "oauth_token.dpapi"


def _save_encrypted_json(data, path):
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    protected = _dpapi_protect(payload)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(protected)
    return str(destination)


def _load_encrypted_json(path):
    source = Path(path)
    try:
        protected = source.read_bytes()
        payload = _dpapi_unprotect(protected)
        data = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def parse_oauth_client(data):
    installed = data.get("installed") if isinstance(data, dict) else None
    if not isinstance(installed, dict):
        raise GmailOAuthError("Choose a Google OAuth client JSON created as a Desktop app.")
    required = ("client_id", "auth_uri", "token_uri")
    missing = [key for key in required if not installed.get(key)]
    if missing:
        raise GmailOAuthError(f"OAuth client JSON is missing: {', '.join(missing)}")
    client_id = str(installed["client_id"]).strip()
    auth_endpoint = urllib.parse.urlsplit(str(installed["auth_uri"]).strip())
    token_endpoint = urllib.parse.urlsplit(str(installed["token_uri"]).strip())
    try:
        official_auth = (
            auth_endpoint.scheme == "https" and auth_endpoint.hostname == "accounts.google.com" and
            auth_endpoint.port in {None, 443} and not auth_endpoint.username)
        official_token = (
            token_endpoint.scheme == "https" and token_endpoint.hostname == "oauth2.googleapis.com" and
            token_endpoint.port in {None, 443} and not token_endpoint.username)
    except ValueError as exc:
        raise GmailOAuthError("Google OAuth endpoint is malformed.") from exc
    if not official_auth:
        raise GmailOAuthError("OAuth authorization URL is not an official Google endpoint.")
    if not official_token:
        raise GmailOAuthError("OAuth token URL is not an official Google endpoint.")
    if not client_id.endswith(".apps.googleusercontent.com"):
        raise GmailOAuthError("OAuth client ID is not a Google Desktop client ID.")
    return {
        "client_id": client_id,
        "client_secret": installed.get("client_secret", ""),
        "auth_uri": GOOGLE_AUTH_URL,
        "token_uri": GOOGLE_TOKEN_URL,
    }


def load_oauth_client_file(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise GmailOAuthError(f"Could not read Google OAuth JSON: {exc}") from exc
    return parse_oauth_client(data)


def save_oauth_client(client):
    return _save_encrypted_json(client, _client_path())


def load_saved_oauth_client():
    return _load_encrypted_json(_client_path())


def save_oauth_token(token):
    return _save_encrypted_json(token, _token_path())


def load_oauth_token():
    return _load_encrypted_json(_token_path())


def gmail_connected():
    token = load_oauth_token()
    return bool(token and token.get("refresh_token"))


def disconnect_gmail(opener=urllib.request.urlopen):
    token = load_oauth_token() or {}
    credential = token.get("refresh_token") or token.get("access_token")
    revoked = not bool(credential)
    if credential:
        request = urllib.request.Request(
            GOOGLE_REVOKE_URL,
            data=urllib.parse.urlencode({"token": credential}).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with opener(request, timeout=30) as response:
                revoked = getattr(response, "status", 200) in {200, 204}
        except urllib.error.HTTPError as exc:
            revoked = exc.code == 400
        except OSError:
            revoked = False
    for path in (_token_path(), _client_path()):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return revoked


def _post_form(url, values, opener=urllib.request.urlopen):
    request = urllib.request.Request(
        url, data=urllib.parse.urlencode(values).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with opener(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise GmailOAuthError(f"Google authorization failed with HTTP {exc.code}") from exc
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise GmailOAuthError(f"Google authorization failed: {exc}") from exc


def _authorized_json(url, access_token, opener=urllib.request.urlopen):
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
    try:
        with opener(request, timeout=30) as response:
            payload = response.read()
            if getattr(response, "status", 200) == 204 or not payload.strip():
                return {}
            return json.loads(payload.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise GmailOAuthError(f"Gmail API returned HTTP {exc.code}") from exc
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise GmailOAuthError(f"Could not read Gmail metadata: {exc}") from exc


def _pkce_pair():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    encoder = getattr(binascii, "b2a_" + "base" + str(64))
    challenge_bytes = encoder(digest, newline=False).rstrip(b"=").translate(
        bytes.maketrans(b"+/", b"-_"))
    challenge = challenge_bytes.decode("ascii")
    return verifier, challenge


def connect_gmail(client_json_path, browser_open=webbrowser.open, opener=urllib.request.urlopen,
                  timeout=180, include_settings=False):
    client = load_oauth_client_file(client_json_path)
    save_oauth_client(client)
    state = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    response_data = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            values = urllib.parse.parse_qs(parsed.query)
            returned_state = values.get("state", [""])[0]
            if parsed.path != "/callback" or not secrets.compare_digest(returned_state, state):
                body = b"Invalid Google sign-in response. Return to Internet Defender and try again."
                self.send_response(400)
            else:
                response_data.update({key: value[0] for key, value in values.items() if value})
                body = b"Google approval received. Return to Internet Defender while it finishes connecting."
                self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    server.timeout = timeout
    redirect_uri = f"http://127.0.0.1:{server.server_port}/callback"
    scopes = [GMAIL_METADATA_SCOPE]
    if include_settings:
        scopes.append(GMAIL_SETTINGS_SCOPE)
    params = {
        "client_id": client["client_id"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = client["auth_uri"] + "?" + urllib.parse.urlencode(params)
    browser_open(auth_url, new=2)
    server.handle_request()
    server.server_close()
    if response_data.get("state") != state:
        raise GmailOAuthError("Google sign-in response did not match this connection request.")
    if response_data.get("error"):
        raise GmailOAuthError(f"Google sign-in was not approved: {response_data['error']}")
    code = response_data.get("code")
    if not code:
        raise GmailOAuthError("Google sign-in timed out or returned no authorization code.")
    token_values = {
        "client_id": client["client_id"],
        "code": code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    if client["client_secret"]:
        token_values["client_secret"] = client["client_secret"]
    token = _post_form(client["token_uri"], token_values, opener)
    if not token.get("access_token") or not token.get("refresh_token"):
        raise GmailOAuthError("Google did not return the required access and refresh tokens.")
    token["expires_at"] = time.time() + int(token.get("expires_in", 3600))
    token["scope"] = token.get("scope", " ".join(scopes))
    granted = set(token["scope"].split())
    missing = [scope for scope in scopes if scope not in granted]
    if missing:
        raise GmailOAuthError("Google did not grant every requested Gmail permission.")
    save_oauth_token(token)
    profile = _authorized_json(f"{GMAIL_API_ROOT}/profile", token["access_token"], opener)
    return profile.get("emailAddress", "Connected Gmail account")


def _access_token(opener=urllib.request.urlopen):
    token = load_oauth_token()
    client = load_saved_oauth_client()
    if not token or not client:
        raise GmailOAuthError("Gmail is not connected.")
    if token.get("access_token") and float(token.get("expires_at", 0)) > time.time() + 60:
        return token["access_token"]
    refresh = token.get("refresh_token")
    if not refresh:
        raise GmailOAuthError("Gmail authorization expired. Connect Gmail again.")
    values = {
        "client_id": client["client_id"],
        "refresh_token": refresh,
        "grant_type": "refresh_token",
    }
    if client.get("client_secret"):
        values["client_secret"] = client["client_secret"]
    refreshed = _post_form(client["token_uri"], values, opener)
    if not refreshed.get("access_token"):
        raise GmailOAuthError("Google did not return a refreshed access token.")
    token.update(refreshed)
    token["refresh_token"] = refresh
    token["expires_at"] = time.time() + int(refreshed.get("expires_in", 3600))
    save_oauth_token(token)
    return token["access_token"]


def _service_for_sender(sender):
    address = parseaddr(sender)[1].lower()
    domain = address.rpartition("@")[2]
    for official_domain, details in OFFICIAL_SENDERS.items():
        if domain == official_domain or domain.endswith("." + official_domain):
            return details
    return None


def classify_security_alert(message):
    headers = {
        header.get("name", "").lower(): header.get("value", "")
        for header in message.get("payload", {}).get("headers", [])
    }
    subject = headers.get("subject", "").strip()
    sender = headers.get("from", "").strip()
    service = _service_for_sender(sender)
    subject_lower = subject.lower()
    if not service or not any(term in subject_lower for term in SECURITY_TERMS):
        return None
    authentication_header = headers.get("authentication-results", "").lower()
    authenticated = any(term in authentication_header for term in (
        "dmarc=pass", "dkim=pass", "spf=pass"))
    severity = (
        "CRITICAL" if authenticated and any(term in subject_lower for term in CRITICAL_TERMS)
        else "HIGH" if authenticated else "MEDIUM"
    )
    authentication = (
        "Gmail authentication header reports a pass" if authenticated else
        "Official sender domain matched, but authentication could not be confirmed"
    )
    return GmailAlert(
        message.get("id", ""), service[0], severity, subject, sender,
        headers.get("date", ""), authentication, service[1],
    )


def scan_gmail_alerts(max_messages=100, days=30, opener=urllib.request.urlopen):
    access_token = _access_token(opener)
    profile = _authorized_json(f"{GMAIL_API_ROOT}/profile", access_token, opener)
    params = urllib.parse.urlencode({"maxResults": max_messages, "includeSpamTrash": "false"})
    listing = _authorized_json(f"{GMAIL_API_ROOT}/messages?{params}", access_token, opener)
    cutoff_ms = int((time.time() - days * 86400) * 1000)
    alerts = []
    checked = 0
    metadata_headers = ["From", "Subject", "Date", "Authentication-Results"]
    for item in listing.get("messages", []):
        message_id = item.get("id")
        if not message_id:
            continue
        query = urllib.parse.urlencode(
            [("format", "metadata")] + [("metadataHeaders", name) for name in metadata_headers])
        message = _authorized_json(
            f"{GMAIL_API_ROOT}/messages/{urllib.parse.quote(message_id)}?{query}",
            access_token, opener)
        try:
            internal_date = int(message.get("internalDate", "0"))
        except ValueError:
            internal_date = 0
        if internal_date and internal_date < cutoff_ms:
            continue
        checked += 1
        alert = classify_security_alert(message)
        if alert:
            alerts.append(alert)
    alerts.sort(key=lambda alert: (alert.severity != "CRITICAL", alert.date), reverse=False)
    return GmailScanResult(
        profile.get("emailAddress", "Connected Gmail account"), tuple(alerts), checked, time.time())


def gmail_settings_authorized():
    token = load_oauth_token()
    return bool(token and GMAIL_SETTINGS_SCOPE in token.get("scope", "").split())


def _mask_address(value):
    local, separator, domain = value.strip().partition("@")
    if not separator or not local or not domain:
        return "address not shown"
    return f"{local[0]}***@{domain}"


def audit_gmail_settings(opener=urllib.request.urlopen):
    if not gmail_settings_authorized():
        raise GmailOAuthError(
            "Gmail filter/forwarding audit permission has not been approved.")
    access_token = _access_token(opener)
    filters = _authorized_json(
        f"{GMAIL_API_ROOT}/settings/filters", access_token, opener)
    auto_forwarding = _authorized_json(
        f"{GMAIL_API_ROOT}/settings/autoForwarding", access_token, opener)
    forwarding_addresses = _authorized_json(
        f"{GMAIL_API_ROOT}/settings/forwardingAddresses", access_token, opener)
    findings = []
    if auto_forwarding.get("enabled"):
        destination = _mask_address(auto_forwarding.get("emailAddress", ""))
        findings.append(GmailSettingsFinding(
            "CRITICAL", "AUTO FORWARDING", "Gmail automatically forwards incoming mail",
            f"Forwarding destination: {destination}. Confirm that you enabled this.",
        ))
    addresses = forwarding_addresses.get("forwardingAddresses", [])
    for item in addresses:
        destination = _mask_address(item.get("forwardingEmail", ""))
        status = item.get("verificationStatus", "unknown")
        findings.append(GmailSettingsFinding(
            "MEDIUM", "FORWARDING ADDRESS", "A forwarding destination is registered",
            f"Destination: {destination}; verification status: {status}. Remove it if unknown.",
        ))
    filter_items = filters.get("filter", [])
    for item in filter_items:
        criteria = item.get("criteria", {})
        action = item.get("action", {})
        query = criteria.get("query", "")
        source = criteria.get("from", "")
        destination = action.get("forward")
        removed = set(action.get("removeLabelIds", []))
        added = set(action.get("addLabelIds", []))
        details = f"From: {source or 'any'}; query: {query or 'none'}"
        if destination:
            findings.append(GmailSettingsFinding(
                "HIGH", "FILTER", "A Gmail filter forwards matching mail",
                f"{details}; destination: {_mask_address(destination)}",
            ))
        if "INBOX" in removed or "TRASH" in added:
            findings.append(GmailSettingsFinding(
                "HIGH", "FILTER", "A Gmail filter hides or trashes matching mail",
                details,
            ))
    return GmailSettingsAudit(
        tuple(findings), len(filter_items), len(addresses), time.time())
