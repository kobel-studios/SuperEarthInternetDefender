import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defender_core import _dpapi_protect, _dpapi_unprotect


CHECKLIST_STEPS = (
    "password_changed",
    "sessions_removed",
    "recovery_details_checked",
    "connected_apps_reviewed",
    "mfa_enabled",
    "payments_reviewed",
    "post_recovery_verified",
)
PROVIDER_PLANS = {
    "Google": {
        "recovery": "https://accounts.google.com/signin/recovery",
        "security": "https://myaccount.google.com/security-checkup",
        "devices": "https://myaccount.google.com/device-activity",
        "connected_apps": "https://myaccount.google.com/connections",
        "payments": "https://payments.google.com/",
    },
    "Microsoft": {
        "recovery": "https://account.live.com/password/reset",
        "security": "https://account.microsoft.com/security",
        "devices": "https://account.microsoft.com/devices",
        "connected_apps": "https://account.live.com/consent/Manage",
        "payments": "https://account.microsoft.com/billing/orders",
    },
    "Discord": {
        "recovery": "https://support.discord.com/hc/en-us/articles/24160905919511-My-Discord-Account-was-Hacked-or-Compromised",
        "security": "https://discord.com/settings/devices",
        "devices": "https://discord.com/settings/devices",
        "connected_apps": "https://discord.com/settings/authorized-apps",
        "payments": "https://discord.com/settings/billing",
    },
    "Steam": {
        "recovery": "https://help.steampowered.com/en/wizard/HelpWithAccountStolen",
        "security": "https://store.steampowered.com/twofactor/manage",
        "devices": "https://store.steampowered.com/account/authorizeddevices",
        "connected_apps": "https://steamcommunity.com/dev/apikey",
        "payments": "https://store.steampowered.com/account/history/",
    },
    "Epic Games": {
        "recovery": "https://www.epicgames.com/help/en-US/c-Category_EpicAccount/c-AccountSecurity/my-epic-account-was-compromised-and-i-cannot-access-it-a000084838",
        "security": "https://www.epicgames.com/account/password",
        "devices": "https://www.epicgames.com/account/connections",
        "connected_apps": "https://www.epicgames.com/account/connections",
        "payments": "https://www.epicgames.com/account/transactions",
    },
    "Roblox": {
        "recovery": "https://www.roblox.com/login/forgot-password-or-username",
        "security": "https://www.roblox.com/my/account#!/security",
        "devices": "https://www.roblox.com/my/account#!/security",
        "connected_apps": "https://www.roblox.com/my/account#!/security",
        "payments": "https://www.roblox.com/transactions",
    },
    "PlayStation": {
        "recovery": "https://www.playstation.com/en-us/support/account/recover-account-psn/",
        "security": "https://www.playstation.com/en-us/support/account/security-best-practice-psn/",
        "devices": "https://www.playstation.com/en-us/support/account/deactivate-playstation-console/",
        "connected_apps": "https://www.playstation.com/en-us/support/account/link-social-streaming-service-playstation/",
        "payments": "https://www.playstation.com/en-us/support/store/check-ps-store-transaction-subscription-service/",
    },
    "Facebook": {
        "recovery": "https://www.facebook.com/hacked",
        "security": "https://www.facebook.com/settings?tab=security",
        "devices": "https://www.facebook.com/settings?tab=security",
        "connected_apps": "https://www.facebook.com/settings?tab=applications",
        "payments": "https://www.facebook.com/settings?tab=payments",
    },
    "Instagram": {
        "recovery": "https://www.instagram.com/hacked/",
        "security": "https://www.instagram.com/accounts/password/change/",
        "devices": "https://www.instagram.com/accounts/login_activity/",
        "connected_apps": "https://www.instagram.com/accounts/manage_access/",
        "payments": "https://www.instagram.com/accounts/payments/",
    },
    "TikTok": {
        "recovery": "https://support.tiktok.com/en/log-in-troubleshoot/log-in/my-account-has-been-hacked",
        "security": "https://www.tiktok.com/setting/security",
        "devices": "https://www.tiktok.com/setting/security",
        "connected_apps": "https://www.tiktok.com/setting/security",
        "payments": "https://www.tiktok.com/setting/balance",
    },
    "Reddit": {
        "recovery": "https://support.reddithelp.com/hc/en-us/articles/360045768792-I-need-help-with-a-hacked-or-compromised-account",
        "security": "https://www.reddit.com/settings/safety",
        "devices": "https://www.reddit.com/account-activity",
        "connected_apps": "https://www.reddit.com/prefs/apps",
        "payments": "https://www.reddit.com/settings/premium",
    },
    "Amazon": {
        "recovery": "https://www.amazon.com/gp/help/customer/display.html?nodeId=GX2R36VQ3Z4Q7ZLG",
        "security": "https://www.amazon.com/a/settings/approval",
        "devices": "https://www.amazon.com/hz/mycd/digital-console/alldevices",
        "connected_apps": "https://www.amazon.com/hz/mycd/myx?pageType=content",
        "payments": "https://www.amazon.com/gp/css/order-history",
    },
}


@dataclass(frozen=True)
class AccountRecord:
    id: str
    service: str
    account_label: str
    recovery_channel: str
    notes: str
    created_at: float


@dataclass(frozen=True)
class KnownDevice:
    id: str
    service: str
    device_name: str
    notes: str
    created_at: float


@dataclass(frozen=True)
class RecoveryProgress:
    account_id: str
    steps: dict
    updated_at: float


@dataclass(frozen=True)
class PostRecoveryResult:
    serious_local_findings: int
    serious_network_findings: int
    unrecognized_remote_access: int
    incomplete_checklists: int
    secured: bool


@dataclass(frozen=True)
class AccountCandidate:
    account_id: str
    service: str
    account_label: str
    certainty: str
    reason: str


@dataclass(frozen=True)
class StolenAccountReportDraft:
    service: str
    account_label: str
    title: str
    body: str
    submission_url: str


def liberation_root():
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "InternetDefender" / "account_liberation"


def _store_path(name):
    return liberation_root() / f"{name}.dpapi"


def _load_store(name, default):
    path = _store_path(name)
    try:
        payload = _dpapi_unprotect(path.read_bytes())
        data = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return default
    return data


def _save_store(name, data):
    path = _store_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    path.write_bytes(_dpapi_protect(payload))
    return str(path)


def list_accounts():
    return tuple(AccountRecord(**item) for item in _load_store("accounts", []))


def add_account(service, account_label, recovery_channel="Gmail", notes=""):
    service = service.strip()
    account_label = account_label.strip()
    if not service or not account_label:
        raise ValueError("Service and account label are required.")
    accounts = list(list_accounts())
    record = AccountRecord(
        uuid.uuid4().hex, service, account_label, recovery_channel.strip(), notes.strip(), time.time())
    accounts.append(record)
    _save_store("accounts", [asdict(item) for item in accounts])
    return record


def remove_account(account_id):
    accounts = [item for item in list_accounts() if item.id != account_id]
    _save_store("accounts", [asdict(item) for item in accounts])
    progress = _load_store("progress", {})
    progress.pop(account_id, None)
    _save_store("progress", progress)
    return True


def list_known_devices():
    return tuple(KnownDevice(**item) for item in _load_store("devices", []))


def add_known_device(service, device_name, notes=""):
    service = service.strip()
    device_name = device_name.strip()
    if not service or not device_name:
        raise ValueError("Service and device name are required.")
    devices = list(list_known_devices())
    record = KnownDevice(uuid.uuid4().hex, service, device_name, notes.strip(), time.time())
    devices.append(record)
    _save_store("devices", [asdict(item) for item in devices])
    return record


def remove_known_device(device_id):
    devices = [item for item in list_known_devices() if item.id != device_id]
    _save_store("devices", [asdict(item) for item in devices])
    return True


def checklist_for(account_id):
    stored = _load_store("progress", {})
    values = stored.get(account_id, {})
    return RecoveryProgress(
        account_id,
        {step: bool(values.get(step, False)) for step in CHECKLIST_STEPS},
        float(values.get("updated_at", 0)),
    )


def save_checklist(account_id, steps):
    stored = _load_store("progress", {})
    values = {step: bool(steps.get(step, False)) for step in CHECKLIST_STEPS}
    values["updated_at"] = time.time()
    stored[account_id] = values
    _save_store("progress", stored)
    return checklist_for(account_id)


def checklist_completion(progress):
    completed = sum(bool(progress.steps.get(step)) for step in CHECKLIST_STEPS)
    return completed, len(CHECKLIST_STEPS)


def provider_plan(service):
    for name, plan in PROVIDER_PLANS.items():
        if name.lower() == service.strip().lower():
            return name, dict(plan)
    return service.strip() or "Other", {
        "recovery": "",
        "security": "",
        "devices": "",
        "connected_apps": "",
        "payments": "",
    }


def prioritize_alert(alert):
    subject = alert.subject.lower()
    if any(term in subject for term in (
            "password changed", "recovery phone", "recovery email", "email changed",
            "2-step verification disabled", "two-step verification disabled")):
        return "RECOVERY DETAILS CHANGED", 100
    if any(term in subject for term in (
            "purchase", "payment", "transaction", "order", "charge")):
        return "PAYMENT WARNING", 85
    if any(term in subject for term in (
            "new sign-in", "new login", "unusual", "suspicious", "new device")):
        return "LOGIN WARNING", 70
    return "SECURITY WARNING", 50


def blast_radius(accounts, alerts):
    affected_services = {alert.service.lower() for alert in alerts}
    results = []
    for account in accounts:
        directly_alerted = account.service.lower() in affected_services
        if directly_alerted:
            results.append({
                "account_id": account.id,
                "service": account.service,
                "account_label": account.account_label,
                "reason": "An official security alert named this service.",
            })
    known = {item["service"].lower() for item in results}
    for alert in alerts:
        if alert.service.lower() not in known:
            results.append({
                "account_id": "",
                "service": alert.service,
                "account_label": "Not in encrypted inventory",
                "reason": "An official security alert named this service.",
            })
            known.add(alert.service.lower())
    return tuple(results)


def discover_account_candidates(accounts, alerts, broad_local_risk=False):
    accounts = tuple(accounts)
    alerts = tuple(alerts)
    candidates = []
    seen_accounts = set()
    services = tuple(dict.fromkeys(alert.service for alert in alerts))
    for service in services:
        matches = [account for account in accounts if account.service.lower() == service.lower()]
        if matches:
            certainty = "LIKELY MATCH" if len(matches) == 1 else "NEEDS CONFIRMATION"
            reason = (
                "One encrypted inventory account matches the officially alerted service." if len(matches) == 1 else
                "Several encrypted inventory accounts match the officially alerted service."
            )
            for account in matches:
                seen_accounts.add(account.id)
                candidates.append(AccountCandidate(
                    account.id, account.service, account.account_label, certainty, reason))
        else:
            candidates.append(AccountCandidate(
                "", service, "Not in encrypted inventory", "ACCOUNT UNKNOWN",
                "An official security alert named this service, but no saved account label matched."))
    gmail_recovery_at_risk = any(alert.service.lower() == "google" for alert in alerts)
    for account in accounts:
        if account.id in seen_accounts:
            continue
        if gmail_recovery_at_risk and "gmail" in account.recovery_channel.lower():
            candidates.append(AccountCandidate(
                account.id, account.service, account.account_label, "POSSIBLE RECOVERY RISK",
                "Google security was alerted and this account uses Gmail as a recovery channel."))
            seen_accounts.add(account.id)
        elif broad_local_risk:
            candidates.append(AccountCandidate(
                account.id, account.service, account.account_label, "POSSIBLE LOCAL RISK",
                "Serious clues on this PC could expose accounts used on the computer."))
            seen_accounts.add(account.id)
    return tuple(candidates)


def build_stolen_account_report(account, alerts, evidence=None):
    evidence = dict(evidence or {})
    service, plan = provider_plan(account.service)
    relevant_alerts = [alert for alert in alerts if alert.service.lower() == service.lower()]
    lines = [
        "STOLEN ACCOUNT REPORT DRAFT — REVIEW BEFORE SUBMITTING",
        "",
        f"Service: {service}",
        f"Account label: {account.account_label}",
        "",
        "Reason for report:",
        "I may have experienced unauthorized access to this account. Please help me verify ownership, "
        "secure the account, and revoke sessions or connected apps I do not recognize.",
        "",
        "Official security alerts found:",
    ]
    if relevant_alerts:
        for alert in relevant_alerts[:10]:
            subject = " ".join(str(alert.subject).split())[:300]
            date = " ".join(str(alert.date or "date not shown").split())[:120]
            lines.append(f"- {alert.severity}: {subject} ({date})")
    else:
        lines.append("- No provider-specific email alert was available; local security clues triggered review.")
    lines.extend([
        "",
        "Local safety summary:",
        f"- Serious local findings: {int(evidence.get('serious_local_count', 0))}",
        f"- Serious network findings: {int(evidence.get('serious_network_count', 0))}",
        f"- Unrecognized remote-access findings: {int(evidence.get('unrecognized_remote_count', 0))}",
        f"- Serious Gmail settings findings: {int(evidence.get('serious_settings_count', 0))}",
        "",
        "Requested help:",
        "- Check for unauthorized password, recovery-detail, device, session, connected-app, and purchase changes.",
        "- Restore the account to its rightful owner and revoke access that the owner does not approve.",
        "",
        "No password, verification code, API key, browser cookie, or session token is included in this draft.",
        "Review every line before submitting it through the provider's official page.",
    ])
    return StolenAccountReportDraft(
        service, account.account_label, f"Possible stolen {service} account", "\n".join(lines),
        plan.get("recovery") or plan.get("security") or "",
    )


def post_recovery_result(local_findings, network_findings, remote_findings, accounts):
    serious_local = sum(
        getattr(item, "severity", "") in {"HIGH", "CRITICAL"} for item in local_findings)
    serious_network = sum(
        item.get("severity") in {"HIGH", "CRITICAL"} for item in network_findings)
    incomplete = 0
    for account in accounts:
        completed, total = checklist_completion(checklist_for(account.id))
        if completed < total:
            incomplete += 1
    secured = not serious_local and not serious_network and not remote_findings and not incomplete
    return PostRecoveryResult(
        serious_local, serious_network, len(remote_findings), incomplete, secured)


def save_encrypted_recovery_report(data, root=None):
    report_root = Path(root or liberation_root() / "reports")
    report_root.mkdir(parents=True, exist_ok=True)
    report = {
        "created_at": time.time(),
        "notice": (
            "Encrypted local recovery record. It contains no passwords or verification codes and was not submitted automatically."
        ),
        "data": data,
    }
    payload = json.dumps(report, separators=(",", ":")).encode("utf-8")
    path = report_root / f"recovery_{int(report['created_at'])}.dpapi"
    path.write_bytes(_dpapi_protect(payload))
    return str(path)


def load_encrypted_recovery_report(path):
    payload = _dpapi_unprotect(Path(path).read_bytes())
    return json.loads(payload.decode("utf-8"))
