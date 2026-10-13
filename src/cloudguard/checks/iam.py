"""
checks/iam.py - identity checks (who can log in, and how)
=========================================================

What is this file?
    Five checks on IAM (Identity and Access Management, the AWS
    service for users, passwords, keys, and permissions).

Why does it matter?
    Most AWS breaches start with a stolen password or access key.
    These checks look for the classic weak spots: root without MFA,
    root access keys, users without MFA, old keys, weak passwords.

Requirements covered: 2.1 - 2.5
"""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudguard.checks.base import AuditContext, CheckInfo, error_code
from cloudguard.models import Finding, Severity


# ============================================================
# SECTION 1: Check descriptions
# ------------------------------------------------------------
# Each CheckInfo says what we check, how bad a failure is,
# which CIS AWS Foundations Benchmark v3.0.0 control it maps
# to, and how to fix it.
# ============================================================

ROOT_MFA = CheckInfo(
    "IAM-01", "Root account has MFA enabled", Severity.CRITICAL, "1.5",
    "Sign in as root and enable a hardware or virtual MFA device.",
)
ROOT_KEYS = CheckInfo(
    "IAM-02", "Root account has no access keys", Severity.CRITICAL, "1.4",
    "Delete root access keys. Use IAM roles or users for API access.",
)
USER_MFA = CheckInfo(
    "IAM-03", "Console users have MFA enabled", Severity.HIGH, "1.10",
    "Enable MFA for every IAM user that has a console password.",
)
KEY_AGE = CheckInfo(
    "IAM-04", "Access keys are rotated within 90 days", Severity.MEDIUM, "1.14",
    "Create a new key, update apps to use it, then deactivate and delete the old one.",
)
PASSWORD_POLICY = CheckInfo(
    "IAM-05", "Password policy requires 14+ characters", Severity.MEDIUM, "1.8",
    "Set an account password policy with MinimumPasswordLength >= 14.",
)

MAX_KEY_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14


# ============================================================
# SECTION 2: Root account checks (IAM-01, IAM-02)
# ------------------------------------------------------------
# "Root" is the email login that created the AWS account. It
# can do anything and can't be restricted, so it must have MFA
# and should never have API keys.
# GetAccountSummary returns simple counters for both:
#   AccountMFAEnabled        = 1 if root has MFA
#   AccountAccessKeysPresent = 1 if root has access keys
# ============================================================

def _account_summary(ctx: AuditContext) -> dict:
    # Cache it, because both root checks need the same data.
    if "account_summary" not in ctx.cache:
        resp = ctx.client("iam").get_account_summary()
        ctx.cache["account_summary"] = resp["SummaryMap"]
    return ctx.cache["account_summary"]


def check_root_mfa(ctx: AuditContext) -> list[Finding]:
    enabled = _account_summary(ctx).get("AccountMFAEnabled", 0) == 1
    if enabled:
        return [ROOT_MFA.passed("root")]
    return [ROOT_MFA.failed("root", "Root user has no MFA device.")]


def check_root_keys(ctx: AuditContext) -> list[Finding]:
    has_keys = _account_summary(ctx).get("AccountAccessKeysPresent", 0) > 0
    if has_keys:
        return [ROOT_KEYS.failed("root", "Root user has at least one access key.")]
    return [ROOT_KEYS.passed("root")]


# ============================================================
# SECTION 3: The credential report (used by IAM-03, IAM-04)
# ------------------------------------------------------------
# The credential report is a CSV file AWS builds with one row
# per user: has a password? has MFA? key ages? It's the cheapest
# way to see every user at once (2 API calls, not 1 per user).
#
# Step 1: ask AWS to generate it (it may take a few seconds)
# Step 2: poll until it's COMPLETE
# Step 3: download and parse the CSV
# ============================================================

def _credential_report(ctx: AuditContext) -> list[dict]:
    if "credential_report" in ctx.cache:
        return ctx.cache["credential_report"]

    iam = ctx.client("iam")

    # Steps 1 and 2: generate and wait (max ~10 seconds).
    for _attempt in range(10):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(1)

    # Step 3: download and parse.
    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    rows = list(csv.DictReader(io.StringIO(text)))

    # The root user is covered by IAM-01/02, so skip its row here.
    rows = [r for r in rows if r.get("user") != "<root_account>"]
    ctx.cache["credential_report"] = rows
    return rows


def check_user_mfa(ctx: AuditContext) -> list[Finding]:
    rows = _credential_report(ctx)

    # A user "has console access" if they have a password.
    console_users = [r for r in rows if r.get("password_enabled") == "true"]
    findings = [
        USER_MFA.failed(f"iam-user/{r['user']}", "Console password set, MFA not active.")
        for r in console_users
        if r.get("mfa_active") != "true"
    ]
    if not findings:
        findings.append(USER_MFA.passed("iam-users", f"{len(console_users)} console user(s) checked."))
    return findings


def _parse_aws_time(value: str | None) -> datetime | None:
    """The report uses ISO 8601 times, or 'N/A' when there's no value."""
    if not value or value in ("N/A", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_key_age(ctx: AuditContext) -> list[Finding]:
    rows = _credential_report(ctx)
    now = datetime.now(timezone.utc)
    findings: list[Finding] = []
    active_keys = 0

    # Each user can have up to 2 access keys: key 1 and key 2.
    for row in rows:
        for n in (1, 2):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            active_keys += 1
            rotated = _parse_aws_time(row.get(f"access_key_{n}_last_rotated"))
            if rotated and (now - rotated).days > MAX_KEY_AGE_DAYS:
                age = (now - rotated).days
                findings.append(KEY_AGE.failed(
                    f"iam-user/{row['user']}/key{n}", f"Key is {age} days old.",
                ))

    if not findings:
        findings.append(KEY_AGE.passed("access-keys", f"{active_keys} active key(s) checked."))
    return findings


# ============================================================
# SECTION 4: Password policy (IAM-05)
# ------------------------------------------------------------
# If no policy exists, AWS answers with the error "NoSuchEntity".
# That's a FAIL, not an ERROR: "no policy" is the insecure state.
# ============================================================

def check_password_policy(ctx: AuditContext) -> list[Finding]:
    try:
        policy = ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            return [PASSWORD_POLICY.failed("password-policy", "No password policy is set.")]
        raise

    length = policy.get("MinimumPasswordLength", 0)
    if length < MIN_PASSWORD_LENGTH:
        return [PASSWORD_POLICY.failed("password-policy", f"Minimum length is {length}.")]
    return [PASSWORD_POLICY.passed("password-policy", f"Minimum length is {length}.")]


# ============================================================
# SECTION 5: Export list for the registry
# ============================================================

CHECKS = [
    (ROOT_MFA, check_root_mfa),
    (ROOT_KEYS, check_root_keys),
    (USER_MFA, check_user_mfa),
    (KEY_AGE, check_key_age),
    (PASSWORD_POLICY, check_password_policy),
]
