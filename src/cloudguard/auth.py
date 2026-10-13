"""
auth.py - MFA login and the read-only audit role
================================================

What is this file?
    The code that turns "a person with an MFA code" into
    "a 15-minute, read-only AWS session".

How it works (the whole flow in 5 steps):
    1. Load your normal AWS login ("base credentials"). It is
       guarded so it can ONLY ask STS for the audit role.
    2. You type a 6-digit MFA code (hidden, never saved).
    3. We call STS AssumeRole with that code. AWS checks the code
       and the role's trust policy, then returns temporary keys
       that expire in 15 minutes.
    4. We build a new boto3 session from those keys, in memory only,
       and attach the read-only guard to it.
    5. We ask AWS "who am I now?" and confirm we really are the
       audit role. If not, we refuse to continue.

Requirements covered: 1.1 - 1.6, 8.7, 9.3, 11.1 - 11.4
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime

import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

from cloudguard.guard import AUDIT_OPERATIONS, BASE_OPERATIONS, install_guard


# ============================================================
# SECTION 1: Settings and constants
# ============================================================

# SECURITY: 900 seconds (15 min) is the SHORTEST session STS allows.
# Short sessions mean stolen keys stop working quickly.
SESSION_SECONDS = 900

# An MFA code is exactly 6 digits. We reject anything else
# before sending it to AWS.
MFA_CODE_PATTERN = re.compile(r"^\d{6}$")

# Every role session we create is named "cloudguard-<time>".
# The name shows up in CloudTrail, so admins can see exactly
# when cloudguard was used.
SESSION_NAME_PREFIX = "cloudguard-"


# ============================================================
# SECTION 2: Data shapes and errors
# ------------------------------------------------------------
# AuthConfig   = what we need to log in (none of it is secret)
# AuditSession = what we get after logging in (secret, memory only)
# ============================================================

@dataclass(frozen=True)
class AuthConfig:
    role_arn: str        # e.g. arn:aws:iam::123456789012:role/CloudGuardAuditRole
    mfa_serial: str      # e.g. arn:aws:iam::123456789012:mfa/your-device
    region: str          # e.g. us-east-1
    profile: str | None  # AWS CLI profile for base credentials (None = default chain)


@dataclass
class AuditSession:
    # SECURITY: this session holds the temporary keys. It is never
    # written to disk, env vars, or ~/.aws. Locking the app drops it.
    boto_session: boto3.Session
    account_id: str
    expires_at: datetime   # when AWS will reject these keys


class AuthConfigError(Exception):
    """Setup problem (no credentials, bad profile). Exit code 2."""


class AuthFailed(Exception):
    """
    Login failed. SECURITY (Req 11.4): the message is always the same
    generic text. We don't tell an attacker whether the code, the
    device, or the role was the wrong part.
    """

    def __init__(self) -> None:
        super().__init__("Authentication failed")


# ============================================================
# SECTION 3: The real AWS authenticator
# ============================================================

class AwsAuthenticator:
    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        # Unguarded session used ONLY to resolve base credentials
        # (see _guarded_base). Never used to call AWS directly.
        self._loader: boto3.Session | None = None

    # --------------------------------------------------------
    # Step 1: load and check base credentials (no MFA yet)
    # --------------------------------------------------------
    def preflight(self) -> None:
        """Make sure base credentials exist before we ask for MFA (Req 1.5)."""
        try:
            loader = boto3.Session(profile_name=self.config.profile, region_name=self.config.region)
        except ProfileNotFound as exc:
            raise AuthConfigError(f"AWS profile not found: {self.config.profile}") from exc

        base = self._guarded_base(loader)
        try:
            # Confirms the base credentials actually work.
            # The result is NOT shown to the user (Req 11.1).
            base.client("sts").get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            raise AuthConfigError("AWS credentials are invalid or expired.") from exc

        self._loader = loader

    def _guarded_base(self, loader: boto3.Session) -> boto3.Session:
        """
        A fresh, guarded session holding the current base credentials.

        Why two sessions? SSO and web-identity profiles make their own
        AWS calls to fetch credentials (sso:GetRoleCredentials,
        sts:AssumeRoleWithWebIdentity), through the session they belong
        to. A guard on that session would block them. So the loader
        resolves credentials, and everything OUR code sends goes through
        a separate session that has the guard.

        Rebuilt on every login, so refreshable credentials (SSO, assumed
        role profiles) are re-read instead of going stale while locked.
        """
        try:
            creds = loader.get_credentials()
            frozen = creds.get_frozen_credentials() if creds is not None else None
        except (ClientError, BotoCoreError) as exc:
            raise AuthConfigError("AWS credentials are invalid or expired.") from exc
        if frozen is None or not frozen.access_key:
            raise AuthConfigError(
                "No AWS credentials found. Configure a profile (aws configure / aws sso login) "
                "or pass --profile."
            )

        base = boto3.Session(
            aws_access_key_id=frozen.access_key,
            aws_secret_access_key=frozen.secret_key,
            aws_session_token=frozen.token,
            region_name=self.config.region,
        )
        # SECURITY (Req 1.6): base creds may only call AssumeRole
        # and GetCallerIdentity. Installed BEFORE any client exists.
        install_guard(base, BASE_OPERATIONS)
        return base

    # --------------------------------------------------------
    # Step 2: check the code's format (subclasses may add more)
    # --------------------------------------------------------
    def _verify_code(self, mfa_code: str) -> None:
        if not MFA_CODE_PATTERN.fullmatch(mfa_code):
            raise AuthFailed()

    # --------------------------------------------------------
    # Steps 3 to 5: assume the role, build the session, verify it
    # --------------------------------------------------------
    def authenticate(self, mfa_code: str) -> AuditSession:
        if self._loader is None:
            self.preflight()
        self._verify_code(mfa_code)
        base = self._guarded_base(self._loader)

        # Step 3: trade the MFA code for 15-minute keys.
        try:
            resp = base.client("sts").assume_role(
                RoleArn=self.config.role_arn,
                RoleSessionName=f"{SESSION_NAME_PREFIX}{int(time.time())}",
                SerialNumber=self.config.mfa_serial,
                TokenCode=mfa_code,
                DurationSeconds=SESSION_SECONDS,
            )
        except (ClientError, BotoCoreError) as exc:
            raise AuthFailed() from exc
        creds = resp["Credentials"]

        # Step 4: an in-memory session from the temporary keys.
        # SECURITY: passing keys directly means nothing is written to
        # disk or environment variables (Req 13.2).
        audit = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.config.region,
        )
        # SECURITY (Req 8.6): attach the read-only guard first.
        install_guard(audit, AUDIT_OPERATIONS)

        # Step 5: prove we are the audit role and nothing else (Req 8.7).
        try:
            identity = audit.client("sts").get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            raise AuthFailed() from exc
        if not self._is_audit_role(identity["Arn"]):
            raise AuthFailed()

        return AuditSession(
            boto_session=audit,
            account_id=identity["Account"],
            expires_at=creds["Expiration"],
        )

    # --------------------------------------------------------
    # Helper: does this identity ARN belong to our audit role?
    # --------------------------------------------------------
    def _is_audit_role(self, identity_arn: str) -> bool:
        """
        Role ARN:     arn:aws:iam::<acct>:role/<path/>CloudGuardAuditRole
        Assumed ARN:  arn:aws:sts::<acct>:assumed-role/CloudGuardAuditRole/cloudguard-<time>
        Account, role name, and session prefix must all match.
        """
        role_parts = self.config.role_arn.split(":")
        if len(role_parts) < 6:
            return False
        role_account = role_parts[4]
        role_name = role_parts[5].split("/")[-1]

        expected = f"arn:aws:sts::{role_account}:assumed-role/{role_name}/{SESSION_NAME_PREFIX}"
        return identity_arn.startswith(expected)


# ============================================================
# SECTION 4: The demo authenticator
# ------------------------------------------------------------
# Same flow as above, but against moto (fake AWS) so the demo is
# free and offline. Real AWS checks the MFA code, so here we check
# it ourselves against a random code shown on screen (Req 9.3).
# ============================================================

class DemoAuthenticator(AwsAuthenticator):
    def __init__(self, config: AuthConfig) -> None:
        super().__init__(config)
        # SECURITY: `secrets` gives cryptographically strong randomness,
        # unlike `random`. A new code is generated every run.
        self.demo_code = f"{secrets.randbelow(1_000_000):06d}"

        # Scripted screen recordings (docs/demo.tape) can't read the code
        # off the screen, so they may fix it. Demo mode only: there are no
        # real credentials behind it, and AwsAuthenticator ignores this.
        fixed = os.environ.get("CLOUDGUARD_DEMO_CODE", "")
        if MFA_CODE_PATTERN.fullmatch(fixed):
            self.demo_code = fixed

    def _verify_code(self, mfa_code: str) -> None:
        super()._verify_code(mfa_code)
        # SECURITY: compare_digest takes the same time whether the
        # first digit or the last digit is wrong (no timing hints).
        if not hmac.compare_digest(mfa_code, self.demo_code):
            raise AuthFailed()
