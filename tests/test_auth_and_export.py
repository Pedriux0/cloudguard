"""
test_auth_and_export.py - login rules and private file writing
=============================================================
"""

from __future__ import annotations

import os

import pytest

from cloudguard.auth import AuthConfig, AuthFailed, AwsAuthenticator, DemoAuthenticator
from cloudguard.demo import start_demo
from cloudguard.export import write_private


# ============================================================
# SECTION 1: Authentication rules
# ============================================================

@pytest.fixture
def demo_auth():
    mock, config = start_demo()
    yield DemoAuthenticator(config)
    mock.stop()


def test_valid_code_returns_read_only_session(demo_auth):
    session = demo_auth.authenticate(demo_auth.demo_code)
    assert session.account_id == "123456789012"
    # Expires in at most 15 minutes.
    from datetime import datetime, timezone
    seconds = (session.expires_at - datetime.now(timezone.utc)).total_seconds()
    assert 0 < seconds <= 900


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 456"])
def test_malformed_codes_are_rejected(demo_auth, bad):
    with pytest.raises(AuthFailed, match="^Authentication failed$"):
        demo_auth.authenticate(bad)


def test_identity_must_be_the_audit_role():
    auth = AwsAuthenticator(AuthConfig(
        role_arn="arn:aws:iam::111122223333:role/CloudGuardAuditRole",
        mfa_serial="arn:aws:iam::111122223333:mfa/me", region="us-east-1", profile=None,
    ))
    good = "arn:aws:sts::111122223333:assumed-role/CloudGuardAuditRole/cloudguard-1700000000"
    assert auth._is_audit_role(good)
    # Wrong account, wrong role, admin user, wrong session name:
    assert not auth._is_audit_role("arn:aws:sts::999999999999:assumed-role/CloudGuardAuditRole/cloudguard-1")
    assert not auth._is_audit_role("arn:aws:sts::111122223333:assumed-role/AdminRole/cloudguard-1")
    assert not auth._is_audit_role("arn:aws:iam::111122223333:user/admin")
    assert not auth._is_audit_role("arn:aws:sts::111122223333:assumed-role/CloudGuardAuditRole/other")


def test_base_credentials_from_a_provider_that_calls_aws(tmp_path, monkeypatch):
    """
    SSO and web-identity profiles fetch credentials with their own AWS
    calls (sso:GetRoleCredentials, sts:AssumeRoleWithWebIdentity). The
    guard must not block those, only the calls cloudguard itself makes.
    """
    from moto import mock_aws

    token = tmp_path / "token"
    token.write_text("fake-oidc-token")
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/ci")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token))

    with mock_aws():
        auth = AwsAuthenticator(AuthConfig(
            role_arn="arn:aws:iam::123456789012:role/CloudGuardAuditRole",
            mfa_serial="arn:aws:iam::123456789012:mfa/me", region="us-east-1", profile=None,
        ))
        auth.preflight()   # used to raise BlockedOperationError

        # Our own calls are still guarded.
        from cloudguard.guard import BlockedOperationError
        base = auth._guarded_base(auth._loader)
        with pytest.raises(BlockedOperationError):
            base.client("iam").list_users()


def test_demo_codes_are_random():
    auths = [DemoAuthenticator(AuthConfig("r", "m", "us-east-1", None)) for _ in range(20)]
    codes = {a.demo_code for a in auths}
    assert len(codes) > 1
    assert all(len(c) == 6 and c.isdigit() for c in codes)


def test_demo_code_can_be_fixed_for_recordings(monkeypatch):
    config = AuthConfig("r", "m", "us-east-1", None)
    monkeypatch.setenv("CLOUDGUARD_DEMO_CODE", "424242")
    assert DemoAuthenticator(config).demo_code == "424242"

    # Anything that isn't exactly 6 digits is ignored (random code instead).
    monkeypatch.setenv("CLOUDGUARD_DEMO_CODE", "12345")
    assert DemoAuthenticator(config).demo_code != "12345"


# ============================================================
# SECTION 2: Private export
# ============================================================

def test_export_file_is_owner_only(tmp_path):
    path = write_private(str(tmp_path / "r.md"), "hello")
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_export_never_silently_overwrites(tmp_path):
    target = tmp_path / "r.md"
    write_private(str(target), "first")
    with pytest.raises(FileExistsError):
        write_private(str(target), "second")
    assert target.read_text() == "first"


def test_export_overwrite_tightens_permissions(tmp_path):
    target = tmp_path / "r.md"
    target.write_text("old")
    os.chmod(target, 0o644)
    write_private(str(target), "new", overwrite=True)
    assert target.read_text() == "new"
    assert (target.stat().st_mode & 0o777) == 0o600


def test_export_refuses_symlinks(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("keep me")
    link = tmp_path / "link.md"
    link.symlink_to(real)
    with pytest.raises(OSError):
        write_private(str(link), "attack", overwrite=True)
    assert real.read_text() == "keep me"
