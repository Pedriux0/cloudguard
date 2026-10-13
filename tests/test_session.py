"""
test_session.py - login, locking, and wiping (Req 11, 12, 13, 10.2)
==================================================================

Each test plays a short "script" of user actions against the real
SecureSession, using the demo fake AWS account, a fake keyboard,
and a fake clock (so "wait 10 minutes" takes 0 seconds).
"""

from __future__ import annotations

import pytest

from cloudguard.auth import DemoAuthenticator
from cloudguard.demo import start_demo
from cloudguard.session import EXIT_AUTH_FAILED, EXIT_OK, IDLE_TIMEOUT_SECONDS, SecureSession

from conftest import TIMEOUT, FakeClock, FakeTerminal, Wait


@pytest.fixture
def demo():
    mock, config = start_demo()
    yield DemoAuthenticator(config), config
    mock.stop()


def make_session(demo, script):
    auth, config = demo
    clock = FakeClock()
    term = FakeTerminal(script, clock)
    session = SecureSession(auth, term, region=config.region, demo=True, clock=clock)
    return session, term, clock


# ============================================================
# SECTION 1: Authentication
# ============================================================

def test_nothing_is_shown_before_authentication(demo):
    session, term, _ = make_session(demo, ["quit"])
    assert session.run() == EXIT_OK
    assert "Account" not in term.output   # no account data leaked
    assert term.prompts == ["MFA code: "]


def test_three_wrong_codes_exit_with_code_3(demo):
    session, term, _ = make_session(demo, ["000000", "abc", "999999x"])
    # (a real code could be 000000 by chance; force a different one)
    session.auth.demo_code = "123456"
    assert session.run() == EXIT_AUTH_FAILED
    assert term.output.count("Authentication failed") == 3


def test_commands_are_not_accepted_while_locked(demo):
    """Typing a command at the MFA prompt is just a wrong code."""
    session, term, _ = make_session(demo, ["audit", "show HIGH", "help"])
    session.auth.demo_code = "123456"
    assert session.run() == EXIT_AUTH_FAILED
    assert "cloudguard audit" not in term.output


def test_correct_code_unlocks_and_audit_finds_planted_problems(demo):
    auth, _ = demo
    session, term, _ = make_session(demo, [auth.demo_code, "audit", "quit"])
    assert session.run() == EXIT_OK

    out = term.output
    assert "Unlocked." in out
    for check_id in ("IAM-01", "IAM-03", "IAM-05", "S3-01", "S3-03", "NET-01", "LOG-01"):
        assert check_id in out
    # Wiped on quit, and secrets gone.
    assert session.audit_session is None and session.report is None


# ============================================================
# SECTION 2: Idle lock and expiry (Req 12)
# ============================================================

def test_idle_for_10_minutes_locks_and_wipes(demo):
    auth, _ = demo
    session, term, clock = make_session(demo, [auth.demo_code, "audit", TIMEOUT, "quit"])
    wipes_before = term.wipes

    assert session.run() == EXIT_OK
    assert "Locked after 10 minutes of inactivity." in term.output
    # Asked for MFA again after the lock.
    assert term.prompts.count("MFA code: ") == 2
    # The command prompt never waits longer than 10 minutes.
    assert max(term.timeouts) <= IDLE_TIMEOUT_SECONDS
    assert term.wipes > wipes_before


def test_lock_clears_credentials_and_findings(demo):
    auth, _ = demo
    session, term, _ = make_session(demo, [auth.demo_code])

    # Log in, run an audit, then lock directly.
    assert session._authenticate_loop() == "unlocked"
    session._dispatch("audit")
    assert session.report is not None and session.audit_session is not None

    session.lock("test")
    assert session.report is None
    assert session.audit_session is None


def test_activity_resets_idle_timer(demo):
    """Typing every 9 minutes keeps the session open (until the 15-min cap)."""
    auth, _ = demo
    script = [auth.demo_code, Wait(540, "help"), "quit"]
    session, term, _ = make_session(demo, script)
    assert session.run() == EXIT_OK
    assert "inactivity" not in term.output


def test_session_expires_after_15_minutes_even_if_active(demo):
    auth, _ = demo
    # 9 + 9 = 18 minutes of activity: past the 15-minute STS limit.
    script = [auth.demo_code, Wait(540, "help"), Wait(540, "audit"), "quit"]
    session, term, _ = make_session(demo, script)
    assert session.run() == EXIT_OK
    assert "Session expired (15-minute limit)." in term.output
    assert "cloudguard audit" not in term.output   # the late `audit` never ran


def test_prompt_shows_countdown(demo):
    auth, _ = demo
    session, term, _ = make_session(demo, [auth.demo_code, "quit"])
    session.run()
    command_prompts = [p for p in term.prompts if "cloudguard [" in p]
    assert command_prompts and command_prompts[0].startswith("[DEMO] cloudguard [1")


def test_lock_command(demo):
    auth, _ = demo
    session, term, _ = make_session(demo, [auth.demo_code, "lock", "quit"])
    assert session.run() == EXIT_OK
    assert "Locked by user." in term.output


# ============================================================
# SECTION 3: Export needs confirmation (Req 7.3)
# ============================================================

def test_export_without_yes_writes_nothing(demo, tmp_path):
    auth, _ = demo
    target = tmp_path / "report.md"
    script = [auth.demo_code, "audit", f"export markdown {target}", "no", "quit"]
    session, term, _ = make_session(demo, script)
    session.run()
    assert not target.exists()
    assert "Export cancelled." in term.output


def test_export_with_yes_writes_private_file(demo, tmp_path):
    auth, _ = demo
    target = tmp_path / "report.json"
    script = [auth.demo_code, "audit", f"export json {target}", "yes", "quit"]
    session, _, _ = make_session(demo, script)
    session.run()
    assert target.exists()
    assert (target.stat().st_mode & 0o777) == 0o600
    assert '"demo": true' in target.read_text()
