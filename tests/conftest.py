"""
conftest.py - shared test helpers (pytest loads this automatically)
==================================================================

Provides:
    aws          -> a fresh fake AWS (moto) for each test
    audit_ctx    -> an AuditContext with the READ-ONLY guard installed,
                    exactly like the real app uses
    FakeClock    -> lets tests jump forward in time instantly
    FakeTerminal -> a scripted keyboard and a recorded screen
"""

from __future__ import annotations

import io
import os

import boto3
import pytest
from moto import mock_aws
from rich.console import Console

from cloudguard.checks.base import AuditContext
from cloudguard.guard import AUDIT_OPERATIONS, install_guard

REGION = "us-east-1"
ACCOUNT = "123456789012"   # moto's default account


# ============================================================
# SECTION 1: Fake AWS
# ------------------------------------------------------------
# Fake credentials + moto = no test can ever reach real AWS.
# ============================================================

@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def aws():
    """Yields an UNGUARDED session, used only to set up test data."""
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def audit_ctx(aws):
    """The guarded, read-only context that checks run with."""
    session = boto3.Session(region_name=REGION)
    install_guard(session, AUDIT_OPERATIONS)
    return AuditContext(session=session, region=REGION, account_id=ACCOUNT)


# ============================================================
# SECTION 2: Fake clock and fake terminal
# ------------------------------------------------------------
# FakeTerminal takes a script: a list of things the "user" does.
#   "audit"         -> types a line
#   TIMEOUT         -> walks away until the prompt times out
#   Wait(300, "x")  -> waits 300 seconds, then types "x"
# Everything printed is captured in `output`, and every screen
# wipe is counted in `wipes`.
# ============================================================

class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


TIMEOUT = object()


class Wait:
    def __init__(self, seconds: float, line: str) -> None:
        self.seconds, self.line = seconds, line


class FakeTerminal:
    def __init__(self, script: list, clock: FakeClock) -> None:
        self.script = list(script)
        self.clock = clock
        self._buffer = io.StringIO()
        self.console = Console(file=self._buffer, width=200, color_system=None)
        self.wipes = 0
        self.prompts: list[str] = []
        self.timeouts: list[float] = []

    @property
    def output(self) -> str:
        return self._buffer.getvalue()

    def print(self, *args, **kwargs) -> None:
        self.console.print(*args, **kwargs)

    def wipe(self) -> None:
        self.wipes += 1

    def mark_sensitive(self) -> None:
        pass

    def flush_input(self) -> None:
        pass

    def _next(self, timeout: float | None):
        if not self.script:
            raise EOFError   # script finished = user pressed Ctrl+D
        item = self.script.pop(0)
        if item is TIMEOUT:
            self.clock.advance(timeout if timeout is not None else 0)
            return None
        if isinstance(item, Wait):
            self.clock.advance(item.seconds)
            return item.line
        return item

    def read_hidden(self, prompt: str) -> str:
        self.prompts.append(prompt)
        value = self._next(None)
        return "" if value is None else value

    def read_line(self, prompt: str, timeout: float) -> str | None:
        self.prompts.append(prompt)
        self.timeouts.append(timeout)
        return self._next(timeout)
