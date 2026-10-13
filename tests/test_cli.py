"""
test_cli.py - process-level behavior (exit wipe, Ctrl+C before login)
====================================================================
"""

from __future__ import annotations

import sys

from cloudguard import cli
from cloudguard.terminal import CLEAR_ALL, Terminal


def test_exit_wipe_only_after_account_data_was_shown(capsys):
    """Setup errors must stay readable; account data must not."""
    term = Terminal()
    term.wipe_if_sensitive()
    assert CLEAR_ALL not in capsys.readouterr().out

    term.mark_sensitive()
    term.wipe_if_sensitive()
    assert CLEAR_ALL in capsys.readouterr().out

    # wipe() resets the flag, so a later goodbye message isn't erased.
    term.wipe_if_sensitive()
    assert CLEAR_ALL not in capsys.readouterr().out


def test_ctrl_c_before_session_exits_cleanly(monkeypatch, capsys):
    def interrupted(_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "harden_process", lambda _terminal: None)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "_real_authenticator", interrupted)

    assert cli.main(["--role-arn", "r", "--mfa-serial", "m"]) == 0
    assert "Traceback" not in capsys.readouterr().err
