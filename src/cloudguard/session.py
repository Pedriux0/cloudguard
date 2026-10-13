"""
session.py - the secure, self-locking shell
===========================================

What is this file?
    The interactive "cloudguard>" shell. It has two states:

        LOCKED    -> no AWS keys, no results. Only accepts an MFA
                     code or "quit".
        UNLOCKED  -> holds 15-minute read-only keys. Accepts commands
                     like `audit` and `show`.

    State diagram:
        LOCKED --(good MFA)--> UNLOCKED
        UNLOCKED --(10 min idle / keys expire / `lock`)--> LOCKED
        anything --(quit / Ctrl+C / Ctrl+D / terminal closed)--> EXIT

    Every move to LOCKED or EXIT wipes the screen and scrollback,
    and drops the keys and results from memory.

Requirements covered: 7.1 - 7.3, 11.5, 11.6, 12.1 - 12.5, 13.1 - 13.3
"""

from __future__ import annotations

import gc
import os
import time
from datetime import datetime, timezone
from typing import Callable

from rich.markup import escape

from cloudguard import render
from cloudguard.auth import AuditSession, AuthConfigError, AuthFailed, AwsAuthenticator
from cloudguard.checks.base import AuditContext
from cloudguard.export import write_private
from cloudguard.models import Report
from cloudguard.runner import run_audit


# ============================================================
# SECTION 1: Security settings
# ============================================================

IDLE_TIMEOUT_SECONDS = 600   # Req 12.1: lock after 10 minutes with no input
MAX_AUTH_ATTEMPTS = 3        # Req 11.5: exit after 3 wrong codes in a row

# Exit codes, so scripts and humans know how it ended.
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_AUTH_FAILED = 3

HELP_TEXT = """[bold]Commands[/]
  audit                         run all security checks
  show <SEVERITY|CHECK-ID>      details + fix, e.g. `show HIGH` or `show S3-03`
  export <markdown|json> <file> save the report (asks first, file is private 0600)
  lock                          lock now (wipes screen, asks for MFA again)
  help                          this list
  quit | exit                   wipe screen and close"""


class SecureSession:
    # ============================================================
    # SECTION 2: Setup
    # ------------------------------------------------------------
    # `clock` is injectable so tests can "fast-forward time"
    # instead of really waiting 10 minutes.
    # ============================================================
    def __init__(
        self,
        authenticator: AwsAuthenticator,
        terminal,
        region: str,
        demo: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.auth = authenticator
        self.term = terminal
        self.region = region
        self.demo = demo
        self.clock = clock

        # SECURITY: these two hold sensitive data. They are None
        # whenever the session is LOCKED.
        self.audit_session: AuditSession | None = None
        self.report: Report | None = None

        self._deadline = 0.0   # clock() time when the AWS keys expire

    @property
    def locked(self) -> bool:
        return self.audit_session is None

    # ============================================================
    # SECTION 3: Main loop
    # ------------------------------------------------------------
    # Alternate between "log in" and "take commands" until the
    # user quits. The `finally` makes sure we ALWAYS wipe, even
    # if something crashes.
    # ============================================================
    def run(self) -> int:
        try:
            while True:
                outcome = self._authenticate_loop()
                if outcome == "quit":
                    return EXIT_OK
                if outcome == "failed":
                    return EXIT_AUTH_FAILED
                if outcome == "config":
                    return EXIT_CONFIG

                if self._command_loop() == "quit":
                    return EXIT_OK
                # otherwise the session locked: loop back to login

        except (KeyboardInterrupt, EOFError):
            return EXIT_OK   # Ctrl+C / Ctrl+D = quit (Req 13.3)
        finally:
            self._forget_secrets()
            self.term.wipe()
            self.term.print("cloudguard closed. Screen cleared, credentials discarded.")

    # ============================================================
    # SECTION 4: LOCKED state - authentication
    # ------------------------------------------------------------
    # Req 11.6: while locked, the only things you can do are
    # enter an MFA code or quit. No command can show account data.
    # ============================================================
    def _authenticate_loop(self) -> str:
        if self.demo:
            self.term.print(render.DEMO_BANNER)
            self.term.print(f"Demo MFA code: [bold]{self.auth.demo_code}[/]  (a real run uses your MFA device)")
        self.term.print("[bold]cloudguard is locked.[/] Enter your MFA code, or type 'quit'.")

        for attempt in range(1, MAX_AUTH_ATTEMPTS + 1):
            # SECURITY (Req 11.1, 11.3): hidden prompt. The code is
            # never echoed and never accepted as an argument.
            code = self.term.read_hidden("MFA code: ")
            if code.lower() in ("quit", "exit"):
                return "quit"

            try:
                session = self.auth.authenticate(code)
            except AuthFailed:
                left = MAX_AUTH_ATTEMPTS - attempt
                self.term.print(f"[red]Authentication failed.[/] {left} attempt(s) left.")
                continue
            except AuthConfigError as exc:
                # Base credentials missing or expired (e.g. SSO token ran
                # out while locked). A setup problem, not a wrong code.
                self.term.print(f"[red]Setup error:[/] {escape(str(exc))}")
                return "config"
            finally:
                # SECURITY: drop our reference to the code right away.
                code = None  # noqa: F841

            self._unlock(session)
            return "unlocked"

        self.term.print("[red]Too many failed attempts.[/]")
        return "failed"

    def _unlock(self, session: AuditSession) -> None:
        self.audit_session = session
        # Turn the AWS expiry time into a deadline on our own clock.
        # Never more than 15 min, even if AWS returned a longer time.
        remaining = (session.expires_at - datetime.now(timezone.utc)).total_seconds()
        self._deadline = self.clock() + max(0.0, min(remaining, 900.0))
        self.term.wipe()
        # From now on the screen may show account data: wipe it on exit.
        self.term.mark_sensitive()
        self.term.print(f"[green]Unlocked.[/] Account {session.account_id}. Type 'help' for commands.")

    # ============================================================
    # SECTION 5: UNLOCKED state - the command loop
    # ------------------------------------------------------------
    # Each prompt waits for at most the SMALLER of:
    #   - 10 minutes (idle limit), or
    #   - the time left before the AWS keys expire.
    # Typing a command restarts the 10-minute timer, because a new
    # prompt (with a fresh timeout) is shown after every command.
    # ============================================================
    def _command_loop(self) -> str:
        while True:
            left = self._seconds_left()
            if left <= 0:
                self.lock("Session expired (15-minute limit).")
                return "locked"

            line = self.term.read_line(self._prompt(left), timeout=min(IDLE_TIMEOUT_SECONDS, left))

            # No input in time -> lock. Say why.
            if line is None:
                reason = (
                    "Session expired (15-minute limit)."
                    if self._seconds_left() <= 0
                    else f"Locked after {IDLE_TIMEOUT_SECONDS // 60} minutes of inactivity."
                )
                self.lock(reason)
                return "locked"

            # Keys may have expired while the user was typing.
            if self._seconds_left() <= 0:
                self.lock("Session expired (15-minute limit).")
                return "locked"

            result = self._dispatch(line)
            if result in ("quit", "locked"):
                return result

    def _seconds_left(self) -> float:
        return self._deadline - self.clock()

    def _prompt(self, seconds_left: float) -> str:
        """Req 12.4: show the countdown, e.g. 'cloudguard [14:32]> '."""
        mins, secs = divmod(int(seconds_left), 60)
        tag = "[DEMO] " if self.demo else ""
        return f"{tag}cloudguard [{mins:02d}:{secs:02d}]> "

    # ============================================================
    # SECTION 6: Commands
    # ============================================================
    def _dispatch(self, line: str) -> str | None:
        parts = line.split()
        if not parts:
            return None
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("quit", "exit"):
            return "quit"
        if cmd == "lock":
            self.lock("Locked by user.")
            return "locked"
        if cmd == "help":
            self.term.print(HELP_TEXT)
        elif cmd == "audit":
            self._cmd_audit()
        elif cmd == "show":
            self._cmd_show(args)
        elif cmd == "export":
            return self._cmd_export(args)
        else:
            self.term.print(f"Unknown command '{escape(cmd)}'. Type 'help'.")
        return None

    def _cmd_audit(self) -> None:
        self.term.print("Running checks (read-only)...")
        ctx = AuditContext(
            session=self.audit_session.boto_session,
            region=self.region,
            account_id=self.audit_session.account_id,
        )
        self.report = run_audit(ctx, demo=self.demo)
        self.term.print(render.summary_table(self.report))
        self.term.print("Use `show <SEVERITY|CHECK-ID>` for details and fixes.")

    def _cmd_show(self, args: list[str]) -> None:
        if self.report is None:
            self.term.print("No results yet. Run `audit` first.")
            return
        if not args:
            self.term.print("Usage: show <CRITICAL|HIGH|MEDIUM|LOW|CHECK-ID>")
            return
        matches = render.select_findings(self.report, args[0])
        if not matches:
            self.term.print(f"No findings match '{escape(args[0])}'.")
        for finding in matches:
            self.term.print(render.detail_view(finding))

    def _cmd_export(self, args: list[str]) -> str | None:
        """
        Req 7.3: saving is opt-in, confirmed, and private (0600).
        Returns "locked" if the user goes idle at a confirmation prompt.
        """
        if self.report is None:
            self.term.print("No results yet. Run `audit` first.")
            return None
        if len(args) != 2 or args[0].lower() not in ("markdown", "json"):
            self.term.print("Usage: export <markdown|json> <file>")
            return None

        fmt, path = args[0].lower(), args[1]
        content = render.to_markdown(self.report) if fmt == "markdown" else render.to_json(self.report)

        # SECURITY: warn, because the file is a map of your weak spots.
        self.term.print(
            "[yellow]Warning:[/] this file will contain sensitive details about your AWS "
            "account. It will be readable only by you (0600)."
        )
        answer = self._confirm(f"Write {fmt} report to {path}? Type 'yes' to confirm: ")
        if answer is None:
            return "locked"
        if answer != "yes":
            self.term.print("Export cancelled.")
            return None

        try:
            try:
                written = write_private(path, content, overwrite=False)
            except FileExistsError:
                answer = self._confirm("File exists. Overwrite? Type 'yes' to confirm: ")
                if answer is None:
                    return "locked"
                if answer != "yes":
                    self.term.print("Export cancelled.")
                    return None
                # Can still fail: the path may be a directory or a symlink.
                written = write_private(path, content, overwrite=True)
        except OSError as exc:
            self.term.print(f"[red]Could not write file:[/] {escape(str(exc.strerror or exc))}")
            return None

        self.term.print(f"[green]Saved[/] {escape(written)} (permissions 0600).")
        return None

    def _confirm(self, prompt: str) -> str | None:
        """
        Yes/no question that ALSO respects the idle and expiry limits.
        Returns None if it locked while waiting.
        """
        left = self._seconds_left()
        answer = self.term.read_line(prompt, timeout=max(0.0, min(IDLE_TIMEOUT_SECONDS, left)))
        if answer is None or self._seconds_left() <= 0:
            self.lock("Locked while waiting for confirmation.")
            return None
        return answer.strip().lower()

    # ============================================================
    # SECTION 7: Locking and forgetting
    # ------------------------------------------------------------
    # Req 12.2: wipe the screen and scrollback, drop keys and results,
    # and throw away half-typed input.
    #
    # Honest limitation: Python can't securely overwrite memory.
    # The best we can do is drop every reference and run the
    # garbage collector, so the data can be freed and reused.
    # ============================================================
    def lock(self, reason: str) -> None:
        self._forget_secrets()
        self.term.flush_input()
        self.term.wipe()
        self.term.print(f"[yellow]{reason}[/] Screen cleared and credentials discarded.")

    def _forget_secrets(self) -> None:
        self.audit_session = None
        self.report = None
        self._deadline = 0.0
        gc.collect()


# ============================================================
# SECTION 8: Process-level hardening (called once from cli.py)
# ============================================================

def disable_core_dumps() -> None:
    """
    A "core dump" is a file of the program's memory, written on a crash.
    SECURITY: it could contain the AWS keys, so we turn it off.
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass  # not supported on this OS; nothing else to do


def secure_umask() -> None:
    """
    SECURITY: any file this process creates is private by default
    (backup safety net for export.py, which already uses 0600).
    """
    os.umask(0o077)
