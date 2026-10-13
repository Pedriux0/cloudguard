"""
terminal.py - safe keyboard input and screen wiping
===================================================

What is this file?
    All reading from the keyboard and writing to the screen goes
    through the Terminal class in this file.

Why does it exist?
    Three security features live here:
      1. Hidden input for the MFA code (nothing echoed to screen)
      2. Input with a timeout, so the app can lock after 10 min idle
      3. Wiping the screen AND the scrollback (the history you
         can scroll up to see)

    Keeping all input/output in one class also lets the tests swap
    in a fake keyboard and a fake screen.

Requirements covered: 11.1, 12.2, 13.1

SECURITY (Req 13.1): this file never imports `readline`. readline
is the Python module that gives up-arrow history and can save it to
a file. Without it, typed commands exist only for the moment they
are being processed.
"""

from __future__ import annotations

import getpass
import os
import select
import sys
import termios
import time

from rich.console import Console

STDIN_FD = 0   # file descriptor 0 = the keyboard


# ============================================================
# SECTION 1: The "wipe everything" escape code
# ------------------------------------------------------------
# Terminals understand special character sequences ("ANSI codes"):
#   ESC[3J  -> erase the scrollback buffer
#   ESC[H   -> move the cursor to the top-left
#   ESC[2J  -> erase the visible screen
# Works in macOS Terminal, iTerm2, and most Linux terminals.
# (Limitation: tmux/screen keep their own buffer. See README.)
# ============================================================

CLEAR_ALL = "\033[3J\033[H\033[2J"


class Terminal:
    """Real keyboard and screen."""

    def __init__(self) -> None:
        # rich Console = colored output. record=False (the default)
        # means it keeps no copy of what was printed.
        self.console = Console(highlight=False)
        # Bytes typed but not yet used as a full line (see read_line).
        self._pending = b""

    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------
    def print(self, *args, **kwargs) -> None:
        self.console.print(*args, **kwargs)

    def wipe(self) -> None:
        """Clear the screen and scrollback (Req 12.2, 13.3)."""
        try:
            sys.stdout.write(CLEAR_ALL)
            sys.stdout.flush()
        except (OSError, ValueError):
            pass  # the terminal is already closed; nothing left to wipe

    # --------------------------------------------------------
    # Input: hidden (for the MFA code)
    # --------------------------------------------------------
    def read_hidden(self, prompt: str) -> str:
        """getpass turns off echo, so the code never shows on screen."""
        return getpass.getpass(prompt).strip()

    # --------------------------------------------------------
    # Input: normal line, but with a timeout (for commands)
    # --------------------------------------------------------
    def read_line(self, prompt: str, timeout: float) -> str | None:
        """
        Show a prompt and wait up to `timeout` seconds for Enter.
        Returns the typed line, or None if time ran out.
        Raises EOFError on Ctrl+D.

        How: select() asks the operating system "tell me when the
        keyboard has a full line ready, but give up after N seconds".
        """
        sys.stdout.write(prompt)
        sys.stdout.flush()

        # We read raw bytes from the keyboard (file descriptor 0) and
        # keep our own small buffer. Why not sys.stdin.readline()?
        # Python's stdin has a hidden buffer. If two lines arrive at once
        # (for example, a paste), the second line hides in that buffer
        # and select() can't see it. The prompt would then hang until
        # the timeout. Our own buffer avoids that.
        deadline = time.monotonic() + max(timeout, 0)
        while b"\n" not in self._pending:
            remaining = deadline - time.monotonic()
            ready, _, _ = select.select([STDIN_FD], [], [], max(remaining, 0))
            if not ready:
                sys.stdout.write("\n")
                return None
            chunk = os.read(STDIN_FD, 4096)
            if not chunk:       # 0 bytes = end of input (Ctrl+D)
                raise EOFError
            self._pending += chunk

        line, _, self._pending = self._pending.partition(b"\n")
        return line.decode("utf-8", errors="replace").strip()

    def flush_input(self) -> None:
        """
        Throw away anything half-typed when the session locks.
        SECURITY: otherwise text typed before the lock could be
        read as input after it.
        """
        self._pending = b""
        try:
            termios.tcflush(STDIN_FD, termios.TCIFLUSH)
        except (termios.error, OSError, ValueError):
            pass  # not a real terminal (e.g. piped input); nothing to flush
