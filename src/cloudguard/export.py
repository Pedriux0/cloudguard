"""
export.py - writing a report file safely
========================================

What is this file?
    One function that writes a report file so only YOU can read it.

Why does it exist?
    A security report is a map of an account's weak spots. If other
    users on the machine could read it, that would be a leak.

Requirements covered: 7.3, 7.5
"""

from __future__ import annotations

import os


def write_private(path: str, content: str, overwrite: bool = False) -> str:
    """
    Write `content` to `path` with permissions 0600 (owner read/write only).
    Returns the final absolute path.

    Raises FileExistsError if the file exists and overwrite is False,
    so the caller can ask the user before overwriting.
    """
    path = os.path.abspath(os.path.expanduser(path))

    # ============================================================
    # How the file is opened (each flag is a safety choice)
    # ------------------------------------------------------------
    # O_CREAT    -> create the file if it doesn't exist
    # O_EXCL     -> ...but FAIL if it already exists (no silent overwrite)
    # O_TRUNC    -> (only when overwrite=True) empty the old file first
    # O_NOFOLLOW -> SECURITY: refuse if the path is a symlink. This stops
    #               a trick where a link points our write at another file.
    # 0o600      -> SECURITY: the file is created private from the very
    #               first moment. There's no window where others can read it.
    # ============================================================
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_TRUNC if overwrite else os.O_EXCL

    fd = os.open(path, flags, 0o600)
    try:
        # If we're overwriting an OLD file that had looser permissions,
        # tighten it to 0600 too.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1   # fdopen now owns the file; don't close it twice
            fh.write(content)
    finally:
        if fd != -1:
            os.close(fd)
    return path
