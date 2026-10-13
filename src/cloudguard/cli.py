"""
cli.py - where the program starts
=================================

What is this file?
    Reads the command-line options, sets up the safety features,
    and hands control to the SecureSession.

Usage:
    cloudguard --demo
    cloudguard --role-arn <ARN> --mfa-serial <ARN> [--profile P] [--region R]

    Or set CLOUDGUARD_ROLE_ARN and CLOUDGUARD_MFA_SERIAL instead of flags.

SECURITY (Req 13.5): no option takes a secret. The role ARN and MFA
device ARN are just names. So the launch command can sit in your
shell history without exposing anything. The MFA code is only typed
into the hidden prompt.

Exit codes:
    0 = normal exit   1 = unexpected error   2 = setup problem   3 = too many failed logins

Requirements covered: 1.1 - 1.5, 13.4, 13.5
"""

from __future__ import annotations

import argparse
import atexit
import logging
import os
import signal
import sys

from cloudguard import __version__

EXIT_ERROR = 1
EXIT_CONFIG = 2


# ============================================================
# SECTION 1: Command-line options
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudguard",
        description="Read-only, MFA-protected AWS security audit.",
    )
    p.add_argument("--demo", action="store_true", help="run against a fake AWS account (free, offline)")
    p.add_argument("--profile", help="AWS profile for your base credentials")
    p.add_argument("--region", help="region for regional checks (default: profile region or us-east-1)")
    p.add_argument("--role-arn", help="ARN of CloudGuardAuditRole (or env CLOUDGUARD_ROLE_ARN)")
    p.add_argument("--mfa-serial", help="ARN of your MFA device (or env CLOUDGUARD_MFA_SERIAL)")
    p.add_argument("--version", action="version", version=f"cloudguard {__version__}")
    return p


# ============================================================
# SECTION 2: Process hardening
# ------------------------------------------------------------
# Done before anything sensitive happens.
# ============================================================

def harden_process(terminal) -> None:
    from cloudguard.session import disable_core_dumps, secure_umask

    # SECURITY: no memory dumps on crash, private files by default.
    disable_core_dumps()
    secure_umask()

    # SECURITY (Req 13.4): silence AWS SDK logging so nothing about
    # requests or credentials is ever printed or written to a log.
    for name in ("boto3", "botocore", "urllib3", "s3transfer"):
        logging.getLogger(name).setLevel(logging.CRITICAL)

    # SECURITY (Req 13.3): closing the terminal sends SIGHUP; `kill`
    # sends SIGTERM. Turn both into a normal exit, so the session's
    # `finally` block wipes the screen and drops credentials.
    def _graceful_exit(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGHUP, _graceful_exit)
    signal.signal(signal.SIGTERM, _graceful_exit)

    # Last safety net: wipe the screen on exit if account data may still
    # be on it. (Always wiping would also erase setup error messages.)
    atexit.register(terminal.wipe_if_sensitive)


# ============================================================
# SECTION 3: Building the authenticator (demo or real)
# ============================================================

def _resolve_region(args) -> str:
    """--region, else the profile's region, else us-east-1 (Req 1.3)."""
    if args.region:
        return args.region
    import boto3
    from botocore.exceptions import ProfileNotFound
    try:
        return boto3.Session(profile_name=args.profile).region_name or "us-east-1"
    except ProfileNotFound:
        return "us-east-1"   # preflight() reports the bad profile clearly


def _real_authenticator(args):
    from cloudguard.auth import AuthConfig, AwsAuthenticator

    role_arn = args.role_arn or os.environ.get("CLOUDGUARD_ROLE_ARN")
    mfa_serial = args.mfa_serial or os.environ.get("CLOUDGUARD_MFA_SERIAL")
    if not role_arn or not mfa_serial:
        raise ValueError(
            "Missing --role-arn / --mfa-serial (or CLOUDGUARD_ROLE_ARN / CLOUDGUARD_MFA_SERIAL). "
            "Deploy infra/cloudguard-role.yaml first. See README."
        )

    config = AuthConfig(
        role_arn=role_arn,
        mfa_serial=mfa_serial,
        region=_resolve_region(args),
        profile=args.profile,
    )
    authenticator = AwsAuthenticator(config)
    authenticator.preflight()   # fails fast if base credentials are missing
    return authenticator, config


# ============================================================
# SECTION 4: main()
# ============================================================

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from cloudguard.auth import AuthConfigError, DemoAuthenticator
    from cloudguard.session import SecureSession
    from cloudguard.terminal import Terminal

    terminal = Terminal()
    harden_process(terminal)

    # The session needs a real keyboard: hidden input and timeouts
    # don't work when input is piped from a file.
    if not sys.stdin.isatty():
        terminal.print("cloudguard must be run in an interactive terminal.")
        return EXIT_CONFIG

    mock = None
    try:
        # ---- Step 1: pick demo or real AWS --------------------
        if args.demo:
            from cloudguard.demo import DemoUnavailable, start_demo
            try:
                mock, config = start_demo()
            except DemoUnavailable as exc:
                terminal.print(f"[red]{exc}[/]")
                return EXIT_CONFIG
            authenticator = DemoAuthenticator(config)
        else:
            try:
                authenticator, config = _real_authenticator(args)
            except (ValueError, AuthConfigError) as exc:
                # Req 1.5: a clear message, no stack trace.
                terminal.print(f"[red]Setup error:[/] {exc}")
                return EXIT_CONFIG

        # ---- Step 2: hand over to the secure session ----------
        session = SecureSession(authenticator, terminal, region=config.region, demo=args.demo)
        return session.run()

    except SystemExit as exc:            # from the SIGHUP/SIGTERM handler
        return int(exc.code or 0)
    except KeyboardInterrupt:            # Ctrl+C before the session started
        return 0
    except Exception:                    # noqa: BLE001
        # SECURITY: no traceback. It could show internal details.
        terminal.wipe()
        terminal.print("[red]Unexpected error. cloudguard closed and credentials were discarded.[/]")
        return EXIT_ERROR
    finally:
        if mock is not None:
            mock.stop()


if __name__ == "__main__":
    sys.exit(main())
