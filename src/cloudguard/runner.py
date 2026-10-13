"""
runner.py - runs every check and collects the results
=====================================================

What is this file?
    A loop over ALL_CHECKS that builds one Report.

Why does it exist?
    One broken check must not stop the audit. If a check crashes
    (no permission, AWS hiccup, or the guard blocking a call),
    we turn the crash into an ERROR finding and move on (Req 6.3).

Requirements covered: 6.3
"""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguard.checks import ALL_CHECKS
from cloudguard.checks.base import AuditContext, error_code
from cloudguard.guard import BlockedOperationError
from cloudguard.models import Report


def run_audit(ctx: AuditContext, demo: bool = False) -> Report:
    report = Report(
        account_id=ctx.account_id,
        region=ctx.region,
        generated_at=datetime.now(timezone.utc),
        demo=demo,
    )

    for info, check in ALL_CHECKS:
        try:
            report.findings.extend(check(ctx))

        # The guard stopped a call that isn't on the allow-list.
        # This should never happen; if it does, we want it to be loud.
        except BlockedOperationError as exc:
            report.findings.append(info.error("guard", str(exc)))

        # Anything else: AWS error, network error, or a bug.
        # SECURITY: we record only the error type/code, not a full
        # traceback. That keeps internal details out of the report.
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            code = error_code(exc) or type(exc).__name__
            report.findings.append(info.error("account", f"Check failed: {code}"))

    return report
