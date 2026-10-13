"""
checks/base.py - shared building blocks for every check
=======================================================

What is this file?
    Two small helpers that every check uses:
      - AuditContext: everything a check needs (AWS session, region, account)
      - CheckInfo:    the fixed facts about a check (ID, severity, CIS, fix)

Why does it exist?
    Each check describes itself once (CheckInfo) and then only
    has to say "PASS for this resource" or "FAIL for that one".
    This keeps every check file short and easy to read.

Result style used by all checks:
    - One FAIL finding per bad resource (e.g. per public bucket)
    - If nothing is bad, ONE PASS finding that says how many were checked
    This keeps the report short, but still shows what was covered (Req 6.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

import boto3

from cloudguard.models import Finding, Severity, Status


# ============================================================
# SECTION 1: AuditContext - the "toolbox" passed to each check
# ------------------------------------------------------------
# `session` is the GUARDED read-only boto3 session, so every
# client a check creates is already behind the allow-list.
# `cache` lets checks share expensive results (for example, the
# IAM credential report is downloaded once, used by 2 checks).
# ============================================================

@dataclass
class AuditContext:
    session: boto3.Session
    region: str
    account_id: str
    cache: dict[str, Any] = field(default_factory=dict)

    def client(self, service: str, region: str | None = None):
        """Create an AWS client for a service, in the audit region by default."""
        return self.session.client(service, region_name=region or self.region)


# ============================================================
# SECTION 2: CheckInfo - the fixed facts about one check
# ------------------------------------------------------------
# A check fills these in once. Then `info.passed(...)` and
# `info.failed(...)` build Findings with all fields set.
# ============================================================

@dataclass(frozen=True)
class CheckInfo:
    check_id: str
    title: str
    severity: Severity
    cis: str
    remediation: str

    def _make(self, status: Status, resource: str, detail: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=status,
            severity=self.severity,
            resource=resource,
            cis=self.cis,
            remediation=self.remediation,
            detail=detail,
        )

    def passed(self, resource: str, detail: str = "") -> Finding:
        return self._make(Status.PASS, resource, detail)

    def failed(self, resource: str, detail: str = "") -> Finding:
        return self._make(Status.FAIL, resource, detail)

    def error(self, resource: str, detail: str = "") -> Finding:
        return self._make(Status.ERROR, resource, detail)


# A check is any function that takes the context and returns findings.
CheckFn = Callable[[AuditContext], list[Finding]]


# ============================================================
# SECTION 3: Small helper for AWS error codes
# ------------------------------------------------------------
# boto3 raises ClientError with a code like "NoSuchEntity" or
# "AccessDenied". This pulls the code out safely.
# ============================================================

def error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None) or {}
    return response.get("Error", {}).get("Code", "")


ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
