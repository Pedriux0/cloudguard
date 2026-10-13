"""
models.py - the shapes of our data
==================================

What is this file?
    It defines the "nouns" of the program: a Finding (one result of
    one check) and a Report (all findings from one audit).

Why does it exist?
    Every other part of the program (checks, renderer, exporter)
    agrees on these shapes, so they can work together without
    knowing about each other.

Requirements covered: 6.1, 6.2, 7.4
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum


# ============================================================
# SECTION 1: Severity and Status
# ------------------------------------------------------------
# Severity = how bad a problem is.
# It's an IntEnum, so CRITICAL (4) > HIGH (3) and we can sort
# findings from worst to least bad with a normal sort.
#
# Status = what happened when the check ran.
#   PASS  -> the setting is secure
#   FAIL  -> the setting is insecure (a real problem)
#   ERROR -> we couldn't check it (no permission, bug, etc.)
# ============================================================

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


# ============================================================
# SECTION 2: Finding - one result of one check
# ------------------------------------------------------------
# Example: "Bucket 'photos' is public -> FAIL, CRITICAL".
# frozen=True means a Finding can't be changed after creation.
# That keeps results trustworthy once a check produces them.
# ============================================================

@dataclass(frozen=True)
class Finding:
    check_id: str        # short ID, e.g. "S3-03"
    title: str           # human sentence, e.g. "Bucket is not public"
    status: Status       # PASS / FAIL / ERROR
    severity: Severity   # how bad it is if it FAILs
    resource: str        # what we looked at, e.g. "s3://photos"
    cis: str             # CIS Benchmark control number, e.g. "2.1.4"
    remediation: str     # one-line "how to fix it"
    detail: str = ""     # optional extra context

    def to_dict(self) -> dict:
        """Plain dict version, used for JSON export."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.name,
            "resource": self.resource,
            "cis": self.cis,
            "remediation": self.remediation,
            "detail": self.detail,
        }


# ============================================================
# SECTION 3: Report - everything from one audit run
# ------------------------------------------------------------
# Holds the list of findings plus "who/where/when" context.
# SECURITY: a Report only ever lives in memory. It's written to
# disk only when the user explicitly runs `export` (Req 7.5).
# ============================================================

@dataclass
class Report:
    account_id: str
    region: str
    generated_at: datetime
    demo: bool = False
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, dict[str, int]]:
        """
        Summary numbers for the report header (Req 7.4).
        Returns e.g.:
            {"status":   {"PASS": 7, "FAIL": 4, "ERROR": 0},
             "severity": {"CRITICAL": 1, "HIGH": 3, ...}}   <- FAILs only
        """
        by_status = Counter(f.status.value for f in self.findings)
        # Severity only matters for problems, so we count FAILs only.
        by_severity = Counter(
            f.severity.name for f in self.findings if f.status is Status.FAIL
        )
        return {
            "status": {s.value: by_status.get(s.value, 0) for s in Status},
            "severity": {
                s.name: by_severity.get(s.name, 0)
                for s in sorted(Severity, reverse=True)
            },
        }

    def sorted_findings(self) -> list[Finding]:
        """Worst first: FAIL before ERROR before PASS, then by severity."""
        status_rank = {Status.FAIL: 0, Status.ERROR: 1, Status.PASS: 2}
        return sorted(
            self.findings,
            key=lambda f: (status_rank[f.status], -f.severity, f.check_id),
        )
