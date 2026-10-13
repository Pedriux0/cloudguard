"""
checks/logging_checks.py - detection checks (would we notice an attack?)
=======================================================================

What is this file?
    Two checks on the services that record and detect activity:
      - CloudTrail: the account's "security camera". It logs
        every API call (who did what, when, from where).
      - GuardDuty: AWS's threat detection. It watches logs and
        alerts on suspicious behavior.

Why does it matter?
    If these are off, an attacker can work in the account and
    nobody will know, during or after the incident.

Note: this file is named logging_checks.py (not logging.py)
so it doesn't clash with Python's built-in `logging` module.

Requirements covered: 5.1 - 5.3
SECURITY (Req 5.3): we only READ these settings. We never turn
anything on for the user. That would change their account and cost money.
"""

from __future__ import annotations

from cloudguard.checks.base import AuditContext, CheckInfo
from cloudguard.models import Finding, Severity


# ============================================================
# SECTION 1: Check descriptions
# ============================================================

CLOUDTRAIL = CheckInfo(
    "LOG-01", "A multi-region CloudTrail trail is logging", Severity.HIGH, "3.1",
    "Create a multi-region trail (the first copy of management events is free).",
)
GUARDDUTY = CheckInfo(
    "LOG-02", "GuardDuty is enabled in this region", Severity.MEDIUM, "- (AWS FSBP GuardDuty.1)",
    "Enable GuardDuty in this region (has a 30-day free trial, then usage-based cost).",
)


# ============================================================
# SECTION 2: CloudTrail (LOG-01)
# ------------------------------------------------------------
# We need at least ONE trail that is:
#   1. multi-region (records ALL regions, not just one), AND
#   2. actually logging right now (a trail can be paused)
# describe_trails lists trails. get_trail_status says if it's on.
# The status call goes to the trail's home region.
# ============================================================

def check_cloudtrail(ctx: AuditContext) -> list[Finding]:
    trails = ctx.client("cloudtrail").describe_trails().get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]

    for trail in multi_region:
        home = trail.get("HomeRegion", ctx.region)
        status = ctx.client("cloudtrail", region=home).get_trail_status(Name=trail["TrailARN"])
        if status.get("IsLogging"):
            return [CLOUDTRAIL.passed(f"trail/{trail['Name']}", "Multi-region and logging.")]

    detail = (
        f"{len(trails)} trail(s) found, {len(multi_region)} multi-region, none logging."
        if trails else "No CloudTrail trails exist."
    )
    return [CLOUDTRAIL.failed("cloudtrail", detail)]


# ============================================================
# SECTION 3: GuardDuty (LOG-02)
# ------------------------------------------------------------
# GuardDuty works per region. A "detector" is GuardDuty's
# on-switch for that region. We need one with Status ENABLED.
# ============================================================

def check_guardduty(ctx: AuditContext) -> list[Finding]:
    gd = ctx.client("guardduty")
    detector_ids = gd.list_detectors().get("DetectorIds", [])

    for detector_id in detector_ids:
        if gd.get_detector(DetectorId=detector_id).get("Status") == "ENABLED":
            return [GUARDDUTY.passed(f"guardduty/{ctx.region}", f"Detector {detector_id} enabled.")]

    return [GUARDDUTY.failed(f"guardduty/{ctx.region}", "No enabled GuardDuty detector.")]


# ============================================================
# SECTION 4: Export list for the registry
# ============================================================

CHECKS = [
    (CLOUDTRAIL, check_cloudtrail),
    (GUARDDUTY, check_guardduty),
]
