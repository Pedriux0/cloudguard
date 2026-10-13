"""
guard.py - the code-level "read-only" filter
============================================

What is this file?
    A filter that sits inside boto3 (the AWS SDK). Before ANY request
    leaves this program, the filter checks it against an allow-list.
    If the request isn't on the list, it's blocked and never sent.

Why does it exist?
    This is layer 3 of our 3-layer read-only design:
        Layer 1 - IAM Allow  : the AWS role can only do 15 read actions
        Layer 2 - IAM Deny   : the role explicitly denies everything else
        Layer 3 - THIS FILE  : the program itself refuses to send writes
    Layers 1 and 2 protect the AWS account. Layer 3 also protects
    against using the tool with the WRONG credentials (for example,
    an admin profile by mistake). Even then, nothing can be changed.

Requirements covered: 1.6, 8.6
"""

from __future__ import annotations

import boto3


# ============================================================
# SECTION 1: The allow-lists
# ------------------------------------------------------------
# boto3 names an API call by service + operation, for example
# ("s3", "ListBuckets"). These sets are the ONLY calls allowed.
#
# Two separate lists, because we use two separate identities:
#   BASE_OPERATIONS  -> your normal AWS login. It is only allowed
#                       to ask STS for the audit role.
#                       (STS = Security Token Service, the AWS
#                       service that hands out temporary keys.)
#   AUDIT_OPERATIONS -> the temporary audit role. It is only
#                       allowed to READ what the checks need.
# ============================================================

BASE_OPERATIONS: dict[str, set[str]] = {
    "sts": {"AssumeRole", "GetCallerIdentity"},
}

AUDIT_OPERATIONS: dict[str, set[str]] = {
    "sts":        {"GetCallerIdentity"},
    "iam":        {"GenerateCredentialReport", "GetCredentialReport",
                   "GetAccountSummary", "GetAccountPasswordPolicy"},
    "s3":         {"ListBuckets", "GetPublicAccessBlock", "GetBucketPolicyStatus",
                   "GetBucketPolicy"},
    "s3control":  {"GetPublicAccessBlock"},
    "ec2":        {"DescribeSecurityGroups"},
    "cloudtrail": {"DescribeTrails", "GetTrailStatus"},
    "guardduty":  {"ListDetectors", "GetDetector"},
}


# ============================================================
# SECTION 2: API name -> IAM permission name
# ------------------------------------------------------------
# The SDK's operation name and the IAM permission name are
# usually the same, but not always. Example: the S3 API call
# "ListBuckets" needs the IAM permission "s3:ListAllMyBuckets".
#
# Tests use this map to prove that iam-policy.json allows
# EXACTLY the same things this file allows (no drift).
# ============================================================

_IAM_NAME_OVERRIDES: dict[tuple[str, str], str] = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "GetPublicAccessBlock"): "s3:GetBucketPublicAccessBlock",
    ("s3control", "GetPublicAccessBlock"): "s3:GetAccountPublicAccessBlock",
}


def iam_actions(operations: dict[str, set[str]]) -> set[str]:
    """Turn an allow-list into the IAM permission names it needs."""
    actions: set[str] = set()
    for service, ops in operations.items():
        for op in ops:
            default = f"{service}:{op}"
            actions.add(_IAM_NAME_OVERRIDES.get((service, op), default))
    return actions


# ============================================================
# SECTION 3: The blocking hook
# ------------------------------------------------------------
# botocore (the engine under boto3) fires a "before-call" event
# right before it signs and sends each request. We listen for
# that event. If the call isn't allowed, we raise an error, and
# the request never reaches AWS.
# ============================================================

class BlockedOperationError(Exception):
    """Raised when code tries to call an AWS API outside the allow-list."""


def install_guard(session: boto3.Session, allowed: dict[str, set[str]]) -> None:
    """
    Attach the read-only filter to a boto3 session.

    IMPORTANT: call this BEFORE creating any clients from the session.
    Each client copies the session's event hooks when it's created.
    """

    def _check(model, **_kwargs) -> None:
        service = model.service_model.service_name   # e.g. "s3"
        operation = model.name                       # e.g. "DeleteBucket"

        # SECURITY: deny by default. Anything not listed is blocked.
        if operation not in allowed.get(service, set()):
            raise BlockedOperationError(
                f"Blocked non-allow-listed AWS call: {service}:{operation}"
            )

    # "before-call" with no service suffix = listen to EVERY service.
    session.events.register("before-call", _check, unique_id="cloudguard-guard")
