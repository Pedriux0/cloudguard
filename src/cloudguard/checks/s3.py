"""
checks/s3.py - storage checks (is any data public?)
===================================================

What is this file?
    Three checks on S3 (Simple Storage Service, AWS file storage).

Why does it matter?
    Public S3 buckets are one of the most common causes of cloud
    data leaks. AWS has a safety switch called "Block Public Access"
    (BPA) at two levels:
        - account level: applies to every bucket in the account
        - bucket level:  applies to one bucket
    All four BPA settings must be ON to be fully protected.

Requirements covered: 3.1 - 3.4
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from cloudguard.checks.base import ACCESS_DENIED_CODES, AuditContext, CheckInfo, error_code
from cloudguard.models import Finding, Severity


# ============================================================
# SECTION 1: Check descriptions
# ============================================================

ACCOUNT_BPA = CheckInfo(
    "S3-01", "Account-level S3 Block Public Access is fully on", Severity.HIGH, "2.1.4",
    "S3 console > Block Public Access settings for this account > turn on all 4 settings.",
)
BUCKET_BPA = CheckInfo(
    "S3-02", "Bucket-level Block Public Access is fully on", Severity.HIGH, "2.1.4",
    "Bucket > Permissions > Block public access > turn on all 4 settings.",
)
BUCKET_PUBLIC = CheckInfo(
    "S3-03", "Bucket is not public", Severity.CRITICAL, "2.1.4",
    "Remove public grants from the bucket policy and turn on Block Public Access.",
)

# The four BPA switches. All must be True.
BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

# AWS error codes that mean "this setting was never configured".
NO_BPA_CODES = {"NoSuchPublicAccessBlockConfiguration"}
NO_POLICY_CODES = {"NoSuchBucketPolicy"}


def _all_on(config: dict) -> bool:
    return all(config.get(k) is True for k in BPA_KEYS)


def _off_list(config: dict) -> str:
    off = [k for k in BPA_KEYS if config.get(k) is not True]
    return "Off: " + ", ".join(off)


# ============================================================
# SECTION 2: Account-level Block Public Access (S3-01)
# ------------------------------------------------------------
# This setting lives in "s3control" (account-wide S3 settings),
# not in the regular "s3" API.
# ============================================================

def check_account_bpa(ctx: AuditContext) -> list[Finding]:
    resource = f"account/{ctx.account_id}"
    try:
        resp = ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)
    except ClientError as exc:
        if error_code(exc) in NO_BPA_CODES:
            return [ACCOUNT_BPA.failed(resource, "Block Public Access is not configured.")]
        raise

    config = resp["PublicAccessBlockConfiguration"]
    if _all_on(config):
        return [ACCOUNT_BPA.passed(resource)]
    return [ACCOUNT_BPA.failed(resource, _off_list(config))]


# ============================================================
# SECTION 3: Per-bucket checks (S3-02, S3-03)
# ------------------------------------------------------------
# We loop over every bucket once and run both checks.
# If we're not allowed to read one bucket, we record an ERROR
# for that bucket and keep going (Req 3.4). One locked bucket
# shouldn't stop the whole audit.
# ============================================================

def _buckets(ctx: AuditContext) -> list[str]:
    if "buckets" not in ctx.cache:
        resp = ctx.client("s3").list_buckets()
        ctx.cache["buckets"] = [b["Name"] for b in resp.get("Buckets", [])]
    return ctx.cache["buckets"]


def check_bucket_bpa(ctx: AuditContext) -> list[Finding]:
    s3 = ctx.client("s3")
    buckets = _buckets(ctx)
    findings: list[Finding] = []

    for name in buckets:
        resource = f"s3://{name}"
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            code = error_code(exc)
            if code in NO_BPA_CODES:
                findings.append(BUCKET_BPA.failed(resource, "Block Public Access is not configured."))
            elif code in ACCESS_DENIED_CODES:
                findings.append(BUCKET_BPA.error(resource, "Access denied reading BPA settings."))
            else:
                findings.append(BUCKET_BPA.error(resource, f"AWS error: {code or type(exc).__name__}"))
            continue

        if not _all_on(config):
            findings.append(BUCKET_BPA.failed(resource, _off_list(config)))

    if not findings:
        findings.append(BUCKET_BPA.passed("s3-buckets", f"{len(buckets)} bucket(s) checked."))
    return findings


def _policy_allows_everyone(policy_json: str) -> bool:
    """
    Our own simple "is this policy public?" test, used only as a fallback.
    Public = an Allow statement whose Principal is "*" (anyone), with no
    Condition limiting it. AWS's own evaluation (below) is smarter, so we
    prefer it whenever AWS gives us an answer.
    """
    statements = json.loads(policy_json).get("Statement", [])
    if isinstance(statements, dict):          # a single statement can be a dict
        statements = [statements]
    for st in statements:
        principal = st.get("Principal")
        anyone = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
        if st.get("Effect") == "Allow" and anyone and not st.get("Condition"):
            return True
    return False


def _is_bucket_public(s3, name: str) -> bool | None:
    """
    Returns True/False, or None if the bucket has no policy at all.
    Step 1: ask AWS (GetBucketPolicyStatus gives a ready-made IsPublic).
    Step 2: if AWS gives no answer (some S3-compatible APIs and test
            mocks don't), read the policy and check it ourselves.
    """
    try:
        status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
    except ClientError as exc:
        if error_code(exc) in NO_POLICY_CODES:
            return None
        raise
    if "IsPublic" in status:
        return bool(status["IsPublic"])

    try:
        policy = s3.get_bucket_policy(Bucket=name)["Policy"]
    except ClientError as exc:
        if error_code(exc) in NO_POLICY_CODES:
            return None
        raise
    return _policy_allows_everyone(policy)


def check_bucket_public(ctx: AuditContext) -> list[Finding]:
    s3 = ctx.client("s3")
    buckets = _buckets(ctx)
    findings: list[Finding] = []

    for name in buckets:
        resource = f"s3://{name}"
        try:
            public = _is_bucket_public(s3, name)
        except ClientError as exc:
            code = error_code(exc)
            if code in ACCESS_DENIED_CODES:
                findings.append(BUCKET_PUBLIC.error(resource, "Access denied reading bucket policy."))
            else:
                findings.append(BUCKET_PUBLIC.error(resource, f"AWS error: {code or type(exc).__name__}"))
            continue

        # None = no bucket policy, so the policy can't make it public.
        if public:
            findings.append(BUCKET_PUBLIC.failed(resource, "Bucket policy allows public access."))

    if not findings:
        findings.append(BUCKET_PUBLIC.passed("s3-buckets", f"{len(buckets)} bucket(s) checked."))
    return findings


# ============================================================
# SECTION 4: Export list for the registry
# ============================================================

CHECKS = [
    (ACCOUNT_BPA, check_account_bpa),
    (BUCKET_BPA, check_bucket_bpa),
    (BUCKET_PUBLIC, check_bucket_public),
]
