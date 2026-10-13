"""
test_guard.py - proof that cloudguard cannot change AWS (Req 8, 10.2)
====================================================================

These tests try to do "bad" things on purpose and check that:
    - the call is blocked BEFORE it reaches AWS, and
    - the resource is still there afterwards.
They also check that the 3 copies of the allow-list (guard.py,
iam-policy.json, CloudFormation YAML) never drift apart.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import boto3
import pytest

from cloudguard.guard import (
    AUDIT_OPERATIONS,
    BASE_OPERATIONS,
    BlockedOperationError,
    iam_actions,
    install_guard,
)
from cloudguard.runner import run_audit

ROOT = Path(__file__).resolve().parents[1]


# ============================================================
# SECTION 1: Write calls are blocked
# ============================================================

def test_guard_blocks_delete_bucket_and_bucket_survives(aws, audit_ctx):
    aws.client("s3").create_bucket(Bucket="important-data")

    with pytest.raises(BlockedOperationError):
        audit_ctx.client("s3").delete_bucket(Bucket="important-data")

    names = [b["Name"] for b in aws.client("s3").list_buckets()["Buckets"]]
    assert "important-data" in names


def test_guard_blocks_opening_a_firewall(aws, audit_ctx):
    ec2 = aws.client("ec2")
    gid = ec2.describe_security_groups()["SecurityGroups"][0]["GroupId"]

    with pytest.raises(BlockedOperationError):
        audit_ctx.client("ec2").authorize_security_group_ingress(
            GroupId=gid,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

    rules = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]["IpPermissions"]
    assert not any(r.get("IpProtocol") == "-1" and r.get("IpRanges") for r in rules)


def test_guard_blocks_iam_changes(aws, audit_ctx):
    with pytest.raises(BlockedOperationError):
        audit_ctx.client("iam").create_user(UserName="backdoor")
    assert aws.client("iam").list_users()["Users"] == []


def test_base_credentials_can_only_assume_role(aws):
    base = boto3.Session(region_name="us-east-1")
    install_guard(base, BASE_OPERATIONS)
    with pytest.raises(BlockedOperationError):
        base.client("s3").list_buckets()


def test_blocked_call_inside_a_check_becomes_error_finding(audit_ctx, monkeypatch):
    """If a check ever tries a write, the audit continues with an ERROR."""
    from cloudguard import checks
    from cloudguard.checks.iam import ROOT_MFA

    def evil_check(ctx):
        ctx.client("s3").delete_bucket(Bucket="x")
        return []

    monkeypatch.setattr(checks, "ALL_CHECKS", [(ROOT_MFA, evil_check)])
    monkeypatch.setattr("cloudguard.runner.ALL_CHECKS", [(ROOT_MFA, evil_check)])

    report = run_audit(audit_ctx)
    assert [f.status.value for f in report.findings] == ["ERROR"]
    assert "DeleteBucket" in report.findings[0].detail


# ============================================================
# SECTION 2: The allow-list is identical in all 3 places
# ============================================================

def test_iam_policy_json_matches_guard():
    policy = json.loads((ROOT / "iam-policy.json").read_text())
    allow, deny = policy["Statement"]
    expected = iam_actions(AUDIT_OPERATIONS)

    assert allow["Effect"] == "Allow" and set(allow["Action"]) == expected
    assert deny["Effect"] == "Deny" and set(deny["NotAction"]) == expected
    # SECURITY: no wildcards anywhere.
    assert not any("*" in a for a in allow["Action"])


def test_cloudformation_template_matches_guard():
    text = (ROOT / "infra" / "cloudguard-role.yaml").read_text()
    # Every "- service:Action" list item in the template.
    items = re.findall(r"^\s+- ([a-z0-9]+:[A-Za-z]+)\s*$", text, flags=re.MULTILINE)
    expected = iam_actions(AUDIT_OPERATIONS)

    half = len(items) // 2
    allow_list, deny_list = items[:half], items[half:]
    assert set(allow_list) == expected
    assert set(deny_list) == expected
    assert "aws:MultiFactorAuthPresent" in text
    assert "MaxSessionDuration: 3600" in text


def test_operator_user_can_only_assume_the_audit_role():
    """The person running cloudguard gets ONE permission, and only with MFA."""
    # 1. The standalone JSON policy
    allow, deny = json.loads((ROOT / "iam-operator-policy.json").read_text())["Statement"]
    assert allow["Effect"] == "Allow" and allow["Action"] == "sts:AssumeRole"
    assert allow["Resource"].endswith(":role/CloudGuardAuditRole")
    assert deny["Effect"] == "Deny" and deny["NotAction"] == "sts:AssumeRole"

    # 2. The CloudFormation copy (checked as text)
    text = (ROOT / "infra" / "cloudguard-operator.yaml").read_text()
    allowed_actions = re.findall(r"^\s+Action:\s*(\S+)\s*$", text, flags=re.MULTILINE)
    assert allowed_actions == ["sts:AssumeRole"]
    assert "role/CloudGuardAuditRole" in text
    assert "NotAction: sts:AssumeRole" in text

    # 3. MFA is enforced where AWS evaluates it: the ROLE's trust policy.
    trust = json.loads((ROOT / "iam-trust-policy.json").read_text())["Statement"][0]
    assert trust["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] == "true"
    # No console password: there must be no real "LoginProfile:" YAML key
    # (comments mentioning it are fine).
    assert not re.search(r"^\s+LoginProfile:", text, flags=re.MULTILINE)


def test_allow_list_is_read_only_by_name():
    """Req 8: every allowed call is a Get/List/Describe/Generate call."""
    for service, ops in AUDIT_OPERATIONS.items():
        for op in ops:
            assert re.match(r"^(Get|List|Describe|Generate)", op), f"{service}:{op}"
