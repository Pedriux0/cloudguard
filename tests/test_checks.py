"""
test_checks.py - every check category has a PASS and a FAIL test (Req 10.1)
==========================================================================

Pattern used in every test:
    1. Arrange: create AWS resources in moto (the "unguarded" session)
    2. Act:     run ONE check with the guarded, read-only context
    3. Assert:  the check says PASS or FAIL as expected
"""

from __future__ import annotations

import json

from cloudguard.checks import iam, logging_checks, network, s3
from cloudguard.models import Status

BPA_ALL_ON = {k: True for k in s3.BPA_KEYS}


def statuses(findings):
    return {f.status for f in findings}


# ============================================================
# IAM
# ============================================================

def test_root_mfa_fails_when_missing(aws, audit_ctx):
    # moto's root account has no MFA by default.
    assert statuses(iam.check_root_mfa(audit_ctx)) == {Status.FAIL}


def test_root_keys_pass_when_none(aws, audit_ctx):
    assert statuses(iam.check_root_keys(audit_ctx)) == {Status.PASS}


def test_console_user_without_mfa_fails(aws, audit_ctx):
    client = aws.client("iam")
    client.create_user(UserName="alice")
    client.create_login_profile(UserName="alice", Password="Long-Passw0rd-123!")

    findings = iam.check_user_mfa(audit_ctx)
    assert [f.status for f in findings] == [Status.FAIL]
    assert findings[0].resource == "iam-user/alice"


def test_api_only_user_does_not_need_mfa(aws, audit_ctx):
    aws.client("iam").create_user(UserName="ci-bot")   # no password = no console
    assert statuses(iam.check_user_mfa(audit_ctx)) == {Status.PASS}


def test_password_policy_missing_fails(aws, audit_ctx):
    assert statuses(iam.check_password_policy(audit_ctx)) == {Status.FAIL}


def test_password_policy_strong_passes(aws, audit_ctx):
    aws.client("iam").update_account_password_policy(MinimumPasswordLength=14)
    assert statuses(iam.check_password_policy(audit_ctx)) == {Status.PASS}


def test_new_access_key_passes_age_check(aws, audit_ctx):
    client = aws.client("iam")
    client.create_user(UserName="bob")
    client.create_access_key(UserName="bob")
    assert statuses(iam.check_key_age(audit_ctx)) == {Status.PASS}


def test_old_access_key_fails_age_check(audit_ctx, monkeypatch):
    # Feed the check a credential report with a 200-day-old key.
    audit_ctx.cache["credential_report"] = [{
        "user": "carol",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": "2020-01-01T00:00:00+00:00",
        "access_key_2_active": "false",
    }]
    findings = iam.check_key_age(audit_ctx)
    assert [f.status for f in findings] == [Status.FAIL]
    assert findings[0].resource == "iam-user/carol/key1"


# ============================================================
# S3
# ============================================================

def test_account_bpa_missing_fails(aws, audit_ctx):
    assert statuses(s3.check_account_bpa(audit_ctx)) == {Status.FAIL}


def test_account_bpa_on_passes(aws, audit_ctx):
    aws.client("s3control").put_public_access_block(
        AccountId=audit_ctx.account_id, PublicAccessBlockConfiguration=BPA_ALL_ON,
    )
    assert statuses(s3.check_account_bpa(audit_ctx)) == {Status.PASS}


def test_bucket_bpa(aws, audit_ctx):
    client = aws.client("s3")
    client.create_bucket(Bucket="open-bucket")
    client.create_bucket(Bucket="closed-bucket")
    client.put_public_access_block(Bucket="closed-bucket", PublicAccessBlockConfiguration=BPA_ALL_ON)

    findings = s3.check_bucket_bpa(audit_ctx)
    failed = {f.resource for f in findings if f.status is Status.FAIL}
    assert failed == {"s3://open-bucket"}


def test_public_bucket_policy_fails(aws, audit_ctx):
    client = aws.client("s3")
    client.create_bucket(Bucket="public-site")
    client.put_bucket_policy(Bucket="public-site", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::public-site/*"}],
    }))
    findings = s3.check_bucket_public(audit_ctx)
    assert [(f.status, f.resource) for f in findings] == [(Status.FAIL, "s3://public-site")]


def test_bucket_without_policy_passes(aws, audit_ctx):
    aws.client("s3").create_bucket(Bucket="private-data")
    assert statuses(s3.check_bucket_public(audit_ctx)) == {Status.PASS}


def test_policy_with_condition_is_not_treated_as_public():
    policy = json.dumps({"Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*",
        "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
    }]})
    assert s3._policy_allows_everyone(policy) is False


# ============================================================
# Network
# ============================================================

def _sg(aws, name, permissions):
    ec2 = aws.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=permissions)
    return gid


def test_ssh_open_to_world_fails(aws, audit_ctx):
    gid = _sg(aws, "ssh-open", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    findings = network.check_ssh_open(audit_ctx)
    assert [f.status for f in findings] == [Status.FAIL]
    assert gid in findings[0].resource


def test_ssh_from_office_ip_passes(aws, audit_ctx):
    _sg(aws, "ssh-office", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": [{"CidrIp": "203.0.113.10/32"}]}])
    assert statuses(network.check_ssh_open(audit_ctx)) == {Status.PASS}


def test_rdp_open_via_ipv6_port_range_fails(aws, audit_ctx):
    # Range 3000-4000 includes 3389, and ::/0 is "anywhere" in IPv6.
    _sg(aws, "rdp-v6", [{"IpProtocol": "tcp", "FromPort": 3000, "ToPort": 4000,
                         "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    assert statuses(network.check_rdp_open(audit_ctx)) == {Status.FAIL}


def test_all_traffic_rule_matches_any_port():
    group = {"IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    assert network.is_port_open_to_internet(group, 22)
    assert network.is_port_open_to_internet(group, 3389)


# ============================================================
# Logging and detection
# ============================================================

def _trail(aws, name, multi_region, logging_on):
    aws.client("s3").create_bucket(Bucket=f"{name}-logs")
    ct = aws.client("cloudtrail")
    ct.create_trail(Name=name, S3BucketName=f"{name}-logs", IsMultiRegionTrail=multi_region)
    if logging_on:
        ct.start_logging(Name=name)


def test_no_trail_fails(aws, audit_ctx):
    assert statuses(logging_checks.check_cloudtrail(audit_ctx)) == {Status.FAIL}


def test_single_region_trail_fails(aws, audit_ctx):
    _trail(aws, "only-here", multi_region=False, logging_on=True)
    assert statuses(logging_checks.check_cloudtrail(audit_ctx)) == {Status.FAIL}


def test_multi_region_logging_trail_passes(aws, audit_ctx):
    _trail(aws, "org-trail", multi_region=True, logging_on=True)
    assert statuses(logging_checks.check_cloudtrail(audit_ctx)) == {Status.PASS}


def test_guardduty_off_fails(aws, audit_ctx):
    assert statuses(logging_checks.check_guardduty(audit_ctx)) == {Status.FAIL}


def test_guardduty_on_passes(aws, audit_ctx):
    aws.client("guardduty").create_detector(Enable=True)
    assert statuses(logging_checks.check_guardduty(audit_ctx)) == {Status.PASS}
