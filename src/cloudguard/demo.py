"""
demo.py - a fake AWS account with planted problems
==================================================

What is this file?
    Starts "moto", a library that pretends to be AWS inside this
    Python process. Then it creates a small fake account with some
    mistakes planted on purpose, so the audit has something to find.

Why does it exist?
    You can demo cloudguard to anyone, anywhere, for $0, with no AWS
    account and no internet (Req 9.1, 9.2).

Planted problems (what the audit should catch):
    - root has no MFA                       -> IAM-01 FAIL
    - user "demo-alice" has a password but no MFA -> IAM-03 FAIL
    - no password policy                    -> IAM-05 FAIL
    - no account-level Block Public Access  -> S3-01 FAIL
    - bucket "demo-public-website" is public -> S3-02, S3-03 FAIL
    - security group "demo-ssh-open" allows SSH from anywhere -> NET-01 FAIL
    - only a single-region CloudTrail trail -> LOG-01 FAIL
Things set up correctly (should PASS):
    - bucket "demo-private-logs" has Block Public Access fully on
    - GuardDuty is enabled                  -> LOG-02 PASS
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cloudguard.auth import AuthConfig

DEMO_REGION = "us-east-1"
DEMO_ACCOUNT = "123456789012"   # moto's default fake account ID


class DemoUnavailable(Exception):
    """moto isn't installed."""


def start_demo():
    """
    Start fake AWS, plant the problems, and return
    (mock_handle, AuthConfig). Call mock_handle.stop() when finished.
    """
    # ============================================================
    # SECTION 1: Make sure no REAL AWS can be reached (Req 9.2)
    # ------------------------------------------------------------
    # Fake keys in environment variables. Even if something
    # slipped past moto, AWS would reject these keys.
    # We also hide the user's real ~/.aws files from this process.
    # ============================================================
    os.environ.update({
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": DEMO_REGION,
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    })
    os.environ.pop("AWS_PROFILE", None)

    try:
        from moto import mock_aws
    except ImportError as exc:
        raise DemoUnavailable(
            "Demo mode needs moto. Install it with: pip install -e '.[demo]'"
        ) from exc

    # ============================================================
    # SECTION 2: Start the fake AWS
    # ------------------------------------------------------------
    # From here on, every boto3 call in this process is answered
    # by moto instead of the internet.
    # ============================================================
    mock = mock_aws()
    mock.start()

    import boto3
    seed = boto3.Session(region_name=DEMO_REGION)

    # ============================================================
    # SECTION 3: Create the audit role (same policy as production)
    # ------------------------------------------------------------
    # We load the real iam-policy.json, so the demo uses exactly
    # the policy you'd deploy.
    # ============================================================
    iam = seed.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{DEMO_ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }],
    }
    role = iam.create_role(
        RoleName="CloudGuardAuditRole",
        AssumeRolePolicyDocument=json.dumps(trust),
        MaxSessionDuration=3600,
    )["Role"]
    iam.put_role_policy(
        RoleName="CloudGuardAuditRole",
        PolicyName="CloudGuardReadOnlyAllowList",
        PolicyDocument=_load_policy(),
    )

    # ============================================================
    # SECTION 4: Plant IAM problems
    # ============================================================
    iam.create_user(UserName="demo-alice")
    iam.create_login_profile(UserName="demo-alice", Password="Demo-Passw0rd!x")  # console, no MFA
    iam.create_user(UserName="demo-bob")
    iam.create_access_key(UserName="demo-bob")   # new key: should PASS the 90-day check

    # ============================================================
    # SECTION 5: Plant S3 problems
    # ============================================================
    s3 = seed.client("s3")

    s3.create_bucket(Bucket="demo-public-website")
    s3.put_bucket_policy(
        Bucket="demo-public-website",
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",                       # <- anyone on the internet
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::demo-public-website/*",
            }],
        }),
    )

    s3.create_bucket(Bucket="demo-private-logs")
    s3.put_public_access_block(
        Bucket="demo-private-logs",
        PublicAccessBlockConfiguration={k: True for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
        )},
    )

    # ============================================================
    # SECTION 6: Plant a network problem
    # ============================================================
    ec2 = seed.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]

    ssh = ec2.create_security_group(GroupName="demo-ssh-open", Description="SSH open to world", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=ssh["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    web = ec2.create_security_group(GroupName="demo-web", Description="HTTPS only", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=web["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    # ============================================================
    # SECTION 7: Logging - a weak trail and an enabled GuardDuty
    # ============================================================
    s3.create_bucket(Bucket="demo-trail-logs")
    s3.put_public_access_block(
        Bucket="demo-trail-logs",
        PublicAccessBlockConfiguration={k: True for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
        )},
    )
    ct = seed.client("cloudtrail")
    ct.create_trail(Name="demo-single-region", S3BucketName="demo-trail-logs", IsMultiRegionTrail=False)
    ct.start_logging(Name="demo-single-region")

    seed.client("guardduty").create_detector(Enable=True)

    config = AuthConfig(
        role_arn=role["Arn"],
        mfa_serial=f"arn:aws:iam::{DEMO_ACCOUNT}:mfa/demo-device",
        region=DEMO_REGION,
        profile=None,
    )
    return mock, config


def _load_policy() -> str:
    """Read iam-policy.json from the project root."""
    path = Path(__file__).resolve().parents[2] / "iam-policy.json"
    if path.exists():
        return path.read_text(encoding="utf-8")

    # Fallback for non-editable installs: build the same policy from guard.py.
    from cloudguard.guard import AUDIT_OPERATIONS, iam_actions
    actions = sorted(iam_actions(AUDIT_OPERATIONS))
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": "*"},
            {"Effect": "Deny", "NotAction": actions, "Resource": "*"},
        ],
    })
