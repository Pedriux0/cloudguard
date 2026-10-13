"""
checks/network.py - firewall checks (what's open to the internet?)
=================================================================

What is this file?
    Two checks on EC2 security groups. A security group is a
    virtual firewall attached to servers.

Why does it matter?
    SSH (port 22) and RDP (port 3389) are remote-admin doors.
    If a security group lets the whole internet reach them
    (0.0.0.0/0 for IPv4, ::/0 for IPv6), bots will start
    guessing passwords within minutes.

Requirements covered: 4.1 - 4.3
"""

from __future__ import annotations

from cloudguard.checks.base import AuditContext, CheckInfo
from cloudguard.models import Finding, Severity


# ============================================================
# SECTION 1: Check descriptions
# ============================================================

SSH_OPEN = CheckInfo(
    "NET-01", "No security group allows SSH (22) from the internet", Severity.HIGH, "5.2 / 5.3",
    "Restrict port 22 to your IP or VPN range, or use SSM Session Manager instead of SSH.",
)
RDP_OPEN = CheckInfo(
    "NET-02", "No security group allows RDP (3389) from the internet", Severity.HIGH, "5.2 / 5.3",
    "Restrict port 3389 to your IP or VPN range, or use SSM Fleet Manager instead of RDP.",
)

# "Anywhere on the internet", in IPv4 and IPv6 form.
ANYWHERE_V4 = "0.0.0.0/0"
ANYWHERE_V6 = "::/0"


# ============================================================
# SECTION 2: Rule matching (Req 4.3)
# ------------------------------------------------------------
# A rule is dangerous for a port if BOTH are true:
#   1. It covers the port:
#        - protocol "-1" means ALL traffic, all ports, OR
#        - protocol tcp and FromPort <= port <= ToPort
#          (so a range like 0-65535 also counts)
#   2. Its source is the whole internet (0.0.0.0/0 or ::/0)
# ============================================================

def _rule_covers_port(rule: dict, port: int) -> bool:
    protocol = str(rule.get("IpProtocol"))
    if protocol == "-1":
        return True
    if protocol not in ("tcp", "6"):   # "6" is TCP's protocol number
        return False
    return rule.get("FromPort", -1) <= port <= rule.get("ToPort", -1)


def _rule_open_to_internet(rule: dict) -> bool:
    v4 = any(r.get("CidrIp") == ANYWHERE_V4 for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == ANYWHERE_V6 for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


def is_port_open_to_internet(group: dict, port: int) -> bool:
    return any(
        _rule_covers_port(rule, port) and _rule_open_to_internet(rule)
        for rule in group.get("IpPermissions", [])   # IpPermissions = inbound rules
    )


# ============================================================
# SECTION 3: Load security groups once, check both ports
# ------------------------------------------------------------
# A paginator automatically follows "next page" tokens, so we
# get every group even in big accounts.
# ============================================================

def _security_groups(ctx: AuditContext) -> list[dict]:
    if "security_groups" not in ctx.cache:
        paginator = ctx.client("ec2").get_paginator("describe_security_groups")
        groups: list[dict] = []
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
        ctx.cache["security_groups"] = groups
    return ctx.cache["security_groups"]


def _check_port(ctx: AuditContext, info: CheckInfo, port: int) -> list[Finding]:
    groups = _security_groups(ctx)
    findings = [
        info.failed(
            f"{g['GroupId']} ({g.get('GroupName', '')})",
            f"Port {port} is open to the internet.",
        )
        for g in groups
        if is_port_open_to_internet(g, port)
    ]
    if not findings:
        findings.append(info.passed("security-groups", f"{len(groups)} group(s) checked in {ctx.region}."))
    return findings


def check_ssh_open(ctx: AuditContext) -> list[Finding]:
    return _check_port(ctx, SSH_OPEN, 22)


def check_rdp_open(ctx: AuditContext) -> list[Finding]:
    return _check_port(ctx, RDP_OPEN, 3389)


# ============================================================
# SECTION 4: Export list for the registry
# ============================================================

CHECKS = [
    (SSH_OPEN, check_ssh_open),
    (RDP_OPEN, check_rdp_open),
]
