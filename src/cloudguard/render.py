"""
render.py - turning a Report into something readable
====================================================

What is this file?
    Three ways to show a Report:
      - summary_table(): colored table for the terminal
      - detail_view():   full info, including how to fix
      - to_markdown() / to_json(): text for `export`

Why does it exist?
    The checks only produce data. This file is the only place that
    decides how the data looks, so changing the look never risks
    changing the security logic.

Requirements covered: 7.1, 7.2, 7.4, 9.4
"""

from __future__ import annotations

import json

from rich.panel import Panel
from rich.table import Table

from cloudguard.models import Finding, Report, Severity, Status


# ============================================================
# SECTION 1: Colors
# ------------------------------------------------------------
# FAIL = red, ERROR = yellow, PASS = green. Severity gets its own
# color scale so the worst problems stand out first.
# ============================================================

STATUS_STYLE = {Status.FAIL: "bold red", Status.ERROR: "yellow", Status.PASS: "green"}
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}
DEMO_BANNER = "[bold black on yellow] DEMO DATA - fake AWS account (moto), no real resources [/]"


# ============================================================
# SECTION 2: Header (who / where / when / how many)
# ============================================================

def header_text(report: Report) -> str:
    c = report.counts()
    s = c["status"]
    sev = c["severity"]
    return (
        f"Account [bold]{report.account_id}[/]  Region [bold]{report.region}[/]  "
        f"Time {report.generated_at:%Y-%m-%d %H:%M:%S} UTC\n"
        f"[red]FAIL {s['FAIL']}[/]  [yellow]ERROR {s['ERROR']}[/]  [green]PASS {s['PASS']}[/]   "
        f"|  CRITICAL {sev['CRITICAL']}  HIGH {sev['HIGH']}  MEDIUM {sev['MEDIUM']}  LOW {sev['LOW']}"
    )


# ============================================================
# SECTION 3: Terminal views
# ============================================================

def summary_table(report: Report) -> Table:
    """The table shown after `audit` (Req 7.1). Worst problems on top."""
    title = "cloudguard audit" + ("  [DEMO DATA]" if report.demo else "")
    table = Table(title=title, caption=header_text(report), show_lines=False)
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Resource", overflow="fold")
    table.add_column("Title", overflow="fold")

    for f in report.sorted_findings():
        table.add_row(
            f"[{SEVERITY_STYLE[f.severity]}]{f.severity.name}[/]",
            f"[{STATUS_STYLE[f.status]}]{f.status.value}[/]",
            f.check_id,
            f.resource,
            f.title,
        )
    return table


def select_findings(report: Report, selector: str) -> list[Finding]:
    """
    `show HIGH`   -> every finding with severity HIGH
    `show S3-03`  -> every finding from check S3-03
    """
    key = selector.strip().upper()
    if key in Severity.__members__:
        return [f for f in report.sorted_findings() if f.severity.name == key]
    return [f for f in report.sorted_findings() if f.check_id.upper() == key]


def detail_view(finding: Finding) -> Panel:
    """One box per finding, with the fix (Req 7.2)."""
    body = (
        f"[bold]Status:[/] [{STATUS_STYLE[finding.status]}]{finding.status.value}[/]   "
        f"[bold]Severity:[/] {finding.severity.name}   [bold]CIS:[/] {finding.cis}\n"
        f"[bold]Resource:[/] {finding.resource}\n"
        f"[bold]Detail:[/] {finding.detail or '-'}\n"
        f"[bold]Fix:[/] {finding.remediation}"
    )
    return Panel(body, title=f"{finding.check_id} - {finding.title}", expand=False)


# ============================================================
# SECTION 4: Export formats (plain text, no colors)
# ============================================================

def to_markdown(report: Report) -> str:
    c = report.counts()
    lines = [
        "# cloudguard audit report",
        "",
    ]
    if report.demo:
        lines += ["> **DEMO DATA**: generated against a fake AWS account (moto).", ""]
    lines += [
        f"- **Account:** {report.account_id}",
        f"- **Region:** {report.region}",
        f"- **Generated:** {report.generated_at:%Y-%m-%d %H:%M:%S} UTC",
        f"- **Status:** FAIL {c['status']['FAIL']} / ERROR {c['status']['ERROR']} / PASS {c['status']['PASS']}",
        "- **Failed by severity:** "
        + ", ".join(f"{k} {v}" for k, v in c["severity"].items()),
        "",
        "| Severity | Status | Check | Resource | Title | CIS | Fix |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in report.sorted_findings():
        cells = [f.severity.name, f.status.value, f.check_id, f.resource, f.title, f.cis, f.remediation]
        # A "|" inside a cell would break the Markdown table, so escape it.
        lines.append("| " + " | ".join(str(x).replace("|", "\\|") for x in cells) + " |")
    return "\n".join(lines) + "\n"


def to_json(report: Report) -> str:
    return json.dumps(
        {
            "account_id": report.account_id,
            "region": report.region,
            "generated_at": report.generated_at.isoformat(),
            "demo": report.demo,
            "summary": report.counts(),
            "findings": [f.to_dict() for f in report.sorted_findings()],
        },
        indent=2,
    )
