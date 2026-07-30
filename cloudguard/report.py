"""
Report generators: console (rich), JSON, and SARIF.

SARIF (Static Analysis Results Interchange Format) is the format GitHub's
code scanning / Security tab natively understands, so a SARIF report from
CloudGuard can be uploaded directly via a GitHub Action and show up as
native inline PR annotations, without needing any custom UI.
"""
import json
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


def print_console_report(findings, score_info, scan_mode: str):
    console = Console()
    console.print()
    console.print(Panel.fit(
        f"[bold]CloudGuard Scan Report[/bold]  ({scan_mode})",
        border_style="blue"
    ))

    grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    console.print(
        f"\nSecurity Score: [bold {grade_color.get(score_info['grade'], 'white')}]"
        f"{score_info['score']}/100 (Grade {score_info['grade']})[/]"
    )
    console.print(f"Resources scanned: {score_info['resources_scanned']}")
    console.print(f"Total findings: {score_info['total_findings']}\n")

    if not findings:
        console.print("[bold green]No issues found. Clean scan.[/bold green]\n")
        return

    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Rule", width=8, no_wrap=True)
    table.add_column("Resource", width=24, no_wrap=False)
    table.add_column("Issue", ratio=3)
    table.add_column("CIS Control", width=14, no_wrap=True)

    # Sort critical first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order[x.severity.value]):
        color = SEVERITY_COLOR[f.severity.value]
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.rule_id,
            f"{f.resource_type}\n{f.resource_id}",
            f"{f.title}\n[dim]{f.description}[/dim]\n[italic]Fix: {f.remediation}[/italic]",
            f.cis_control or "-",
        )
    console.print(table)
    console.print()


def to_json(findings, score_info, scan_mode: str) -> str:
    report = {
        "tool": "CloudGuard",
        "scan_mode": scan_mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score_info,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(report, indent=2)


def to_sarif(findings) -> str:
    """Minimal but valid SARIF 2.1.0 output for GitHub code scanning upload."""
    rules_seen = {}
    results = []

    for f in findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation},
                "properties": {"cis_control": f.cis_control or ""},
            }

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.source_file or f.resource_id},
                "region": {"startLine": f.source_line or 1},
            }
        }
        sarif_level = {"CRITICAL": "error", "HIGH": "error",
                        "MEDIUM": "warning", "LOW": "note"}[f.severity.value]

        results.append({
            "ruleId": f.rule_id,
            "level": sarif_level,
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [location],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CloudGuard",
                    "informationUri": "https://github.com/yashchavan24/cloudguard",
                    "version": "0.1.0",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
