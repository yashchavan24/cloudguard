"""
Scan engine: ties together parsers/collectors + rules to produce a
list of Findings, and computes an overall security score.
"""
from .rules.checks import ALL_RULES
from .rules.base import SEVERITY_WEIGHT, Severity
from .parsers.terraform import parse_terraform_directory


def scan_terraform(path: str):
    """Run all IaC-capable rules against every resource in a Terraform directory."""
    resources, parse_errors = parse_terraform_directory(path)
    findings = []
    for resource_type, name, config, source_file in resources:
        for rule in ALL_RULES:
            if resource_type in rule.applies_to:
                findings.extend(
                    rule.check_terraform_resource(resource_type, name, config, source_file)
                )
    return findings, parse_errors, len(resources)


def scan_live_aws(session):
    """Run all live-capable rules against every resource pulled from a real AWS account."""
    from .collectors.aws_live import collect_all
    resources, collector_errors = collect_all(session)
    findings = []
    for resource_type, resource_id, data in resources:
        for rule in ALL_RULES:
            if resource_type in rule.applies_to:
                findings.extend(
                    rule.check_live_resource(resource_type, resource_id, data)
                )
    return findings, collector_errors, len(resources)


def compute_score(findings, resource_count: int) -> dict:
    """
    Produces a 0-100 security score (100 = no issues found).
    Score subtracts weighted penalty per finding, normalized against
    resource count so a bigger environment isn't unfairly penalized
    just for having more resources to misconfigure.
    """
    if resource_count == 0:
        return {"score": 100, "grade": "A", "total_findings": 0}

    total_penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    # Normalize: penalty per resource, scaled, capped at 100
    normalized_penalty = min(100, (total_penalty / max(resource_count, 1)) * 15)
    score = max(0, round(100 - normalized_penalty))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    by_severity = {sev.value: 0 for sev in Severity}
    for f in findings:
        by_severity[f.severity.value] += 1

    return {
        "score": score,
        "grade": grade,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "resources_scanned": resource_count,
    }
