"""
Core data structures for the CloudGuard rule engine.

Both the static (Terraform) scanner and the live AWS scanner emit
the same Finding objects, so downstream reporting/scoring code is
completely shared between the two scan modes.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Numeric weight used for scoring (higher = worse)
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


@dataclass
class Finding:
    rule_id: str                 # e.g. "CG001"
    title: str                   # short human title
    severity: Severity
    resource_type: str           # e.g. "aws_s3_bucket"
    resource_id: str             # e.g. "my_bucket" or live ARN
    description: str             # what's wrong
    remediation: str             # how to fix it
    cis_control: Optional[str] = None   # CIS AWS Foundations Benchmark ref
    source_file: Optional[str] = None   # for IaC findings
    source_line: Optional[int] = None
    scan_mode: str = "iac"       # "iac" or "live"
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        d = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "description": self.description,
            "remediation": self.remediation,
            "cis_control": self.cis_control,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "scan_mode": self.scan_mode,
        }
        return d


class Rule:
    """
    Base class for a single security rule.

    Each rule implements `check_terraform_resource` and/or
    `check_live_resource` depending on which scan modes it supports.
    A rule declares which resource_type(s) it applies to so the
    engine can dispatch efficiently.
    """
    id: str = "CG000"
    title: str = "Unnamed rule"
    severity: Severity = Severity.MEDIUM
    cis_control: Optional[str] = None
    applies_to: tuple = ()   # resource types this rule inspects

    def check_terraform_resource(self, resource_type: str, resource_name: str,
                                  config: dict, source_file: str) -> list[Finding]:
        """Return a list of Findings (usually 0 or 1) for a parsed TF resource block."""
        return []

    def check_live_resource(self, resource_type: str, resource_id: str,
                             data: dict) -> list[Finding]:
        """Return a list of Findings for a live AWS resource fetched via boto3."""
        return []
