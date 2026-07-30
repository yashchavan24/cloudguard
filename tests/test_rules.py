"""
Unit tests for CloudGuard's rule engine.

Run with: pytest tests/ -v
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudguard.engine import scan_terraform, compute_score

VULNERABLE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable")
SECURE_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "secure")


class TestVulnerableConfig:
    """The intentionally-vulnerable example should trigger every category of rule."""

    @pytest.fixture(scope="class")
    def findings(self):
        f, errors, count = scan_terraform(VULNERABLE_PATH)
        assert errors == []
        return f

    def test_detects_all_findings(self, findings):
        assert len(findings) == 12

    def test_detects_public_s3_acl(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "data_bucket"]
        assert "CG001" in ids

    def test_detects_disabled_public_access_block(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "data_bucket_pab"]
        assert "CG001" in ids

    def test_detects_missing_s3_encryption(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "data_bucket"]
        assert "CG002" in ids

    def test_detects_missing_s3_versioning(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "data_bucket"]
        assert "CG003" in ids

    def test_detects_open_ssh(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "web_sg"]
        assert "CG010" in ids

    def test_detects_open_rdp(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "web_sg"]
        assert "CG011" in ids

    def test_detects_wide_open_security_group(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "web_sg"]
        assert "CG012" in ids

    def test_detects_iam_wildcard_policy(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "overly_broad"]
        assert "CG020" in ids

    def test_detects_unencrypted_ebs(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "unencrypted_volume"]
        assert "CG030" in ids

    def test_detects_public_rds(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "public_db"]
        assert "CG031" in ids

    def test_detects_unencrypted_rds(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "public_db"]
        assert "CG032" in ids

    def test_detects_risky_lambda_role(self, findings):
        ids = [f.rule_id for f in findings if f.resource_id == "risky_function"]
        assert "CG040" in ids

    def test_score_is_grade_f(self, findings):
        score = compute_score(findings, resource_count=7)
        assert score["grade"] == "F"
        assert score["score"] <= 5


class TestSecureConfig:
    """A properly-configured example should produce zero false positives."""

    @pytest.fixture(scope="class")
    def findings(self):
        f, errors, count = scan_terraform(SECURE_PATH)
        assert errors == []
        return f

    def test_no_findings(self, findings):
        assert len(findings) == 0, f"Unexpected findings on secure config: {findings}"

    def test_score_is_perfect(self, findings):
        score = compute_score(findings, resource_count=6)
        assert score["grade"] == "A"
        assert score["score"] == 100


class TestScoring:
    def test_empty_scan_scores_100(self):
        score = compute_score([], resource_count=0)
        assert score["score"] == 100
        assert score["grade"] == "A"

    def test_score_never_negative(self):
        from cloudguard.rules.base import Finding, Severity
        many_criticals = [
            Finding(
                rule_id="CG001", title="test", severity=Severity.CRITICAL,
                resource_type="x", resource_id=f"r{i}", description="d", remediation="r",
            )
            for i in range(50)
        ]
        score = compute_score(many_criticals, resource_count=5)
        assert score["score"] >= 0
