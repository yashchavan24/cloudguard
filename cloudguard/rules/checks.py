"""
Concrete security rules.

Each rule works against BOTH:
  - a parsed Terraform resource block (dict of attributes), and/or
  - a live AWS resource description (dict returned by boto3), when applicable

Keeping one rule class per check (rather than one giant if/else) makes it
trivial to add new rules and to unit test each one in isolation.
"""
from .base import Rule, Finding, Severity


def _cidr_is_open(cidr: str) -> bool:
    return cidr in ("0.0.0.0/0", "::/0")


# ---------------------------------------------------------------------------
# S3 rules
# ---------------------------------------------------------------------------

class S3PublicAccessRule(Rule):
    id = "CG001"
    title = "S3 bucket allows public access"
    severity = Severity.CRITICAL
    cis_control = "CIS AWS 2.1.5"
    applies_to = ("aws_s3_bucket", "aws_s3_bucket_public_access_block", "s3_bucket")

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        findings = []
        if resource_type == "aws_s3_bucket_public_access_block":
            blocks = ["block_public_acls", "block_public_policy",
                      "ignore_public_acls", "restrict_public_buckets"]
            if any(config.get(b) is False for b in blocks):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    resource_type=resource_type, resource_id=resource_name,
                    description="One or more public access block settings is disabled, "
                                 "allowing the bucket to be made public.",
                    remediation="Set block_public_acls, block_public_policy, "
                                "ignore_public_acls and restrict_public_buckets all to true.",
                    cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
                ))
        if resource_type == "aws_s3_bucket":
            acl = config.get("acl")
            if acl in ("public-read", "public-read-write"):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    resource_type=resource_type, resource_id=resource_name,
                    description=f"Bucket ACL is set to '{acl}', exposing objects publicly.",
                    remediation="Set acl to 'private' and use bucket policies with least "
                                "privilege for any required access.",
                    cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
                ))
        return findings

    def check_live_resource(self, resource_type, resource_id, data):
        findings = []
        if resource_type == "s3_bucket":
            pab = data.get("public_access_block", {})
            if not pab or not all(pab.get(k) for k in
                                   ["BlockPublicAcls", "BlockPublicPolicy",
                                    "IgnorePublicAcls", "RestrictPublicBuckets"]):
                findings.append(Finding(
                    rule_id=self.id, title=self.title, severity=self.severity,
                    resource_type=resource_type, resource_id=resource_id,
                    description="Bucket does not have full public access block enabled.",
                    remediation="Enable all four S3 Block Public Access settings for this bucket.",
                    cis_control=self.cis_control, scan_mode="live", evidence=pab,
                ))
        return findings


class S3EncryptionRule(Rule):
    id = "CG002"
    title = "S3 bucket missing default encryption"
    severity = Severity.HIGH
    cis_control = "CIS AWS 2.1.1"
    applies_to = ("aws_s3_bucket", "s3_bucket")

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_s3_bucket":
            return []
        if "server_side_encryption_configuration" not in config:
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="Bucket has no server_side_encryption_configuration block.",
                remediation="Add a server_side_encryption_configuration block using "
                             "AES256 or aws:kms.",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "s3_bucket":
            return []
        if not data.get("encryption_enabled"):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="Bucket has no default encryption configured.",
                remediation="Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


class S3VersioningRule(Rule):
    id = "CG003"
    title = "S3 bucket versioning disabled"
    severity = Severity.LOW
    cis_control = "CIS AWS 2.1.3"
    applies_to = ("aws_s3_bucket", "s3_bucket")

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_s3_bucket":
            return []
        versioning = config.get("versioning", {})
        if isinstance(versioning, list):
            versioning = versioning[0] if versioning else {}
        enabled = versioning.get("enabled") if isinstance(versioning, dict) else None
        if enabled is not True:
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="Versioning is not explicitly enabled, risking permanent "
                             "data loss from accidental deletes/overwrites.",
                remediation="Set versioning { enabled = true } on the bucket.",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "s3_bucket":
            return []
        if data.get("versioning_status") != "Enabled":
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="Bucket versioning is not enabled.",
                remediation="Enable versioning on this bucket.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


# ---------------------------------------------------------------------------
# Security group / network rules
# ---------------------------------------------------------------------------

class OpenSSHRule(Rule):
    id = "CG010"
    title = "Security group allows unrestricted SSH (22) access"
    severity = Severity.CRITICAL
    cis_control = "CIS AWS 5.2"
    applies_to = ("aws_security_group", "security_group")
    PORT = 22

    def _scan_ingress(self, ingress_rules, resource_type, resource_id, source_file, scan_mode):
        findings = []
        for rule in ingress_rules:
            from_port = rule.get("from_port") or rule.get("FromPort")
            to_port = rule.get("to_port") or rule.get("ToPort")
            cidrs = rule.get("cidr_blocks") or [
                r.get("CidrIp") for r in rule.get("IpRanges", [])
            ]
            if from_port is None or to_port is None:
                continue
            if from_port <= self.PORT <= to_port:
                for cidr in (cidrs or []):
                    if cidr and _cidr_is_open(cidr):
                        findings.append(Finding(
                            rule_id=self.id, title=self.title, severity=self.severity,
                            resource_type=resource_type, resource_id=resource_id,
                            description=f"Port {self.PORT} is open to {cidr}, allowing "
                                         "SSH access from anywhere on the internet.",
                            remediation="Restrict the CIDR range to known/trusted IPs, "
                                         "or require access via a bastion host / VPN.",
                            cis_control=self.cis_control, source_file=source_file,
                            scan_mode=scan_mode,
                        ))
        return findings

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_security_group":
            return []
        ingress = config.get("ingress", [])
        if isinstance(ingress, dict):
            ingress = [ingress]
        return self._scan_ingress(ingress, resource_type, resource_name, source_file, "iac")

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "security_group":
            return []
        return self._scan_ingress(data.get("IpPermissions", []), resource_type,
                                   resource_id, None, "live")


class OpenRDPRule(OpenSSHRule):
    id = "CG011"
    title = "Security group allows unrestricted RDP (3389) access"
    PORT = 3389


class OpenAllPortsRule(Rule):
    id = "CG012"
    title = "Security group allows all ports/protocols from the internet"
    severity = Severity.CRITICAL
    cis_control = "CIS AWS 5.3"
    applies_to = ("aws_security_group", "security_group")

    def _check(self, ingress_rules):
        for rule in ingress_rules:
            proto = rule.get("protocol") or rule.get("IpProtocol")
            from_port = rule.get("from_port", rule.get("FromPort", 0))
            to_port = rule.get("to_port", rule.get("ToPort", 65535))
            cidrs = rule.get("cidr_blocks") or [
                r.get("CidrIp") for r in rule.get("IpRanges", [])
            ]
            wide_open_ports = (from_port in (0, None) and to_port in (65535, None))
            wide_open_proto = proto in ("-1", -1)
            if (wide_open_ports or wide_open_proto) and any(
                    c and _cidr_is_open(c) for c in (cidrs or [])):
                return True
        return False

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_security_group":
            return []
        ingress = config.get("ingress", [])
        if isinstance(ingress, dict):
            ingress = [ingress]
        if self._check(ingress):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="Security group permits all ports/protocols from 0.0.0.0/0.",
                remediation="Scope ingress rules to specific ports and trusted CIDR ranges.",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "security_group":
            return []
        if self._check(data.get("IpPermissions", [])):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="Security group permits all ports/protocols from 0.0.0.0/0.",
                remediation="Scope ingress rules to specific ports and trusted CIDR ranges.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


# ---------------------------------------------------------------------------
# IAM rules
# ---------------------------------------------------------------------------

class IAMWildcardPolicyRule(Rule):
    id = "CG020"
    title = "IAM policy grants wildcard action/resource permissions"
    severity = Severity.CRITICAL
    cis_control = "CIS AWS 1.16"
    applies_to = ("aws_iam_policy", "aws_iam_role_policy", "iam_policy")

    def _policy_is_wildcard(self, policy_doc: dict) -> bool:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = [resources] if isinstance(resources, str) else resources
            if "*" in actions and "*" in resources:
                return True
        return False

    def _wildcard_via_jsonencode_heuristic(self, policy_raw: str) -> bool:
        """
        Terraform commonly writes policies as jsonencode({...}), which is an
        HCL function call, not valid JSON -- json.loads can't parse it directly.
        Fully evaluating arbitrary HCL expressions is out of scope, so we fall
        back to a targeted regex heuristic: flag it only when an Allow effect,
        a wildcard Action, and a wildcard Resource all appear together in the
        same statement text. This catches the common "Action = *, Resource = *"
        admin-policy pattern while avoiding matches spread across unrelated
        statements in a multi-statement policy.
        """
        import re
        stmt_pattern = re.compile(r"\{[^{}]*\}")
        for stmt in stmt_pattern.findall(policy_raw):
            has_allow = re.search(r'Effect\s*=\s*"Allow"', stmt)
            has_wildcard_action = re.search(r'Action\s*=\s*(\["?\*"?\]|"\*")', stmt)
            has_wildcard_resource = re.search(r'Resource\s*=\s*(\["?\*"?\]|"\*")', stmt)
            if has_allow and has_wildcard_action and has_wildcard_resource:
                return True
        return False

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type not in ("aws_iam_policy", "aws_iam_role_policy"):
            return []
        import json
        policy_raw = config.get("policy")
        if not policy_raw:
            return []

        if isinstance(policy_raw, dict):
            policy_doc = policy_raw
        elif isinstance(policy_raw, str):
            try:
                policy_doc = json.loads(policy_raw)
            except json.JSONDecodeError:
                # Likely a jsonencode(...) HCL expression rather than raw JSON
                if self._wildcard_via_jsonencode_heuristic(policy_raw):
                    return [Finding(
                        rule_id=self.id, title=self.title, severity=self.severity,
                        resource_type=resource_type, resource_id=resource_name,
                        description="Policy (via jsonencode) allows Action:* on "
                                     "Resource:*, granting full administrative access.",
                        remediation="Scope the policy to specific actions and resource "
                                     "ARNs following least-privilege principles.",
                        cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
                    )]
                return []
        else:
            return []

        if self._policy_is_wildcard(policy_doc):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="Policy allows Action:* on Resource:*, granting full "
                             "administrative access.",
                remediation="Scope the policy to specific actions and resource ARNs "
                             "following least-privilege principles.",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "iam_policy":
            return []
        policy_doc = data.get("policy_document", {})
        if self._policy_is_wildcard(policy_doc):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="Policy allows Action:* on Resource:*, granting full "
                             "administrative access.",
                remediation="Scope the policy to specific actions and resource ARNs.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


class IAMUserNoMFARule(Rule):
    id = "CG021"
    title = "IAM user has console access without MFA enabled"
    severity = Severity.HIGH
    cis_control = "CIS AWS 1.2"
    applies_to = ("iam_user",)

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "iam_user":
            return []
        if data.get("has_console_password") and not data.get("mfa_enabled"):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="User has console login enabled but no MFA device registered.",
                remediation="Enforce MFA for all IAM users with console access via an "
                             "IAM policy condition or Organizations SCP.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


class IAMRootAccessKeyRule(Rule):
    id = "CG022"
    title = "Root account has active access keys"
    severity = Severity.CRITICAL
    cis_control = "CIS AWS 1.4"
    applies_to = ("iam_account_summary",)

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "iam_account_summary":
            return []
        if data.get("AccountAccessKeysPresent", 0) > 0:
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id="root",
                description="The AWS account root user has one or more active access keys.",
                remediation="Delete root access keys immediately; use IAM roles/users "
                             "with least privilege for all programmatic access instead.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


# ---------------------------------------------------------------------------
# EBS / RDS rules
# ---------------------------------------------------------------------------

class EBSEncryptionRule(Rule):
    id = "CG030"
    title = "EBS volume is not encrypted"
    severity = Severity.HIGH
    cis_control = "CIS AWS 2.2.1"
    applies_to = ("aws_ebs_volume", "ebs_volume")

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_ebs_volume":
            return []
        if config.get("encrypted") is not True:
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="EBS volume does not have encryption enabled.",
                remediation="Set encrypted = true (optionally with a customer-managed KMS key).",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "ebs_volume":
            return []
        if not data.get("Encrypted"):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="EBS volume is not encrypted.",
                remediation="Migrate data to an encrypted volume; enable "
                             "'encryption by default' at the account/region level.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


class RDSPublicAccessRule(Rule):
    id = "CG031"
    title = "RDS instance is publicly accessible"
    severity = Severity.CRITICAL
    cis_control = "CIS AWS 2.3.1"
    applies_to = ("aws_db_instance", "rds_instance")

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_db_instance":
            return []
        if config.get("publicly_accessible") is True:
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="RDS instance has publicly_accessible = true.",
                remediation="Set publicly_accessible = false and access the DB via a "
                             "VPC/private subnet or bastion host.",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "rds_instance":
            return []
        if data.get("PubliclyAccessible"):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="RDS instance is publicly accessible.",
                remediation="Disable public accessibility and restrict access via VPC/security groups.",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


class RDSEncryptionRule(Rule):
    id = "CG032"
    title = "RDS instance storage is not encrypted"
    severity = Severity.HIGH
    cis_control = "CIS AWS 2.3.2"
    applies_to = ("aws_db_instance", "rds_instance")

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        if resource_type != "aws_db_instance":
            return []
        if config.get("storage_encrypted") is not True:
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="RDS instance does not have storage_encrypted set to true.",
                remediation="Set storage_encrypted = true (requires recreation if already provisioned).",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []

    def check_live_resource(self, resource_type, resource_id, data):
        if resource_type != "rds_instance":
            return []
        if not data.get("StorageEncrypted"):
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_id,
                description="RDS instance storage is not encrypted.",
                remediation="Enable storage encryption (requires snapshot + restore for existing instances).",
                cis_control=self.cis_control, scan_mode="live",
            )]
        return []


# ---------------------------------------------------------------------------
# Lambda rules
# ---------------------------------------------------------------------------

class LambdaOverPermissiveRoleRule(Rule):
    id = "CG040"
    title = "Lambda function execution role is overly permissive"
    severity = Severity.HIGH
    cis_control = "CIS AWS 1.16"
    applies_to = ("aws_lambda_function",)

    def check_terraform_resource(self, resource_type, resource_name, config, source_file):
        # Heuristic: flag if the function references a role that (elsewhere in the
        # same plan) attaches AdministratorAccess — full cross-resource resolution
        # happens in the scanner, this rule just checks the obvious inline case.
        role = config.get("role", "")
        if isinstance(role, str) and "admin" in role.lower():
            return [Finding(
                rule_id=self.id, title=self.title, severity=self.severity,
                resource_type=resource_type, resource_id=resource_name,
                description="Lambda function's execution role name suggests broad/admin "
                             "privileges (e.g. references an 'admin' role).",
                remediation="Create a dedicated least-privilege execution role scoped "
                             "to only the resources this function needs.",
                cis_control=self.cis_control, source_file=source_file, scan_mode="iac",
            )]
        return []


# Registry of all rules — imported by the engine
ALL_RULES = [
    S3PublicAccessRule(),
    S3EncryptionRule(),
    S3VersioningRule(),
    OpenSSHRule(),
    OpenRDPRule(),
    OpenAllPortsRule(),
    IAMWildcardPolicyRule(),
    IAMUserNoMFARule(),
    IAMRootAccessKeyRule(),
    EBSEncryptionRule(),
    RDSPublicAccessRule(),
    RDSEncryptionRule(),
    LambdaOverPermissiveRoleRule(),
]
