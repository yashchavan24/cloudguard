# CloudGuard

**A cloud security posture scanner that finds misconfigurations before they ship — and again after they're deployed.**

CloudGuard scans **Terraform (IaC)** for security misconfigurations before infrastructure is ever deployed, and scans **live AWS accounts** via `boto3` for drift and runtime misconfigurations. Both modes share a single rule engine, so a rule written once (e.g. "flag public S3 buckets") checks both your `.tf` files *and* your real AWS account with zero duplicated logic.

```
$ cloudguard scan --path ./terraform

Security Score: 0/100 (Grade F)
Resources scanned: 7
Total findings: 12

CRITICAL  CG001  aws_s3_bucket/data_bucket        S3 bucket allows public access
CRITICAL  CG010  aws_security_group/web_sg        Unrestricted SSH (22) access
CRITICAL  CG020  aws_iam_policy/overly_broad       IAM policy grants Action:*/Resource:*
...
```

## Why this project

Most student security projects are either pure theory or a single-file script. CloudGuard is built the way a real internal security tool would be: a shared rule engine across two very different data sources (static config files vs. live cloud APIs), CI/CD integration via a real output standard (SARIF), and a test suite that proves both true positives *and* the absence of false positives.

## Architecture

```
                    ┌─────────────────┐
                    │   Rule Engine    │   13 rules across S3, EC2/SG,
                    │  (rules/checks)  │   IAM, EBS, RDS, Lambda
                    └────────┬─────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────▼──────────┐       ┌──────────▼─────────┐
    │  Terraform Parser    │       │   AWS Live Collector │
    │  (python-hcl2)        │       │   (boto3, read-only)  │
    └─────────┬──────────┘       └──────────┬─────────┘
              │                             │
      .tf files on disk              real AWS account
     (pre-deployment check)         (post-deployment audit)
```

Each `Rule` implements `check_terraform_resource()` and/or `check_live_resource()` — the same class checks both a parsed HCL block and a live `boto3` API response, normalized into a shared `Finding` object. This is the core design decision: **one rule, two enforcement points** (shift-left in CI, and continuous audit in production).

## What it checks (13 rules, mapped to CIS AWS Foundations Benchmark)

| Category | Rules |
|---|---|
| **S3** | Public ACL/access block, missing encryption, versioning disabled |
| **Security Groups** | Unrestricted SSH (22), unrestricted RDP (3389), all-ports-open to 0.0.0.0/0 |
| **IAM** | Wildcard `Action:*`/`Resource:*` policies, users with console access but no MFA, active root access keys |
| **EBS** | Unencrypted volumes |
| **RDS** | Publicly accessible instances, unencrypted storage |
| **Lambda** | Overly permissive execution roles |

Every finding includes: severity, a plain-English description, a concrete remediation step, and (where applicable) the specific CIS Benchmark control it maps to — so output reads like a real audit finding, not a generic linter warning.

## Two scan modes, one engine

```bash
# Static: scan Terraform before you ever apply it
cloudguard scan --path ./terraform

# Live: audit resources that already exist in a real AWS account
cloudguard scan --live --profile my-aws-profile --region us-east-1

# Both, output as SARIF for GitHub's native Security tab
cloudguard scan --path ./terraform --live --format sarif --output results.sarif

# CI-friendly: fail the build if anything HIGH or above is found
cloudguard scan --path ./terraform --fail-on high
```

## CI/CD integration

The included [GitHub Action](.github/workflows/cloudguard-scan.yml) runs CloudGuard on every push/PR and uploads SARIF results directly to GitHub's native **Security > Code scanning** tab — findings show up as inline PR annotations, the same way CodeQL results do. No custom dashboard required to get this benefit; it plugs into infrastructure GitHub already provides.

## Scoring

Each scan produces a 0-100 score (and letter grade) based on severity-weighted findings normalized against the number of resources scanned, so a large environment with a few real issues isn't penalized the same as a small environment where every resource is misconfigured.

## Demo fixtures

- [`examples/vulnerable/`](examples/vulnerable) — deliberately misconfigured Terraform that triggers every rule (scores 0/F)
- [`examples/secure/`](examples/secure) — the same infrastructure, properly configured (scores 100/A)

This pair exists specifically to demonstrate the tool doesn't just detect issues — it doesn't cry wolf on clean infrastructure either. Run both and compare:

```bash
cloudguard scan --path examples/vulnerable
cloudguard scan --path examples/secure
```

## Installation

```bash
git clone https://github.com/yashchavan24/cloudguard.git
cd cloudguard
pip install -e .
cloudguard --help
```

For live AWS scanning, configure credentials the standard way (`aws configure`, environment variables, or an IAM role) — CloudGuard only ever performs read-only `Describe`/`List`/`Get` API calls, never anything that modifies account state.

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

18 tests cover: every rule against the vulnerable fixture (true positive check), the full rule set against the secure fixture (false positive check), and scoring edge cases.

## Roadmap

- [ ] CloudFormation and Azure ARM template support
- [ ] Auto-generated remediation diffs (suggest the fixed Terraform, not just the problem)
- [ ] Web dashboard for scan history and drift-over-time tracking
- [ ] GCP support (IAM, Cloud Storage, Compute Engine)

## License

MIT
