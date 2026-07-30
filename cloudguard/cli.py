"""
CloudGuard CLI.

Usage:
    cloudguard scan --path ./terraform
    cloudguard scan --path ./terraform --format json --output report.json
    cloudguard scan --path ./terraform --format sarif --output report.sarif
    cloudguard scan --live --profile default --region us-east-1
"""
import sys
import click

from .engine import scan_terraform, scan_live_aws, compute_score
from .report import print_console_report, to_json, to_sarif


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """CloudGuard — IaC and live AWS misconfiguration scanner."""
    pass


@cli.command()
@click.option("--path", type=click.Path(exists=True), default=None,
              help="Path to a Terraform directory or .tf file to scan.")
@click.option("--live", is_flag=True, default=False,
              help="Scan the live AWS account instead of (or in addition to) IaC.")
@click.option("--profile", default=None, help="AWS profile name (for --live).")
@click.option("--region", default="us-east-1", help="AWS region (for --live).")
@click.option("--format", "output_format", type=click.Choice(["console", "json", "sarif"]),
              default="console", help="Report output format.")
@click.option("--output", "output_file", type=click.Path(), default=None,
              help="Write report to this file instead of stdout.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "never"]),
              default="never",
              help="Exit with non-zero status if any finding meets/exceeds this severity. "
                   "Useful for CI pipelines.")
def scan(path, live, profile, region, output_format, output_file, fail_on):
    """Run a security scan against Terraform files and/or a live AWS account."""
    if not path and not live:
        click.echo("Error: specify --path <terraform_dir> and/or --live", err=True)
        sys.exit(2)

    all_findings = []
    total_resources = 0
    scan_modes = []

    if path:
        click.echo(f"Scanning Terraform at {path} ...", err=True)
        findings, parse_errors, resource_count = scan_terraform(path)
        all_findings.extend(findings)
        total_resources += resource_count
        scan_modes.append("iac")
        for fname, err in parse_errors:
            click.echo(f"  [warn] failed to parse {fname}: {err}", err=True)

    if live:
        from .collectors.aws_live import get_session
        click.echo(f"Scanning live AWS account (region={region}) ...", err=True)
        try:
            session = get_session(profile=profile, region=region)
            findings, collector_errors, resource_count = scan_live_aws(session)
            all_findings.extend(findings)
            total_resources += resource_count
            scan_modes.append("live")
            for cname, err in collector_errors:
                click.echo(f"  [warn] {cname} failed: {err}", err=True)
        except Exception as e:
            click.echo(f"Error connecting to AWS: {e}", err=True)
            click.echo("Check your credentials (env vars, ~/.aws/credentials, or --profile).",
                       err=True)
            sys.exit(1)

    score_info = compute_score(all_findings, total_resources)
    scan_mode_label = "+".join(scan_modes)

    if output_format == "console":
        print_console_report(all_findings, score_info, scan_mode_label)
    elif output_format == "json":
        report = to_json(all_findings, score_info, scan_mode_label)
        if output_file:
            with open(output_file, "w") as f:
                f.write(report)
            click.echo(f"JSON report written to {output_file}", err=True)
        else:
            click.echo(report)
    elif output_format == "sarif":
        report = to_sarif(all_findings)
        if output_file:
            with open(output_file, "w") as f:
                f.write(report)
            click.echo(f"SARIF report written to {output_file}", err=True)
        else:
            click.echo(report)

    # CI-friendly exit code
    if fail_on != "never":
        threshold_order = ["low", "medium", "high", "critical"]
        threshold_idx = threshold_order.index(fail_on)
        severities_present = {f.severity.value.lower() for f in all_findings}
        for sev in threshold_order[threshold_idx:]:
            if sev in severities_present:
                click.echo(f"\nFailing build: found {sev.upper()} severity issue(s).", err=True)
                sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    cli()
