"""
Live AWS collectors.

Each function pulls a specific resource type via boto3 and normalizes
it into the plain-dict shape that rules/checks.py expects, so the same
Rule classes can check both Terraform-parsed config and live API data.

Requires AWS credentials to be available via the standard boto3 chain
(environment variables, ~/.aws/credentials, or an instance/role profile).
Every collector is read-only (list/describe/get calls only) — CloudGuard
never modifies account state.
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_session(profile: str = None, region: str = "us-east-1"):
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def collect_s3_buckets(session) -> list[tuple]:
    """Returns [(resource_type, bucket_name, data_dict), ...]"""
    s3 = session.client("s3")
    out = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        return [], str(e)

    for b in buckets:
        name = b["Name"]
        data = {}
        try:
            pab = s3.get_public_access_block(Bucket=name)
            data["public_access_block"] = pab["PublicAccessBlockConfiguration"]
        except ClientError:
            data["public_access_block"] = {}

        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            data["encryption_enabled"] = bool(
                enc.get("ServerSideEncryptionConfiguration", {}).get("Rules"))
        except ClientError:
            data["encryption_enabled"] = False

        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            data["versioning_status"] = ver.get("Status", "Disabled")
        except ClientError:
            data["versioning_status"] = "Disabled"

        out.append(("s3_bucket", name, data))
    return out, None


def collect_security_groups(session) -> list[tuple]:
    ec2 = session.client("ec2")
    out = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                out.append(("security_group", sg["GroupId"], sg))
    except ClientError as e:
        return [], str(e)
    return out, None


def collect_iam_users(session) -> list[tuple]:
    iam = session.client("iam")
    out = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                data = {"has_console_password": False, "mfa_enabled": False}
                try:
                    iam.get_login_profile(UserName=username)
                    data["has_console_password"] = True
                except ClientError:
                    pass
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                data["mfa_enabled"] = len(mfa_devices) > 0
                out.append(("iam_user", username, data))
    except ClientError as e:
        return [], str(e)
    return out, None


def collect_iam_policies(session) -> list[tuple]:
    """Only checks customer-managed policies (Scope='Local') to avoid noise
    from AWS-managed policies which are already vetted by AWS."""
    iam = session.client("iam")
    out = []
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                doc = version["PolicyVersion"]["Document"]
                out.append(("iam_policy", arn, {"policy_document": doc}))
    except ClientError as e:
        return [], str(e)
    return out, None


def collect_iam_account_summary(session) -> list[tuple]:
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError as e:
        return [], str(e)
    return [("iam_account_summary", "account", summary)], None


def collect_ebs_volumes(session) -> list[tuple]:
    ec2 = session.client("ec2")
    out = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                out.append(("ebs_volume", vol["VolumeId"], vol))
    except ClientError as e:
        return [], str(e)
    return out, None


def collect_rds_instances(session) -> list[tuple]:
    rds = session.client("rds")
    out = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                out.append(("rds_instance", db["DBInstanceIdentifier"], db))
    except ClientError as e:
        return [], str(e)
    return out, None


COLLECTORS = [
    collect_s3_buckets,
    collect_security_groups,
    collect_iam_users,
    collect_iam_policies,
    collect_iam_account_summary,
    collect_ebs_volumes,
    collect_rds_instances,
]


def collect_all(session):
    """
    Runs every collector, returns (all_resources, errors) where
    all_resources is a flat list of (resource_type, resource_id, data)
    and errors is a list of (collector_name, error_message).
    """
    all_resources = []
    errors = []
    for collector in COLLECTORS:
        resources, error = collector(session)
        if error:
            errors.append((collector.__name__, error))
        all_resources.extend(resources)
    return all_resources, errors
