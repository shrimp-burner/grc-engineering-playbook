"""Collect AWS security evidence into the JSON files the controls engine reads.

Optional: requires boto3 and a reachable AWS endpoint (real, or LocalStack).
This is the seam the architecture diagram calls "the collector"; the engine and the
control sets are unchanged whether the evidence comes from here or a fixture.

Fail-closed: a file is written ONLY when its API calls succeed. If any collection
fails, the failures are reported and the process exits non-zero, so a scheduled run
with broken credentials cannot produce a green dashboard from empty files.

    python -m grc_playbook.collect_aws --endpoint http://localhost:4566 --out demo/evidence
    python -m grc_playbook.collect_aws --out demo/evidence     # real account, default creds
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _client(service, endpoint, region):
    import boto3
    kwargs = {"endpoint_url": endpoint} if endpoint else {}
    return boto3.client(service, region_name=region, **kwargs)


def _age_days(dt):
    return None if dt is None else (datetime.now(timezone.utc) - dt).days


def _pages(client, op, key, **kw):
    """Return every page-able item for an operation (full population, not page one)."""
    try:
        paginator = client.get_paginator(op)
        items = []
        for page in paginator.paginate(**kw):
            items.extend(page.get(key, []))
        return items
    except Exception:  # noqa: BLE001  no paginator / unsupported -> single call
        return client.__getattribute__(op)(**kw).get(key, [])


def collect(endpoint, out_dir, region="us-east-1", verbose=True):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written, errors = [], []

    def write(name, data, ok):
        if not ok:
            return
        (out / (name + ".json")).write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")
        written.append(name)
        collected_at[name] = stamp()
        if verbose:
            print("  collected: {0}.json".format(name))

    collected_at = {}  # source -> ISO timestamp, written to _meta.json for freshness checks
    stamp = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")

    def step(label, fn):
        """Run a collector; return (data, ok). On failure record and skip the file."""
        try:
            return fn(), True
        except Exception as e:  # noqa: BLE001
            errors.append("{0}: {1}: {2}".format(label, type(e).__name__, e))
            if verbose:
                print("  FAILED: {0} ({1})".format(label, e))
            return None, False

    account = "aws"
    acct, ok = step("sts:GetCallerIdentity", lambda: _client("sts", endpoint, region).get_caller_identity()["Account"])
    if ok:
        account = acct

    # ---- Amazon S3 ----------------------------------------------------------
    s3 = _client("s3", endpoint, region)

    def _s3():
        rows = []
        for b in _pages(s3, "list_buckets", "Buckets"):
            name = b["Name"]
            enc = _opt(lambda: s3.get_bucket_encryption(Bucket=name))
            algo = None
            if enc:
                algo = enc["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            pab = _opt(lambda: s3.get_public_access_block(Bucket=name), {}).get("PublicAccessBlockConfiguration", {})
            ver = s3.get_bucket_versioning(Bucket=name)
            log = s3.get_bucket_logging(Bucket=name)
            tags = _opt(lambda: s3.get_bucket_tagging(Bucket=name), {}).get("TagSet", [])
            rows.append({
                "name": name, "account": account,
                "encryption": {"enabled": algo is not None, "type": algo},
                "public_access": {"acl_public": not bool(pab.get("BlockPublicAcls", False)),
                                  "block_public_acls": bool(pab.get("BlockPublicAcls", False))},
                "versioning": ver.get("Status") == "Enabled",
                "logging_target": (log.get("LoggingEnabled") or {}).get("TargetBucket"),
                "tags": {t["Key"]: t["Value"] for t in tags},
            })
        return rows

    data, ok = step("s3:ListBuckets", _s3)
    write("s3_buckets", data, ok)

    # ---- AWS IAM ------------------------------------------------------------
    iam = _client("iam", endpoint, region)

    def _iam_users():
        rows = []
        for u in _pages(iam, "list_users", "Users"):
            name = u["UserName"]
            console = _opt(lambda: iam.get_login_profile(UserName=name)) is not None
            mfa = len(_pages(iam, "list_mfa_devices", "MFADevices", UserName=name)) > 0
            keys = _pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=name)
            tags = _opt(lambda: iam.list_user_tags(UserName=name), {}).get("Tags", [])
            rows.append({"user_name": name, "account": account, "console_access": console, "mfa_active": mfa,
                         "access_keys": [{"key_id": k["AccessKeyId"], "age_days": _age_days(k.get("CreateDate"))} for k in keys],
                         "tags": {t["Key"]: t["Value"] for t in tags} or None})
        return rows

    data, ok = step("iam:ListUsers", _iam_users)
    write("iam_users", data, ok)

    data, ok = step("iam:GetAccountPasswordPolicy",
                    lambda: _pw(iam.get_account_password_policy().get("PasswordPolicy", {})))
    write("account_password_policy", data, ok)

    data, ok = step("iam:GetAccountSummary", lambda: {
        "mfa_enabled": bool(iam.get_account_summary().get("SummaryMap", {}).get("AccountMFAEnabled")),
        "access_keys": iam.get_account_summary().get("SummaryMap", {}).get("AccountAccessKeysPresent", 0)})
    write("root_account", data, ok)

    # ---- AWS KMS ------------------------------------------------------------
    kms = _client("kms", endpoint, region)

    def _kms():
        rows = []
        for k in _pages(kms, "list_keys", "Keys"):
            meta = kms.describe_key(KeyId=k["KeyId"]).get("KeyMetadata", {})
            if meta.get("KeyManager") == "AWS":
                continue
            rot = kms.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled", False)
            rows.append({"id": k["KeyId"], "description": meta.get("Description", ""), "rotation_enabled": bool(rot)})
        return rows

    data, ok = step("kms:ListKeys", _kms)
    write("kms_keys", data, ok)

    # ---- Amazon EC2 ---------------------------------------------------------
    ec2 = _client("ec2", endpoint, region)

    def _sgs():
        rows = []
        for g in _pages(ec2, "describe_security_groups", "SecurityGroups"):
            ports = []
            for perm in g.get("IpPermissions", []):
                ranges = perm.get("IpRanges", []) + perm.get("Ipv6Ranges", [])
                if any(r.get("CidrIp") == "0.0.0.0/0" or r.get("CidrIpv6") == "::/0" for r in ranges) and perm.get("FromPort") is not None:
                    ports.append(str(perm["FromPort"]))
            rows.append({"name": g.get("GroupName", ""), "open_to_world": sorted(set(ports))})
        return rows

    data, ok = step("ec2:DescribeSecurityGroups", _sgs)
    write("security_groups", data, ok)

    data, ok = step("ec2:DescribeVolumes", lambda: [
        {"id": v["VolumeId"], "encrypted": bool(v.get("Encrypted"))} for v in _pages(ec2, "describe_volumes", "Volumes")])
    write("ebs_volumes", data, ok)

    # ---- Amazon ECR ---------------------------------------------------------
    ecr = _client("ecr", endpoint, region)
    data, ok = step("ecr:DescribeRepositories", lambda: [
        {"name": r["repositoryName"],
         "scan_on_push": bool((r.get("imageScanningConfiguration") or {}).get("scanOnPush")),
         "immutable_tags": r.get("imageTagMutability") == "IMMUTABLE"}
        for r in _pages(ecr, "describe_repositories", "repositories")])
    write("ecr_repositories", data, ok)

    # ---- Amazon SQS / SNS ---------------------------------------------------
    sqs = _client("sqs", endpoint, region)
    data, ok = step("sqs:ListQueues", lambda: [
        {"name": url.rstrip("/").split("/")[-1],
         "encrypted": bool(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]).get("Attributes", {}).get("KmsMasterKeyId"))}
        for url in sqs.list_queues().get("QueueUrls", [])])
    write("sqs_queues", data, ok)

    sns = _client("sns", endpoint, region)
    data, ok = step("sns:ListTopics", lambda: [
        {"name": t["TopicArn"].split(":")[-1],
         "encrypted": bool(sns.get_topic_attributes(TopicArn=t["TopicArn"]).get("Attributes", {}).get("KmsMasterKeyId"))}
        for t in sns.list_topics().get("Topics", [])])
    write("sns_topics", data, ok)

    # ---- CloudWatch Logs ----------------------------------------------------
    logs = _client("logs", endpoint, region)
    data, ok = step("logs:DescribeLogGroups", lambda: [
        {"name": g["logGroupName"], "retention_days": g.get("retentionInDays")}
        for g in _pages(logs, "describe_log_groups", "logGroups")])
    write("cloudwatch_log_groups", data, ok)

    # ---- AWS CloudTrail -----------------------------------------------------
    ct = _client("cloudtrail", endpoint, region)

    def _trails():
        rows = []
        for t in ct.describe_trails().get("trailList", []):
            rows.append({"name": t.get("Name"), "account": account,
                         "is_logging": bool(ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")),
                         "multi_region": bool(t.get("IsMultiRegionTrail")), "org_trail": bool(t.get("IsOrganizationTrail")),
                         "kms_key_id": t.get("KmsKeyId"), "log_validation": bool(t.get("LogFileValidationEnabled")),
                         "destination_bucket": t.get("S3BucketName")})
        return rows

    data, ok = step("cloudtrail:DescribeTrails", _trails)
    write("cloudtrail_trails", data, ok)

    # ---- GuardDuty (the only analytics service collected today; Security Hub /
    #      Inspector / Macie / Config / Access Analyzer run against bundled fixtures
    #      in examples/evidence/ and are marked ERROR by the engine if not collected)
    gd = _client("guardduty", endpoint, region)
    data, ok = step("guardduty:ListDetectors", lambda: [{"account": account, "detector_enabled": len(gd.list_detectors().get("DetectorIds", [])) > 0}])
    write("guardduty", data, ok)

    # Collection timestamps, so the controls engine can fail closed on stale evidence.
    (out / "_meta.json").write_text(json.dumps(collected_at, indent=2) + "\n", encoding="utf-8")

    return written, errors


# --- tolerant optional calls: a legitimately-absent setting returns the default,
#     but a permission or other error propagates and fails the collection (fail closed).
#     This distinguishes "no encryption configured" (a finding) from "AccessDenied"
#     (a collection failure) - the exact confusion that manufactures green dashboards.
_ABSENT = {
    "NoSuchBucketEncryptionConfiguration", "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchTagSet", "NoSuchTagSetError", "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy", "NoSuchEntity", "NoSuchLifecycleConfiguration",
    "ReplicationConfigurationNotFoundError",
}


def _opt(fn, default=None):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        if code in _ABSENT:
            return default
        raise


def _pw(policy):
    return {"min_length": policy.get("MinimumPasswordLength", 0),
            "reuse_prevention": policy.get("PasswordReusePrevention", 0),
            "max_age_days": policy.get("MaxPasswordAge"),
            "require_symbols": policy.get("RequireSymbols", False),
            "require_numbers": policy.get("RequireNumbers", False)}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="grc-playbook collect_aws", description="Collect AWS evidence for the controls engine.")
    ap.add_argument("--endpoint", default=None, help="AWS endpoint URL (e.g. http://localhost:4566 for LocalStack)")
    ap.add_argument("--out", default="demo/evidence", help="output evidence directory")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args(argv)
    try:
        import boto3  # noqa: F401
    except ImportError:
        print("boto3 is required for collection: pip install boto3")
        return 2
    print("collecting evidence from {0} -> {1}".format(args.endpoint or "AWS (default endpoint)", args.out))
    written, errors = collect(args.endpoint, args.out, args.region)
    print("done: {0} evidence source(s) written".format(len(written)))
    if errors:
        print("\n{0} collection failure(s) (files not written, so the engine fails closed):".format(len(errors)))
        for e in errors:
            print("  - " + e)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
