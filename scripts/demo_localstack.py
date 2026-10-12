#!/usr/bin/env python3
"""LocalStack demo: stand up a few insecure AWS resources, collect real evidence
from them with boto3, and evaluate the NIST CSF 2.0 control set against it.

    python scripts/demo_localstack.py --endpoint http://localhost:4566

Requires a running LocalStack (https://localstack.cloud) and boto3. Nothing here is
scheduled or shipped; it is the reproducible script behind the demo.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from grc_playbook import EXAMPLES, collect_aws, controls  # noqa: E402


def banner(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def seed(endpoint):
    import boto3
    c = lambda svc: boto3.client(svc, endpoint_url=endpoint, region_name="us-east-1")

    def step(label, fn):
        try:
            fn()
            print("  seeded: " + label)
        except Exception as e:  # noqa: BLE001
            print("  seeded: {0}  (already present or unsupported: {1})".format(label, type(e).__name__))

    s3 = c("s3")

    def _buckets():
        s3.create_bucket(Bucket="acme-prod-backup")            # no encryption, no versioning -> fails
        s3.create_bucket(Bucket="acme-prod-data")
        s3.put_bucket_encryption(Bucket="acme-prod-data",
                                 ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        s3.put_bucket_versioning(Bucket="acme-prod-data", VersioningConfiguration={"Status": "Enabled"})
        s3.put_public_access_block(Bucket="acme-prod-data",
                                   PublicAccessBlockConfiguration={"BlockPublicAcls": True, "BlockPublicPolicy": True,
                                                                   "IgnorePublicAcls": True, "RestrictPublicBuckets": True})
    step("s3 buckets (one secure, one not)", _buckets)

    kms = c("kms")
    step("kms key without rotation", lambda: kms.create_key(Description="legacy app key"))

    ecr = c("ecr")

    def _ecr():
        ecr.create_repository(repositoryName="legacy", imageScanningConfiguration={"scanOnPush": False})
        ecr.create_repository(repositoryName="app", imageScanningConfiguration={"scanOnPush": True}, imageTagMutability="IMMUTABLE")
    step("ecr repos (one scanned+immutable, one not)", _ecr)

    sqs = c("sqs")
    step("sqs queue without encryption", lambda: sqs.create_queue(QueueName="legacy"))

    iam = c("iam")
    step("iam user without MFA", lambda: iam.create_user(UserName="svc-deployer"))

    ec2 = c("ec2")

    def _sg():
        vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
        ec2.create_security_group(GroupName="sg-app-01", Description="app", VpcId=vpc)
        gid = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["sg-app-01"]}])["SecurityGroups"][0]["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    step("security group open to 0.0.0.0/0:22", _sg)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default="http://localhost:4566")
    ap.add_argument("--out", default=str(ROOT / "demo" / "evidence"))
    ap.add_argument("--framework", default="nist-csf-2.0")
    ap.add_argument("--no-seed", action="store_true")
    args = ap.parse_args(argv)

    banner("1. Seed a few resources in LocalStack (some deliberately insecure)")
    if not args.no_seed:
        seed(args.endpoint)

    banner("2. Collect real evidence from AWS APIs via boto3")
    written, errors = collect_aws.collect(args.endpoint, args.out)
    print("  {0} evidence source(s) written to {1}".format(len(written), args.out))
    for e in errors:
        print("  collection failure (engine will fail closed): {0}".format(e))

    banner("3. Evaluate the NIST CSF 2.0 control set against the collected evidence")
    fw_file = EXAMPLES / "frameworks" / (args.framework + ".json")
    report = controls.run(EXAMPLES, controls_file=fw_file, evidence_dir=args.out)
    aws_sources = {c["ref"]: c["aws"] for c in json.loads(fw_file.read_text())["controls"] if c.get("aws")}
    failing = [r for r in report["results"] if r["status"] == "FAIL" and r["ref"] in aws_sources]
    print("\n  AWS-backed subcategories currently failing:")
    for r in failing:
        print("    {0:<12} {1}".format(r["ref"], aws_sources[r["ref"]]))

    banner("Result")
    s = report["summary"]
    print("  {PASS} pass | {FAIL} fail | {ERROR} error | {MANUAL} manual | {total} total".format(**s))
    print("  The engine and the control set did not change; only the evidence source did.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
