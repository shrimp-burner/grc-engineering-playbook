# Live run against LocalStack

The fixtures in `examples/` are the demo harness. This is the same engine and the same NIST
CSF 2.0 control set evaluated against **live boto3 calls** into a LocalStack AWS environment,
so the CCM loop runs end to end without a cloud account. Reproduce:

```bash
docker run -d --name grc-localstack -p 4566:4566 localstack/localstack:3.8
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
python scripts/demo_localstack.py --endpoint http://localhost:4566 --out demo/evidence
```

`demo_localstack.py` does three things against the emulator:

1. **Seed** real resources, some deliberately insecure: an unencrypted S3 bucket, an IAM user
   without MFA and without tags, and a security group open to `0.0.0.0/0:22`.
2. **Collect** evidence with real paginated boto3 calls (S3, IAM, KMS, EC2, SQS, SNS, CloudWatch
   Logs, and more). Each source is written only if its calls succeed, and every write is stamped
   into `_meta.json` so freshness is checkable.
3. **Evaluate** the NIST CSF 2.0 control set against that live-collected evidence.

## What it showed

The seeded misconfigurations came back as FAILs with the exact resource:

```
[FAIL] PR.IR-01   sg-app-01        open_to_world = ['22']   (the open security group)
[FAIL] PR.PS-01   acme-prod-backup versioning = False       (the insecure bucket)
[FAIL] GV.RR-02   svc-deployer     tags.team = None         (the untagged no-MFA user)
```

The correctly-seeded resources (encrypted bucket, etc.) reported PASS, so the engine is not just
crying wolf.

## The important part: the ERRORs

The LocalStack 3.8 community image did not implement every service the collector calls: ECR,
CloudTrail, and GuardDuty (plus Security Hub, Inspector, Macie, and AWS Config, which the collector
does not gather at all in this reference) returned not-yet-implemented errors, so those evidence
files were never written. The engine did exactly what
decision D2 says it must: instead of a green checkmark from missing data, each affected control
reported ERROR:

```
[ERR ] CSF-DE.CM-03 ... evidence source missing: evidence/cloudtrail_trails.json (silent gap = control failure)
```

Eleven ERRORs, zero false PASSes. A broken evidence pipeline surfaces as a gap, not as compliance.
Same engine, same control set - only the evidence source changed, from fixtures to a live API. That
is the whole point of the collector/engine split.
