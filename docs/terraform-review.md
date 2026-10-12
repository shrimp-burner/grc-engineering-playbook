# Terraform review: how I read an IaC change

When someone hands me a Terraform snippet and asks "what's wrong with this," I am not hunting for a
single gotcha. I am reading for a small set of failure modes that show up over and over, and for
each one I want to say three things: what it is, why it matters, and what the fix looks like. This
is the walkthrough of [`examples/terraform/broken/main.tf`](../examples/terraform/broken/main.tf)
to [`examples/terraform/fixed/main.tf`](../examples/terraform/fixed/main.tf) - the same insecure
stack, remediated.

The same checks run as a CI gate (`python -m grc_playbook iac examples/terraform/broken` exits
non-zero), so the insecure version never merges. That is the real answer: the review below is what
a human reasons through, and the gate is what makes it automatic. Prevention and detection.

## The broken stack

```hcl
resource "aws_s3_bucket" "evidence" {
  bucket = "acme-evidence-broken"
  # no server-side encryption / public access block / versioning
}

resource "aws_security_group" "app" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  username            = "admin"
  password            = "hunter2"
  storage_encrypted   = false
  publicly_accessible = true
}

resource "aws_iam_policy" "deployer" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
```

## What I flag, in the order I notice it

**1. The S3 bucket has no controls at all.** No encryption at rest, no public access block, no
versioning, no logging. This is the one attackers and auditors both find first. Fix: KMS
server-side encryption, all four public-access-block flags on, versioning on, access logging to a
separate log bucket. (The fixed file does the first three.)

**2. SSH open to the world.** `0.0.0.0/0:22` is the single most-scanned thing on the internet; it
will be found in minutes. Fix: scope it to a known CIDR (the fix uses `10.0.0.0/8`), or better,
kill SSH entirely and use Session Manager so there is no inbound port to attack.

**3. An inline database password.** `password = "hunter2"` is a secret committed to source control
- it is now in the git history forever and in every plan output. Fix: a `sensitive` variable
supplied at deploy time (Secrets Manager in production), and rotate it, because it already leaked.

**4. The RDS instance is public and unencrypted.** `publicly_accessible = true` plus
`storage_encrypted = false` is a database reachable from the internet with no at-rest protection.
Fix: the fixed file sets `storage_encrypted = true` and `publicly_accessible = false`; in a real
deployment I would also pin the instance to private subnets so the internet path does not exist at
all, and rotate the master password, which has now leaked alongside the inline secret.

**5. Full-admin IAM.** `Action = "*"` on `Resource = "*"` is full admin on a deployer role. Fix:
scope to the exact actions and resources the deploy actually needs - the fix cuts it to
`s3:GetObject`/`PutObject` on one bucket.

One more thing worth saying out loud: the fixed security group still opens SSH to `10.0.0.0/8`,
which is better than the internet but still a very wide range. Live, I would tighten it to the
actual VPN or bastion CIDR, or drop inbound SSH entirely for Session Manager.

## The point

None of these are exotic. That is exactly why they belong in a gate, not in a human's head. A
reviewer should spend their judgment on the things a rule cannot express - is this data
classification right, does this architecture make sense - not on pattern-matching `0.0.0.0/0` for
the hundredth time. Encode the known-bad patterns so CI blocks them, and the human review gets
better, not replaced.
