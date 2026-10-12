# Mirrors src/grc_playbook/policy.py `_iam_findings` in OPA/Rego, so the same
# dangerous-allow check runs either way: as stdlib Python in `policy.py`, or as
# policy-as-code via OPA (`opa eval`). Both encode the same two denials:
#   1. full admin:          Allow with Action "*" and Resource "*"
#   2. wildcard iam on all: Allow with (Action "iam:*" or "*") and Resource "*"
#
# Usage (with OPA installed):
#   opa eval --format pretty \
#     --data examples/rego/iam_deny.rego \
#     --input examples/policies/iam-admin-too-broad.json \
#     "data.grc.deny"
#
# The Deny-statement SCPs are covered separately by policy.py's org-coverage
# check (Guardrails), which is easier to read in Python than in Rego.

package grc

import rego.v1

actions(stmt) := act if {
	act := stmt.Action
	is_array(act)
}

actions(stmt) := [stmt.Action] if not is_array(stmt.Action)

resources(stmt) := res if {
	res := stmt.Resource
	is_array(res)
}

resources(stmt) := [stmt.Resource] if not is_array(stmt.Resource)

# Denial 1: full admin.
deny contains msg if {
	some stmt in input.Statement
	stmt.Effect == "Allow"
	"*" in actions(stmt)
	"*" in resources(stmt)
	msg := "full admin (\"*\" on \"*\")"
}

# Denial 2: wildcard iam on all resources. Mirrors policy.py's elif: this branch
# only fires when the statement is NOT already full admin (so Action "*" is
# excluded here), and the action is the iam:* wildcard specifically.
deny contains msg if {
	some stmt in input.Statement
	stmt.Effect == "Allow"
	not ("*" in actions(stmt))
	"iam:*" in actions(stmt)
	"*" in resources(stmt)
	msg := "wildcard iam on all resources"
}
