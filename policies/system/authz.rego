# OPA server authorization.
#
# Loaded only by the OPA service, never by the embedded kernel — it governs the
# server's REST API rather than GRIEFER's response decisions.
#
# OPA's management API can create, replace and delete policies at runtime. On a
# server holding the rules that decide what GRIEFER may do, that is the highest
# value target in the deployment: rewrite the policy and every safety guarantee
# in docs/SAFETY_MODEL.md evaporates without a single line of GRIEFER changing.
#
# This policy makes the server read-only. It is loaded with
# `--authorization=basic`, which routes every API request through
# data.system.authz.allow.

package system.authz

import rego.v1

# Default deny. Anything not named below is refused, so a future OPA version
# adding an endpoint does not silently widen the surface.
default allow := false

# Health probing, which the platform must be able to do.
allow if {
	input.path == ["health"]
}

# Reading a decision. This is the only thing GRIEFER asks OPA to do.
allow if {
	input.method in {"GET", "POST"}
	input.path == ["v1", "data", "griefer", "response", "decision"]
}

# The policy version, used to confirm the running bundle matches the binary's.
allow if {
	input.method == "GET"
	input.path == ["v1", "data", "griefer", "response", "policy_version"]
}

# Everything else is refused, including:
#   PUT/DELETE /v1/policies/*   — replacing or removing the decision policy
#   PUT/PATCH  /v1/data/*       — injecting base documents the policy reads
#   GET        /v1/policies     — enumerating the rules before rewriting them
#   POST       /v1/compile      — partial evaluation over arbitrary queries
