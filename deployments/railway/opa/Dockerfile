# GRIEFER Policy Kernel — Open Policy Agent with an immutable policy bundle.
#
# The policy is COPIED INTO the image rather than mounted. On a platform where
# services come and go, a mounted policy is one misconfigured volume away from
# an OPA that starts with no rules — and an OPA with no rules answers
# "undefined", which GRIEFER treats as a denial but which is not the same as
# enforcing anything. Baking the bundle in means the running policy is exactly
# the policy that was reviewed in the commit that built this image.
#
# Build context: repository root.
#   docker build -f deployments/railway/opa/Dockerfile .

FROM openpolicyagent/opa:1.9.0-static

# The decision policy GRIEFER queries, and the server authorization policy that
# makes OPA's own management API read-only. See policies/system/authz.rego.
COPY policies/rego   /policies/rego
COPY policies/system /policies/system

# openpolicyagent/opa:*-static is distroless and already runs as a non-root
# user; it carries no shell and no package manager.
USER 1000:1000

EXPOSE 8181

# --authorization=basic routes every API request through data.system.authz.allow,
# which defaults to deny. Without it, anyone who can reach this port can replace
# the rules that decide what GRIEFER is allowed to do.
ENTRYPOINT ["/opa"]
CMD ["run", "--server", \
     "--addr=0.0.0.0:8181", \
     "--authorization=basic", \
     "--log-level=info", \
     "--set=decision_logs.console=true", \
     "/policies/rego", "/policies/system"]
