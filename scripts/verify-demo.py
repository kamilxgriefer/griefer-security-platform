#!/usr/bin/env python3
"""Assert that a running GRIEFER produced the outcome the documentation claims.

Run after replaying the synthetic scenario. Exits non-zero with a specific
message if any documented property does not hold, so a drift between the README
and the platform fails CI rather than quietly becoming a lie.

Usage: scripts/verify-demo.py [api-base-url]
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 15

# The verdicts documented in README.md and docs/ATTACK_SCENARIOS.md.
EXPECTED_VERDICTS = {
    "preserve_evidence": "simulated",
    "isolate_endpoint": "simulated",
    "require_mfa": "simulated",
    "temporarily_suspend_privileges": "simulated",
    "revoke_sessions": "requires_approval",
    "rotate_exposed_secret": "requires_approval",
    "wipe_endpoint": "denied",
}


def auth_headers() -> dict:
    """The service credential, when the API requires one.

    The script talks to the API through the same authenticated path the console
    uses, rather than a privileged side door — a verification tool that can
    bypass authentication proves less than it appears to.
    """
    token = os.environ.get("INTERNAL_API_TOKEN", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def get(url: str) -> dict:
    request = urllib.request.Request(url, headers=auth_headers())
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def post(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **auth_headers()},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def main() -> int:
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080").rstrip("/")
    failures: list[str] = []

    page = get(f"{base}/api/v1/incidents?limit=1")
    if page["total"] != 1:
        print(f"FAIL expected exactly 1 incident, found {page['total']}")
        return 1

    incident = page["items"][0]
    print(f"incident {incident['id']}")

    checks = [
        ("severity", incident["severity"], "critical", incident["severity"] == "critical"),
        ("risk_score", incident["risk_score"], ">= 70", incident["risk_score"] >= 70),
        ("findings", len(incident["findings"]), "5", len(incident["findings"]) == 5),
        (
            "evidence categories",
            len({f["category"] for f in incident["findings"]}),
            "5",
            len({f["category"] for f in incident["findings"]}) == 5,
        ),
        (
            "critical assets in blast radius",
            incident["blast_radius"]["critical_assets"],
            ">= 2",
            incident["blast_radius"]["critical_assets"] >= 2,
        ),
        (
            "confidence",
            incident["confidence"],
            "<= 0.95",
            0 < incident["confidence"] <= 0.95,
        ),
    ]
    for name, actual, expected, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {actual} (expected {expected})")
        if not ok:
            failures.append(f"{name}={actual}, expected {expected}")

    # Reachability provenance must describe a real path, or the console draws
    # edges that were never observed.
    reachable = incident["blast_radius"].get("reachable") or []
    known = {node["id"] for node in reachable}
    for node in reachable:
        if node["hops"] > 0 and node.get("from") not in known:
            failures.append(f"{node['id']} claims an unreachable parent {node.get('from')!r}")
    print(f"  ok   blast-radius provenance: {len(reachable)} nodes, all parents resolvable")

    print("policy verdicts:")
    for action_type, expected in EXPECTED_VERDICTS.items():
        result = post(
            f"{base}/api/v1/actions/evaluate",
            {
                "incident_id": incident["id"],
                "action_type": action_type,
                "mode": "simulate",
                "requested_by": "ci",
                "automated": True,
            },
        )
        status = result["status"]
        ok = status == expected
        print(f"  {'ok  ' if ok else 'FAIL'} {action_type}: {status} (expected {expected})")
        if not ok:
            failures.append(f"{action_type} returned {status}, expected {expected}")
        if result.get("executed_at") is not None:
            failures.append(f"{action_type} reported executed_at; v0.1 ships no actuator")

    # Every decision must have produced an audit entry.
    audit = get(f"{base}/api/v1/audit?limit=200")
    evaluated = sum(1 for e in (audit["items"] or []) if e["action"] == "policy.evaluated")
    ok = evaluated >= len(EXPECTED_VERDICTS)
    print(f"  {'ok  ' if ok else 'FAIL'} audit: {evaluated} policy.evaluated entries")
    if not ok:
        failures.append(f"only {evaluated} policy decisions were audited")

    if failures:
        print("\nFAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("\nAll documented properties hold.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as exc:
        print(f"FAIL could not reach the GRIEFER API: {exc}")
        sys.exit(1)
