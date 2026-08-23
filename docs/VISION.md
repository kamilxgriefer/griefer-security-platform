# Vision

> GRIEFER is an ambitious research and engineering project exploring verifiable,
> policy-governed cyber defense.

This document is about the destination. [ROADMAP.md](ROADMAP.md) is about the
route. Nothing here describes what v0.1 does today.

---

## The bet

Defence has spent a decade getting better at *seeing*. Telemetry volume,
detection content and analytics have all improved enormously. What has not
improved at the same rate is the ability to *act on what was seen* — quickly,
correctly, and in a way the organisation can later defend.

The gap has a specific shape:

- **Seeing is fragmented.** The evidence exists, spread across tools that each
  hold one facet and none hold the story.
- **Acting is risky.** Containment that stops an attack is the same action that
  locks out a real employee if the read was wrong.
- **Justifying is retrospective.** The reasoning behind a 3 a.m. decision is
  reconstructed weeks later from chat logs.
- **Proving is absent.** Almost no organisation can demonstrate that a control
  it deployed actually stops the technique it was bought to stop.

GRIEFER's bet is that these are one problem. A platform that models the
environment as a graph, decides through explicit policy, and records its
reasoning can close all four — and that trying to close any one of them alone
produces the tools we already have.

## Seven commitments

### 1. The Security Graph is the substrate

Not a data lake with a graph view bolted on. The graph *is* the model: identities,
accounts, sessions, endpoints, applications, secrets, cloud resources and the
relationships between them.

Attacks are traversals. An attacker takes an identity, uses it to reach a
session, uses that to reach a secret, uses that to reach data. Detection that
looks at events in isolation is trying to infer a path from footprints; a graph
lets you ask the question directly — and, more usefully, lets you ask *what does
this unlock* before the attacker gets there.

### 2. Identity first

Hosts get rebuilt. Addresses rotate. Tokens expire. The identity persists, and in
the intrusions that matter it is the thing being abused.

GRIEFER groups evidence by acting identity by default. That choice runs through
the whole design — the correlation subject, the graph's centre of gravity, the
first thing an analyst sees.

### 3. Vendor neutrality is a design constraint, not a marketing line

Normalise at the boundary. The internal model belongs to GRIEFER, and a connector
translates into it. That means:

- No detection logic is written against a vendor's field names.
- Replacing an EDR is a connector change, not a detection rewrite.
- The platform can be pointed at a lab, an air-gapped network, or a mixed estate.

The cost is real — a connector is work, and normalisation loses fidelity — and
it is worth paying, because a defence platform that can only be used by
customers of one vendor is a feature of that vendor's product.

### 4. Local-first deployment

GRIEFER must run entirely on infrastructure its operator controls: a laptop, a
lab, an isolated network, an on-premise cluster. No mandatory SaaS, no telemetry
egress, no phoning home.

Security telemetry is among the most sensitive data an organisation holds. A
platform that requires shipping it elsewhere has made a decision on the
operator's behalf that the operator should be making.

### 5. Verifiable autonomy

Autonomy is not a slider from "manual" to "magic". It is a set of specific
permissions, each justified by specific evidence, each revocable, each recorded.

An autonomous action is acceptable when:

- its effect is bounded and understood,
- its evidence meets a stated bar,
- it can be undone, or a human agreed it need not be,
- the reasoning is written down before the action, not after,
- and the whole chain can be replayed by someone who was not there.

Policy is separate from detection, and stays separate. The component that decides
*whether* is never the component that decides *what happened* — because a system
that can convince itself has no safety property at all.

### 6. Continuous defense validation

The question every security programme should be able to answer, and almost none
can: **does this control still work?**

Not "is the agent installed". Not "did the vendor say so". Does the technique the
control was bought to stop actually get stopped, today, on this estate?

GRIEFER should be able to run safe, controlled validations against systems its
operator owns, and report which defences hold, which have silently regressed, and
which never worked. That closes the loop from detection engineering to evidence.

This is the hardest commitment on the list and the furthest out. It also has the
sharpest safety requirements: validation that can be pointed at someone else's
systems is an attack tool. Constraints are in [SAFETY_MODEL.md](SAFETY_MODEL.md).

### 7. Recovery-first architecture

Containment is not the end of an incident. The organisation still has to get back
to work.

Every action GRIEFER can take should carry its inverse. Every containment step
should record what it changed, precisely enough to reverse. "Recovery" should be
an operation, not a project.

This is why the action catalog treats `rollback_action` as a first-class
property, and why an action with no rollback cannot run without a human — from
the very first version.

## AI, and where it is allowed

AI belongs in this platform. It is genuinely good at the things investigation
needs: summarising a mass of evidence, proposing hypotheses, spotting a pattern
across incidents, drafting a timeline a human then corrects.

It does not belong anywhere near the authority to act.

The boundary GRIEFER commits to:

| AI may | AI may never |
|---|---|
| Summarise evidence | Decide whether an action is permitted |
| Propose hypotheses for a human to test | Approve its own proposal |
| Draft a narrative or a report | Alter a policy |
| Rank what to investigate first | Modify an audit entry |
| Suggest an action for policy evaluation | Reach an actuator |

Structurally: an AI component is a *client* of the Policy Kernel, subject to
exactly the rules a human operator is, and its inputs are treated as
attacker-influenced — because incident data contains attacker-controlled strings,
and prompt injection through telemetry is a real attack against any system that
feeds telemetry to a model.

This is why the control-plane guard exists in v0.1, before there is any AI to
protect: the boundary is easier to hold if it was never crossed.

## What GRIEFER is not trying to be

- **Not a SIEM.** It does not want to be the system of record for all logs.
- **Not a compliance tool.** Evidence it produces may be useful for an audit;
  that is a side effect.
- **Not a managed service.** It is software an operator runs.
- **Not a replacement for people.** It is an attempt to give responders better
  material to decide with, and a record of what they decided.

## How to tell whether this worked

Concrete, falsifiable, and deliberately uncomfortable:

1. An analyst can reconstruct *why* GRIEFER did something, months later, without
   asking anyone who was there.
2. A response that was wrong can be undone in minutes, and the undo is itself
   recorded.
3. An organisation can point at a technique and say "we tested this, here is when,
   here is what happened".
4. A new detection can be added without touching response logic, and a new policy
   without touching detection.
5. Someone hostile who fully compromises one sensor cannot make GRIEFER act
   against a legitimate user.

Point 5 is the one that matters most, and the one this codebase spends the most
effort on. See [THREAT_MODEL.md](THREAT_MODEL.md).
