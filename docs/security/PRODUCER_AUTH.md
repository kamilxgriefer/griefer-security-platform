# Producer authentication

How to enrol the sensors that send GRIEFER its telemetry, and what enrolling
them changes.

Design and rationale live in [ADR 0009](../adr/0009-authenticated-event-producers.md)
and [ADR 0010](../adr/0010-corroboration-counts-producers.md). This page is the
operator's half: what to set, in what order, and what breaks if you get it
wrong.

## What this buys you

The service credential answers *may this caller reach ingest*. It does not
answer *which sensor is this*, and it cannot: one credential is shared by every
sender, so one leaked copy can post as anything. Producer authentication adds
the second question, and an entitlement that answers it narrowly.

**The entitlement is the control, not the credential.** A producer key proves
which enrolled name is calling; the `_SOURCES` list decides which
`(source_type, source_name)` pairs that name may claim. A producer entitled to
`identity_provider:okta-prod` cannot post an EDR alert, so a compromised sensor
is confined to the story its own telemetry can tell.

Once at least two producers are enrolled, this also raises the automation bar:
`docs/SAFETY_MODEL.md` rule 2 requires evidence from two distinct producers
before GRIEFER acts without a human, so one compromised credential can no longer
fabricate corroboration by sending two categories.

## Enrolling a producer

Three variables per producer, plus one list.

```bash
GRIEFER_PRODUCERS=okta-prod,edr-fleet

GRIEFER_PRODUCER_OKTA_PROD_KEY=<32+ bytes>
GRIEFER_PRODUCER_OKTA_PROD_SOURCES=identity_provider:okta-prod

GRIEFER_PRODUCER_EDR_FLEET_KEY=<32+ bytes>
GRIEFER_PRODUCER_EDR_FLEET_SOURCES=endpoint:edr-fleet,endpoint:edr-fleet-eu
```

The variable suffix is the producer name upper-cased with `-` and `.` replaced
by `_`. Two names that flatten to the same suffix are refused at startup rather
than letting one silently inherit the other's key.

Generate each key with `openssl rand -base64 48`. The floor is 32 bytes because
the credential is presented on every event, so a weak one is guessable at ingest
volume. (`make secrets` writes the *local development* `.env.local` and does not
mint producer keys — these are per-sensor and belong in your deployment's secret
store.)

Each sensor then sends two headers alongside the service credential:

```
X-Griefer-Producer: okta-prod
X-Griefer-Producer-Key: <the key>
```

### Startup refuses these

Each of these fails with a sentence naming the variable, rather than starting
into a state you would discover at three in the morning:

| Mistake | Why it is refused |
| --- | --- |
| A producer with no `_SOURCES` | It could claim any source — the exact hole authentication exists to close |
| A source type the event schema does not accept | An entitlement no event can match is a typo, not a policy |
| A key under 32 bytes, or empty | See above |
| Two names flattening to one suffix | The second would inherit the first's credential |
| A keyring without `GRIEFER_INTERNAL_API_TOKEN` | Producer identity is ANDed with the service credential, never a replacement for it |

## The order that matters

**Enrolling the first producer turns the boundary on for every producer.** From
that moment a request with no producer headers is refused with 403 and a
`producer_auth_failures` metric tagged `absent`.

This is the only rule that leaves no bypass. An opt-in per route or per producer
would let an unenrolled sender simply omit the header, which is not a boundary.

So enrol in this order:

1. Add the keyring entry and deploy. Nothing changes yet for other senders —
   until the first producer exists, unattributed events are still accepted.
2. Cut over **every** sensor at once, or accept a refusal window.
3. Watch `producer_auth_failures` by reason. `absent` means a sensor you forgot;
   `unknown_producer` a name mismatch; `wrong_key` a stale key; `malformed` a
   header the sender is mangling.

If step 2 is not realistic in one deploy, do not enrol anybody yet. A partial
cutover is a refusal window, and a refused sensor is a blind spot.

## Rotating a key

`_PREVIOUS_KEY` accepts the outgoing key alongside the new one, so rotation does
not need the sensor and the platform to restart in the same second:

1. Set `GRIEFER_PRODUCER_<SUFFIX>_PREVIOUS_KEY` to the current key and
   `_KEY` to the new one. Deploy. Both now work.
2. Move the sensor to the new key.
3. Confirm no `wrong_key` rejections for that producer, then clear
   `_PREVIOUS_KEY` and deploy again.

**Revocation is a redeploy.** The keyring is read from the environment at
startup, so removing a producer takes effect when the process restarts. ADR 0009
states this plainly rather than dressing it up; a `producer_keys` table with
live revocation is recorded there as deferred, not as done.

## What it does not do

- **It is not a signature.** The key is a bearer credential presented on every
  request. Anyone who can read a request in flight can replay it. TLS is doing
  the work here; per-request HMAC signing is deferred to a v2 in ADR 0009.
- **It does not authenticate the event's contents.** A producer entitled to a
  source can lie about everything inside that source's events. The entitlement
  bounds *which story* it can tell, not whether the story is true.
- **It says nothing about deployments that skip it.** A deployment with no
  producers enrolled keeps today's behaviour, including the weaker corroboration
  bar that `docs/SAFETY_MODEL.md` rule 2 documents rather than glosses.
