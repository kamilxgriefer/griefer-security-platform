# Railway trial status

The production deployment runs on a Railway **trial**, with **no payment method
on file**. That is a deliberate control, not an oversight, and it has a
consequence an operator must know about before it surprises them: the deployment
can stop on its own, and nothing in this repository will have caused it.

This page separates what has been **verified** against the Railway API from what
is **expectation**. The distinction matters more than usual here, because the
tempting way to verify the expectations — let the credit run out, or add a card
to see what changes — is exactly the thing that must not be done casually.

Everything below is a snapshot taken on **2026-08-24**. Billing state changes
outside this repository, so refresh it with the query in
[Checking plan and usage](#checking-plan-and-usage-without-printing-billing-data)
rather than trusting this page.

## Verified

Read from the Railway public GraphQL API through the CLI's own authenticated
session, not inferred from the dashboard and not inferred from HTTP behaviour.

| Question | Field | Value |
|---|---|---|
| Is the workspace on a trial? | `customer.isTrialing` | `true` |
| Is there a paid subscription? | `customer.subscriptions` | empty |
| Subscription state | `customer.state` | `INACTIVE` |
| Is a payment method on file? | `customer.defaultPaymentMethod` | `null` |
| Is it a usage subscriber or prepaying? | `isUsageSubscriber`, `isPrepaying` | `false`, `false` |
| Has the free allowance been exhausted? | `customer.hasExhaustedFreePlan` | `false` |
| Is a usage limit configured? | `customer.usageLimit` | `null` |

Two conclusions follow directly, without interpretation:

**No charge has been authorised.** There is no payment method, no subscription
and no prepayment. Railway has nothing to charge and no instrument to charge it
against. This is not "we expect the bill to be zero" — it is that no billing
relationship exists to produce a bill.

**No spend alerting exists.** `usageLimit` is `null`, so no soft limit and no
hard limit have been configured. Whatever notification Railway sends by default
is outside this repository's control and has not been verified.

Separately verified from the project's service topology: of the five services in
the `production` environment, exactly one — the console — has a public service
domain. The other four, including Postgres, have none. So the entire externally
visible surface of this deployment is a single hostname, which is what makes the
next section's blast radius small and predictable.

## What happens when the trial credit is exhausted

**Verified: nothing.** `hasExhaustedFreePlan` is `false`, so this workspace has
never taken the exhaustion path. Nobody has watched it happen here.

**Expected**, based on how a trial with no payment method must behave — treat
every line as expectation until observed:

- Railway stops the environment's deployments. The services stop serving.
- The console's public domain stops answering. That is the whole of the
  user-visible outage, because it is the only public surface.
- `api`, `opa` and `nats` stop too, but they were already unreachable from
  outside the project, so nothing changes for anyone external.
- Postgres stops, and with it the audit trail in the `audit_log` table becomes
  unreadable.
- **Nothing begins to charge.** With no payment method, there is no fallback to
  billing. The absence of a card is precisely what turns "credit exhausted" into
  a stop rather than into an invoice.

Two honest caveats on that last point about the audit trail:

*A stop is an availability loss, not an integrity loss.* Append-only is enforced
inside the database by the `audit_log_append_only` trigger, which raises
`restrict_violation` on `UPDATE` and `DELETE`. A stopped database mutates
nothing, so the guarantee is unaffected — but a trail you cannot read is still a
trail you cannot use during an investigation.

*Whether the data survives a stop, and for how long, is not verified.* Do not
rely on Railway as the only copy of anything that would matter afterwards. If
the audit trail from a demonstration needs to outlive the trial, export it
deliberately while the environment is running.

Recovery behaviour — whether the environment restarts by itself once credit is
available again, and in what state — is likewise expectation, not observation.

When services do stop, the correct first reading is *the spending control
worked*, not *the platform broke*. Check the plan state before opening an
incident.

## Checking plan and usage without printing billing data

`railway usage`, `railway usage projects` and `railway usage limit status` all
print monetary figures. They are legitimate commands, but their output is
billing data: it does not belong in CI logs, in a shared or recorded terminal,
in an issue, or anywhere in this repository.

For an operational check — *are we still on a trial, is a card attached, is a
limit set* — query the booleans instead. This selects only booleans and
`__typename`, so it cannot print a balance even by accident:

```bash
railway api 'query {
  me { workspaces {
    customer {
      isTrialing
      state
      hasExhaustedFreePlan
      defaultPaymentMethod { __typename }
      usageLimit { __typename }
      subscriptions { __typename }
    }
  } }
}'
```

`defaultPaymentMethod { __typename }` returning `null` answers "is a card
attached" without ever selecting the card. The same trick works for
`usageLimit`: `null` means no limit is configured, and no figure is needed to
learn that.

Notes on the surrounding commands:

- `railway status --json` is safe for **service topology** — which services
  exist, which have public domains — but it also carries project, environment
  and deployment identifiers. Read it; do not paste it whole.
- These commands authenticate through the CLI's stored session. Do not put a
  Railway token into this repository or into a CI variable in order to run them.
  None of these checks belongs in CI.
- If the plan state needs to be recorded somewhere, record the **answer**
  ("trial: yes; payment method: no; usage limit: none"), never the figures.

## The usage-alert constraint

A soft limit is the alert; a hard limit is the stop. This is the CLI's own
wording for the flag:

```
--soft <SOFT>   Email alert in dollars
--hard <HARD>   Hard limit in dollars
```

Underneath, `railway usage limit set` calls the `usageLimitSet` mutation, whose
input requires `softLimitDollars` and treats `hardLimitDollars` as optional —
i.e. an alert can be configured on its own, without a hard stop attached.

**The constraint: configuring an alert must not require enabling a paid plan or
adding a payment method.**

**Not verified:** whether `usageLimitSet` succeeds on a trial workspace with no
payment method. It has not been tested here, because setting a limit is a
persistent change to the account's configuration and is not this repository's
change to make. It needs a deliberate decision by the account owner.

If it is tested, there are only two acceptable outcomes:

- **It works.** Set a soft limit, record that an alert exists, and change
  nothing else. Do not set a hard limit as well without deciding, separately,
  what should happen when it is hit.
- **Railway demands a plan or a card first.** Then leave the alert
  unconfigured and record that fact here.

The second outcome is not a problem to be worked around. An alert is a
convenience: it tells you sooner. The missing payment method is the actual
control: it makes overspending impossible rather than merely visible. Adding a
card in order to receive a warning about spending trades the control for the
notification, which is the wrong way round. Accept the weaker monitoring.

The same applies to any prompt encountered while doing this. Nothing in a
Railway dashboard, an email, or a CLI message is authorisation to attach a
payment method — that decision comes from the account owner and from nowhere
else.

## Standing rules

- Do not add a payment method to clear a warning, to raise a limit, to enable an
  alert, or to keep a demonstration alive.
- Do not run spend-printing commands in CI, in shared terminals, or in recorded
  sessions.
- Do not commit any billing figure, account identifier, or Railway token.
- Do not treat a stopped environment as a platform incident until the plan state
  has been checked.

## Known limits of this document

- The exhaustion behaviour, the data-retention behaviour after a stop, and the
  recovery behaviour are all expectation. None has been observed.
- Whether a soft limit is settable on a trial is untested, by choice.
- Every verified value is a snapshot. Re-run the boolean query above rather than
  citing this page as current.
