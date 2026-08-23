## What this changes

<!-- One or two sentences. The diff shows what; explain why. -->

## Why

<!-- The problem, or the capability this unlocks. Link an issue if one exists. -->

Closes #

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Security fix
- [ ] Detection content
- [ ] Documentation
- [ ] Build, CI or dependencies
- [ ] Refactor with no behaviour change

## Safety review

**Does this change anything in [docs/SAFETY_MODEL.md](../docs/SAFETY_MODEL.md)?**

- [ ] No — nothing about what GRIEFER may do, on what evidence, changes.
- [ ] Yes — and there is an ADR in `docs/adr/` explaining the trade-off.

If **any** box below is ticked, explain it in the section that follows.

- [ ] Adds or changes a response action
- [ ] Adds or changes an evidence category
- [ ] Changes the Rego policy
- [ ] Changes the event schema
- [ ] Changes a trust boundary or validation at one
- [ ] Adds a dependency
- [ ] Touches the audit trail
- [ ] Introduces a component that can reach an actuator

<!-- Explanation, if any box is ticked: -->

## Testing

**How this was verified:**

<!-- Specific. "Ran the tests" is not an answer; which ones, and what did they prove? -->

- [ ] `make check` passes
- [ ] New tests fail without the change
- [ ] Tested against real infrastructure (`make services-up && make test-live`)
- [ ] Verified in the running stack (`make up && make demo`)

**For a console change:**

- [ ] Checked at 375px and at 1280px
- [ ] Keyboard navigable, focus visible
- [ ] Failure states distinguish "no data" from "cannot reach the platform"

## Notes for the reviewer

<!-- Anything you are unsure about, deliberately left out, or want argued with. -->
