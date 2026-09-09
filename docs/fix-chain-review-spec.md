# Fix-chain review enforcement — spec

Follows on from `proposed_fix.applies_after` (commit `8ae2717`), which records
the chain a fix is drafted on but is currently advisory: nothing stops a
reviewer approving a fix whose prerequisites never landed.

## 1. The problem

A prerequisite is an entry in `proposed_fix.applies_after` — an earlier finding
on the same file whose fix this one was drafted on top of. `f2`'s diff was
computed against the file *with `f1` applied*, so it does not apply to the
pristine file; the context lines do not match.

`_post_review` in `lambda/review-api/handler.py` never reads `applies_after`.
Approving `f2` after rejecting `f1` returns 200 and marks `f2` resolved. The
approved set is then unassemblable, and nothing says so.

A prerequisite has three states that matter, not two:

| `f1` state | Effect on `f2` |
|---|---|
| Rejected, or not yet reviewed | `f2`'s base never lands — approving it is incoherent |
| Approved | `f2` is sound as drafted |
| **Edited** | `f2` is stale — its base is the *agent's* `f1`, not the reviewer's |

The third is the one the current data model cannot express. An edit resolves
`f1`, so any "is the prerequisite resolved?" check passes while `f2` was
drafted against content that no longer exists.

### What enforcement does *not* need

An earlier framing of this said the event log was required, because approve,
edit and reject were all thought to resolve a finding. They do not:
`RESOLVING_ACTIONS = {"approved", "edited"}`, and a rejection writes an event
while leaving status untouched.

So `status == "resolved"` is exactly "approved or edited" and is sufficient to
*enforce*. The event log is only needed to tell a reviewer **which** of
"rejected" or "not yet reviewed" applies, and only on the error path. That is a
message-quality refinement, not part of the guarantee.

## 2. Data model change

`applies_after` becomes a list of objects rather than of ids:

```
"applies_after": [
  { "finding_id": "a1b2c3d4e5f60718", "diff_sha256": "9f86d081..." }
]
```

`diff_sha256` is `sha256(prerequisite.proposed_fix.diff)` at the moment this fix
was drafted. Staleness is then a hash comparison against the prerequisite's
*current* diff — no content reconstruction, no diff application in the Lambda.

**No migration.** The chain has never been deployed. Checked rather than
assumed: of 81 items in `iacposture-dev-findings`, 15 carry a `proposed_fix`,
and their keys are `assumptions`, `cleared`, `diff`, `dropped_resources`,
`rationale`, `self_check_new_findings`, `self_check_passed`,
`suppression_attempt` — no `applies_after`, and no `scan_errors` either, since
no remediation has run since that deploy. Producer and consumer land together,
and the object shape is the only shape that ever existed.

Consumers must still treat both fields as optional, because those 15 records
predate them and will be read by the dashboard.

## 3. Enforcement (review-api)

In `_post_review`, after the existing `proposed_fix is None` check and **before**
the ReviewEvent is written — a blocked decision is not an attempted decision and
should leave no audit entry.

Gate applies to `action in RESOLVING_ACTIONS`. **`rejected` is never blocked**:
rejecting is always safe and is the reviewer's escape hatch from a bad chain.

For each entry in `applies_after`:

1. Load the prerequisite (`_get_finding(pr_id, entry["finding_id"])`).
   - Missing → **409**, `"prerequisite <id> no longer exists"`.
2. `prerequisite["status"] != "resolved"` → **409**, unmet.
   - Optionally read its latest event to say "was rejected" vs "has not been
     reviewed". Message only.
3. `sha256(prerequisite.proposed_fix.diff) != entry["diff_sha256"]` → **409**,
   stale: the prerequisite changed after this fix was drafted.

Response body names every unmet prerequisite at once, so a reviewer sees the
whole blocking set rather than discovering it one 409 at a time:

```json
{ "error": "fix depends on prerequisites that are not satisfied",
  "unmet": [ { "finding_id": "...", "reason": "rejected" },
             { "finding_id": "...", "reason": "stale" } ] }
```

Cost: one `get_item` per prerequisite. Chains are per-file and short.

## 4. Cascade (phase 2)

Section 3 catches staleness when the *dependent* is reviewed. It does not catch
`f1` being edited **after** `f2` was already approved — `f2` is resolved and
nothing re-examines it.

On a resolving action that changes the diff (`edited`), reverse-look-up
dependents and flag them:

- `_list_findings(pr_id)` already reads the whole PR partition; filter for
  findings whose `applies_after` contains this `finding_id`.
- For each, set `proposed_fix.stale_reason` and return `status` to
  `needs-human-only`, and write a ReviewEvent with `actor: "system"` recording
  why — the audit trail must show that a machine reopened a human's decision.

Deliberately phase 2: section 3 is the correctness guarantee, this is
containment for a case that requires a specific ordering to reach.

## 5. Dashboard

The API is the guarantee; the UI is the affordance. Both, not either.

- `FindingDetailPage` additionally calls `listFindings(prId)` (it already makes
  two calls) and computes unmet prerequisites client-side.
- Pass `disabled` and `disabledReason` to `ReviewActions` — both props already
  exist. Reason text names the blocking findings and links to them.
- Reject stays enabled when approve and edit are blocked.
- A 409 from the API still renders in `ReviewActions`' existing error slot, for
  the race where a prerequisite changes between page load and submit.

## 6. Decisions

- [x] **Detect staleness by hashing the prerequisite's diff**, not the base
  content. Hashing the base would make review-api reconstruct the file by
  applying the approved chain, i.e. implement diff application in a Lambda.
- [x] **Derived hash, not a revision counter.** A counter is equivalent in power
  but must be bumped in both remediation-agent and review-api, and can drift.
  A hash of existing content cannot.
- [x] **Block, don't warn.** "The agent proposes, it never decides" cuts both
  ways: the system should not let a reviewer record a decision it knows cannot
  be carried out.
- [x] **Editing a dependent is blocked on the same terms as approving it.** An
  edit resolves the finding just as an approval does. A reviewer who wants a
  fix independent of its chain rejects it and lets a re-run redraft it.
- [ ] Whether a *rejected* prerequisite should also invalidate downstream fixes
  eagerly (it does not change their diffs, but it does guarantee they can never
  be satisfied). Leaning yes, as part of phase 2.

## 7. Tests

review-api:
- approve blocked when a prerequisite is unresolved; 409, no ReviewEvent written
- approve blocked when a prerequisite's diff hash has changed; reason `stale`
- approve allowed when every prerequisite is resolved and unchanged
- **reject allowed** with an unmet prerequisite — the escape hatch
- edit blocked on the same terms as approve
- a fix with `applies_after: []` is unaffected
- multiple unmet prerequisites are all reported in one response

remediation-agent:
- `applies_after` entries carry `finding_id` and the prerequisite's `diff_sha256`
- the hash matches what a later `sha256` of that prerequisite's stored diff gives

Phase 2:
- editing `f1` returns an approved `f2` to `needs-human-only` with a system event
- a finding with no dependents is untouched
