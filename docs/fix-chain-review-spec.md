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

### Why status cannot answer this, and the event log can

`RESOLVING_ACTIONS = {"approved", "edited"}`. A rejection writes a ReviewEvent
and deliberately leaves status alone, because the underlying finding is still
real.

`status` is therefore a lossy cache of the last *resolving* action, and it is
never retracted. Approve `f1` (status `resolved`), then reject it: status stays
`resolved` while the latest decision on it was a rejection. A status-based
check would read that `f1` as satisfied.

Nor is `resolved` terminal. `_post_review` never reads the current status, so a
finding can be approved, then edited, then edited again — `agent_diff` is
explicitly designed for it ("preserved on the first edit only") and
`test_second_edit_does_not_overwrite_the_agents_original_diff` covers it.

So satisfaction is **the latest ReviewEvent for that finding**, on the main
path, not the error path. Satisfied means the latest action is `approved` or
`edited`; `rejected` or no events means unmet.

### Chain shape after the supersede fix

Written before superseded findings dropped out of chains. They no longer
consume a link: a finding another fix already cleared gets `status:
"superseded"` and no `proposed_fix`, so it never appears in a later fix's
`applies_after`. Chains are correspondingly shorter, which reduces — but does
not remove — the blast radius below.

Measured on the 14 stored diffs (all drafted pre-chain, against the pristine
file, so indicative rather than predictive). Blast radius is how many
downstream fixes one rejection invalidates:

| File | fixes | worst case, all-chained | worst case, overlap-pruned |
|---|---|---|---|
| `demo-1 main.tf` | 9 | 8 | 6 |
| `pugetscope bootstrap/main.tf` | 2 | 1 | 0 |
| `pugetscope modules/security_groups/main.tf` | 3 | 2 | 1 |

Across all single rejections: 40 invalidations → 23. Pruning `applies_after`
to prerequisites whose changed regions a fix's hunks actually overlap is
therefore worth doing, but it is a refinement: the seven `demo-1` bucket fixes
genuinely touch the same three-line resource and stay one chain. Note also
that `demo-1/main.tf` is 14 lines, so with three lines of diff context nearly
everything overlaps everything — that file overstates entanglement, and the
realistically-sized `pugetscope` files separate far more cleanly.

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
2. Read its latest ReviewEvent (`_list_events`, take the last by `sk`).
   - Latest action `rejected` → **409**, reason `rejected`: the base will never
     exist.
   - No events → **409**, reason `undecided`: the base is not yet determined.
3. `entry` has no `diff_sha256` → **409**, reason `unverifiable`. Absent is not
   the same as fresh, and this fails closed.
4. `sha256(prerequisite.proposed_fix.diff) != entry["diff_sha256"]` → **409**,
   reason `stale`: the prerequisite's content changed after this fix was drafted.

Rejection is not staleness. `f1`'s content is unchanged, so its hash still
matches — the fix simply is not landing. That is why step 2 is doing work step 4
cannot, and the two need distinct reasons: a stale dependent is redrafted
against the new base, a rejected one against the chain minus `f1`.

The check runs over **every** entry, not just the immediate predecessor, and
that transitivity is what makes hashing the diff a sound proxy for the base
content. `f2`'s base is `f1`'s output; `f1`'s output is fixed by (`f1`'s base,
`f1`'s diff); `f1`'s base is the pristine snapshot or `f0`'s output.
`applies_after` carries the cumulative chain, so if every recorded hash matches,
the composed base is bit-identical. The base case is the snapshot's
immutability: `scans/<pr_id>/` is written once per run into a versioned bucket.

Response body names every unmet prerequisite at once, so a reviewer sees the
whole blocking set rather than discovering it one 409 at a time:

```json
{ "error": "fix depends on prerequisites that are not satisfied",
  "unmet": [ { "finding_id": "...", "reason": "rejected" },
             { "finding_id": "...", "reason": "stale" } ] }
```

Cost: one `get_item` plus one event query per prerequisite. Chains are per-file
and, since superseded findings no longer consume a link, shorter than the
counts in §1.

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

Phase 2 only because section 3 must land first, **not** because the case is
exotic. Approve `f1`, approve `f2`, then edit `f1` is a supported workflow —
`resolved` is not terminal and repeat edits are a tested behaviour — and
section 3 does nothing for it, because `f2`'s decision has already happened.
Without this, the stale dependent sits there marked resolved and
unassemblable. This is the other half of the guarantee.

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
- [x] **A superseded finding is not a chain link.** It has no fix of its own to
  depend on or to be depended upon, so it is skipped entirely rather than
  recorded as a satisfied prerequisite.
- [ ] Whether to prune `applies_after` to prerequisites a fix's hunks actually
  overlap. Measured at a 43% reduction in total blast radius on current data
  (see above), but it is a heuristic: non-overlapping hunks can still interact
  semantically, which is exactly how the AES256/KMS pair collides.
- [ ] Whether rejecting a previously-approved finding should retract its
  `resolved` status. It would make status faithful to the latest decision and
  shrink this problem, but it changes review semantics that were chosen
  deliberately, for every consumer of status and not just chains. Enforcement
  works either way, since it reads events.
- [ ] Whether a *rejected* prerequisite should also invalidate downstream fixes
  eagerly (it does not change their diffs, but it does guarantee they can never
  be satisfied). Leaning yes, as part of phase 2.

## 7. Tests

review-api:
- approve blocked when a prerequisite's latest event is `rejected`, **including
  when that rejection followed an approval and left status `resolved`** — the
  case a status check misses
- approve blocked when a prerequisite has no events at all; 409, no ReviewEvent
  written
- approve blocked when an entry carries no `diff_sha256`; reason `unverifiable`
- approve blocked when a prerequisite's diff hash has changed; reason `stale`
- approve allowed when every prerequisite is resolved and unchanged
- **reject allowed** with an unmet prerequisite — the escape hatch
- edit blocked on the same terms as approve
- a fix with `applies_after: []` is unaffected
- a `superseded` finding has no `proposed_fix`, so approve and edit 409 on it
  through the existing check — the decision belongs on the superseding fix
- multiple unmet prerequisites are all reported in one response

remediation-agent:
- `applies_after` entries carry `finding_id` and the prerequisite's `diff_sha256`
- the hash matches what a later `sha256` of that prerequisite's stored diff gives

Phase 2:
- editing `f1` returns an approved `f2` to `needs-human-only` with a system event
- a finding with no dependents is untouched
