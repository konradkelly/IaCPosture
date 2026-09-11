"""review-api Lambda (spec §4.1, §4.4 step 6).

CRUD behind API Gateway for the review dashboard: list a PR's findings, fetch
one finding with its proposed diff, record a human's approve/edit/reject
decision, and read a finding's audit trail.

This is the "human approves" half of the project's core principle -- the agent
proposes, a person disposes. Every decision writes an immutable ReviewEvent
(spec §5) alongside the status change, so nothing is silently decided.

Wired to an API Gateway HTTP API (payload format 2.0), one Lambda handling
every route via `routeKey` dispatch. Every route sits behind a Cognito JWT
authorizer, so by the time this code runs the caller has a verified identity --
which is where a review's `actor` comes from. See _actor_from_claims.
"""

import decimal
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")

dynamodb = boto3.resource("dynamodb")

# Reviewer actions, per spec §5's ReviewEvent.action enum. "approved"/"edited"
# mean the human accepted a fix, so the finding becomes "resolved". "rejected"
# refuses the proposed fix -- the underlying finding is still real, so its
# status deliberately does not move.
RESOLVING_ACTIONS = {"approved", "edited"}
VALID_ACTIONS = RESOLVING_ACTIONS | {"rejected"}


class _DecimalEncoder(json.JSONEncoder):
    """DynamoDB returns every number as Decimal, which json can't serialize."""

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return int(o) if o % 1 == 0 else float(o)
        return super().default(o)


def handler(event, context):
    route_key = event.get("routeKey")
    params = event.get("pathParameters") or {}

    try:
        if route_key == "GET /prs/{pr_id}/findings":
            return _ok(_list_findings(params["pr_id"]))

        if route_key == "GET /prs/{pr_id}/findings/{finding_id}":
            finding = _get_finding(params["pr_id"], params["finding_id"])
            if finding is None:
                return _error(404, "finding not found")
            return _ok(finding)

        if route_key == "GET /prs/{pr_id}/findings/{finding_id}/events":
            return _ok(_list_events(params["pr_id"], params["finding_id"]))

        if route_key == "POST /prs/{pr_id}/findings/{finding_id}/review":
            return _post_review(
                params["pr_id"], params["finding_id"], event.get("body"), event
            )

        return _error(404, f"unknown route {route_key!r}")
    except Exception:
        # Never leak internals to an HTTP client; CloudWatch has the detail.
        logger.exception("review-api failed handling %s", route_key)
        return _error(500, "internal error")


def _actor_from_claims(event):
    """The caller's identity, taken from the JWT the authorizer verified.

    API Gateway will not invoke this function unless the token's signature,
    issuer, audience and expiry all check out, so these claims are trustworthy
    in a way a request body never is. Preferring email over sub keeps the audit
    trail readable; sub is the fallback because email is only guaranteed when
    the pool is configured to require it.

    Returns None if the claims are missing entirely, which should mean the
    authorizer was removed from the route -- treated as an auth failure rather
    than quietly attributing the decision to nobody.
    """
    claims = (
        (event.get("requestContext") or {}).get("authorizer") or {}
    ).get("jwt", {}).get("claims") or {}

    actor = claims.get("email") or claims.get("cognito:username") or claims.get("sub")
    return actor or None


# ---------- routes ----------

def _list_findings(pr_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    items = _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        ExpressionAttributeValues={":pk": f"PR#{pr_id}", ":sk_prefix": "FINDING#"},
    )
    return {"pr_id": pr_id, "count": len(items), "findings": items}


def _get_finding(pr_id, finding_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    response = table.get_item(Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}"})
    return response.get("Item")


def _event_pk(pr_id, finding_id):
    """Partition key for one finding's audit trail.

    Includes pr_id, which spec §5's `FINDING#<finding_id>` shorthand omits.
    finding_id is a content hash of the finding, so the identical rule on the
    identical file produces the identical id in every PR that scans it -- ids
    are unique within a PR, not across them. Keyed on finding_id alone, a
    decision recorded against one PR surfaces in the audit trail of every
    other PR that happens to contain the same finding, attributing decisions
    nobody made on that PR. For an audit log whose purpose is that nothing is
    silently decided, that's the one failure it cannot have.
    """
    return f"PR#{pr_id}#FINDING#{finding_id}"


def _list_events(pr_id, finding_id):
    """Audit trail for one finding, scoped to the PR it was decided on."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    items = _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        ExpressionAttributeValues={":pk": _event_pk(pr_id, finding_id), ":sk_prefix": "EVENT#"},
    )
    return {"finding_id": finding_id, "count": len(items), "events": items}


def _post_review(pr_id, finding_id, raw_body, event):
    # Identity first: nothing about this request is worth parsing if we can't
    # say who made it.
    actor = _actor_from_claims(event)
    if actor is None:
        logger.error("review POST reached the handler with no verified JWT claims")
        return _error(401, "unauthenticated")

    try:
        body = json.loads(raw_body or "{}")
    except json.JSONDecodeError:
        return _error(400, "body must be valid JSON")

    action = body.get("action")
    if action not in VALID_ACTIONS:
        return _error(400, f"action must be one of {sorted(VALID_ACTIONS)}")

    # An "actor" in the body is ignored rather than honoured: it used to be the
    # source of truth, and silently preferring it again would let a caller sign
    # someone else's name to a decision.

    edited_diff = body.get("edited_diff")
    if action == "edited" and not edited_diff:
        return _error(400, "edited_diff is required when action is 'edited'")
    if action != "edited" and edited_diff is not None:
        return _error(400, "edited_diff is only valid when action is 'edited'")

    finding = _get_finding(pr_id, finding_id)
    if finding is None:
        return _error(404, "finding not found")

    proposed_fix = finding.get("proposed_fix")
    if action in RESOLVING_ACTIONS and proposed_fix is None:
        return _error(409, "finding has no proposed fix to act on")

    # Checked before the ReviewEvent is written: a blocked decision is not an
    # attempted decision, and should leave no trace in the audit trail.
    # Rejection is never blocked -- it is always safe, and it is the reviewer's
    # only escape hatch from a chain gone bad.
    if action in RESOLVING_ACTIONS:
        unmet = _unmet_prerequisites(pr_id, proposed_fix)
        if unmet:
            logger.info(
                "%s of finding %s blocked on prerequisites: %s", action, finding_id, unmet,
            )
            return _response(409, {
                "error": "fix depends on prerequisites that are not satisfied",
                "unmet": unmet,
            })

    now = datetime.now(timezone.utc).isoformat()
    table = dynamodb.Table(DYNAMODB_TABLE)

    # Event written before the finding is mutated: a failure partway through
    # then leaves a recoverable trace (an attempted decision with no state
    # change) rather than the reverse -- a state change nobody logged, which
    # is the failure mode spec §1 forbids.
    table.put_item(Item={
        "pk": _event_pk(pr_id, finding_id),
        "sk": f"EVENT#{now}",
        "finding_id": finding_id,
        "pr_id": pr_id,
        "actor": actor,
        "action": action,
        "notes": body.get("notes", ""),
        "edited_diff": edited_diff,
        "created_at": now,
    })

    status = None
    if action in RESOLVING_ACTIONS:
        status = "resolved"
        update_expression = "SET #status = :status, updated_at = :now"
        values = {":status": status, ":now": now}

        if action == "edited":
            update_expression += ", proposed_fix = :pf"
            values[":pf"] = {
                **proposed_fix,
                "diff": edited_diff,
                # Preserved on the first edit only, never overwritten again --
                # it's the only record of what the agent actually proposed,
                # which the fix-acceptance metric (spec §7) is computed
                # against.
                "agent_diff": proposed_fix.get("agent_diff") or proposed_fix.get("diff"),
                # self_check_passed is never asserted by a human, for the same
                # reason spec §6 forbids it being asserted by the LLM: an
                # edited diff has not been through the scanner, so it cannot
                # inherit a passing check. cleared is reset alongside it --
                # neither half of the self-check is known until a scan
                # actually runs against this diff. Any self_check_passed the
                # client sent is ignored; this is computed, not accepted.
                "self_check_passed": False,
                "self_check_new_findings": [],
                "cleared": False,
                # Reset for the same reason, and load-bearing in the other
                # direction: a reviewer's most likely response to "the fix did
                # not parse" is to hand-correct the syntax, and carrying the
                # agent's parse failure onto their edit would keep reporting a
                # file that no longer exists as broken.
                "scan_errors": [],
            }

        table.update_item(
            Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}"},
            UpdateExpression=update_expression,
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=values,
        )

    # An edit replaced this fix's diff, so every fix drafted on top of it is
    # now rooted on content that no longer exists. _unmet_prerequisites catches
    # that when the dependent is reviewed; it does nothing for a dependent
    # already approved, because that decision has already happened and nothing
    # re-examines it. Approve f1, approve f2, then edit f1 is a supported
    # sequence -- "resolved" is not terminal and repeat edits are deliberate --
    # so without this the stale dependent sits there marked resolved and
    # unassemblable. See docs/fix-chain-review-spec.md §4.
    #
    # Only on "edited": approving or rejecting leaves the diff untouched, and
    # it is the diff these dependents were drafted against.
    reopened = []
    if action == "edited":
        reopened = _reopen_dependents(pr_id, finding_id, actor, now)

    return _ok({
        "finding_id": finding_id,
        "action": action,
        "status": status,
        "recorded_at": now,
        # Named in the response so the reviewer who caused the cascade learns
        # about it immediately, rather than finding it later in someone else's
        # queue.
        "reopened_dependents": reopened,
    })


# ---------- helpers ----------

def _reopen_dependents(pr_id, edited_finding_id, actor, now):
    """Return every fix drafted on top of this one to human review.

    Reads the whole PR partition, which _list_findings already does for the
    dashboard, and filters for findings naming this one as a prerequisite.
    There is no reverse index and no need for one: chains are per-file and the
    partition is a single PR's findings.

    Each dependent gets stale_reason, so the dashboard can say *why* a fix it
    previously showed as resolved is open again, and a ReviewEvent with actor
    "system". That event is the point. A machine is reopening a decision a
    human recorded, and an audit log whose purpose is that nothing is silently
    decided cannot let that happen off the books.

    Status goes to needs-human-only regardless of what it was: the dependent's
    self-check was run against a base that has since changed, so it no longer
    evidences anything, whatever it concluded at the time.
    """
    table = dynamodb.Table(DYNAMODB_TABLE)
    reopened = []

    for candidate in _list_findings(pr_id)["findings"]:
        candidate_id = candidate.get("finding_id")
        if candidate_id == edited_finding_id:
            continue

        proposed_fix = candidate.get("proposed_fix") or {}
        chain = proposed_fix.get("applies_after") or []
        depends = any(
            (entry.get("finding_id") if isinstance(entry, dict) else entry) == edited_finding_id
            for entry in chain
        )
        if not depends:
            continue

        stale_reason = (
            f"Prerequisite {edited_finding_id} was edited by {actor} at {now}, "
            "so this fix is drafted against content that no longer exists. "
            "It needs redrafting against the edited base before it can be applied."
        )
        table.update_item(
            Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{candidate_id}"},
            UpdateExpression=(
                "SET #status = :status, proposed_fix.stale_reason = :reason, updated_at = :now"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": "needs-human-only",
                ":reason": stale_reason,
                ":now": now,
            },
        )
        table.put_item(Item={
            "pk": _event_pk(pr_id, candidate_id),
            # Suffixed so a cascade cannot collide with the edit that caused
            # it, which carries the same timestamp.
            "sk": f"EVENT#{now}#system",
            "finding_id": candidate_id,
            "pr_id": pr_id,
            "actor": "system",
            "action": "reopened",
            "notes": stale_reason,
            "edited_diff": None,
            "created_at": now,
        })
        reopened.append(candidate_id)

    if reopened:
        logger.info(
            "edit of %s reopened dependent findings %s", edited_finding_id, reopened,
        )
    return reopened


def _unmet_prerequisites(pr_id, proposed_fix):
    """Prerequisites of this fix that can't currently be satisfied.

    A prerequisite is an earlier finding on the same file whose fix this one
    was drafted on top of, so this diff's context lines describe the file
    *with that fix applied*. Approving a dependent whose base never lands
    yields an approved set nobody can assemble, and until now nothing said so.

    Returns a list of {finding_id, reason}, naming every blocker at once so a
    reviewer sees the whole blocking set rather than discovering it one 409 at
    a time. Empty means every prerequisite is satisfied and unchanged.
    """
    unmet = []
    for entry in proposed_fix.get("applies_after") or []:
        # Entries were bare id strings before the chain carried hashes, and
        # findings written by that build are still readable. They can't be
        # verified, so they fail closed rather than being waved through.
        if not isinstance(entry, dict):
            unmet.append({"finding_id": str(entry), "reason": "unverifiable"})
            continue

        prerequisite_id = entry.get("finding_id")
        prerequisite = _get_finding(pr_id, prerequisite_id)
        if prerequisite is None:
            unmet.append({"finding_id": prerequisite_id, "reason": "missing"})
            continue

        # Satisfaction is the *latest* ReviewEvent, not status. status is a
        # lossy cache of the last resolving action and is never retracted: a
        # rejection deliberately leaves it alone, so approving a finding and
        # then rejecting it leaves status "resolved" while the standing
        # decision on it is a rejection. A status check reads that as
        # satisfied. The event log is the only place the truth survives.
        events = _list_events(pr_id, prerequisite_id)["events"]
        if not events:
            unmet.append({"finding_id": prerequisite_id, "reason": "undecided"})
            continue
        if max(events, key=lambda e: e["sk"])["action"] not in RESOLVING_ACTIONS:
            unmet.append({"finding_id": prerequisite_id, "reason": "rejected"})
            continue

        # Absent is not the same as fresh.
        recorded_hash = entry.get("diff_sha256")
        if not recorded_hash:
            unmet.append({"finding_id": prerequisite_id, "reason": "unverifiable"})
            continue

        # Distinct from "rejected", and the distinction is actionable: a stale
        # dependent is redrafted against the new base, a rejected one against
        # the chain minus that link. A rejected prerequisite's content is
        # unchanged, so its hash still matches -- the two checks catch
        # genuinely different failures.
        prerequisite_fix = prerequisite.get("proposed_fix") or {}
        current_diff = prerequisite_fix.get("diff")
        if current_diff is None or _diff_sha256(current_diff) != recorded_hash:
            unmet.append({"finding_id": prerequisite_id, "reason": "stale"})

    return unmet


def _diff_sha256(diff_text):
    """Must stay identical to remediation-agent's helper of the same name."""
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def _query_all(table, **kwargs):
    """Query to exhaustion -- a single Query caps at 1MB of items."""
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return items
        kwargs["ExclusiveStartKey"] = last_key


def _ok(body):
    return _response(200, body)


def _error(status_code, message):
    return _response(status_code, {"error": message})


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body, cls=_DecimalEncoder),
    }
