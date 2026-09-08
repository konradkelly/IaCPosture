"""review-api Lambda (spec §4.1, §4.4 step 6).

CRUD behind API Gateway for the review dashboard: list a PR's findings, fetch
one finding with its proposed diff, record a human's approve/edit/reject
decision, and read a finding's audit trail.

This is the "human approves" half of the project's core principle -- the agent
proposes, a person disposes. Every decision writes an immutable ReviewEvent
(spec §5) alongside the status change, so nothing is silently decided.

Wired to an API Gateway HTTP API (payload format 2.0), one Lambda handling
every route via `routeKey` dispatch.
"""

import decimal
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
            return _ok(_list_events(params["finding_id"]))

        if route_key == "POST /prs/{pr_id}/findings/{finding_id}/review":
            return _post_review(params["pr_id"], params["finding_id"], event.get("body"))

        return _error(404, f"unknown route {route_key!r}")
    except Exception:
        # Never leak internals to an HTTP client; CloudWatch has the detail.
        logger.exception("review-api failed handling %s", route_key)
        return _error(500, "internal error")


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


def _list_events(finding_id):
    """Audit trail for one finding. ReviewEvents live under their own
    partition (pk = FINDING#<id>, spec §5), not under the PR's."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    items = _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        ExpressionAttributeValues={":pk": f"FINDING#{finding_id}", ":sk_prefix": "EVENT#"},
    )
    return {"finding_id": finding_id, "count": len(items), "events": items}


def _post_review(pr_id, finding_id, raw_body):
    try:
        body = json.loads(raw_body or "{}")
    except json.JSONDecodeError:
        return _error(400, "body must be valid JSON")

    action = body.get("action")
    if action not in VALID_ACTIONS:
        return _error(400, f"action must be one of {sorted(VALID_ACTIONS)}")

    actor = body.get("actor")
    if not actor:
        return _error(400, "actor is required")

    # Don't write an audit event pointing at a finding that doesn't exist.
    if _get_finding(pr_id, finding_id) is None:
        return _error(404, "finding not found")

    now = datetime.now(timezone.utc).isoformat()
    table = dynamodb.Table(DYNAMODB_TABLE)

    table.put_item(Item={
        "pk": f"FINDING#{finding_id}",
        "sk": f"EVENT#{now}",
        "finding_id": finding_id,
        "pr_id": pr_id,
        "actor": actor,
        "action": action,
        "notes": body.get("notes", ""),
        "created_at": now,
    })

    status = None
    if action in RESOLVING_ACTIONS:
        status = "resolved"
        table.update_item(
            Key={"pk": f"PR#{pr_id}", "sk": f"FINDING#{finding_id}"},
            UpdateExpression="SET #status = :status, updated_at = :now",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": status, ":now": now},
        )

    return _ok({
        "finding_id": finding_id,
        "action": action,
        "status": status,
        "recorded_at": now,
    })


# ---------- helpers ----------

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
