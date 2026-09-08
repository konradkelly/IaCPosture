"""Tests for review-api's handler. DynamoDB is mocked -- no AWS calls."""

import decimal
import json
from unittest.mock import MagicMock, patch

import pytest

import handler


# The identity API Gateway's JWT authorizer hands the function once it has
# verified the token. Tests default to a signed-in reviewer because that is the
# only way a request reaches the handler in deployed form.
SIGNED_IN = {"sub": "user-uuid-1", "email": "konrad@example.com"}


def _event(route_key, path_params=None, body=None, claims=SIGNED_IN):
    event = {
        "routeKey": route_key,
        "pathParameters": path_params or {},
        "body": json.dumps(body) if body is not None else None,
        "requestContext": {},
    }
    if claims is not None:
        event["requestContext"]["authorizer"] = {"jwt": {"claims": claims}}
    return event


def _body(response):
    return json.loads(response["body"])


@pytest.fixture
def mock_table():
    with patch.object(handler, "dynamodb") as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        yield table


FINDING = {
    "pk": "PR#manual-1",
    "sk": "FINDING#abc123",
    "finding_id": "abc123",
    "source": "tfsec",
    "rule_id": "aws-s3-enable-bucket-encryption",
    "file": "main.tf",
    # DynamoDB hands numbers back as Decimal -- the encoder must cope.
    "line_range": [decimal.Decimal(1), decimal.Decimal(3)],
    "status": "fix-proposed",
    "proposed_fix": {
        "diff": "--- a/main.tf\n+++ b/main.tf\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        "rationale": "adds encryption",
        "self_check_passed": True,
        "self_check_new_findings": [],
        "cleared": True,
    },
}

# A finding the pipeline hasn't produced a fix for yet -- nothing to approve
# or edit.
FINDING_NO_FIX = {**FINDING, "status": "mapped", "proposed_fix": None}


# ---------- reads ----------

def test_list_findings_returns_the_prs_findings(mock_table):
    mock_table.query.return_value = {"Items": [FINDING]}

    response = handler.handler(_event("GET /prs/{pr_id}/findings", {"pr_id": "manual-1"}), None)

    assert response["statusCode"] == 200
    payload = _body(response)
    assert payload["count"] == 1
    # Decimals survived serialization as plain ints.
    assert payload["findings"][0]["line_range"] == [1, 3]


def test_get_finding_404s_when_absent(mock_table):
    mock_table.get_item.return_value = {}

    response = handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}", {"pr_id": "manual-1", "finding_id": "nope"}), None
    )

    assert response["statusCode"] == 404


def test_list_events_reads_the_finding_partition_not_the_pr(mock_table):
    mock_table.query.return_value = {"Items": []}

    handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/events", {"pr_id": "manual-1", "finding_id": "abc123"}),
        None,
    )

    values = mock_table.query.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":pk"] == "FINDING#abc123"
    assert values[":sk_prefix"] == "EVENT#"


def test_unknown_route_404s(mock_table):
    response = handler.handler(_event("DELETE /everything"), None)
    assert response["statusCode"] == 404


# ---------- review decisions ----------

def test_approve_writes_an_audit_event_and_resolves_the_finding(mock_table):
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "approved", "notes": "looks right"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"

    event_item = mock_table.put_item.call_args.kwargs["Item"]
    assert event_item["pk"] == "FINDING#abc123"
    assert event_item["sk"].startswith("EVENT#")
    assert event_item["actor"] == "konrad@example.com"
    assert event_item["action"] == "approved"

    update_values = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert update_values[":status"] == "resolved"


def test_reject_audits_the_decision_but_leaves_the_finding_open(mock_table):
    """Rejecting a proposed fix doesn't make the vulnerability go away."""
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "rejected"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] is None
    mock_table.put_item.assert_called_once()
    mock_table.update_item.assert_not_called()


def test_edit_replaces_the_diff_preserves_the_agents_and_voids_the_self_check(mock_table):
    mock_table.get_item.return_value = {"Item": FINDING}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_diff": "--- a/main.tf\n+reviewer edit\n"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["diff"] == "--- a/main.tf\n+reviewer edit\n"
    assert written["agent_diff"].endswith("-old\n+new\n")
    # spec §6's guarantee applies just as much to a human edit: an unscanned
    # diff cannot carry a passing self-check.
    assert written["self_check_passed"] is False
    assert written["self_check_new_findings"] == []
    assert written["cleared"] is False

    event_item = mock_table.put_item.call_args.kwargs["Item"]
    assert event_item["edited_diff"] == "--- a/main.tf\n+reviewer edit\n"


def test_second_edit_does_not_overwrite_the_agents_original_diff(mock_table):
    already_edited = {
        **FINDING,
        "proposed_fix": {
            "diff": "first edit",
            "agent_diff": "the agent's original",
            "self_check_passed": False,
            "self_check_new_findings": [],
            "cleared": False,
        },
    }
    mock_table.get_item.return_value = {"Item": already_edited}

    handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_diff": "second edit"},
        ),
        None,
    )

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["agent_diff"] == "the agent's original"


def test_edit_without_a_diff_is_rejected(mock_table):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"}, {"action": "edited"}),
        None,
    )

    assert response["statusCode"] == 400
    mock_table.put_item.assert_not_called()


def test_edited_diff_on_a_non_edit_action_is_rejected(mock_table):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved", "edited_diff": "sneaky"}),
        None,
    )

    assert response["statusCode"] == 400
    mock_table.put_item.assert_not_called()


@pytest.mark.parametrize("action", ["approved", "edited"])
def test_approve_or_edit_without_a_proposed_fix_is_a_conflict(mock_table, action):
    mock_table.get_item.return_value = {"Item": FINDING_NO_FIX}

    body = {"action": action}
    if action == "edited":
        body["edited_diff"] = "would-be edit"

    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"}, body),
        None,
    )

    assert response["statusCode"] == 409
    mock_table.put_item.assert_not_called()


def test_self_check_passed_in_the_request_body_is_ignored(mock_table):
    """The client can send whatever it likes -- only the server-computed value
    on an edit (always False) ends up written."""
    mock_table.get_item.return_value = {"Item": FINDING}

    handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_diff": "x", "self_check_passed": True},
        ),
        None,
    )

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["self_check_passed"] is False


@pytest.mark.parametrize("body,expected_fragment", [
    ({"action": "yolo"}, "action must be one of"),
    ({}, "action must be one of"),
])
def test_review_rejects_bad_input_without_writing(mock_table, body, expected_fragment):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"}, body),
        None,
    )

    assert response["statusCode"] == 400
    assert expected_fragment in _body(response)["error"]
    mock_table.put_item.assert_not_called()


def test_actor_comes_from_the_token_not_the_request_body(mock_table):
    """The whole point of the authorizer: a caller cannot sign someone else's
    name to a decision by putting it in the body."""
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved", "actor": "someone-else"}),
        None,
    )

    assert response["statusCode"] == 200
    assert mock_table.put_item.call_args.kwargs["Item"]["actor"] == "konrad@example.com"


def test_review_without_verified_claims_is_rejected(mock_table):
    """Defence in depth: if the authorizer is ever detached from the route, the
    handler refuses rather than recording an unattributable decision."""
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved"}, claims=None),
        None,
    )

    assert response["statusCode"] == 401
    mock_table.put_item.assert_not_called()
    mock_table.update_item.assert_not_called()


def test_actor_falls_back_to_sub_when_the_token_carries_no_email(mock_table):
    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "abc123"},
               {"action": "approved"}, claims={"sub": "user-uuid-1"}),
        None,
    )

    assert response["statusCode"] == 200
    assert mock_table.put_item.call_args.kwargs["Item"]["actor"] == "user-uuid-1"


def test_review_on_a_missing_finding_writes_no_orphan_event(mock_table):
    mock_table.get_item.return_value = {}

    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "ghost"},
               {"action": "approved"}),
        None,
    )

    assert response["statusCode"] == 404
    mock_table.put_item.assert_not_called()


# ---------- failure handling ----------

def test_unexpected_error_returns_500_without_leaking_details(mock_table):
    mock_table.query.side_effect = RuntimeError("ProvisionedThroughputExceeded: secret internals")

    response = handler.handler(_event("GET /prs/{pr_id}/findings", {"pr_id": "manual-1"}), None)

    assert response["statusCode"] == 500
    assert _body(response) == {"error": "internal error"}


def test_query_all_follows_pagination(mock_table):
    mock_table.query.side_effect = [
        {"Items": [FINDING], "LastEvaluatedKey": {"pk": "PR#manual-1", "sk": "FINDING#abc123"}},
        {"Items": [{**FINDING, "finding_id": "def456"}]},
    ]

    response = handler.handler(_event("GET /prs/{pr_id}/findings", {"pr_id": "manual-1"}), None)

    assert _body(response)["count"] == 2
    assert mock_table.query.call_count == 2
