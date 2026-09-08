"""Tests for review-api's handler. DynamoDB is mocked -- no AWS calls."""

import decimal
import json
from unittest.mock import MagicMock, patch

import pytest

import handler


def _event(route_key, path_params=None, body=None):
    return {
        "routeKey": route_key,
        "pathParameters": path_params or {},
        "body": json.dumps(body) if body is not None else None,
    }


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
}


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
            {"action": "approved", "actor": "konrad", "notes": "looks right"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"

    event_item = mock_table.put_item.call_args.kwargs["Item"]
    assert event_item["pk"] == "FINDING#abc123"
    assert event_item["sk"].startswith("EVENT#")
    assert event_item["actor"] == "konrad"
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
            {"action": "rejected", "actor": "konrad"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    assert _body(response)["status"] is None
    mock_table.put_item.assert_called_once()
    mock_table.update_item.assert_not_called()


@pytest.mark.parametrize("body,expected_fragment", [
    ({"action": "yolo", "actor": "konrad"}, "action must be one of"),
    ({"action": "approved"}, "actor is required"),
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


def test_review_on_a_missing_finding_writes_no_orphan_event(mock_table):
    mock_table.get_item.return_value = {}

    response = handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "manual-1", "finding_id": "ghost"},
               {"action": "approved", "actor": "konrad"}),
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
