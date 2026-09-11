"""Tests for review-api's handler. DynamoDB is mocked -- no AWS calls."""

import decimal
import hashlib
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
        # A real empty page, not a bare MagicMock. _query_all pages until
        # LastEvaluatedKey is falsy, and every attribute of a MagicMock is
        # truthy -- an unconfigured query makes it loop forever rather than
        # fail, which hangs the run instead of reporting anything. Tests that
        # care about query results override this.
        table.query.return_value = {"Items": []}
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


# ---------- fix-chain scaffolding (docs/fix-chain-review-spec.md) ----------

# The prerequisite: an earlier fix to the same file. PREREQ_HASH is what a
# dependent drafted on top of it records.
PREREQ_DIFF = "--- a/main.tf\n+++ b/main.tf\n@@ -1,1 +1,1 @@\n-old\n+first fix\n"
PREREQ = {
    **FINDING,
    "sk": "FINDING#earlier1",
    "finding_id": "earlier1",
    "proposed_fix": {**FINDING["proposed_fix"], "diff": PREREQ_DIFF},
}
PREREQ_HASH = hashlib.sha256(PREREQ_DIFF.encode("utf-8")).hexdigest()


def _dependent(applies_after):
    return {
        **FINDING,
        "proposed_fix": {**FINDING["proposed_fix"], "applies_after": applies_after},
    }


def _event_item(action, timestamp):
    return {"sk": f"EVENT#{timestamp}", "action": action, "actor": "someone"}


def _chain(mock_table, dependent, prerequisite, events):
    """Wire the mock so the dependent is fetched first, then its prerequisite,
    and the prerequisite's audit trail reads back as `events`."""
    mock_table.get_item.side_effect = [{"Item": dependent}, {"Item": prerequisite}]
    mock_table.query.return_value = {"Items": events}


def _review(action, **extra):
    body = {"action": action, **extra}
    return _event(
        "POST /prs/{pr_id}/findings/{finding_id}/review",
        {"pr_id": "manual-1", "finding_id": "abc123"},
        body,
    )


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


def test_list_events_reads_the_finding_partition_scoped_to_its_pr(mock_table):
    mock_table.query.return_value = {"Items": []}

    handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/events", {"pr_id": "manual-1", "finding_id": "abc123"}),
        None,
    )

    values = mock_table.query.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":pk"] == "PR#manual-1#FINDING#abc123"
    assert values[":sk_prefix"] == "EVENT#"


def test_audit_trails_do_not_bleed_between_prs_sharing_a_finding_id(mock_table):
    """finding_id is a content hash, so the same rule on the same file yields
    the same id in every PR that scans it. A decision recorded on one PR must
    not appear in another PR's audit trail."""
    mock_table.get_item.return_value = {"Item": FINDING}

    handler.handler(
        _event("POST /prs/{pr_id}/findings/{finding_id}/review",
               {"pr_id": "demo-1", "finding_id": "shared-id"},
               {"action": "approved"}),
        None,
    )
    written_pk = mock_table.put_item.call_args.kwargs["Item"]["pk"]

    mock_table.query.return_value = {"Items": []}
    handler.handler(
        _event("GET /prs/{pr_id}/findings/{finding_id}/events",
               {"pr_id": "other-pr", "finding_id": "shared-id"}),
        None,
    )
    read_pk = mock_table.query.call_args.kwargs["ExpressionAttributeValues"][":pk"]

    assert written_pk == "PR#demo-1#FINDING#shared-id"
    assert read_pk != written_pk


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
    assert event_item["pk"] == "PR#manual-1#FINDING#abc123"
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


def test_an_edit_preserves_what_the_fix_is_drafted_on(mock_table):
    """applies_after is deliberately not in the reset list alongside the
    self-check fields. Those are claims about whether this diff was verified,
    which a hand-edit invalidates. applies_after is a fact about what the diff
    is rooted on, and editing the diff does not re-root it -- the reviewer's
    version still only applies once its prerequisites do."""
    chain = [{"finding_id": "earlier1", "diff_sha256": PREREQ_HASH}]
    _chain(mock_table, _dependent(chain), PREREQ, [_event_item("approved", "2026-01-01")])

    handler.handler(_review("edited", edited_diff="reviewer version"), None)

    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["applies_after"] == chain
    assert written["self_check_passed"] is False


def test_editing_an_unparseable_fix_clears_the_agents_parse_failure(mock_table):
    """The likeliest response to "the fix did not parse" is a reviewer fixing
    the syntax by hand. Carrying the agent's parse failure onto that edit would
    keep flagging a file that no longer exists as broken -- and scan_errors
    outranks every other badge, so it would mask the edit's real state."""
    unparseable = {
        **FINDING,
        "status": "needs-human-only",
        "proposed_fix": {
            **FINDING["proposed_fix"],
            "self_check_passed": False,
            "cleared": False,
            "scan_errors": ["main.tf"],
        },
    }
    mock_table.get_item.return_value = {"Item": unparseable}

    response = handler.handler(
        _event(
            "POST /prs/{pr_id}/findings/{finding_id}/review",
            {"pr_id": "manual-1", "finding_id": "abc123"},
            {"action": "edited", "edited_diff": "--- a/main.tf\n+  }\n"},
        ),
        None,
    )

    assert response["statusCode"] == 200
    written = mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":pf"]
    assert written["scan_errors"] == []
    # Still unverified, just for the ordinary reason now: no scan has run
    # against the reviewer's diff either.
    assert written["self_check_passed"] is False


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


# ---------- fix-chain enforcement (docs/fix-chain-review-spec.md §3) ----------

SATISFIED = [{"finding_id": "earlier1", "diff_sha256": PREREQ_HASH}]


def _unmet(response):
    return _body(response)["unmet"]


def test_approve_is_blocked_when_the_prerequisite_was_rejected(mock_table):
    """And specifically when that rejection followed an approval, so the
    prerequisite's status is still "resolved". This is the case a status-based
    check gets wrong: rejection deliberately leaves status alone, so status
    reports the stale approval while the standing decision is the rejection."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [
        _event_item("approved", "2026-01-01"),
        _event_item("rejected", "2026-01-02"),
    ])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "rejected"}]
    # A blocked decision is not an attempted decision.
    mock_table.put_item.assert_not_called()
    mock_table.update_item.assert_not_called()


def test_approve_is_blocked_when_the_prerequisite_has_no_events(mock_table):
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "undecided"}]
    mock_table.put_item.assert_not_called()


def test_approve_is_blocked_when_the_entry_carries_no_hash(mock_table):
    """Absent is not the same as fresh, so it fails closed. Covers the records
    written before the chain carried hashes, whose entries are bare id strings."""
    _chain(mock_table, _dependent([{"finding_id": "earlier1"}]), PREREQ,
           [_event_item("approved", "2026-01-01")])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "unverifiable"}]


def test_approve_is_blocked_when_the_prerequisites_diff_changed(mock_table):
    """The prerequisite was edited after this fix was drafted on it, so this
    diff's context describes a file that no longer exists."""
    edited = {
        **PREREQ,
        "proposed_fix": {**PREREQ["proposed_fix"], "diff": "--- a/main.tf\n+reviewer rewrote it\n"},
    }
    _chain(mock_table, _dependent(SATISFIED), edited, [_event_item("edited", "2026-01-01")])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "stale"}]


def test_approve_is_blocked_when_the_prerequisite_is_gone(mock_table):
    mock_table.get_item.side_effect = [{"Item": _dependent(SATISFIED)}, {}]

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "missing"}]


def test_approve_is_allowed_when_the_prerequisite_is_resolved_and_unchanged(mock_table):
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("approved", "2026-01-01")])

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 200
    assert _body(response)["status"] == "resolved"
    mock_table.put_item.assert_called_once()


def test_an_edited_prerequisite_still_satisfies_if_its_diff_is_unchanged(mock_table):
    """Satisfaction is about the latest action being resolving, and staleness
    is a separate hash question. An edit that happened to leave the diff
    byte-identical blocks nothing."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("edited", "2026-01-01")])

    assert handler.handler(_review("approved"), None)["statusCode"] == 200


def test_reject_is_never_blocked_by_an_unmet_prerequisite(mock_table):
    """The reviewer's escape hatch from a bad chain. Rejecting is always safe:
    it records that this fix is refused, which is true regardless of what
    happened upstream of it."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [])

    response = handler.handler(_review("rejected"), None)

    assert response["statusCode"] == 200
    mock_table.put_item.assert_called_once()
    # Rejection still leaves status alone.
    mock_table.update_item.assert_not_called()


def test_edit_is_blocked_on_the_same_terms_as_approve(mock_table):
    """An edit resolves the finding just as an approval does, so it cannot be
    a way around the gate. A reviewer wanting a fix independent of its chain
    rejects it and lets a re-run redraft it."""
    _chain(mock_table, _dependent(SATISFIED), PREREQ, [_event_item("rejected", "2026-01-01")])

    response = handler.handler(_review("edited", edited_diff="reviewer version"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [{"finding_id": "earlier1", "reason": "rejected"}]
    mock_table.put_item.assert_not_called()


def test_a_fix_with_an_empty_chain_is_unaffected(mock_table):
    mock_table.get_item.return_value = {"Item": _dependent([])}

    assert handler.handler(_review("approved"), None)["statusCode"] == 200


def test_a_fix_predating_the_chain_field_is_unaffected(mock_table):
    """applies_after is absent entirely on the 15 records written before it
    existed. Absent means "not chained", which is what those records are."""
    mock_table.get_item.return_value = {"Item": FINDING}

    assert handler.handler(_review("approved"), None)["statusCode"] == 200


def test_every_unmet_prerequisite_is_reported_at_once(mock_table):
    """So a reviewer sees the whole blocking set rather than discovering it one
    409 at a time."""
    second = {**PREREQ, "sk": "FINDING#earlier2", "finding_id": "earlier2"}
    chain = [
        {"finding_id": "earlier1", "diff_sha256": PREREQ_HASH},
        {"finding_id": "earlier2", "diff_sha256": "a stale hash"},
    ]
    mock_table.get_item.side_effect = [
        {"Item": _dependent(chain)}, {"Item": PREREQ}, {"Item": second},
    ]
    mock_table.query.side_effect = [
        {"Items": [_event_item("rejected", "2026-01-01")]},
        {"Items": [_event_item("approved", "2026-01-01")]},
    ]

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _unmet(response) == [
        {"finding_id": "earlier1", "reason": "rejected"},
        {"finding_id": "earlier2", "reason": "stale"},
    ]


def test_a_superseded_finding_is_refused_by_the_existing_no_fix_check(mock_table):
    """It has no fix of its own, so it is not a chain link in either direction
    -- the decision belongs on the fix that superseded it."""
    mock_table.get_item.return_value = {
        "Item": {**FINDING, "status": "superseded", "superseded_by": "earlier1",
                 "proposed_fix": None},
    }

    response = handler.handler(_review("approved"), None)

    assert response["statusCode"] == 409
    assert _body(response)["error"] == "finding has no proposed fix to act on"


# ---------- cascade on edit (docs/fix-chain-review-spec.md §4) ----------

# A fix drafted on top of FINDING, already accepted by a human.
DEPENDENT = {
    **FINDING,
    "sk": "FINDING#dependent1",
    "finding_id": "dependent1",
    "status": "resolved",
    "proposed_fix": {
        **FINDING["proposed_fix"],
        "applies_after": [{"finding_id": "abc123", "diff_sha256": "whatever-it-was"}],
    },
}


def _updates_for(mock_table, finding_id):
    return [
        call for call in mock_table.update_item.call_args_list
        if call.kwargs["Key"]["sk"] == f"FINDING#{finding_id}"
    ]


def test_editing_a_fix_reopens_the_dependents_drafted_on_it(mock_table):
    """Section 3 blocks a dependent at review time. It does nothing for one
    already approved, because that decision has happened -- so an edit has to
    reach forward and reopen it, or the approved set is quietly unassemblable."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, DEPENDENT]}

    response = handler.handler(_review("edited", edited_diff="reviewer version"), None)

    assert response["statusCode"] == 200
    assert _body(response)["reopened_dependents"] == ["dependent1"]

    reopened = _updates_for(mock_table, "dependent1")
    assert len(reopened) == 1
    values = reopened[0].kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "needs-human-only"
    assert "abc123" in values[":reason"]

    # A machine reopening a human's decision has to be on the record.
    system_events = [
        call.kwargs["Item"] for call in mock_table.put_item.call_args_list
        if call.kwargs["Item"]["actor"] == "system"
    ]
    assert len(system_events) == 1
    assert system_events[0]["pk"] == "PR#manual-1#FINDING#dependent1"
    assert system_events[0]["action"] == "reopened"


def test_a_finding_with_no_dependents_is_untouched_by_an_edit(mock_table):
    unrelated = {**FINDING, "sk": "FINDING#other", "finding_id": "other"}
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, unrelated]}

    response = handler.handler(_review("edited", edited_diff="reviewer version"), None)

    assert _body(response)["reopened_dependents"] == []
    assert _updates_for(mock_table, "other") == []
    # Only the reviewer's own event was written.
    mock_table.put_item.assert_called_once()
    assert mock_table.put_item.call_args.kwargs["Item"]["actor"] == "konrad@example.com"


def test_approving_a_fix_does_not_cascade(mock_table):
    """Only an edit changes the diff, and it is the diff dependents were
    drafted against. An approval leaves it exactly as it was."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [FINDING, DEPENDENT]}

    response = handler.handler(_review("approved"), None)

    assert _body(response)["reopened_dependents"] == []
    assert _updates_for(mock_table, "dependent1") == []


def test_the_cascade_skips_the_finding_being_edited(mock_table):
    """A fix naming itself would otherwise reopen the very finding the
    reviewer just resolved."""
    self_referential = {
        **FINDING,
        "proposed_fix": {
            **FINDING["proposed_fix"],
            "applies_after": [{"finding_id": "abc123", "diff_sha256": PREREQ_HASH}],
        },
    }
    mock_table.get_item.side_effect = [{"Item": self_referential}, {"Item": PREREQ}]
    mock_table.query.side_effect = [
        {"Items": [_event_item("approved", "2026-01-01")]},
        {"Items": [self_referential]},
    ]

    response = handler.handler(_review("edited", edited_diff="reviewer version"), None)

    assert _body(response)["reopened_dependents"] == []


def test_a_cascade_event_cannot_collide_with_the_edit_that_caused_it(mock_table):
    """Both carry the same timestamp, and ReviewEvents are keyed on it. Without
    a distinct suffix the cascade would overwrite the reviewer's own event on a
    finding that is both edited and a dependent."""
    mock_table.get_item.return_value = {"Item": FINDING}
    mock_table.query.return_value = {"Items": [DEPENDENT]}

    handler.handler(_review("edited", edited_diff="reviewer version"), None)

    sort_keys = [call.kwargs["Item"]["sk"] for call in mock_table.put_item.call_args_list]
    assert len(sort_keys) == len(set(sort_keys))
