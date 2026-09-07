"""Tests for remediation-agent's handler.

No AWS/Anthropic calls are made -- DynamoDB, S3, the terraform-scanner
Lambda invocation, and the Anthropic client are all mocked. The self-check
comparison tests use real captured terraform-scanner output from
fixtures/ (see fixtures/README.md) rather than hand-written scan responses,
per that README's guidance to keep ground truth accurate.
"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import handler

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name, side):
    with open(FIXTURES / name / side / "scan-response.json") as f:
        return json.load(f)


def _read_fixture_tf(name, side):
    return (FIXTURES / name / side / "main.tf").read_text()


def _pairs(scan_response):
    return {(f["source"], f["rule_id"]) for f in scan_response["findings"]}


# ---------- _evaluate_self_check ----------

def test_self_check_clean_fix_single_rule_clears():
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == "aws-s3-enable-bucket-encryption")
    baseline_pairs = _pairs(before)

    passed, new_findings = handler._evaluate_self_check(finding, after["findings"], baseline_pairs)

    assert passed is True
    assert new_findings == []


@pytest.mark.parametrize("rule_id", ["CKV_AWS_24", "aws-ec2-no-public-ingress-sgr"])
def test_self_check_clean_fix_clears_multiple_sources_at_once(rule_id):
    before = _load_fixture("open-ssh-ingress", "before")
    after = _load_fixture("open-ssh-ingress", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == rule_id)
    baseline_pairs = _pairs(before)

    passed, new_findings = handler._evaluate_self_check(finding, after["findings"], baseline_pairs)

    assert passed is True
    assert new_findings == []


def test_self_check_fails_when_original_finding_not_cleared():
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "aws-s3-enable-bucket-encryption")
    baseline_pairs = _pairs(before)

    # Rescan identical to the baseline -- as if the "fix" changed nothing.
    passed, new_findings = handler._evaluate_self_check(finding, before["findings"], baseline_pairs)

    assert passed is False
    assert new_findings == []


def test_self_check_fails_when_fix_introduces_a_new_finding():
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == "aws-s3-enable-bucket-encryption")
    baseline_pairs = _pairs(before)

    rescan_findings = after["findings"] + [
        {"source": "tfsec", "rule_id": "aws-s3-new-thing-introduced-by-fix"}
    ]

    passed, new_findings = handler._evaluate_self_check(finding, rescan_findings, baseline_pairs)

    assert passed is False
    assert new_findings == ["tfsec:aws-s3-new-thing-introduced-by-fix"]


# ---------- _compute_diff ----------

def test_compute_diff_matches_fixture_after_content():
    before_content = _read_fixture_tf("s3-bucket-encryption", "before")
    after_content = _read_fixture_tf("s3-bucket-encryption", "after")

    diff_text = handler._compute_diff(before_content, after_content, "main.tf")

    assert "a/main.tf" in diff_text
    assert "b/main.tf" in diff_text
    assert "+resource \"aws_s3_bucket_server_side_encryption_configuration\" \"data\"" in diff_text


# ---------- handler() end to end ----------

def _fake_anthropic_response(payload_dict):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(payload_dict))])


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_handler_marks_fix_proposed_on_clean_self_check(mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client):
    before = _load_fixture("s3-bucket-encryption", "before")
    after = _load_fixture("s3-bucket-encryption", "after")
    finding = next(f for f in before["findings"] if f["rule_id"] == "aws-s3-enable-bucket-encryption")
    finding = {**finding, "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [finding]},          # _query_mapped_findings
        {"Items": before["findings"]}, # _query_baseline_pairs
    ]
    mock_dynamodb.Table.return_value = mock_table

    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }

    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "after"),
        "rationale": "Added a default SSE configuration for the bucket.",
    })

    mock_lambda_client.invoke.return_value = {
        "Payload": SimpleNamespace(read=lambda: json.dumps(after).encode())
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result == {"pr_id": "fixture-s3-enc-before", "fix_proposed_count": 1, "needs_human_only_count": 0}

    mock_s3.put_object.assert_called_once()
    put_kwargs = mock_s3.put_object.call_args.kwargs
    assert put_kwargs["Key"] == f"scans/fixture-s3-enc-before/self-check-{finding['finding_id']}/main.tf"

    mock_table.update_item.assert_called_once()
    update_kwargs = mock_table.update_item.call_args.kwargs
    assert update_kwargs["ExpressionAttributeValues"][":status"] == "fix-proposed"
    proposed_fix = update_kwargs["ExpressionAttributeValues"][":pf"]
    assert proposed_fix["self_check_passed"] is True
    assert proposed_fix["self_check_new_findings"] == []


@patch.object(handler, "_get_anthropic_client")
@patch.object(handler, "lambda_client")
@patch.object(handler, "s3")
@patch.object(handler, "dynamodb")
def test_handler_marks_needs_human_only_when_fix_does_not_clear_finding(
    mock_dynamodb, mock_s3, mock_lambda_client, mock_get_client
):
    before = _load_fixture("s3-bucket-encryption", "before")
    finding = next(f for f in before["findings"] if f["rule_id"] == "aws-s3-enable-bucket-encryption")
    finding = {**finding, "status": "mapped"}

    mock_table = MagicMock()
    mock_table.query.side_effect = [
        {"Items": [finding]},
        {"Items": before["findings"]},
    ]
    mock_dynamodb.Table.return_value = mock_table

    mock_s3.get_object.return_value = {
        "Body": SimpleNamespace(read=lambda: _read_fixture_tf("s3-bucket-encryption", "before").encode())
    }

    # LLM "fix" that changes nothing meaningful -- self-check should catch it.
    mock_get_client.return_value.messages.create.return_value = _fake_anthropic_response({
        "corrected_file_content": _read_fixture_tf("s3-bucket-encryption", "before"),
        "rationale": "No-op.",
    })

    # Rescan comes back identical to the original baseline.
    mock_lambda_client.invoke.return_value = {
        "Payload": SimpleNamespace(read=lambda: json.dumps(before).encode())
    }

    result = handler.handler({"pr_id": "fixture-s3-enc-before"}, None)

    assert result == {"pr_id": "fixture-s3-enc-before", "fix_proposed_count": 0, "needs_human_only_count": 1}

    update_kwargs = mock_table.update_item.call_args.kwargs
    assert update_kwargs["ExpressionAttributeValues"][":status"] == "needs-human-only"
    assert update_kwargs["ExpressionAttributeValues"][":pf"]["self_check_passed"] is False
