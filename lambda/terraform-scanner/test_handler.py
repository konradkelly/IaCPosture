"""Tests for terraform-scanner's handler.

No AWS calls are made -- S3, DynamoDB, and both scanner subprocesses are
mocked. The focus is the distinction the scanner owes its callers: a scan
that ran and found nothing, versus a scan that did not run or could not read
its input. Those used to be the same empty list, and remediation-agent reads
an empty list as proof that a fix worked.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import handler

FIXTURES = Path(__file__).parent / "fixtures"

WORK_DIR = "/tmp/scan-abc123"


def _proc(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _checkov_report(failed_checks=(), parsing_errors=()):
    """checkov's non-quiet JSON shape (Report.get_dict upstream)."""
    return {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": list(failed_checks),
            "skipped_checks": [],
            "parsing_errors": list(parsing_errors),
        },
        "summary": {"passed": 0, "failed": len(failed_checks), "skipped": 0,
                    "parsing_errors": len(parsing_errors)},
    }


# ---------- a tool that failed is not a tool that found nothing ----------

@patch.object(handler.subprocess, "run")
def test_tfsec_producing_no_output_raises_rather_than_scanning_clean(mock_run):
    """The false-pass path. tfsec always emits an object with --format json,
    so empty stdout means the binary failed -- and returning [] for that would
    tell remediation-agent the file is clean."""
    mock_run.return_value = _proc(stdout="", stderr="fork/exec: permission denied", returncode=126)

    with pytest.raises(handler.ScannerError, match="tfsec produced no output"):
        handler._run_tfsec(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_tfsec_producing_unparseable_output_raises(mock_run):
    mock_run.return_value = _proc(stdout="panic: runtime error\n", returncode=2)

    with pytest.raises(handler.ScannerError, match="unparseable"):
        handler._run_tfsec(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_tfsec_null_results_is_a_clean_scan_not_an_error(mock_run):
    """tfsec's genuine clean scan. Must stay distinguishable from the failures
    above -- if this raised, every clean self-check would fail."""
    mock_run.return_value = _proc(stdout=json.dumps({"results": None}), returncode=0)

    assert handler._run_tfsec(WORK_DIR) == []


@patch.object(handler.subprocess, "run")
def test_checkov_producing_no_output_raises(mock_run):
    mock_run.return_value = _proc(stdout="", stderr="MemoryError", returncode=137)

    with pytest.raises(handler.ScannerError, match="checkov produced no output"):
        handler._run_checkov(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_checkov_producing_unparseable_output_raises(mock_run):
    mock_run.return_value = _proc(stdout="Traceback (most recent call last):\n", returncode=1)

    with pytest.raises(handler.ScannerError, match="unparseable"):
        handler._run_checkov(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_a_scan_timeout_propagates(mock_run):
    """Already the behaviour before ScannerError existed, and worth pinning:
    a timeout must not be swallowed into an empty result either."""
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="tfsec", timeout=240)

    with pytest.raises(subprocess.TimeoutExpired):
        handler._run_tfsec(WORK_DIR)


# ---------- parse errors ----------

def test_parse_errors_are_reported_relative_to_the_work_dir():
    """checkov reports parsing_errors as the absolute path it walked, unlike
    its check records -- callers key on the same relative path the findings
    use, so both have to come back in the same form."""
    report = _checkov_report(parsing_errors=[f"{WORK_DIR}/main.tf", f"{WORK_DIR}/modules/vpc/net.tf"])

    assert handler._checkov_parse_errors(report, WORK_DIR) == ["main.tf", "modules/vpc/net.tf"]


def test_a_clean_report_has_no_parse_errors():
    assert handler._checkov_parse_errors(_checkov_report(), WORK_DIR) == []


def test_checkovs_bare_summary_shape_is_not_read_as_unknown():
    """When a report holds nothing at all, checkov drops "results" and emits
    only a summary. Parsing errors would themselves make the report non-empty
    (Report.is_empty counts them upstream), so this shape means zero parse
    errors -- not that the answer is unavailable."""
    bare_summary = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
                    "resource_count": 0, "checkov_version": "3.2.0"}

    assert handler._checkov_parse_errors(bare_summary, WORK_DIR) == []


# ---------- handler() ----------

@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_handler_surfaces_parse_errors_without_discarding_real_findings(
    mock_download, mock_tfsec, mock_checkov, mock_write
):
    """One unparseable file among several doesn't invalidate the others'
    findings, so this is reported rather than raised."""
    mock_download.return_value = ["main.tf", "broken.tf"]
    mock_tfsec.return_value = [{
        "long_id": "aws-s3-enable-bucket-encryption",
        "location": {"filename": "main.tf", "start_line": 1, "end_line": 3},
        "severity": "HIGH",
    }]
    mock_checkov.return_value = _checkov_report(parsing_errors=["broken.tf"])

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    assert result["scan_errors"] == ["broken.tf"]
    assert result["finding_count"] == 1
    mock_write.assert_called_once()


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_handler_reports_no_scan_errors_on_a_clean_scan(
    mock_download, mock_tfsec, mock_checkov, mock_write
):
    mock_download.return_value = ["main.tf"]
    mock_tfsec.return_value = []
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == []
    assert result["findings"] == []
    mock_write.assert_not_called()


@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_handler_lets_a_scanner_failure_reach_the_caller(mock_download, mock_tfsec):
    """remediation-agent turns this into a failed Lambda invocation and leaves
    the finding at status "mapped" for a retry, rather than scoring the fix."""
    mock_download.return_value = ["main.tf"]
    mock_tfsec.side_effect = handler.ScannerError("tfsec produced no output (exit 126)")

    with pytest.raises(handler.ScannerError):
        handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)


# ---------- the fixture ----------

def test_the_unparseable_fixture_is_actually_unparseable():
    """Guards the fixture itself: it only tests anything if the brace really is
    missing. A well-meant edit that balanced it would leave every test above
    passing while the case they describe quietly stopped existing."""
    content = (FIXTURES / "unparseable" / "main.tf").read_text()

    assert content.count("{") > content.count("}")
