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

# Captured verbatim from the deployed terraform-scanner on 2026-09-09, invoked
# against fixtures/unparseable/main.tf. tfsec does not report a parse failure as
# JSON with empty results -- it prints this to stdout and abandons the scan. The
# work dir is the real one from that run, kept so the path form (leading slash
# stripped, unlike tfsec's findings) stays honest.
TFSEC_WORK_DIR = "/tmp/scan-3e096e4b02db497fa9761136cbeed2e3"
TFSEC_PARSE_FAILURE_STDOUT = (
    "Error: scan failed: tmp/scan-3e096e4b02db497fa9761136cbeed2e3/main.tf:18,37-38: "
    "Unclosed configuration block; There is no closing brace for this block before "
    "the end of the file. This may be caused by incorrect brace nesting elsewhere "
    "in this file.\n"
)


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
def test_tfsec_output_that_is_neither_json_nor_a_parse_error_raises(mock_run):
    """A genuine crash still has to raise -- only output that names the file it
    choked on is downgraded to a reportable parse error."""
    mock_run.return_value = _proc(stdout="panic: runtime error\n", returncode=2)

    with pytest.raises(handler.ScannerError, match="unparseable"):
        handler._run_tfsec(WORK_DIR)


@patch.object(handler.subprocess, "run")
def test_tfsec_parse_failure_is_reported_not_raised(mock_run):
    """Against the real captured output. Raising here would be safe but wrong:
    remediation-agent turns a raised error into a retry with the finding left
    at "mapped", so an agent that drops a brace would loop -- re-drafting, re-
    failing, and costing a model call each time -- while no reviewer ever sees
    it. Reported, it becomes needs-human-only with the reason attached."""
    mock_run.return_value = _proc(stdout=TFSEC_PARSE_FAILURE_STDOUT, returncode=1)

    results, parse_errors = handler._run_tfsec(TFSEC_WORK_DIR)

    assert results == []
    assert parse_errors == ["main.tf"]


@patch.object(handler.subprocess, "run")
def test_tfsec_null_results_is_a_clean_scan_not_an_error(mock_run):
    """tfsec's genuine clean scan. Must stay distinguishable from the failures
    above -- if this raised, every clean self-check would fail."""
    mock_run.return_value = _proc(stdout=json.dumps({"results": None}), returncode=0)

    assert handler._run_tfsec(WORK_DIR) == ([], [])


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


def test_paths_are_relativized_whether_or_not_the_leading_slash_survived():
    """tfsec keeps the leading slash in its findings and drops it in its parse
    errors, so both forms reach this from the same run."""
    assert handler._relativize_path(f"{WORK_DIR}/main.tf", WORK_DIR) == "main.tf"
    assert handler._relativize_path(f"{WORK_DIR.lstrip('/')}/main.tf", WORK_DIR) == "main.tf"
    assert handler._relativize_path("/main.tf", WORK_DIR) == "main.tf"


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


def _emf_lines(captured_out):
    """Every EMF record in stdout, parsed, with the shape CloudWatch requires
    checked: an _aws block whose metric names and dimension keys all exist as
    top-level fields. A record that fails this is silently ignored by
    CloudWatch, which is the failure mode a test has to catch."""
    records = []
    for line in captured_out.splitlines():
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "_aws" not in rec:
            continue
        aws = rec["_aws"]
        assert isinstance(aws["Timestamp"], int)
        for block in aws["CloudWatchMetrics"]:
            assert block["Namespace"] == "IaCPosture"
            for dim_set in block["Dimensions"]:
                for key in dim_set:
                    assert key in rec, f"dimension {key} has no value"
            for m in block["Metrics"]:
                assert m["Name"] in rec, f"metric {m['Name']} has no value"
                assert isinstance(rec[m["Name"]], (int, float))
        records.append(rec)
    return records


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
    mock_tfsec.return_value = ([{
        "long_id": "aws-s3-enable-bucket-encryption",
        "location": {"filename": "main.tf", "start_line": 1, "end_line": 3},
        "severity": "HIGH",
    }], [])
    mock_checkov.return_value = _checkov_report(parsing_errors=["broken.tf"])

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    assert result["scan_errors"] == ["broken.tf"]
    assert result["finding_count"] == 1
    mock_write.assert_called_once()


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_a_persisted_scan_emits_findings_per_scan_as_emf(
    mock_download, mock_tfsec, mock_checkov, mock_write, capsys
):
    """Spec §4.1's findings-per-scan metric, as one Embedded Metric Format
    line on stdout. Printed rather than logged: Lambda prefixes logger output
    and EMF needs the whole event to be the JSON."""
    mock_download.return_value = ["main.tf"]
    mock_tfsec.return_value = ([{
        "long_id": "aws-s3-enable-bucket-encryption",
        "location": {"filename": "main.tf", "start_line": 1, "end_line": 3},
        "severity": "HIGH",
    }] * 3, [])
    mock_checkov.return_value = _checkov_report(parsing_errors=["broken.tf"])

    handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/"}, None)

    records = _emf_lines(capsys.readouterr().out)
    assert len(records) == 1
    rec = records[0]
    assert rec["FindingsPerScan"] == 3
    assert rec["ScanParseErrors"] == 1
    assert rec["Environment"] == handler.ENVIRONMENT
    assert rec["pr_id"] == "pr-1"


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_a_self_check_scan_emits_no_metric(
    mock_download, mock_tfsec, mock_checkov, mock_write, capsys
):
    """persist=False is a rescan of one patched file for a self-check, not a
    scan of a PR. Counting it would make every remediation run look like a
    burst of tiny scans."""
    mock_download.return_value = ["main.tf"]
    mock_tfsec.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    handler.handler({"pr_id": "pr-1", "s3_prefix": "fixes/pr-1/f1/", "persist": False}, None)

    assert _emf_lines(capsys.readouterr().out) == []


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_handler_reports_no_scan_errors_on_a_clean_scan(
    mock_download, mock_tfsec, mock_checkov, mock_write
):
    mock_download.return_value = ["main.tf"]
    mock_tfsec.return_value = ([], [])
    mock_checkov.return_value = _checkov_report()

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == []
    assert result["findings"] == []
    mock_write.assert_not_called()


@patch.object(handler, "_write_findings")
@patch.object(handler, "_run_checkov")
@patch.object(handler, "_run_tfsec")
@patch.object(handler, "_download_snapshot")
def test_handler_merges_parse_errors_from_both_tools(
    mock_download, mock_tfsec, mock_checkov, mock_write
):
    """The two parsers disagree on what they can read, so neither alone is the
    oracle -- and a file they both choke on must be listed once, not twice.

    Paths are given already-relative here because handler() scans into a work
    dir it names itself; relativizing the absolute forms the tools really emit
    is covered by _relativize_path and _checkov_parse_errors directly."""
    mock_download.return_value = ["main.tf", "odd.tf"]
    mock_tfsec.return_value = ([], ["main.tf"])
    mock_checkov.return_value = _checkov_report(parsing_errors=["main.tf", "odd.tf"])

    result = handler.handler({"pr_id": "pr-1", "s3_prefix": "scans/pr-1/", "persist": False}, None)

    assert result["scan_errors"] == ["main.tf", "odd.tf"]


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
