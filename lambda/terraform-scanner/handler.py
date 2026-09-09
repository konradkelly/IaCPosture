"""terraform-scanner Lambda (spec §4.1, §4.4 step 3).

Runs tfsec + Checkov against a Terraform snapshot stored in S3 and writes
raw findings (status: "raw") to the DynamoDB findings table. Also used by
remediation-agent (spec §4.4 step 5) to self-check a proposed fix — that
call path passes persist=false and just reads the returned findings.

Event shape:
{
  "pr_id": "manual-1",
  "s3_prefix": "scans/manual-1/",   # directory of .tf files under ARTIFACTS_BUCKET
  "iac_type": "terraform",
  "persist": true                    # optional, default true
}

Each returned finding's "file" is relative to s3_prefix (e.g. "main.tf"), not
a local /tmp path -- callers can reconstruct the object's S3 key as
f"{s3_prefix}{finding['file']}".

Returns {pr_id, finding_count, findings, scan_errors}. "scan_errors" lists
files the scanner could not parse. It is not cosmetic: a file that fails to
parse produces no findings, and remediation-agent's self-check reads "no
findings" as proof that a fix cleared its finding. A caller that ignores
scan_errors will read an unparseable file as a clean one. A tool that fails
outright (no output, unparseable output) raises ScannerError instead -- that
is a scan that did not happen, not a scan with a result.
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TFSEC_BIN = "/opt/bin/tfsec"
LAYER_PYTHON_PATH = "/opt/python"
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
# Checkov's own import is the dominant cost here, not the scan itself: it eagerly
# loads its full multi-framework check registry (~50-100s cold-start observed in
# testing), separate from the Lambda's own init phase. TODO: switch to importing
# checkov.terraform.runner.Runner in-process (skips checkov.main's non-Terraform
# framework loading, roughly halves this) instead of shelling out per-invocation.
SCAN_TIMEOUT_SECONDS = 240

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")


class ScannerError(RuntimeError):
    """A scanner did not run to completion.

    Deliberately distinct from "the scanner ran and found nothing". Both used
    to arrive here as an empty list, and the difference matters more than
    anywhere else in this project: remediation-agent proves a fix by rescanning
    it and checking the finding no longer fires. A crashed, timed-out, or
    OOM-killed scanner reports zero findings, which that check reads as "the
    finding is gone" -- so swallowing a tool failure hands out a
    scanner-verified badge for a scan that never ran.
    """


def handler(event, context):
    pr_id = event["pr_id"]
    s3_prefix = event["s3_prefix"].rstrip("/") + "/"
    iac_type = event.get("iac_type", "terraform")
    persist = event.get("persist", True)

    if iac_type != "terraform":
        raise ValueError(f"terraform-scanner cannot handle iac_type={iac_type!r}")

    work_dir = f"/tmp/scan-{uuid.uuid4().hex}"
    os.makedirs(work_dir, exist_ok=True)

    try:
        downloaded = _download_snapshot(ARTIFACTS_BUCKET, s3_prefix, work_dir)
        if not downloaded:
            raise ValueError(f"no .tf files found under s3://{ARTIFACTS_BUCKET}/{s3_prefix}")

        tfsec_results = _run_tfsec(work_dir)
        checkov_report = _run_checkov(work_dir)

        findings = _normalize_tfsec(tfsec_results, pr_id, work_dir) + _normalize_checkov(checkov_report, pr_id)

        scan_errors = _checkov_parse_errors(checkov_report, work_dir)
        if scan_errors:
            # Reported, not raised: the other files in the snapshot scanned
            # fine and their findings are real. Raising would throw those away
            # over one bad file. It is the caller's job to decide what an
            # unscannable file means -- for remediation-agent's self-check it
            # is fatal, for a baseline scan it is a warning.
            logger.warning("checkov could not parse %d file(s): %s", len(scan_errors), scan_errors)

        if persist:
            _write_findings(findings)

        return {
            "pr_id": pr_id,
            "finding_count": len(findings),
            "findings": findings,
            "scan_errors": scan_errors,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _download_snapshot(bucket, prefix, dest_dir):
    paginator = s3.get_paginator("list_objects_v2")
    downloaded = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".tf"):
                continue
            rel_path = key[len(prefix):]
            local_path = os.path.join(dest_dir, rel_path)
            os.makedirs(os.path.dirname(local_path) or dest_dir, exist_ok=True)
            s3.download_file(bucket, key, local_path)
            downloaded.append(local_path)
    return downloaded


def _run_tfsec(work_dir):
    proc = subprocess.run(
        [TFSEC_BIN, work_dir, "--format", "json", "--no-color"],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    # tfsec exits non-zero when it finds issues -- that's expected, not a failure.
    # Empty stdout is not: with --format json tfsec always emits an object, even
    # for a clean scan (as {"results": null}), so nothing at all means the binary
    # itself failed.
    if not proc.stdout.strip():
        raise ScannerError(
            f"tfsec produced no output (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
        )
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"tfsec produced unparseable output: {proc.stdout[:500]}") from exc
    # "results": null is tfsec's clean scan, distinct from the failures above.
    return parsed.get("results") or []


def _run_checkov(work_dir):
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    if LAYER_PYTHON_PATH not in existing.split(os.pathsep):
        env["PYTHONPATH"] = os.pathsep.join(p for p in (LAYER_PYTHON_PATH, existing) if p)
    # Avoids an unnecessary PyPI network call on every cold start.
    env["CKV_SKIP_PACKAGE_UPDATE_CHECK"] = "true"

    proc = subprocess.run(
        [sys.executable, "-m", "checkov.main", "-d", work_dir, "--framework", "terraform", "-o", "json", "--compact"],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
        env=env,
    )
    # checkov exits non-zero when it finds failed checks -- that's expected, not a failure.
    if not proc.stdout.strip():
        raise ScannerError(
            f"checkov produced no output (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"checkov produced unparseable output: {proc.stdout[:500]}") from exc


def _relativize_path(file_path, work_dir):
    """Strip the scratch directory back off a path a tool reported.

    Handles both forms the tools emit: tfsec echoes the absolute path it was
    invoked with (work_dir/main.tf), and checkov's parsing_errors carry the
    same, while its check records are already root-relative (/main.tf).
    """
    prefix = work_dir.rstrip("/") + "/"
    if file_path.startswith(prefix):
        return file_path[len(prefix):]
    return file_path.lstrip("/")


def _normalize_tfsec(results, pr_id, work_dir):
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for r in results:
        location = r.get("location") or {}
        findings.append(_build_finding(
            pr_id=pr_id,
            source="tfsec",
            rule_id=r.get("long_id") or r.get("rule_id", "unknown"),
            # tfsec reports the full local path it was invoked with (work_dir/main.tf).
            file_path=_relativize_path(location.get("filename", ""), work_dir),
            line_range=[location.get("start_line"), location.get("end_line")],
            severity=(r.get("severity") or "UNKNOWN").upper(),
            now=now,
        ))
    return findings


def _checkov_parse_errors(report, work_dir):
    """Files checkov could not parse, relative to work_dir.

    checkov is the parse oracle here because it is the only one of the two
    tools that reports the failure as data: tfsec writes parse trouble to
    stderr and still emits a well-formed (empty) result set, which is
    indistinguishable from a clean scan at this layer.

    A file that fails to parse contributes no findings, so without this a
    syntactically broken .tf scans exactly like a compliant one -- and
    remediation-agent's self-check would read that as proof its fix worked.

    Absent "results" is checkov's shape for a report with nothing in it at all
    (see Report.get_dict / is_empty upstream); parsing errors would themselves
    make the report non-empty, so that shape means zero parse errors, not
    unknown.
    """
    parse_errors = ((report.get("results") or {}).get("parsing_errors")) or []
    return sorted({_relativize_path(path, work_dir) for path in parse_errors})


def _normalize_checkov(report, pr_id):
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    failed_checks = ((report.get("results") or {}).get("failed_checks")) or []
    for c in failed_checks:
        findings.append(_build_finding(
            pr_id=pr_id,
            source="checkov",
            rule_id=c.get("check_id", "unknown"),
            # checkov reports paths root-relative to the scanned dir (/main.tf).
            file_path=c.get("file_path", "").lstrip("/"),
            line_range=list(c.get("file_line_range") or [None, None]),
            severity=(c.get("severity") or "UNKNOWN").upper(),
            now=now,
        ))
    return findings


def _build_finding(pr_id, source, rule_id, file_path, line_range, severity, now):
    # Deterministic id so re-scanning the same PR overwrites prior findings for
    # the same (source, rule, location) instead of accumulating duplicates.
    finding_key = f"{source}:{rule_id}:{file_path}:{line_range}"
    finding_id = hashlib.sha1(finding_key.encode()).hexdigest()[:16]
    return {
        "pk": f"PR#{pr_id}",
        "sk": f"FINDING#{finding_id}",
        "finding_id": finding_id,
        "iac_type": "terraform",
        "source": source,
        "rule_id": rule_id,
        "file": file_path,
        "line_range": line_range,
        "severity": severity,
        "control_mappings": [],
        "status": "raw",
        "proposed_fix": None,
        "created_at": now,
        "updated_at": now,
    }


def _write_findings(findings):
    table = dynamodb.Table(DYNAMODB_TABLE)
    with table.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as batch:
        for finding in findings:
            batch.put_item(Item=finding)
