"""remediation-agent Lambda (spec §4.1, §4.4 step 5; docs/remediation-agent-spec.md).

For each finding with status "mapped" under a PR, drafts a corrected version
of the offending file via the Anthropic API, computes a unified diff against
the original in code, then proves the fix works by re-invoking
terraform-scanner (persist=false) against the patched content and comparing
(source, rule_id) pairs before/after. self_check_passed is always computed
here, never asserted by the LLM -- that's the project's core integrity
guarantee.

Event shape:
{ "pr_id": "manual-test-1" }
"""

import collections
import difflib
import json
import logging
import os
from datetime import datetime, timezone

import anthropic
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET")
ANTHROPIC_SECRET_ARN = os.environ.get("ANTHROPIC_SECRET_ARN")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
TERRAFORM_SCANNER_FUNCTION_NAME = os.environ.get("TERRAFORM_SCANNER_FUNCTION_NAME")

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")
lambda_client = boto3.client("lambda")

# Cold-start cache -- the API key doesn't change within a warm execution
# environment, so fetch it at most once per container (same pattern as
# mapping-agent).
_anthropic_client = None

REMEDIATION_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "corrected_file_content": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["corrected_file_content", "rationale"],
    "additionalProperties": False,
}


def handler(event, context):
    pr_id = event["pr_id"]

    mapped_findings = _query_mapped_findings(pr_id)

    fix_proposed_count = 0
    needs_human_count = 0
    error_count = 0

    for finding in mapped_findings:
        try:
            self_check_passed = _remediate_finding(pr_id, finding)
        except Exception:
            # One finding's failure shouldn't abandon the rest of the batch.
            # Status stays "mapped", so a re-run retries this finding.
            logger.exception("remediation failed for finding %s", finding.get("finding_id"))
            error_count += 1
            continue

        if self_check_passed:
            fix_proposed_count += 1
        else:
            needs_human_count += 1

    return {
        "pr_id": pr_id,
        "fix_proposed_count": fix_proposed_count,
        "needs_human_only_count": needs_human_count,
        "error_count": error_count,
    }


def _remediate_finding(pr_id, finding):
    finding_id = finding["finding_id"]
    file_path = finding["file"]

    original_content = _fetch_original_content(pr_id, file_path)
    remediation = _call_remediation_agent(finding, original_content)
    corrected_content = remediation["corrected_file_content"]
    rationale = remediation["rationale"]

    diff_text = _compute_diff(original_content, corrected_content, file_path)

    # Gate before the self-check, not after: a suppression would *pass* the
    # self-check by construction, so there is no point scanning it.
    suppressions = _find_added_suppressions(diff_text)
    if suppressions:
        logger.warning(
            "remediation for finding %s tried to suppress the scanner rather than fix it: %s",
            finding_id, suppressions,
        )
        _write_result(
            finding, diff_text, rationale,
            self_check_passed=False, self_check_new_findings=[], cleared=False,
            suppression_attempt=suppressions,
        )
        return False

    _upload_scratch_file(pr_id, finding_id, file_path, corrected_content)
    rescan_findings = _invoke_self_check(pr_id, finding_id)

    baseline_counts = _query_baseline_counts(pr_id, file_path)
    self_check_passed, self_check_new_findings, cleared = _evaluate_self_check(
        finding, rescan_findings, baseline_counts
    )

    _write_result(
        finding, diff_text, rationale, self_check_passed, self_check_new_findings, cleared
    )
    return self_check_passed


def _query_all(table, **kwargs):
    """Query to exhaustion. A Query caps at 1MB of read items and applies
    FilterExpression only afterwards, so one page can return few (or zero)
    matches while more wait behind a continuation token. Under-reading the
    baseline below would weaken the "no new findings" half of the self-check."""
    items = []
    while True:
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return items
        kwargs["ExclusiveStartKey"] = last_key


def _query_mapped_findings(pr_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    return _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression="#status = :status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":pk": f"PR#{pr_id}",
            ":sk_prefix": "FINDING#",
            ":status": "mapped",
        },
    )


def _query_baseline_counts(pr_id, file_path):
    """How many times each (source, rule_id) fires on file_path in the baseline
    scan, across every status.

    Counts rather than a set: one file often carries several instances of the
    same rule (three open-ingress rules in one security group, say), and the
    self-check has to distinguish "one of them was fixed" from "none were"."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    items = _query_all(
        table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression="#file = :file",
        ExpressionAttributeNames={"#file": "file"},
        ExpressionAttributeValues={
            ":pk": f"PR#{pr_id}",
            ":sk_prefix": "FINDING#",
            ":file": file_path,
        },
    )
    return collections.Counter((item["source"], item["rule_id"]) for item in items)


def _fetch_original_content(pr_id, file_path):
    obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=f"scans/{pr_id}/{file_path}")
    return obj["Body"].read().decode("utf-8")


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        secret = secretsmanager.get_secret_value(SecretId=ANTHROPIC_SECRET_ARN)
        _anthropic_client = anthropic.Anthropic(api_key=secret["SecretString"])
    return _anthropic_client


def _call_remediation_agent(finding, original_content):
    prompt = (
        "Scanner finding to fix:\n"
        f"  source: {finding['source']}\n"
        f"  rule_id: {finding['rule_id']}\n"
        f"  severity: {finding['severity']}\n"
        f"  file: {finding['file']}\n"
        f"  line_range: {finding['line_range']}\n\n"
        f"Current file contents:\n{original_content}\n\n"
        "Return the complete corrected file content with a minimal fix for "
        "this specific finding only -- do not restructure unrelated code or "
        "address other findings in the file. Return the full file, not a "
        "diff or a snippet. Also return a short rationale for the fix.\n\n"
        "Fix the underlying configuration. Never silence the scanner: do not "
        "add tfsec:ignore, trivy:ignore, checkov:skip, nosec, or any other "
        "suppression comment. If you believe the flagged configuration is "
        "intentional and correct as written, say so in the rationale and "
        "return the file unchanged -- a human will decide. Suppressing a "
        "finding is not a fix and will be rejected."
    )

    response = _get_anthropic_client().messages.create(
        model=MODEL,
        # Carries a whole rewritten .tf file -- a truncated response fails
        # JSON parsing and wastes the finding's remediation attempt.
        max_tokens=16000,
        output_config={
            "effort": "medium",
            "format": {"type": "json_schema", "schema": REMEDIATION_OUTPUT_SCHEMA},
        },
        messages=[{"role": "user", "content": prompt}],
    )

    text = next((b.text for b in response.content if b.type == "text"), None)
    if text is None:
        raise RuntimeError(f"remediation-agent got no text block for finding {finding['finding_id']}")

    return json.loads(text)


# Directives that make a scanner stop reporting a finding without changing
# any infrastructure. tfsec and checkov are what this project runs; trivy is
# tfsec's successor and accepts the same comment under its own name.
SUPPRESSION_MARKERS = ("tfsec:ignore", "trivy:ignore", "checkov:skip", "nosec")


def _find_added_suppressions(diff_text):
    """Suppression directives the fix would ADD, if any.

    This is the one edit that defeats the integrity guarantee outright. The
    self-check asks "does the scanner still report this finding" -- so a diff
    that merely silences the rule clears the finding, introduces no new ones,
    and comes back self_check_passed=true. The agent would earn a
    scanner-verified badge for changing nothing.

    Observed on real code: asked to fix a CRITICAL 0.0.0.0/0 ingress rule, the
    agent left the CIDR untouched and added `#tfsec:ignore:` plus a confident
    justification. It was caught only because that file happened to hold three
    instances of the rule, so the rescan still reported it -- an accident, not
    a defence, and one that _evaluate_self_check's occurrence counting now
    (correctly) removes.

    Enforced here rather than only forbidden in the prompt: the whole premise
    of the project is that the model's output is checked by code, not trusted.

    Only added lines are examined -- a suppression already in the file is the
    author's decision and none of this function's business.
    """
    added = [
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    return [
        line.strip()
        for line in added
        if any(marker in line.lower() for marker in SUPPRESSION_MARKERS)
    ]


def _compute_diff(original_content, corrected_content, file_path):
    diff_lines = difflib.unified_diff(
        original_content.splitlines(keepends=True),
        corrected_content.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff_lines)


def _self_check_prefix(pr_id, finding_id):
    """Scratch prefix for one finding's patched file.

    A sibling of the PR's snapshot, not the `scans/<pr_id>/self-check-<id>/`
    the build brief specifies: the scanner lists `scans/<pr_id>/` recursively
    and takes every .tf under it, so nesting scratch copies there would make a
    later scan read this agent's own patched files as source. Still under
    `scans/*`, which is what the execution role grants.
    """
    return f"scans/self-checks/{pr_id}/{finding_id}/"


def _upload_scratch_file(pr_id, finding_id, file_path, content):
    key = f"{_self_check_prefix(pr_id, finding_id)}{file_path}"
    s3.put_object(Bucket=ARTIFACTS_BUCKET, Key=key, Body=content.encode("utf-8"))
    return key


def _invoke_self_check(pr_id, finding_id):
    payload = {
        "pr_id": f"{pr_id}-self-check-{finding_id}",
        "s3_prefix": _self_check_prefix(pr_id, finding_id),
        "iac_type": "terraform",
        "persist": False,
    }
    response = lambda_client.invoke(
        FunctionName=TERRAFORM_SCANNER_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    result = json.loads(response["Payload"].read())
    if "FunctionError" in response:
        raise RuntimeError(f"terraform-scanner self-check invocation failed: {result}")
    return result["findings"]


def _evaluate_self_check(finding, rescan_findings, baseline_counts):
    target_pair = (finding["source"], finding["rule_id"])
    rescan_counts = collections.Counter((f["source"], f["rule_id"]) for f in rescan_findings)

    # Occurrence counts, not mere presence. A file can hold several instances
    # of one rule, and fixing the flagged instance leaves the others firing --
    # presence alone would report a real fix as uncleared. The inverse matters
    # more: a rule appearing fewer times than before means an instance
    # genuinely went away, which presence can't see at all.
    cleared = rescan_counts[target_pair] < baseline_counts[target_pair]

    # "New" covers a rule absent from the baseline *and* extra instances of one
    # already there -- a fix that doubles an existing problem isn't clean.
    new_pairs = {
        pair for pair, n in rescan_counts.items() if n > baseline_counts.get(pair, 0)
    }
    no_new_findings = not new_pairs

    self_check_passed = cleared and no_new_findings
    self_check_new_findings = sorted(f"{source}:{rule_id}" for source, rule_id in new_pairs)
    # cleared is returned separately from self_check_passed because a failed
    # self-check has two different meanings a reviewer needs told apart: the
    # fix missed the original finding entirely (cleared=False), or it cleared
    # the original but brought new findings with it (cleared=True) -- the
    # latter is often one edit away from passing, the former is not. Losing
    # this distinction and collapsing both into "self-check failed" is
    # actively misleading, not just less informative.
    return self_check_passed, self_check_new_findings, cleared


def _write_result(
    finding, diff_text, rationale, self_check_passed, self_check_new_findings, cleared,
    suppression_attempt=None,
):
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"pk": finding["pk"], "sk": finding["sk"]},
        UpdateExpression="SET proposed_fix = :pf, #status = :status, updated_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":pf": {
                "diff": diff_text,
                "rationale": rationale,
                "self_check_passed": self_check_passed,
                "self_check_new_findings": self_check_new_findings,
                "cleared": cleared,
                # Non-empty means the fix was refused before it was ever
                # scanned, because it tried to silence the rule. Surfaced so a
                # reviewer sees why rather than an unexplained failed check.
                "suppression_attempt": suppression_attempt or [],
            },
            ":status": "fix-proposed" if self_check_passed else "needs-human-only",
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )
