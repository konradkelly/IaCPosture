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

    for finding in mapped_findings:
        self_check_passed = _remediate_finding(pr_id, finding)
        if self_check_passed:
            fix_proposed_count += 1
        else:
            needs_human_count += 1

    return {
        "pr_id": pr_id,
        "fix_proposed_count": fix_proposed_count,
        "needs_human_only_count": needs_human_count,
    }


def _remediate_finding(pr_id, finding):
    finding_id = finding["finding_id"]
    file_path = finding["file"]

    original_content = _fetch_original_content(pr_id, file_path)
    remediation = _call_remediation_agent(finding, original_content)
    corrected_content = remediation["corrected_file_content"]
    rationale = remediation["rationale"]

    diff_text = _compute_diff(original_content, corrected_content, file_path)

    _upload_scratch_file(pr_id, finding_id, file_path, corrected_content)
    rescan_findings = _invoke_self_check(pr_id, finding_id)

    baseline_pairs = _query_baseline_pairs(pr_id, file_path)
    self_check_passed, self_check_new_findings = _evaluate_self_check(
        finding, rescan_findings, baseline_pairs
    )

    _write_result(finding, diff_text, rationale, self_check_passed, self_check_new_findings)
    return self_check_passed


def _query_mapped_findings(pr_id):
    table = dynamodb.Table(DYNAMODB_TABLE)
    response = table.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression="#status = :status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":pk": f"PR#{pr_id}",
            ":sk_prefix": "FINDING#",
            ":status": "mapped",
        },
    )
    return response.get("Items", [])


def _query_baseline_pairs(pr_id, file_path):
    """(source, rule_id) pairs from every finding this PR has on file_path,
    regardless of status -- the "no new findings" check in step 7 needs the
    baseline scan's full finding set for the file, not just zero."""
    table = dynamodb.Table(DYNAMODB_TABLE)
    response = table.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
        FilterExpression="#file = :file",
        ExpressionAttributeNames={"#file": "file"},
        ExpressionAttributeValues={
            ":pk": f"PR#{pr_id}",
            ":sk_prefix": "FINDING#",
            ":file": file_path,
        },
    )
    return {(item["source"], item["rule_id"]) for item in response.get("Items", [])}


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
        "diff or a snippet. Also return a short rationale for the fix."
    )

    response = _get_anthropic_client().messages.create(
        model=MODEL,
        max_tokens=8192,
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


def _compute_diff(original_content, corrected_content, file_path):
    diff_lines = difflib.unified_diff(
        original_content.splitlines(keepends=True),
        corrected_content.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff_lines)


def _upload_scratch_file(pr_id, finding_id, file_path, content):
    key = f"scans/{pr_id}/self-check-{finding_id}/{file_path}"
    s3.put_object(Bucket=ARTIFACTS_BUCKET, Key=key, Body=content.encode("utf-8"))
    return key


def _invoke_self_check(pr_id, finding_id):
    payload = {
        "pr_id": f"{pr_id}-self-check-{finding_id}",
        "s3_prefix": f"scans/{pr_id}/self-check-{finding_id}/",
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


def _evaluate_self_check(finding, rescan_findings, baseline_pairs):
    target_pair = (finding["source"], finding["rule_id"])
    rescan_pairs = {(f["source"], f["rule_id"]) for f in rescan_findings}

    cleared = target_pair not in rescan_pairs
    new_pairs = rescan_pairs - baseline_pairs
    no_new_findings = not new_pairs

    self_check_passed = cleared and no_new_findings
    self_check_new_findings = sorted(f"{source}:{rule_id}" for source, rule_id in new_pairs)
    return self_check_passed, self_check_new_findings


def _write_result(finding, diff_text, rationale, self_check_passed, self_check_new_findings):
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
            },
            ":status": "fix-proposed" if self_check_passed else "needs-human-only",
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )
