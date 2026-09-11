"""remediation-agent Lambda (spec §4.1, §4.4 step 5; docs/remediation-agent-spec.md).

For each finding with status "mapped" under a PR, drafts a corrected version
of the offending file via the Anthropic API, computes a unified diff against
the original in code, then proves the fix works by re-invoking
terraform-scanner (persist=false) against the patched content and comparing
(source, rule_id) pairs before/after. self_check_passed is always computed
here, never asserted by the LLM -- that's the project's core integrity
guarantee.

Computing it from the rescan is only sound while the rescan actually happened.
A scanner that crashed, and a file the scanner could not parse, both report
zero findings, which the comparison would read as the finding having been
cleared. So a failed invocation is raised (the finding stays "mapped" for a
retry) and a reported parse error short-circuits to needs-human-only before
any verdict is computed.

Findings are remediated one file at a time, in a stable order, each fix
drafted against the file as the previous accepted fix left it. Every file in
the live table carries between 3 and 22 findings, so drafting each fix from
the pristine snapshot produced N competing whole-file rewrites of the same
few lines -- two of which, on demo-1, created the same resource address with
different arguments. proposed_fix.applies_after records the chain a fix was
built on.

Event shape:
{ "pr_id": "manual-test-1" }
"""

import collections
import difflib
import hashlib
import json
import logging
import os
import re
import typing
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

class _Outcome(typing.NamedTuple):
    """What one finding's remediation produced.

    final_passed is the verdict written to the record; scanner_verified is
    the narrower question of whether the rescan proved this fix cleared its
    finding without introducing new ones. They differ whenever a
    human-review gate (a deleted resource, a declared assumption) overrides
    a clean rescan, and only the second one decides whether this fix becomes
    the base for the next finding in the file -- see handler().
    """
    final_passed: bool
    scanner_verified: bool
    content: str | None
    rescan_counts: "collections.Counter | None"
    # This fix's diff, kept so the next fix in the file can record a hash of
    # it in its own applies_after. Only set when scanner_verified, for the
    # same reason content is: an unverified fix never becomes a base.
    diff: str | None


REMEDIATION_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "corrected_file_content": {"type": "string"},
        "rationale": {"type": "string"},
        # Facts the fix depends on that couldn't be checked against the one
        # file the agent was given, AND whose falsity would break something.
        # Schema-required so the model has to answer rather than quietly fold
        # a guess into fluent prose. A non-empty list forces human review --
        # see _remediate_finding.
        #
        # The breakage test is doing real work in the prompt. Asking merely
        # for "unverifiable facts" made every fix declare four of them,
        # including provider-version notes and "SSE-S3 is transparent to
        # clients", so nothing ever passed and the list became boilerplate to
        # skim past -- which is how the one that matters gets missed.
        "assumptions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["corrected_file_content", "rationale", "assumptions"],
    "additionalProperties": False,
}

# `resource "<type>" "<name>" {` -- enough for counting blocks; this is a
# guard, not an HCL parser.
RESOURCE_BLOCK_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)


def handler(event, context):
    pr_id = event["pr_id"]

    mapped_findings = _query_mapped_findings(pr_id)

    fix_proposed_count = 0
    needs_human_count = 0
    superseded_count = 0
    error_count = 0

    for file_path, findings in _group_by_file(mapped_findings):
        try:
            base_content = _fetch_original_content(pr_id, file_path)
        except Exception:
            # Nothing in this file can be remediated without its content, and
            # the failure is the file's, not any one finding's.
            logger.exception("could not read the snapshot for %s", file_path)
            error_count += len(findings)
            continue

        # The finding set of base_content, which starts as the pristine file
        # and is replaced below by each accepted fix's own rescan. Comparing a
        # later fix against the *original* baseline would let it silently undo
        # an earlier one: a rule an earlier fix cleared is still present in the
        # original counts, so its return would not register as a new finding.
        baseline_counts = _query_baseline_counts(pr_id, file_path)
        applies_after = []
        # (source, rule_id) -> the fix that took it to zero in this run. Rules
        # overlap between and within the two scanners, so one fix routinely
        # clears more than its own finding: on demo-1, CKV_AWS_145 wants KMS
        # and aws-s3-enable-bucket-encryption wants any encryption, so a KMS
        # fix satisfies both.
        cleared_by = {}

        for finding in findings:
            # An earlier fix in this file already removed this rule, so there
            # is nothing left to fix. Remediating anyway is not just wasted:
            # the model is handed a file where the issue is already gone,
            # returns it unchanged, and _evaluate_self_check compares a rescan
            # count of 0 against a baseline of 0 -- `0 < 0` is False, so a
            # finding that is genuinely resolved would be written up as a fix
            # that failed to clear it.
            target = (finding.get("source"), finding.get("rule_id"))
            if target in cleared_by:
                logger.info(
                    "finding %s superseded by %s", finding["finding_id"], cleared_by[target],
                )
                _write_superseded(finding, cleared_by[target])
                superseded_count += 1
                continue

            try:
                outcome = _remediate_finding(
                    pr_id, finding, base_content, baseline_counts, list(applies_after),
                )
            except Exception:
                # One finding's failure shouldn't abandon the rest of the file.
                # Status stays "mapped", so a re-run retries this finding. The
                # chain is not advanced, so the next finding is drafted against
                # the same base as this one was.
                logger.exception("remediation failed for finding %s", finding.get("finding_id"))
                error_count += 1
                continue

            if outcome.final_passed:
                fix_proposed_count += 1
            else:
                needs_human_count += 1

            # scanner_verified, not final_passed: a fix held for human review
            # because it deletes a resource or rests on an assumption is still
            # a coherent edit that cleared its finding, and the next fix should
            # build on it. A fix the scanner rejected -- suppression, unparseable,
            # didn't clear, introduced new findings -- is not, and would poison
            # every fix after it in this file.
            if outcome.scanner_verified:
                # Record what this fix took to zero before the baseline moves,
                # so a later finding on one of those rules can be told which
                # fix resolved it rather than just that it is gone.
                for pair, previous in baseline_counts.items():
                    if previous > 0 and outcome.rescan_counts[pair] == 0:
                        cleared_by[pair] = finding["finding_id"]

                base_content = outcome.content
                baseline_counts = outcome.rescan_counts
                # The hash is what makes staleness detectable at review time:
                # review-api compares it against the prerequisite's *current*
                # diff, so a reviewer editing an earlier fix invalidates every
                # fix drafted on top of it without either side reconstructing
                # file content. See docs/fix-chain-review-spec.md §2.
                applies_after.append({
                    "finding_id": finding["finding_id"],
                    "diff_sha256": _diff_sha256(outcome.diff),
                })

    return {
        "pr_id": pr_id,
        "fix_proposed_count": fix_proposed_count,
        "needs_human_only_count": needs_human_count,
        "superseded_count": superseded_count,
        "error_count": error_count,
    }


def _group_by_file(findings):
    """Findings grouped by file, each group in a stable remediation order.

    The order decides which fix every later fix is drafted against, so it has
    to be deterministic: a re-run that shuffled it would produce a different
    chain, and different diffs, from identical inputs. Sorted by position in
    the file, then by identity to break ties between two rules on one line.
    """
    groups = collections.defaultdict(list)
    for finding in findings:
        groups[finding["file"]].append(finding)
    for file_path in sorted(groups):
        yield file_path, sorted(groups[file_path], key=_remediation_order)


def _remediation_order(finding):
    line_range = finding.get("line_range") or []
    start = line_range[0] if line_range else None
    # Both halves of line_range can be null (a rule that names a file rather
    # than a line), and DynamoDB hands the numbers back as Decimal.
    return (
        int(start) if start is not None else 0,
        finding.get("source", ""),
        finding.get("rule_id", ""),
        finding["finding_id"],
    )


def _remediate_finding(pr_id, finding, base_content, baseline_counts, applies_after):
    finding_id = finding["finding_id"]
    file_path = finding["file"]

    # base_content is the file as the previous accepted fix in this file left
    # it, not the pristine snapshot, so the model is shown what it is actually
    # editing and the diff is minimal against that.
    remediation = _call_remediation_agent(finding, base_content)
    corrected_content = remediation["corrected_file_content"]
    rationale = remediation["rationale"]
    assumptions = remediation.get("assumptions") or []

    diff_text = _compute_diff(base_content, corrected_content, file_path)

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
            suppression_attempt=suppressions, applies_after=applies_after,
        )
        return _Outcome(False, False, None, None, None)

    _upload_scratch_file(pr_id, finding_id, file_path, corrected_content)
    rescan_findings, scan_errors = _invoke_self_check(pr_id, finding_id)

    # The scanner could not parse what the agent wrote. An unparseable file
    # yields no findings, and _evaluate_self_check reads no findings as "the
    # rule stopped firing" -- so a fix that breaks the syntax outright would
    # otherwise come back self_check_passed=True, exactly the false pass the
    # suppression gate above exists to prevent. Nothing was proven here, so
    # there is no verdict to compute: return before evaluating.
    if scan_errors:
        logger.warning(
            "remediation for finding %s did not parse: %s", finding_id, scan_errors,
        )
        _write_result(
            finding, diff_text, rationale,
            self_check_passed=False, self_check_new_findings=[], cleared=False,
            assumptions=assumptions, scan_errors=scan_errors,
            applies_after=applies_after,
        )
        return _Outcome(False, False, None, None, None)

    self_check_passed, self_check_new_findings, cleared = _evaluate_self_check(
        finding, rescan_findings, baseline_counts
    )
    # Kept so an accepted fix can hand its own finding set to the next fix in
    # this file as that fix's baseline.
    rescan_counts = collections.Counter(
        (f["source"], f["rule_id"]) for f in rescan_findings
    )
    scanner_verified = self_check_passed

    # A clean rescan proves the finding is gone. It says nothing about whether
    # the infrastructure still works, and these two cases are exactly where
    # that gap bites: a deleted resource always scans clean, and a fix resting
    # on an unverifiable claim scans clean whether or not the claim is true.
    # Both stay proposals a human has to weigh, so the verdict is overridden
    # even when the scanner is satisfied. Scanned first regardless -- the
    # rescan result is still worth showing the reviewer.
    dropped_resources = _find_dropped_resources(base_content, corrected_content)
    if dropped_resources or assumptions:
        logger.info(
            "finding %s held for human review (dropped=%s, assumptions=%s)",
            finding_id, dropped_resources, assumptions,
        )
        self_check_passed = False

    _write_result(
        finding, diff_text, rationale, self_check_passed, self_check_new_findings, cleared,
        dropped_resources=dropped_resources, assumptions=assumptions,
        applies_after=applies_after,
    )
    return _Outcome(
        self_check_passed,
        scanner_verified,
        corrected_content if scanner_verified else None,
        rescan_counts if scanner_verified else None,
        diff_text if scanner_verified else None,
    )


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
        "finding is not a fix and will be rejected.\n\n"
        "Prefer constraining a resource over removing it. Deleting a rule or "
        "resource always satisfies the scanner, but may remove something the "
        "running system depends on. Only delete when the resource is "
        "genuinely unnecessary, and say so explicitly in the rationale.\n\n"
        "You are shown ONE file. You cannot see the rest of the repository, "
        "the running infrastructure, or how any of this is used. Never present "
        "a guess about any of that as established fact in the rationale.\n\n"
        "In `assumptions`, list ONLY claims that meet BOTH tests:\n"
        "  (a) you could not verify it from the file above, AND\n"
        "  (b) if it turned out to be false, applying this fix would break "
        "the running system or leave the finding unfixed.\n"
        "Examples that qualify: that a port being closed won't break "
        "certificate issuance or health checks; that no other system depends "
        "on a rule you narrowed; that traffic reaches the service by some "
        "other path.\n"
        "Do NOT list: provider or module version expectations, naming and "
        "style choices, alternative approaches the reader might prefer, "
        "generic best-practice caveats, or restatements of what the fix does. "
        "Those belong in the rationale if they are worth saying at all.\n"
        "An empty list is the correct and expected answer for a "
        "self-contained fix. Every entry costs a human's attention, so a list "
        "padded with things that cannot actually break anything is worse than "
        "no list at all -- it buries the one that matters."
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


def _find_dropped_resources(original_content, corrected_content):
    """Resources the fix deletes outright, rather than tightening in place.

    Deleting a resource always satisfies the self-check -- the finding is gone
    because the thing that raised it is gone -- so the scanner cannot tell
    "narrowed the CIDR" from "removed the rule". Those are different risk
    classes, and only one of them can take a service down.

    Observed on real code: asked to fix an open port 80 ingress rule, the
    agent deleted it and asserted that certificate issuance used DNS-01. The
    repo's cert-manager ClusterIssuer uses HTTP-01, which needs port 80
    reachable, so applying it would have broken TLS renewal ~60 days later.
    The self-check passed it cleanly.

    Compared per resource *type*, not per address, so renaming a resource
    (a delete plus an add, as in a legitimate
    nodeport_from_internet -> nodeport_from_admin rescope) isn't mistaken for
    a deletion. Returns "<type>.<name>" for the addresses that vanished, so a
    reviewer sees which ones, but only reports when the type's count actually
    falls.
    """
    before = RESOURCE_BLOCK_RE.findall(original_content)
    after = RESOURCE_BLOCK_RE.findall(corrected_content)

    before_types = collections.Counter(t for t, _ in before)
    after_types = collections.Counter(t for t, _ in after)
    if not any(after_types[t] < n for t, n in before_types.items()):
        return []

    vanished = set(before) - set(after)
    shrunk = {t for t, n in before_types.items() if after_types[t] < n}
    return sorted(f"{t}.{n}" for t, n in vanished if t in shrunk)


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
        # Covers terraform-scanner's ScannerError -- a tool that crashed or
        # timed out rather than one that scanned clean. Raising leaves the
        # finding at status "mapped" so a re-run retries it, which is the right
        # outcome: nothing was learned about this fix either way.
        raise RuntimeError(f"terraform-scanner self-check invocation failed: {result}")
    # scan_errors is absent from responses produced before the scanner reported
    # it; treated as "none known" rather than defaulting the check to failed.
    return result["findings"], result.get("scan_errors") or []


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


def _write_superseded(finding, superseded_by):
    """Record that another fix in this file already cleared this finding.

    No proposed_fix is written, because none was drafted -- there was nothing
    left to draft against. That also makes review-api refuse an approve or
    edit on this finding (it 409s when proposed_fix is absent), which is the
    right refusal: the decision to make is on the superseding fix, not here.

    Not "resolved": that status means a human accepted something. This is the
    scanner reporting the rule no longer fires, and it holds only for as long
    as the superseding fix does -- if that fix is rejected, this finding comes
    back. superseded_by is stored so that reversal can find it.
    """
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"pk": finding["pk"], "sk": finding["sk"]},
        UpdateExpression=(
            "SET #status = :status, superseded_by = :by, updated_at = :now"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": "superseded",
            ":by": superseded_by,
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )


def _diff_sha256(diff_text):
    """Hash of a fix's diff, recorded by every fix drafted on top of it.

    Hashing the diff rather than the resulting file content is deliberate: the
    alternative would make review-api reconstruct the base by applying the
    approved chain, i.e. implement diff application inside a Lambda. Because
    applies_after carries the cumulative chain rather than just the immediate
    predecessor, matching every recorded hash is enough to prove the composed
    base is bit-identical -- each fix's output is fixed by its own base and
    diff, and the first base is the scan snapshot, which is written once per
    run into a versioned bucket. See docs/fix-chain-review-spec.md §3.
    """
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def _write_result(
    finding, diff_text, rationale, self_check_passed, self_check_new_findings, cleared,
    suppression_attempt=None, dropped_resources=None, assumptions=None, scan_errors=None,
    applies_after=None,
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
                # Resources the fix deletes outright, and facts it depends on
                # but couldn't verify. Either one forces human review no
                # matter how clean the rescan came back.
                "dropped_resources": dropped_resources or [],
                "assumptions": assumptions or [],
                # The fixes, in order, that this one is drafted on top of --
                # empty means it applies to the pristine file. Every file in
                # this project carries several findings, so most fixes are not
                # independent: applying this diff without these first will not
                # apply cleanly, and approving it without them lands a fix
                # whose context never existed. Each entry is
                # {finding_id, diff_sha256}; the hash is what lets review-api
                # tell "prerequisite was edited" from "prerequisite is intact".
                "applies_after": applies_after or [],
                # Files the scanner couldn't parse. Non-empty means the fix was
                # never actually verified -- distinct from a fix that was
                # verified and failed, which is what a reviewer would otherwise
                # assume from self_check_passed=False.
                "scan_errors": scan_errors or [],
            },
            ":status": "fix-proposed" if self_check_passed else "needs-human-only",
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )
