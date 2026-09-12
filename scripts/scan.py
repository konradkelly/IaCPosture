#!/usr/bin/env python3
"""Run the v1 pipeline against a directory of Terraform, end to end.

Spec §8 v1 calls for a "manual trigger (CLI or simple upload)". Until now
that meant `aws s3 cp`, three separate `aws lambda invoke`s, and reading the
result JSON by hand. This is the one command.

  python scripts/scan.py path/to/terraform
  python scripts/scan.py path/to/terraform --pr-id my-run-1
  python scripts/scan.py path/to/terraform --stages scan,map     # stop before remediation
  python scripts/scan.py path/to/terraform --yes                 # skip the cost prompt

Stages, each a synchronous Lambda invoke, each printed as it completes:

  upload     every .tf, .tf.json, .tfvars and .tfvars.json under the
             directory -> s3://<bucket>/scans/<pr_id>/  (.tfvars is where
             hardcoded secrets actually live, and where variables resolve)
  scan       terraform-scanner, persist=true -> raw findings in DynamoDB
  map        mapping-agent -> control citations, status "mapped"
  remediate  remediation-agent -> one model call per mapped finding, plus a
             self-check scan per fix. This is the stage that costs money and
             minutes, so it asks first unless --yes.

Re-running with the same --pr-id overwrites findings that still fire (ids are
content hashes) and leaves any that no longer fire as they were. For a clean
slate use a new id. Needs AWS credentials for the dev account and `terraform`
on PATH (only to read names from `terraform output`; pass them explicitly to
skip it).

Deliberately synchronous. §4.4 wants the stages chained by SQS/streams; that is
§8.2 item 5 and this script does not pre-empt it. It just makes the pipeline
runnable from one place, which the eval plan (§7.2, remediation safety) also
needs.
"""

import argparse
import json
import pathlib
import subprocess
import sys
import time

import boto3
from botocore.config import Config

REPO = pathlib.Path(__file__).resolve().parents[1]

# Must match terraform-scanner's SNAPSHOT_SUFFIXES: the scanner only downloads
# what it recognises, so anything uploaded outside this set is ignored.
SNAPSHOT_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json")

# remediation-agent may run for its full 900s. The read timeout has to
# outlast it, and retries have to be OFF: a retried RequestResponse invoke of
# a Lambda that is still running would start a second copy of the same
# remediation, doubling the model calls and racing the first on every write.
LAMBDA_CONFIG = Config(read_timeout=920, connect_timeout=10, retries={"max_attempts": 0})


def tf_output(name):
    out = subprocess.run(
        ["terraform", "output", "-raw", name],
        cwd=REPO / "terraform", capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def collect_tf_files(root):
    files = sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.name.endswith(SNAPSHOT_SUFFIXES) and ".terraform" not in p.parts
    )
    if not files:
        sys.exit(f"no Terraform files under {root}")
    return files


def upload(s3, bucket, pr_id, root, files):
    prefix = f"scans/{pr_id}/"
    for path in files:
        key = prefix + path.relative_to(root).as_posix()
        s3.put_object(Bucket=bucket, Key=key, Body=path.read_bytes())
    return prefix


def invoke(lam, function, payload, label):
    print(f"{label:10s} {function} ...", end="", flush=True)
    t0 = time.time()
    resp = lam.invoke(
        FunctionName=function, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    elapsed = time.time() - t0
    if "FunctionError" in resp:
        print(f" FAILED after {elapsed:.0f}s")
        sys.exit(f"{function}: {body.get('errorType')}: {body.get('errorMessage')}")
    print(f" {elapsed:.0f}s")
    return body


def confirm(prompt):
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", type=pathlib.Path, help="Terraform root to scan (recursively)")
    ap.add_argument("--pr-id", help="default: manual-<dirname>-<timestamp>")
    ap.add_argument("--stages", default="scan,map,remediate",
                    help="comma-separated subset of scan,map,remediate, in order (default: all)")
    ap.add_argument("--yes", action="store_true", help="don't ask before the remediation stage")
    ap.add_argument("--bucket", help="artifacts bucket (default: terraform output)")
    ap.add_argument("--scanner", help="terraform-scanner function name (default: terraform output)")
    ap.add_argument("--mapper", help="mapping-agent function name (default: terraform output)")
    ap.add_argument("--remediator", help="remediation-agent function name (default: terraform output)")
    args = ap.parse_args()

    root = args.directory.resolve()
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")
    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    unknown = set(stages) - {"scan", "map", "remediate"}
    if unknown:
        sys.exit(f"unknown stage(s): {sorted(unknown)}")

    pr_id = args.pr_id or f"manual-{root.name}-{time.strftime('%Y%m%dT%H%M%S')}"
    bucket = args.bucket or tf_output("artifacts_bucket_name")
    scanner = args.scanner or tf_output("terraform_scanner_function_name")
    mapper = args.mapper or tf_output("mapping_agent_function_name")
    remediator = args.remediator or tf_output("remediation_agent_function_name")

    s3 = boto3.client("s3")
    lam = boto3.client("lambda", config=LAMBDA_CONFIG)

    files = collect_tf_files(root)
    print(f"pr_id      {pr_id}")
    prefix = upload(s3, bucket, pr_id, root, files)
    print(f"upload     {len(files)} file(s) -> s3://{bucket}/{prefix}")

    if "scan" in stages:
        body = invoke(lam, scanner, {
            "pr_id": pr_id, "s3_prefix": prefix, "iac_type": "terraform", "persist": True,
        }, "scan")
        print(f"           {body['finding_count']} finding(s)", end="")
        if body.get("scan_errors"):
            print(f", could not parse: {body['scan_errors']}", end="")
        print()

    if "map" in stages:
        body = invoke(lam, mapper, {"pr_id": pr_id}, "map")
        print(f"           {body['mapped_count']} mapped, {body['skipped_count']} with no candidate control")

    if "remediate" in stages:
        what = (f"{body['mapped_count']} mapped finding(s)" if "map" in stages
                else "every mapped finding on this PR")
        if not args.yes and not confirm(
            f"           remediate {what}? One model call and one self-check scan each."
        ):
            print("           skipped")
        else:
            body = invoke(lam, remediator, {"pr_id": pr_id}, "remediate")
            print(f"           {body['fix_proposed_count']} fix-proposed, "
                  f"{body['needs_human_only_count']} needs-human-only, "
                  f"{body['superseded_count']} superseded, "
                  f"{body['error_count']} error(s)")

    try:
        url = tf_output("dashboard_url")
        print(f"\nreview     {url}/prs/{pr_id}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


if __name__ == "__main__":
    main()
