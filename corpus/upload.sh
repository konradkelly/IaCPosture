#!/usr/bin/env bash
# Syncs the control corpus to S3 under corpus/, mirroring the bucket layout
# mapping-agent expects (spec §4.4 step 4). Also covered by the artifacts
# bucket's built-in versioning (spec §4.2), so re-running this after an edit
# keeps prior versions recoverable without any extra tooling here.
#
# Usage: ./upload.sh [bucket-name]
# If bucket-name is omitted, reads it from `terraform output -raw artifacts_bucket_name`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUCKET="${1:-}"
if [ -z "$BUCKET" ]; then
  BUCKET="$(cd "${SCRIPT_DIR}/../terraform" && terraform output -raw artifacts_bucket_name)"
fi

aws s3 sync "${SCRIPT_DIR}/frameworks" "s3://${BUCKET}/corpus/frameworks" --delete
aws s3 cp "${SCRIPT_DIR}/rule_mappings.json" "s3://${BUCKET}/corpus/rule_mappings.json"

echo "Synced corpus to s3://${BUCKET}/corpus/"
