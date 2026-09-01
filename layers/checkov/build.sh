#!/usr/bin/env bash
# Builds the Checkov Lambda layer inside the real Lambda Python base image, so
# its compiled dependencies match the actual runtime. Strips numpy and
# boto3/botocore/s3transfer after install -- neither is needed for Terraform
# scanning (verified empirically), and Lambda's Python runtime already bundles
# a newer boto3 than pip resolves here. This cuts the layer from ~244MB to
# ~98MB, keeping the combined layer footprint (with tfsec) well under Lambda's
# 250MB unzipped function+layers ceiling.
#
# Usage: ./build.sh
# Output: ./python/, ./checkov-layer.zip

set -euo pipefail

PYTHON_LAMBDA_IMAGE="public.ecr.aws/lambda/python:3.12"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf python
mkdir -p python

HOST_DIR="$(pwd -W 2>/dev/null || pwd)"

docker run --rm --entrypoint //bin/sh \
  -v "${HOST_DIR}:/build" \
  "$PYTHON_LAMBDA_IMAGE" \
  -c "pip install --no-cache-dir checkov -t /build/python"

# Not needed for Terraform-only scanning; Lambda's runtime already bundles boto3.
rm -rf python/numpy python/numpy.libs python/numpy-*.dist-info \
       python/botocore python/botocore-*.dist-info \
       python/boto3 python/boto3-*.dist-info \
       python/s3transfer python/s3transfer-*.dist-info

find python -type d -name "__pycache__" -prune -exec rm -rf {} \;
find python -type d -name "tests" -prune -exec rm -rf {} \;

python3 -c "
import zipfile, os
out = 'checkov-layer.zip'
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk('python'):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, '.')
            zf.write(full, rel.replace(os.sep, '/'), zipfile.ZIP_DEFLATED)
"

echo "Built checkov-layer.zip ($(du -h checkov-layer.zip | cut -f1))"
