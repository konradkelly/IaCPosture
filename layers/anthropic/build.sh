#!/usr/bin/env bash
# Builds the anthropic (Python SDK) Lambda layer inside the real Lambda
# Python base image, so pydantic-core's compiled wheel matches the runtime.
# Shared by mapping-agent now, remediation-agent later (spec §4.3 pattern:
# build a dependency layer once, reuse across the agents that need it).
#
# Usage: ./build.sh
# Output: ./python/, ./anthropic-layer.zip

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
  -c "pip install --no-cache-dir anthropic -t /build/python"

find python -type d -name "__pycache__" -prune -exec rm -rf {} \;
find python -type d -name "tests" -prune -exec rm -rf {} \;

python3 -c "
import zipfile, os
out = 'anthropic-layer.zip'
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk('python'):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, '.')
            zf.write(full, rel.replace(os.sep, '/'), zipfile.ZIP_DEFLATED)
"

echo "Built anthropic-layer.zip ($(du -h anthropic-layer.zip | cut -f1))"
