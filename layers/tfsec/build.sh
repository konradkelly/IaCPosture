#!/usr/bin/env bash
# Builds the tfsec Lambda layer: downloads the pinned linux-amd64 release
# binary, verifies its checksum, and lays it out under bin/ (Lambda adds
# /opt/bin to PATH automatically for layers with that structure).
#
# Usage: ./build.sh
# Output: ./bin/tfsec, ./tfsec-layer.zip

set -euo pipefail

TFSEC_VERSION="v1.28.14"
TFSEC_SHA256="a32d0799bbefababaa4fcd814da9f4d251cd932789590b99d1d5fcb89ace6f68"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf bin
mkdir -p bin

curl -sL -o bin/tfsec \
  "https://github.com/aquasecurity/tfsec/releases/download/${TFSEC_VERSION}/tfsec-linux-amd64"

echo "${TFSEC_SHA256}  bin/tfsec" | sha256sum -c -
chmod +x bin/tfsec

python3 -c "
import zipfile, os
out = 'tfsec-layer.zip'
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk('bin'):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, '.')
            zi = zipfile.ZipInfo(rel.replace(os.sep, '/'))
            zi.external_attr = 0o100755 << 16
            with open(full, 'rb') as fh:
                zf.writestr(zi, fh.read(), zipfile.ZIP_DEFLATED)
"

echo "Built tfsec-layer.zip ($(du -h tfsec-layer.zip | cut -f1))"
