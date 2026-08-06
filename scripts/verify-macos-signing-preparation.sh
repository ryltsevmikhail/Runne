#!/usr/bin/env bash
set -euo pipefail
repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
python3 -m unittest scripts.tests.test_macos_signing_preparation -v
python3 scripts/check-source-file-length.py --max-lines 300
