#!/usr/bin/env python3
"""Write the deterministic CycloneDX application descriptor."""

import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "bomFormat": "CycloneDX",
    "components": [{"name": "runne-daemon", "type": "application", "version": sys.argv[2]}],
    "specVersion": "1.5",
}
path.write_bytes(
    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
