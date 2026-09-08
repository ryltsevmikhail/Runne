#!/usr/bin/python3 -I
"""Non-authoritative runner for checked-in conformance vectors only."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codec import Rejected, canonical, load_json
from verifier import verify_test_vector


def evaluate(vector: object) -> dict[str, object]:
    if not isinstance(vector, dict) or set(vector) != {"policy","files","package","attestation","now"}:
        raise Rejected("test vector shape is invalid")
    files = vector["files"]
    package = vector["package"]
    if not isinstance(files, dict) or not isinstance(package, dict): raise Rejected("test vector files are invalid")
    try: now = datetime.strptime(vector["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError): raise Rejected("test vector time is invalid") from None
    with tempfile.TemporaryDirectory() as directory:
        root = (Path(directory) / "evidence").resolve(); root.mkdir(); package_root = (Path(directory) / "package").resolve(); package_root.mkdir()
        for name, value in files.items():
            if not isinstance(name, str) or "/" in name: raise Rejected("test vector file name is invalid")
            (root / name).write_bytes(canonical(value) if not isinstance(value, str) else value.encode("ascii"))
        for name, value in package.items():
            target = package_root / name; target.parent.mkdir(parents=True, exist_ok=True)
            if not isinstance(value, dict) or set(value) != {"base64"} or not isinstance(value["base64"], str):
                raise Rejected("test package bytes are invalid")
            try: target.write_bytes(base64.b64decode(value["base64"], validate=True))
            except ValueError: raise Rejected("test package bytes are invalid") from None
        policy = dict(vector["policy"]); policy["package_root"] = str(package_root)
        if policy.get("test_only"):
            policy.setdefault("evidence_signer", {"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-sign-evidence","sha256":hashlib.sha256(b"test signer").hexdigest()})
            policy.setdefault("signer_broker", {"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-signer-broker","sha256":hashlib.sha256(b"test broker").hexdigest()})
            from policy import MODULES
            policy.setdefault("authority_modules", {name:{"path":f"/test/{name}","sha256":hashlib.sha256(name.encode()).hexdigest()} for name in MODULES})
        return verify_test_vector(policy, root, now, Path("/test/verifier"), vector["attestation"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector", type=Path, required=True)
    args = parser.parse_args(argv)
    try: verdict = evaluate(load_json(args.vector.resolve()))
    except Rejected: verdict = {"qualified":False,"reason":"test_vector_rejected"}
    print(json.dumps(verdict, sort_keys=True, separators=(",", ":")))
    return 0 if verdict["qualified"] else 1


if __name__ == "__main__": raise SystemExit(main())
