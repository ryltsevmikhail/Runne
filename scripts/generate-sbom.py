#!/usr/bin/env python3
"""Generate a minimal SPDX-2.3 SBOM for the Rust workspace.

This is a Phase 10 structural artifact: it records exact package identities and
crates-io origins for reproducible builds. It does not perform signing,
notarization or release authorization.
"""

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def cargo_metadata(manifest_path: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--manifest-path", str(manifest_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def crates_io_url(name: str, version: str) -> str:
    return f"https://crates.io/crates/{name}/{version}"


def generate_spdx(workspace_root: Path) -> dict:
    metadata = cargo_metadata(workspace_root / "Cargo.toml")
    packages = metadata.get("packages", [])

    spdx_version = "SPDX-2.3"
    spdx_id = "SPDXRef-DOCUMENT"
    doc_name = "gocode-workspace-sbom"
    doc_namespace = f"https://gocode.dev/sbom/{doc_name}-{datetime.now(timezone.utc).isoformat()}"

    creators = ["Tool: gocode-generate-sbom-0.1.0"]

    sbom = {
        "spdxVersion": spdx_version,
        "dataLicense": "CC0-1.0",
        "SPDXID": spdx_id,
        "name": doc_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": creators,
        },
        "packages": [],
        "relationships": [],
    }

    sbom["packages"].append({
        "SPDXID": "SPDXRef-Workspace-Root",
        "name": "gocode-workspace",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "verificationCode": None,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
    })
    sbom["relationships"].append({
        "spdxElementId": spdx_id,
        "relatedSpdxElement": "SPDXRef-Workspace-Root",
        "relationshipType": "DESCRIBES",
    })

    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]
        pkg_spdx_id = f"SPDXRef-Package-{name}-{version}"
        source = pkg.get("source", "")
        if source:
            if "registry+" in source:
                download = crates_io_url(name, version)
            elif "git+" in source:
                download = source.replace("git+", "", 1)
            else:
                download = source
        else:
            download = "NOASSERTION"

        verification = None
        if pkg.get("checksum"):
            verification = hashlib.sha256(pkg["checksum"].encode()).hexdigest()

        sbom["packages"].append({
            "SPDXID": pkg_spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": download,
            "filesAnalyzed": False,
            "verificationCode": verification,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION" if not source else crates_io_url(name, version),
        })
        sbom["relationships"].append({
            "spdxElementId": "SPDXRef-Workspace-Root",
            "relatedSpdxElement": pkg_spdx_id,
            "relationshipType": "CONTAINS",
        })

    return sbom


def main() -> int:
    workspace_root = Path(__file__).resolve().parent.parent
    sbom = generate_spdx(workspace_root)
    output_path = workspace_root / "target" / "gocode-workspace-sbom.spdx.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False))
    print(f"SBOM written to {output_path}")
    print(f"Packages recorded: {len(sbom['packages']) - 1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
