# SourceCraft native qualification conformance package

Reference source for the runner-owned controller and external verifier required
by D1.1a. It contains no private keys and does not execute macOS native flows.
The production verifier has no caller-selected policy, candidate root, evidence
root, or replay ledger: it reads only the root-owned paths fixed in `policy.py`.
It unconditionally rejects `test_only`. The candidate's Python preflight
remains structural and cannot replace this verifier.

The protected policy has separate `source_revision`, `candidate_sha256` and
`release_tuple_v3_sha256` pins. It also pins the controller, this verifier, the
SourceCraft attestation verifier, reviewed signer, root signer broker and the evidence authority public key. Create
the reproducible installation manifest before copying the reviewed package:

```sh
python3 tools/sourcecraft-native-qualification/installation_manifest.py
```

`controller.py` opens the protected package once, passes that retained
descriptor to both native executor phases as `--package-fd`, and writes the
exact request/preflight/terminal lifecycle receipt before signed evidence is
emitted. The executor must inspect only that inherited descriptor.

`signer.py` is not callable from a qualification cube. The root-owned launchd
broker is the sole production issuer; its unprivileged request client carries
only the fixed `issue` operation and no evidence, key or path. The broker
remeasures the package and package-bound attestation, then atomically writes
the signed envelope with an exact `0400` or `0600` runner-owned seed whose
public key and key id are pinned by policy.

`verifier.py` admits the exact full macOS row and V3 tuple, required selector
set, signing/notarization, isolated DPK profile, direct service admission, and
the fixed `runne/writer-qualification/v1` attestation V2/prelude V1/ACK V1
transcript. Its signature binds the manifest, controller receipt, transcript,
and service admission. It recomputes a bounded exact inventory with descriptor
no-follow loading, requires arm64 Mach-O role measurements and the canary scan
subject, independently runs `codesign`, `spctl`, and provisioning-profile
inspection over the admitted package, then atomically consumes a fixed replay key.

Run test-only vectors without native access. This is a separate harness and is
not the production entrypoint:

```sh
python3 -m unittest tools/sourcecraft-native-qualification/tests/test_conformance.py -v
python3 tools/sourcecraft-native-qualification/vector_harness.py --vector /path/to/test-vector.json
```

The `test_only` policy used by vectors is deliberately rejected by production.
Real controller installation, runner key provisioning, attestation, package
execution and native qualification remain external release gates.
The checked-in macOS parser fixtures are synthetic and redacted; a protected
runner must still capture the live tool outputs before release qualification.
