# runne-release-authority

Pure, fail-closed promotion-domain engine. Production mutation is intentionally
unprovisioned; `fixture-only` exposes the in-memory transactional store for tests.

The paired closed wire schemas are under `docs/schemas/`; this crate does not
depend on project-owner authority, runtime, store, or CLI crates.

Fixture admission verifies raw canonical SHA-256 links only. Its two aggregate
commitments are domain-separated: `gocode.release.candidate-binding/1\0` plus
canonical binding JSON, and `gocode.release.record-set/1\0` plus the ordered
`[linux,windows]` raw-record digest array. Production admission remains absent.
