# Evidence — entry-llama-q4-fixture

Qualification evidence record for matrix entry `entry-llama-q4-fixture`
(matrix revision `2026-09-05-r1`).

| Field | Value |
|---|---|
| artifact_digest | `sha256:a3d27b1a556d63979122c0aa64b44c9f9d69701323b3fa4333839bcd399ee61e` |
| byte_length | 204 |
| artifact | the deterministic zero-tensor GGUF builder fixture (see `docs/golden/local-engine/builder/README.md`); NOT a real model |
| backend_profile | `llama-cpp-cpu-macos-arm64-v1` |
| interpretation_revisions | reasoning_parser `inline-markers-v1`, tokenizer `1` |
| status | STRUCTURAL FIXTURE — proves the matrix/verifier/binding plumbing |

This entry exists so the matrix verifier and the store binding have a
fully checkable committed example. A REAL model entry requires, before
its evidence_ref is filled in (see `llama_cpu` fixture gate):

- a run of `cargo test -p runne-llama-worker --features
  backend-llama-cpp --test llama_cpu` against the exact artifact
  (digest + length recorded above) with the CPU profile
  (`gpu_layers = 0`, seeded sampling, two identical runs);
- recorded provenance (source URI, publisher, acquisition date) and
  license (SPDX id);
- an interpretation-revision pin for every parser the model output
  passes through.

Empty or missing evidence blocks capability claims (verifier rejects).
