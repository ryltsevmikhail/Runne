# Golden fixtures — local engine backend

## GGUF qualification fixture (Task 9, `llama_cpu`)

The CPU qualification test needs a small, licensed GGUF model. It is
**not committed** to the repository and is **never downloaded by a
test**. Point the environment at a local file:

```bash
export RUNNE_LLAMA_TEST_GGUF=/path/to/tiny-licensed-model.gguf
cargo test -p runne-llama-worker --features backend-llama-cpp --test llama_cpu
```

Record for every fixture used in a qualification run (fill this table
in your local qualification evidence, not in the repo):

| Field | Meaning |
|---|---|
| `artifact_digest` | `sha256:<hex>` of the exact GGUF bytes |
| `byte_length` | exact file size |
| provenance | source URI and acquisition date |
| license | SPDX id of the model license |

Constraints asserted by the test itself:

- the file starts with the `GGUF` magic;
- digest and length are verified by the engine **before** native load;
- the CPU profile pins `gpu_layers = 0` (no Metal offload);
- the same seed (`42`) and thread count must reproduce identical
  output bytes across two runs.

Without the environment variable the tests print a skip notice and
pass — the fake-engine conformance suite remains mandatory and always
runs (`tests/crash_oom.rs`, host `tests/worker_backend.rs`).
