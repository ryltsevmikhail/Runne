# Runne Local Engine

First-party local inference components for Runne, using GGUF model files and an optional llama-cpp-2 CPU backend. This directory is a separate Cargo workspace with its own lockfile; no sibling repository is required.

## Components

- `runne-local-model`: model manifests, bounded GGUF parsing, and manifest-builder CLI.
- `runne-model-store`: content-addressed storage and upload handling.
- `runne-inference-protocol`: authenticated host/worker transport.
- `runne-engine-broker`: artifact access grants and file-descriptor transfer.
- `runne-inference-host`: supervised inference lifecycle.
- `runne-llama-worker`: optional native llama.cpp backend.
- `runne-provider-local`: provider adapter and cancellation/recovery handling.
- `runne-engine-platform`: process and resource boundaries.

## Development

From this directory, with the root repository's pinned Rust toolchain:

```bash
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Root workspace checks do not run these tests. Default-feature tests do not certify native inference or model/device compatibility. The public qualification matrix contains only a synthetic structural fixture; it does not qualify any real model or device.

To exercise the optional CPU backend, supply your own appropriately licensed GGUF model and native build prerequisites:

```bash
RUNNE_LLAMA_TEST_GGUF=/absolute/path/to/model.gguf \
  cargo test -p runne-llama-worker --features backend-llama-cpp --test llama_cpu --locked
```

Do not commit model weights. Models and native dependencies retain their own licenses. See the root [README](../README.md), [contribution guide](../CONTRIBUTING.md), and [Apache-2.0 license](../LICENSE).
