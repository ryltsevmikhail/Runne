# gguf-malformed — malformed GGUF corpus

Frozen corpus generator: `crates/runne-local-model/tests/gguf_malformed.rs`
(the vectors are built programmatically there; this directory documents the
corpus and its rejection contract).

Vectors: bad magic; unsupported revision; kv/tensor count bombs; duplicate
metadata key; unsupported metadata value type; oversized declared string;
truncated tensor data; trailing structural inconsistency; duplicate tensor
name; overlapping tensor range; unsupported tensor type; non-power-of-two
alignment.

Contract: every vector is rejected with a typed error; no input may panic,
allocate from an untrusted declared count, spawn a process or invoke
llama.cpp. Limits: `crates/runne-local-model/src/gguf_limits.rs`.
