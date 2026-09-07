# Builder golden fixtures

`golden-manifest.json` — canonical (RFC 8785) bytes produced by
`build_candidate_manifest` for the deterministic zero-tensor GGUF
fixture (architecture `llama`, context 4096, tokenizer `bpe`,
embedded template `{{ .Prompt }}`) with:

```
model-id      test-model
model-revision r1
license       Apache-2.0
source-uri    https://example.test/model
publisher     tester
acquired-at   2026-09-05T00:00:00Z
builder       0.1.0
```

`golden-manifest.json.sha256` — sha256 of the file (with trailing
newline, as the CLI prints it).

Any byte drift in `tests/builder_golden.rs` means the builder's
derived-contract changed. That is allowed only together with an
explicit regeneration of BOTH files in the same commit plus a ledger
entry naming the rule that changed.

Regeneration:

```bash
./target/debug/build-manifest /path/to/fixture.gguf --model-id test-model \
  --model-revision r1 --license Apache-2.0 --source-uri https://example.test/model \
  --publisher tester --acquired-at 2026-09-05T00:00:00Z \
  > docs/golden/local-engine/builder/golden-manifest.json
shasum -a 256 docs/golden/local-engine/builder/golden-manifest.json \
  | cut -d' ' -f1 > docs/golden/local-engine/builder/golden-manifest.json.sha256
```
