# Contributing to Runne

Thank you for helping improve Runne. Small, focused fixes, tests, documentation improvements, and reproducible bug reports are welcome. Please follow our [Code of conduct](CODE_OF_CONDUCT.md).

## Before you start

Read the [README](README.md) for setup and platform limitations and [AGENTS.md](AGENTS.md) for architectural boundaries. Search existing issues before opening one. For a substantial API, dependency, or architectural change, discuss the problem in an issue before implementing it. Report security concerns [privately](SECURITY.md), never through public issues or pull requests.

## Development workflow

1. Fork and clone the repository, then create a focused branch.
2. Install the prerequisites and run `pnpm install --frozen-lockfile`.
3. Make the smallest coherent change; add regression tests for behavior changes.
4. Run checks for the affected components and record the commands and results in your pull request.
5. Explain the problem, solution, compatibility impact, and any checks you could not run. Include screenshots for visible UI changes, with private information removed.

Keep unrelated refactoring and generated artifacts out of the change. Do not commit credentials, local state, logs containing personal information, model weights, build outputs, or planning/report documents. Update user-facing documentation when behavior changes.

## Checks

Run commands from the repository root unless noted otherwise. Use the pinned toolchains; keep lockfiles consistent with intentional dependency changes.

### Rust

```bash
cargo fmt --all --check
cargo test -p runne-domain -p runne-api -p runne-runtime-client --locked
```

Replace or extend the package list with the crates affected by your change. For broader root-workspace checks, install the desktop native prerequisites and stage the daemon first:

```bash
pnpm --filter @runne/desktop stage:bundled-daemon
pnpm --filter @runne/desktop stage:bundled-cli
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Some native integration tests depend on platform facilities or explicit configuration. Report skips and failures accurately; do not bypass security checks to obtain a passing result.

The `runne-project-owner-authority` suite explicitly ignores three historical source-document checks because the corresponding internal documents are not distributed:

- `promotion_document_profile_matches_authoritative_raw_files`
- `v5_document_pins_match_historical_source_files`
- `frozen_v4_program_source_pin_matches_legacy_bytes`

These tests retain their exact hash checks and fail with a missing-file error if explicitly requested without the original documents. Active receipt validation, adversarial cases, and schema/payload checks are not disabled. Legacy release/qualification utilities under `scripts/` can require additional historical or operator-supplied assets; they are not the public source-check gate.

### Desktop and shared UI

```bash
pnpm typecheck
pnpm --filter @runne/desktop test
pnpm --filter @runne/product test
pnpm lint
pnpm lint:architecture
pnpm --filter @runne/desktop build
```

### Local Engine

The root workspace does not cover the engine workspace. For engine changes, run:

```bash
cd local-engine
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

These default-feature checks do not qualify native inference, model compatibility, or device performance. Native-backend changes need additional targeted validation and any required native build dependencies.

## Review expectations

- Preserve the runtime/client boundary and existing security invariants.
- Keep new or modified source files within 300 physical lines. Split larger files by responsibility before adding behavior; do not grow an existing oversized file without agreement. Generated code, lockfiles, migrations, and test fixtures are exceptions, not places to hide production logic.
- Write public documentation and contribution discussions in clear English.
- Distinguish implemented behavior from proposed behavior and tests actually run from expected results.
- Avoid blanket dependency upgrades and unsupported claims about platforms or providers.

Maintainers may request changes or decline work that does not fit the current scope. There is no guaranteed review timeframe. Contributions are provided under the repository's [Apache License 2.0](LICENSE).
