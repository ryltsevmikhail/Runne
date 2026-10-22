# Agent guidance

Runne is a desktop application and provider-neutral runtime for AI coding-agent workflows. Apply these instructions to changes throughout this repository.

## Repository authority

- GitHub `ryltsevmikhail/Runne` is the canonical repository for code, issues, and pull requests. Target `main` with focused branches and passing checks.
- SourceCraft is a historical archive, not an upstream to synchronize automatically. Do not push there as part of normal development.
- The public history was filtered. Never merge or mirror the unfiltered archival history into GitHub; port only explicitly reviewed code changes.
- Keep internal plans, reports, and archival materials outside this checkout. Never add a sibling archive to the public Git index.

## Architectural boundaries

- The runtime is the sole owner of authoritative state.
- CLI and native desktop clients use `runne-runtime-client` and authenticated public contract APIs. Do not import runtime internals into the desktop host or bypass authorization through direct storage access.
- The Vue renderer receives typed DTOs through Tauri IPC; it must not acquire runtime secrets or implement privileged runtime operations.
- Keep domain logic, persistence, provider adapters, platform integration, and UI responsibilities separated.
- Preserve capability, admission, containment, secret-handling, replay, and cancellation invariants. Never turn an unconfirmed process stop into a confirmed cancellation or silently replay a possibly completed external effect.
- Linux is the only active execution-node target. Other platform adapters or control clients are not evidence of supported execution.

## Repository layout

- `apps/desktop/`: Vue 3 renderer and Tauri host.
- `crates/`: Rust runtime, public APIs, CLI, and platform adapters.
- `packages/product/`: shared Vue UI components.
- `contracts/`: client-facing contracts and fixtures.
- `local-engine/`: separate first-party Cargo workspace and lockfile.
- `docs/`: machine-readable technical assets, including schemas, profiles, and golden fixtures. Retain assets referenced by code or tests.

## Development checks

Use Node.js 22+, pnpm 11.10.0, and the pinned Rust 1.97.1 toolchain (edition 2024; declared MSRV 1.95). See [README](README.md) for native dependencies.

```bash
pnpm install --frozen-lockfile
cargo fmt --all --check
cargo test -p runne-domain -p runne-api -p runne-runtime-client --locked
pnpm typecheck
pnpm --filter @runne/desktop test
pnpm lint
pnpm lint:architecture
```

Select additional tests for changed crates. Stage the bundled daemon before root-workspace desktop builds/tests:

```bash
pnpm --filter @runne/desktop stage:bundled-daemon
pnpm --filter @runne/desktop stage:bundled-cli
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Run Local Engine tests separately from `local-engine/` using `cargo test --workspace --locked`; root workspace checks do not cover that workspace. Default-feature contract tests do not establish native inference qualification.

## Change discipline

- Read existing code before editing. Keep changes focused and add regression tests for behavior changes.
- New or modified source files must stay within 300 physical lines, including comments and blank lines. Do not enlarge existing oversized files without explicit agreement; split responsibilities before adding behavior. Generated/vendor files, lockfiles, migrations, and test fixtures are exceptions but must not conceal production logic.
- Preserve public contracts or explicitly describe compatibility changes. Do not silently rewrite golden fixtures to accept a regression.
- Write concise English documentation. Do not add plans, specifications, draft work, evidence reports, or backlog files to this repository.
- Do not add upstream donor source trees. Attribute reused material and respect dependency licenses.
- Never expose keys, tokens, private identifiers, user data, or secret-bearing logs in output or commits.
- Do not perform destructive operations, access production resources, elevate privileges, disable trust/admission controls, enroll credentials, sign, deploy, commit, or publish unless explicitly authorized.
- Record the commands actually run, results, and limitations in the task response or pull request. Never equate a development test pass with release qualification.
