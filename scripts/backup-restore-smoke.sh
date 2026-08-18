#!/usr/bin/env bash
# Restore and schema-transition drill for a GOCODE candidate.
#
# Exercises the real on-disk SQLite backup/restore and forward/rollback
# schema-transition paths (v4 -> CURRENT_SCHEMA_VERSION forward migrations,
# pre-v4/pre-v5 VACUUM INTO snapshots, v12 rollback) against the actual store
# crates, then emits a machine-readable evidence report.
#
# This is a candidate-bound operational drill, not a release approval and not
# a production recovery drill. It reuses the deterministic integration test
# binaries that already prove these paths, because those binaries operate on
# real SQLite files (tempdir) rather than mocked stores.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

evidence_dir="${1:-$repo_root/target/phase9-drill-evidence}"
mkdir -p "$evidence_dir"
report="$evidence_dir/restore-schema-transition-drill.json"

commit="$(git rev-parse HEAD)"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Curated set of real store binaries that prove backup/restore and schema
# forward/rollback transitions. Each is a cargo integration-test target that
# creates a real SQLite database under a tempdir and runs the actual code path.
targets=(
  "gocode-local-store:recent_root_migration"
  "gocode-local-store:replay_projection_v4"
  "gocode-store:schema_v8_upgrade"
  "gocode-store:schema_v12_rollback"
  "gocode-store:schema_v14_compatibility"
  "gocode-store:schema_v15_compatibility"
  "gocode-store:schema_v17_catalog"
  "gocode-store:schema_v17_migration_rollback"
  "gocode-store:schema_v17_snapshots"
  "gocode-store:schema_v18_migration_catalog"
  "gocode-store:schema_v18_promotion_snapshots"
  "gocode-store:schema_compatibility_preflight"
  "gocode-store:migration_sqlite"
  "gocode-store:migration_routing_sqlite"
  "gocode-store:snapshot_write_rollback"
)

declare -a results
overall=0
for spec in "${targets[@]}"; do
  crate="${spec%%:*}"
  target="${spec##*:}"
  name="${crate}::${target}"
  if cargo test -q -p "$crate" --test "$target" -- --include-ignored >/dev/null 2>&1; then
    results+=("$(printf '{"name":"%s","status":"pass"}' "$name")")
  else
    results+=("$(printf '{"name":"%s","status":"fail"}' "$name")")
    overall=1
  fi
done

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
json_lines="$(IFS=,; echo "${results[*]}")"
cat > "$report" <<EOF
{
  "schema": "gocode.phase9-restore-schema-transition-drill/1",
  "commit": "$commit",
  "started_at": "$started_at",
  "finished_at": "$finished_at",
  "disposition": "local_candidate_bound",
  "targets": [$json_lines]
}
EOF

echo "Drill report: $report"
echo "Overall: $([ "$overall" -eq 0 ] && echo PASS || echo FAIL)"
exit "$overall"
