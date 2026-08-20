#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Install local Runne runtime binaries.

Usage:
  scripts/install-local.sh [--release|--debug] [--bin-dir DIR]

Options:
  --release       Build and install release binaries (default)
  --debug         Build and install debug binaries
  --bin-dir DIR   Install directory (default: $RUNNE_INSTALL_BIN or ~/.local/bin)
  -h, --help      Show this help

Installed commands:
  runne
  runned
USAGE
}

profile="release"
bin_dir="${RUNNE_INSTALL_BIN:-$HOME/.local/bin}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      profile="release"
      shift
      ;;
    --debug)
      profile="debug"
      shift
      ;;
    --bin-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --bin-dir requires a directory" >&2
        exit 2
      fi
      bin_dir="$2"
      shift 2
      ;;
    --)
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_args=(build -p runne-cli -p runned)
target_dir="debug"
if [[ "$profile" == "release" ]]; then
  cargo_args+=(--release)
  target_dir="release"
fi

cargo "${cargo_args[@]}"

mkdir -p "$bin_dir"
for binary in runne runned; do
  source_path="$repo_root/target/$target_dir/$binary"
  if [[ ! -x "$source_path" ]]; then
    echo "error: built binary is missing or not executable: $source_path" >&2
    exit 1
  fi
  install -m 0755 "$source_path" "$bin_dir/$binary"
  if [[ "$(uname -s)" == "Darwin" && -n "${RUNNE_MACOS_SIGNING_IDENTITY:-}" ]]; then
    "$repo_root/scripts/sign-macos-binary.sh" --identity "$RUNNE_MACOS_SIGNING_IDENTITY" "$bin_dir/$binary"
  fi
done

cat <<EOF
Installed:
  $bin_dir/runne
  $bin_dir/runned

Run:
  runne --version
  runned
EOF

case ":${PATH:-}:" in
  *":$bin_dir:"*) ;;
  *)
    cat <<EOF

Add this directory to PATH if needed:
  export PATH="$bin_dir:\$PATH"
EOF
    ;;
esac
