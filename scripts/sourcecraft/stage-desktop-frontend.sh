#!/usr/bin/env bash
set -euo pipefail

repo_root="${SOURCECRAFT_WORKSPACE:-$(pwd -P)}"
cd "$repo_root"

test "$(node --version)" = "v22.14.0"
npm ping
npm install --prefix "$repo_root/.ci-tools" pnpm@11.10.0
export PATH="$repo_root/.ci-tools/node_modules/.bin:$PATH"
test "$(pnpm --version)" = "11.10.0"

for attempt in 1 2 3; do
    if pnpm install --frozen-lockfile --ignore-scripts --fetch-timeout 120000; then
        break
    fi
    if [ "$attempt" = 3 ]; then
        exit 1
    fi
    sleep 10
done

pnpm --filter @runne/desktop build
test -f apps/desktop/dist/index.html
test -d apps/desktop/dist/assets
