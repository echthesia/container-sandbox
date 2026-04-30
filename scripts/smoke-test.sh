#!/usr/bin/env bash
# Smoke-test every agent template by running it through the production
# create path: builds the image (validating the Containerfile, all apt /
# npm / curl install steps, and the `test -x <bin>` checks), creates the
# sandbox, then removes it. Doesn't boot the VM or run the agent itself
# — left to manual testing once you trust the templates build.
#
# Usage:  scripts/smoke-test.sh             # all agents
#         scripts/smoke-test.sh codex gemini # specific agents
#
# Requires `container` and the sandbox plugin to be installed (`make install`).

set -euo pipefail

ALL_AGENTS=(claude codex copilot gemini opencode shell)

if [ "$#" -gt 0 ]; then
    AGENTS=("$@")
else
    AGENTS=("${ALL_AGENTS[@]}")
fi

if ! command -v container >/dev/null 2>&1; then
    echo "error: 'container' CLI not found. Install via 'brew install container'." >&2
    exit 2
fi

if ! container sandbox --help >/dev/null 2>&1; then
    echo "error: container sandbox plugin not registered. Run 'make install' first." >&2
    exit 2
fi

WORKSPACE=$(mktemp -d -t container-sandbox-smoke)
echo "smoke-test workspace: $WORKSPACE"
trap 'rm -rf "$WORKSPACE"' EXIT

FAILED=()
declare -a TIMINGS

for agent in "${AGENTS[@]}"; do
    echo
    echo "=== $agent ==="
    start=$(date +%s)
    if name=$(container sandbox create "$agent" "$WORKSPACE" 2>&1); then
        elapsed=$(($(date +%s) - start))
        TIMINGS+=("$agent: ${elapsed}s ✓")
        echo "  ✓ created $name in ${elapsed}s"
        container sandbox rm "$name" >/dev/null 2>&1 || true
    else
        elapsed=$(($(date +%s) - start))
        TIMINGS+=("$agent: ${elapsed}s ✗")
        echo "  ✗ failed after ${elapsed}s:"
        echo "$name" | sed 's/^/    /'
        FAILED+=("$agent")
    fi
done

echo
echo "summary:"
for t in "${TIMINGS[@]}"; do
    echo "  $t"
done

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo
    echo "FAILED: ${FAILED[*]}"
    exit 1
fi

echo
echo "all agents OK."
