#!/usr/bin/env bash
# pre-commit-wrapper.sh — Wraps security hook execution with:
#   1. A 30-second timeout to preserve developer velocity (Requirement 11.3)
#   2. Fail-open behavior for missing binaries or crashes (Error Handling spec)
#
# Usage:
#   scripts/pre-commit-wrapper.sh <hook-binary> [hook-args...]
#
# Exit codes:
#   0 — hook passed OR fail-open triggered (missing binary / crash / timeout)
#   1 — hook detected a finding (commit should be blocked)
#
# Examples:
#   scripts/pre-commit-wrapper.sh gitleaks protect --staged
#   scripts/pre-commit-wrapper.sh semgrep scan --config=p/secrets --error

set -o pipefail

TIMEOUT_SECONDS="${PRE_COMMIT_TIMEOUT:-30}"
HOOK_BINARY="$1"
shift

# --- Guard: no binary specified ---
if [[ -z "$HOOK_BINARY" ]]; then
    echo "[pre-commit-wrapper] ERROR: No hook binary specified." >&2
    echo "[pre-commit-wrapper] Usage: $0 <hook-binary> [args...]" >&2
    exit 0  # fail-open
fi

# --- Guard: binary not found ---
if ! command -v "$HOOK_BINARY" &>/dev/null; then
    echo "[pre-commit-wrapper] WARNING: '$HOOK_BINARY' not found in PATH." >&2
    echo "[pre-commit-wrapper] Skipping hook — install '$HOOK_BINARY' for local security scanning." >&2
    echo "[pre-commit-wrapper] The CI pipeline will still catch issues on push." >&2
    exit 0  # fail-open
fi

# --- Execute hook with timeout ---
if command -v timeout &>/dev/null; then
    # GNU coreutils timeout (Linux)
    timeout "${TIMEOUT_SECONDS}s" "$HOOK_BINARY" "$@"
    EXIT_CODE=$?
elif command -v gtimeout &>/dev/null; then
    # GNU timeout via Homebrew on macOS (brew install coreutils)
    gtimeout "${TIMEOUT_SECONDS}s" "$HOOK_BINARY" "$@"
    EXIT_CODE=$?
else
    # Fallback: use built-in shell background process with wait
    "$HOOK_BINARY" "$@" &
    HOOK_PID=$!

    # Wait for the hook or kill after timeout
    (
        sleep "$TIMEOUT_SECONDS"
        if kill -0 "$HOOK_PID" 2>/dev/null; then
            kill -TERM "$HOOK_PID" 2>/dev/null
        fi
    ) &
    TIMER_PID=$!

    wait "$HOOK_PID" 2>/dev/null
    EXIT_CODE=$?

    # Clean up timer if hook finished before timeout
    kill "$TIMER_PID" 2>/dev/null
    wait "$TIMER_PID" 2>/dev/null
fi

# --- Interpret exit code ---
case $EXIT_CODE in
    0)
        # Hook passed — no findings
        exit 0
        ;;
    1)
        # Hook found issues — block the commit
        echo "" >&2
        echo "[pre-commit-wrapper] ✗ '$HOOK_BINARY' detected issues. Commit blocked." >&2
        echo "[pre-commit-wrapper] Fix the issues above and try again." >&2
        exit 1
        ;;
    124|137)
        # Timeout (124 = timeout exit code, 137 = SIGKILL)
        echo "" >&2
        echo "[pre-commit-wrapper] WARNING: '$HOOK_BINARY' exceeded ${TIMEOUT_SECONDS}s timeout." >&2
        echo "[pre-commit-wrapper] Allowing commit — the CI pipeline will run the full scan." >&2
        exit 0  # fail-open on timeout
        ;;
    126|127)
        # 126 = permission denied, 127 = command not found (shouldn't reach here but safety net)
        echo "" >&2
        echo "[pre-commit-wrapper] WARNING: '$HOOK_BINARY' could not be executed (exit code $EXIT_CODE)." >&2
        echo "[pre-commit-wrapper] Allowing commit — ensure the tool is installed correctly." >&2
        exit 0  # fail-open
        ;;
    *)
        # Unexpected exit code — likely a crash
        echo "" >&2
        echo "[pre-commit-wrapper] WARNING: '$HOOK_BINARY' exited unexpectedly (code $EXIT_CODE)." >&2
        echo "[pre-commit-wrapper] Allowing commit — the CI pipeline will catch any issues." >&2
        exit 0  # fail-open on crash
        ;;
esac
