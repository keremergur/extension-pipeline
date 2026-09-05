#!/usr/bin/env bash
# Dispatches the container to the analyzer, the verifier, or both.
#
# Usage:
#   docker run <image>            # default: verifier (preserves prior behavior)
#   docker run <image> analyzer   # LLM analysis only (no browser needed)
#   docker run <image> verifier   # browser-based verification only
#   docker run <image> both       # analyzer, then verifier (future full pipeline)
#
# The role may also be set via the ROLE env var; a positional arg wins.
# Any args after the role are passed through to the Python entry point.
set -euo pipefail

role="${1:-${ROLE:-verifier}}"
[ "$#" -gt 0 ] && shift   # drop the role arg; anything left passes through

case "$role" in
  analyzer)
    exec python src/analyze_extensions.py "$@"
    ;;
  verifier)
    exec xvfb-run -a python src/verify_extensions.py "$@"
    ;;
  both)
    echo "[entrypoint] running analyzer..." >&2
    python src/analyze_extensions.py "$@"
    echo "[entrypoint] running verifier..." >&2
    exec xvfb-run -a python src/verify_extensions.py "$@"
    ;;
  *)
    echo "[entrypoint] unknown role: '$role' (expected: analyzer | verifier | both)" >&2
    exit 64
    ;;
esac
