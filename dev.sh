#!/bin/sh
# ============================================================
# dev.sh - run cloudguard in an isolated sandbox folder
# ------------------------------------------------------------
# Why this script exists:
#   Everything the tools write (virtualenv, pip downloads, Python
#   bytecode caches, pytest caches) goes into ONE sandbox folder,
#   outside the project and outside your system Python.
#   Nothing is installed globally, and the project folder stays
#   clean (no venv/, __pycache__/, .pytest_cache/, *.egg-info).
#
#   Default sandbox: $TMPDIR/cloudguard-sandbox (macOS per-user temp)
#   Override:        CLOUDGUARD_SANDBOX=/some/other/dir sh dev.sh setup
#
# Usage:
#   sh dev.sh setup   # create sandbox + install pinned dependencies
#   sh dev.sh test    # run the test suite
#   sh dev.sh demo    # run cloudguard against fake AWS (free, offline)
#   sh dev.sh run ... # run cloudguard against real AWS (pass flags)
#   sh dev.sh clean   # delete the sandbox completely
# ============================================================

set -eu

# ---- Where things live ------------------------------------------
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_BASE="${TMPDIR:-/tmp}"
SANDBOX="${CLOUDGUARD_SANDBOX:-${TMP_BASE%/}/cloudguard-sandbox}"
VENV="$SANDBOX/venv"
PY="$VENV/bin/python"

# ---- Keep every write inside the sandbox ------------------------
export PIP_CACHE_DIR="$SANDBOX/pip-cache"        # pip downloads
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONPYCACHEPREFIX="$SANDBOX/pycache"    # .pyc files (no __pycache__ in project)
export PYTHONPATH="$PROJECT_DIR/src"             # run the code in place, no install step

# Pinned exact versions (same as pyproject.toml)
DEPS="boto3==1.43.110 rich==15.0.0 moto[ec2,iam,s3]==5.2.3 pytest==9.1.1"

require_sandbox() {
  if [ ! -x "$PY" ]; then
    echo "Sandbox not found. Run: sh dev.sh setup" >&2
    exit 2
  fi
}

case "${1:-help}" in
  setup)
    mkdir -p "$SANDBOX"
    python3 -m venv "$VENV"
    # shellcheck disable=SC2086  # DEPS is intentionally split into words
    "$PY" -m pip install -q $DEPS
    echo "Sandbox ready: $SANDBOX"
    ;;
  test)
    require_sandbox
    shift
    # -p no:cacheprovider -> pytest writes no .pytest_cache folder
    cd "$PROJECT_DIR" && "$PY" -m pytest -p no:cacheprovider "$@"
    ;;
  demo)
    require_sandbox
    "$PY" -m cloudguard --demo
    ;;
  run)
    require_sandbox
    shift
    "$PY" -m cloudguard "$@"
    ;;
  clean)
    rm -rf "$SANDBOX"
    echo "Removed $SANDBOX"
    ;;
  *)
    sed -n '2,22p' "$0"
    ;;
esac
