#!/usr/bin/env bash
# Run the linter against the project.
#   ./lint.sh         check (CI behavior)
#   ./lint.sh --fix   auto-fix what's safe
set -euo pipefail
cd "$(dirname "$0")"
exec ./venv/bin/ruff check collateral_provider/ "$@"
