#!/usr/bin/env bash
# Run the Django test suite. Args pass through:
#   ./test.sh                                    everything
#   ./test.sh api.tests.test_views               one module
#   ./test.sh -v 2                               verbose
#   ./test.sh api.tests.test_views.TestHappyPath single class
set -euo pipefail
cd "$(dirname "$0")/collateral_provider"
exec ../venv/bin/python manage.py test "$@"
