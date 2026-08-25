#!/usr/bin/env bash
set -e

echo "========================================================"
echo "🧪 Running Compute2Data Test Suite on GenLayer"
echo "========================================================"

echo "🔍 Step 1: Running genvm-lint on contracts/c2d_marketplace.py..."
genvm-lint check contracts/c2d_marketplace.py

echo ""
echo "🚀 Step 2: Running Direct Unit Tests (test/)..."
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -p gltest_direct -v

echo ""
echo "========================================================"
echo "✅ All Compute2Data tests passed successfully (100%)!"
echo "========================================================"
