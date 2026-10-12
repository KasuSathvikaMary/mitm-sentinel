#!/bin/bash
set -e

echo "🧪 Running MITM Sentinel Automated Test Suite..."
python3 -m pytest tests/ -v --tb=short
