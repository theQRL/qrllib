#!/bin/bash
# CI test script - ensures clean build and runs tests

set -e  # Exit on any error

echo "=== CI Test Script ==="
echo "Cleaning and building project, then running tests..."

# Clean any previous build artifacts
echo "Cleaning previous build..."
rm -rf build/
rm -f pyqrllib/_*.so

# Install dependencies first
echo "Installing Python dependencies..."
pip install pytest pytest-cov

# Build the project
echo "Building project..."
./build.sh

# Run tests
echo "Running tests..."
PYTHONPATH=. pytest tests/python --doctest-modules -s --cov pyqrllib --cov-report term-missing --cov-report xml --verbose

echo "=== CI Tests completed successfully! ==="