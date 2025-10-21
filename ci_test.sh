#!/bin/bash
# CI test script - ensures clean build and runs tests

set -e  # Exit on any error

echo "=== CI Test Script ==="
echo "Cleaning and building project, then running tests..."

# Clean any previous build artifacts
echo "Cleaning previous build..."
rm -rf build/
rm -f pyqrllib/_*.so

# Handle swig availability (CI environments might have swig3.0/swig4.0 instead of swig)
if ! command -v swig &> /dev/null; then
    SWIG_CMD=""
    if command -v swig4.0 &> /dev/null; then
        SWIG_CMD="swig4.0"
    elif command -v swig3.0 &> /dev/null; then
        SWIG_CMD="swig3.0"
    fi
    
    if [ -n "$SWIG_CMD" ]; then
        echo "Creating swig symlink from $SWIG_CMD..."
        mkdir -p ~/.local/bin
        ln -sf $(which $SWIG_CMD) ~/.local/bin/swig
        export PATH="$HOME/.local/bin:$PATH"
        echo "swig symlink created: ~/.local/bin/swig -> $SWIG_CMD"
    fi
fi

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