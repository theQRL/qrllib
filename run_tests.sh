#!/bin/bash
# Run tests for pyqrllib with proper environment setup

set -e  # Exit on any error

# Check if the Python extensions are built
if [ ! -f "pyqrllib/_pyqrllib.so" ] || [ ! -f "pyqrllib/_dilithium.so" ] || [ ! -f "pyqrllib/_kyber.so" ]; then
    echo "Python extensions not found. Building project first..."
    ./build.sh
fi

# Set PYTHONPATH to include the current directory so pyqrllib module can be found
export PYTHONPATH=.

# Run pytest with the same configuration as specified in setup.cfg
exec pytest tests/python --doctest-modules -s --cov pyqrllib --cov-report term-missing --cov-report xml --verbose "$@"
