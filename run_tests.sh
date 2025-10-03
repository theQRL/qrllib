#!/bin/bash
# Run tests for pyqrllib with proper environment setup

# Set PYTHONPATH to include the current directory so pyqrllib module can be found
export PYTHONPATH=.

# Run pytest with the same configuration as specified in setup.cfg
exec pytest tests/python --doctest-modules -s --cov pyqrllib --cov-report term-missing --cov-report xml --verbose "$@"