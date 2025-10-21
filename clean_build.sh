#!/bin/bash
# Clean build script for pyqrllib - removes existing build artifacts and builds fresh

set -e  # Exit on any error

echo "Cleaning previous build artifacts..."

# Remove build directory
if [ -d "build" ]; then
    rm -rf build
    echo "Removed build directory"
fi

# Remove compiled extensions from pyqrllib directory
rm -f pyqrllib/_pyqrllib.so
rm -f pyqrllib/_dilithium.so  
rm -f pyqrllib/_kyber.so
echo "Removed existing Python extensions"

# Remove generated Python wrapper files (they will be regenerated)
rm -f pyqrllib/pyqrllib.py.bak 
rm -f pyqrllib/dilithium.py.bak
rm -f pyqrllib/kyber.py.bak
echo "Cleaned up backup files"

# Now run the regular build
echo "Starting fresh build..."
./build.sh

echo "Clean build completed successfully!"