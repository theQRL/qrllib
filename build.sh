#!/bin/bash
# Build script for pyqrllib with CMake

set -e  # Exit on any error

echo "Building pyqrllib..."

# Check if cmake is available
if ! command -v cmake &> /dev/null; then
    echo "Error: cmake is not installed. Please install cmake first."
    exit 1
fi

# Check if swig is available (check swig, swig4.0, swig3.0)
if ! command -v swig &> /dev/null; then
    SWIG_CMD=""
    if command -v swig4.0 &> /dev/null; then
        SWIG_CMD="swig4.0"
    elif command -v swig3.0 &> /dev/null; then
        SWIG_CMD="swig3.0"
    fi
    
    if [ -n "$SWIG_CMD" ]; then
        echo "swig not found, but $SWIG_CMD is available. Creating temporary symlink..."
        # Create a temporary directory for the symlink
        mkdir -p ~/.local/bin
        ln -sf $(which $SWIG_CMD) ~/.local/bin/swig
        export PATH="$HOME/.local/bin:$PATH"
        echo "Temporary swig symlink created at ~/.local/bin/swig -> $SWIG_CMD"
    else
        echo "Error: swig is not installed. Please install swig first."
        exit 1
    fi
fi

# Create build directory if it doesn't exist
mkdir -p build

# Configure the build with CMake
echo "Configuring with CMake..."
cmake -B build \
    -DBUILD_PYTHON=ON \
    -DBUILD_TESTS=OFF \
    -DCMAKE_BUILD_TYPE=Release

# Build the project
echo "Building..."
cmake --build build --config Release -- -j$(nproc)

# Copy the built extensions to the pyqrllib directory
echo "Copying built extensions..."
if [ -f "build/pyqrllib/_pyqrllib.so" ]; then
    cp build/pyqrllib/_pyqrllib.so pyqrllib/
fi
if [ -f "build/pyqrllib/_dilithium.so" ]; then
    cp build/pyqrllib/_dilithium.so pyqrllib/
fi
if [ -f "build/pyqrllib/_kyber.so" ]; then
    cp build/pyqrllib/_kyber.so pyqrllib/
fi

# Copy the generated Python files
if [ -f "build/pyqrllib/pyqrllib.py" ]; then
    cp build/pyqrllib/pyqrllib.py pyqrllib/
fi
if [ -f "build/pyqrllib/dilithium.py" ]; then
    cp build/pyqrllib/dilithium.py pyqrllib/
fi
if [ -f "build/pyqrllib/kyber.py" ]; then
    cp build/pyqrllib/kyber.py pyqrllib/
fi

echo "Build completed successfully!"
echo "Python extensions are now available in the pyqrllib directory."