#!/bin/bash

# Build script for netshield-ebpf
# This script builds the eBPF program and copies it to the expected location

set -e

echo "Building netshield-ebpf..."

# Build debug version
echo "Building debug version..."
cargo +nightly build --target bpfel-unknown-none -Z build-std=core

# Build release version
echo "Building release version..."
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

# Copy files to expected names
DEBUG_DIR="target/bpfel-unknown-none/debug"
RELEASE_DIR="target/bpfel-unknown-none/release"

if [ -f "$DEBUG_DIR/libnetshield_ebpf.so" ]; then
    cp "$DEBUG_DIR/libnetshield_ebpf.so" "$DEBUG_DIR/netshield_xdp.o"
    echo "Created: $DEBUG_DIR/netshield_xdp.o"
fi

if [ -f "$RELEASE_DIR/libnetshield_ebpf.so" ]; then
    cp "$RELEASE_DIR/libnetshield_ebpf.so" "$RELEASE_DIR/netshield_xdp.o"
    echo "Created: $RELEASE_DIR/netshield_xdp.o"
fi

# Copy to main fortexa project directory for easy access
FORTEXA_DIR="../fortexa"
if [ -d "$FORTEXA_DIR" ]; then
    cp "$RELEASE_DIR/netshield_xdp.o" "$FORTEXA_DIR/netshield_xdp.o"
    echo "Copied eBPF object to: $FORTEXA_DIR/netshield_xdp.o"
fi

echo "eBPF build complete!"
echo ""
echo "Available eBPF objects:"
echo "  Debug:   $DEBUG_DIR/netshield_xdp.o"
echo "  Release: $RELEASE_DIR/netshield_xdp.o"
if [ -f "$FORTEXA_DIR/netshield_xdp.o" ]; then
    echo "  Fortexa: $FORTEXA_DIR/netshield_xdp.o"
fi
