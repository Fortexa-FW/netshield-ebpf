# netshield-ebpf (C Implementation)

eBPF/XDP program for Netshield module in Fortexa firewall - C implementation for maximum compatibility and security.

## Overview

This C-based eBPF program provides two implementations:

### Basic Version (`netshield_xdp.c`)
- Fast XDP packet filtering at kernel level
- Rule-based traffic control with 10 rules maximum
- Basic statistics collection
- Optimized for performance

### Secure Version (`netshield_xdp_secure.c`)
- Enhanced security with magic number validation
- Limited to 3 rules for maximum verifier compatibility
- Security-focused packet validation
- Rule integrity checking
- Comprehensive security statistics

## Features

- **XDP Performance**: Zero-copy packet processing at driver level
- **Rule-based Filtering**: IP, port, and protocol-based rules
- **Statistics Collection**: Real-time packet processing metrics
- **Security Validation**: Magic number and rule integrity checks
- **Standard Compatibility**: Uses modern libbpf for maximum compatibility

## Building

### Prerequisites

```bash
# Install required packages (Ubuntu/Debian)
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    bpftool \
    build-essential
```

### Build Commands

```bash
# Build basic eBPF program
make

# Build secure eBPF program
make secure

# Test basic version with bpftool
make test

# Test secure version with bpftool
make test-secure

# Install basic version to system location
sudo make install

# Install secure version to system location
sudo make install-secure

# Clean build artifacts
make clean

# Show build information
make info
```

### Available Targets

| Target | Description |
|--------|-------------|
| `all` | Build basic eBPF program |
| `secure` | Build secure eBPF program |
| `test` | Test basic version with bpftool |
| `test-secure` | Test secure version with bpftool |
| `install` | Install basic version to system |
| `install-secure` | Install secure version to system |
| `clean` | Clean build artifacts |
| `info` | Show build configuration |

## Output Files

### Build Artifacts
- **Basic version**: `build/netshield_xdp.o`
- **Secure version**: `build/netshield_xdp_secure.o`

### System Installation
- **Target location**: `/usr/lib/fortexa/netshield_xdp.o`
- **Permissions**: 644 (readable by all, writable by owner)

## File Structure

```
netshield-ebpf/
├── Makefile                    # Build system
├── netshield_common.h          # Shared definitions
├── netshield_xdp.c            # Basic eBPF implementation
├── netshield_xdp_secure.c     # Secure eBPF implementation
├── build/                     # Compiled objects
│   ├── netshield_xdp.o
│   └── netshield_xdp_secure.o
└── README.md                  # This file
```

## Integration with Fortexa

The Fortexa firewall application integrates with this eBPF module by:

1. **Loading the eBPF program**: Uses the compiled `.o` file from `/usr/lib/fortexa/`
2. **Attaching to interfaces**: Attaches XDP program to network interfaces
3. **Managing rules**: Updates the rules map through eBPF map operations
4. **Monitoring statistics**: Reads packet processing statistics for monitoring
5. **Security validation**: Uses secure version for enhanced protection

### Rule Management

Rules are managed through eBPF maps with the following structure:
- **Source/Destination IP**: IPv4 addresses (0 = any)
- **Source/Destination Port**: TCP/UDP ports (0 = any)
- **Protocol**: IP protocol (0 = any, 6 = TCP, 17 = UDP)
- **Action**: 0 = allow, 1 = drop
- **Magic Number**: Security validation (secure version only)

### Statistics Available

Both versions provide statistics for:
- Packets processed
- Packets allowed
- Packets dropped
- Invalid packets

The secure version additionally tracks:
- Invalid rules (magic number mismatch)
- Security validation failures

## Version Comparison

| Feature | Basic Version | Secure Version |
|---------|---------------|----------------|
| Max Rules | 10 | 3 |
| Magic Validation | ❌ | ✅ |
| Rule Integrity | ❌ | ✅ |
| Performance | High | Medium |
| Security | Basic | Enhanced |
| eBPF Complexity | Low | Medium |

## Development Notes

- **eBPF Verifier Limits**: The secure version is limited to 3 rules to stay within eBPF verifier complexity limits
- **Instruction Limits**: Programs must stay under 1,000,000 instructions
- **Map Types**: Uses HASH maps for better performance and flexibility
- **Compatibility**: Designed for modern libbpf (v1.0+) and recent kernels

## License

GPL-3.0 compatible with kernel eBPF requirements.

## Troubleshooting

### Common Issues

1. **"sequence of jumps is too complex"**
   - Use the basic version instead of secure version
   - Reduce the number of rules
   - Ensure eBPF verifier limits are respected

2. **"failed to load object file"**
   - Check kernel version compatibility
   - Verify all required headers are installed
   - Ensure bpftool is available

3. **Permission denied during install**
   - Use `sudo` for installation commands
   - Check `/usr/lib/fortexa/` directory permissions

### Testing

```bash
# Verify eBPF program loads correctly
sudo bpftool prog load build/netshield_xdp.o /sys/fs/bpf/test type xdp

# Check if program is loaded
sudo bpftool prog show

# Clean up test
sudo rm /sys/fs/bpf/test
```
