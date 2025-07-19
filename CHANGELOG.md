# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- C-based eBPF implementation for better libbpf compatibility
- Basic eBPF program (`netshield_xdp.c`) with 10 rules support
- Secure eBPF program (`netshield_xdp_secure.c`) with enhanced security features
- Magic number validation for rule security (0x4E455453)
- Comprehensive build system with multiple targets
- Statistics collection for packet monitoring
- Protocol-specific port parsing for TCP/UDP
- bpftool integration for testing and validation

### Changed
- Migrated from Rust to C implementation
- Updated build system to use Makefile instead of Cargo
- Optimized for eBPF verifier compliance (reduced complexity)
- Standardized installation to `/usr/lib/fortexa/netshield_xdp.o`

### Fixed
- eBPF verifier "sequence of jumps too complex" errors
- XDP program loading issues
- Instruction limit compliance (under 1,000,000 instructions)
- Map compatibility with modern kernels

### Removed
- Rust eBPF implementation due to compatibility issues

