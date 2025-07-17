# netshield-ebpf

This is the eBPF/XDP component of the Fortexa firewall's Netshield module. It provides high-performance packet filtering at the kernel level.

## Overview

The netshield-ebpf program:
- Attaches to network interfaces as an XDP program
- Filters packets based on rules loaded from userspace
- Provides fast packet processing with minimal overhead
- Supports logging, blocking, and allowing packets

## Building

### Prerequisites

1. Rust nightly toolchain: `rustup toolchain install nightly --component rust-src`
2. bpf-linker: `cargo install bpf-linker`

### Build Commands

Debug build:
```shell
cargo +nightly build --target bpfel-unknown-none -Z build-std=core
```

Release build:
```shell
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

### Output

The compiled eBPF library will be located at:
- Debug: `target/bpfel-unknown-none/debug/libnetshield_ebpf.so`
- Release: `target/bpfel-unknown-none/release/libnetshield_ebpf.so`

## Integration with Fortexa

The main Fortexa application loads this eBPF program using the Aya library and:

1. Loads the `libnetshield_ebpf.so` file
2. Attaches the XDP program to network interfaces
3. Updates the rules map with filtering rules from the REST API
4. Monitors packet filtering results

## Rule Format

Rules are stored in an eBPF map with the following structure:

```rust
struct Rule {
    id: u32,
    enabled: bool,
    direction: u8,        // 0 = Incoming, 1 = Outgoing
    action: u8,           // 0 = Block, 1 = Allow, 2 = Drop, 3 = Accept, 4 = Log
    source_ip: u32,       // IPv4 address, 0 for any
    destination_ip: u32,  // IPv4 address, 0 for any
    source_port: u16,     // Port number, 0 for any
    destination_port: u16, // Port number, 0 for any
    protocol: u8,         // IP protocol (TCP=6, UDP=17), 0 for any
}
```

## Actions

- **Block/Drop**: Drop the packet (XDP_DROP)
- **Allow/Accept**: Pass the packet to the network stack (XDP_PASS)
- **Log**: Log packet details and continue processing

## License

This eBPF code is distributed under either the terms of the GNU General Public License, Version 2 or the MIT license, at your option.
