#![no_std]

use bytemuck::{Pod, Zeroable};

/// Rule struct for eBPF firewall filtering.
///
/// Layout and field meanings:
///   - id: Unique rule identifier (u32)
///   - source_ip, destination_ip: IPv4 addresses in network byte order (u32)
///   - source_port, destination_port: Ports in network byte order (u16)
///   - enabled: 0 = disabled, 1 = enabled (u8)
///   - direction: 0 = Incoming, 1 = Outgoing (u8)
///   - action: 0 = Block, 1 = Allow, 2 = Drop, 3 = Accept, 4 = Log (u8)
///   - protocol: IP protocol (TCP=6, UDP=17, etc.), 0 = any (u8)
///   - _pad: Padding to ensure struct is Pod and a multiple of 8 bytes for eBPF safety
///
/// The struct is #[repr(C)] and fields are ordered and padded to avoid alignment issues
/// and to allow safe zero-copy conversion (bytemuck::Pod) between byte slices and Rule.
/// This is required for safe use in eBPF maps and kernel/userspace communication.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Rule {
    pub id: u32,
    pub source_ip: u32,
    pub destination_ip: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub enabled: u8,            // 0 = disabled, 1 = enabled
    pub direction: u8,          // 0 = Incoming, 1 = Outgoing
    pub action: u8,             // 0 = Block, 1 = Allow, 2 = Drop, 3 = Accept, 4 = Log
    pub protocol: u8,           // IP protocol (TCP=6, UDP=17, etc.), 0 = any
    pub _pad: [u8; 4],          // Padding for alignment
}

// Action constants
pub const ACTION_BLOCK: u8 = 0;
pub const ACTION_ALLOW: u8 = 1;
pub const ACTION_DROP: u8 = 2;
pub const ACTION_ACCEPT: u8 = 3;
pub const ACTION_LOG: u8 = 4;

// Direction constants
pub const DIRECTION_INCOMING: u8 = 0;
pub const DIRECTION_OUTGOING: u8 = 1;
