#![no_std]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub id: u32,
    pub enabled: bool,
    pub direction: u8, // 0 = Incoming, 1 = Outgoing
    pub action: u8,    // 0 = Block, 1 = Allow, 2 = Drop, 3 = Accept, 4 = Log
    pub source_ip: u32,      // IPv4 address in network byte order, 0 for any
    pub destination_ip: u32, // IPv4 address in network byte order, 0 for any
    pub source_port: u16,    // Port in network byte order, 0 for any
    pub destination_port: u16, // Port in network byte order, 0 for any
    pub protocol: u8,        // IP protocol (TCP=6, UDP=17, etc.), 0 for any
}

#[map]
pub static RULES_MAP: HashMap<u32, Rule> = HashMap::with_max_entries(1024, 0);

// Action constants
pub const ACTION_BLOCK: u8 = 0;
pub const ACTION_ALLOW: u8 = 1;
pub const ACTION_DROP: u8 = 2;
pub const ACTION_ACCEPT: u8 = 3;
pub const ACTION_LOG: u8 = 4;

// Direction constants
pub const DIRECTION_INCOMING: u8 = 0;
pub const DIRECTION_OUTGOING: u8 = 1;
