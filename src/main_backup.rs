#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use netshield_ebpf_common::{Rule, ACTION_BLOCK, ACTION_ALLOW, ACTION_DROP, ACTION_ACCEPT, ACTION_LOG};

// Security constants
const MAX_PACKET_SIZE: u32 = 1514; // Standard Ethernet MTU
const MAX_RULES: u32 = 1000;

// eBPF map for rules storage
#[map]
static RULES_MAP: HashMap<u32, [u8; 256]> = HashMap::with_max_entries(MAX_RULES, 0);

// Statistics map for monitoring
#[map]
static STATS_MAP: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

// Statistics keys
const STAT_PACKETS_PROCESSED: u32 = 0;
const STAT_PACKETS_DROPPED: u32 = 1;
const STAT_PACKETS_PASSED: u32 = 2;
const STAT_INVALID_PACKETS: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct PacketInfo {
    src_ip: u32,
    dest_ip: u32,
    src_port: u16,
    dest_port: u16,
    protocol: u8,
    packet_size: u16,
}

#[xdp]
pub fn netshield_ebpf(ctx: XdpContext) -> u32 {
    match try_netshield_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            // Increment error counter and pass packet (do not drop on error)
            increment_stat(STAT_INVALID_PACKETS);
            xdp_action::XDP_PASS
        }
    }
}

fn try_netshield_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    // Increment processed counter
    increment_stat(STAT_PACKETS_PROCESSED);

    // Security check: validate packet size
    let packet_size = ctx.data_end() - ctx.data();
    if packet_size > MAX_PACKET_SIZE as usize {
        increment_stat(STAT_INVALID_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse packet headers with bounds checking
    let packet_info = match parse_packet_safe(&ctx) {
        Some(info) => info,
        None => {
            increment_stat(STAT_INVALID_PACKETS);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // Apply rules-based filtering
    let action = apply_rules(&packet_info)?;

    match action {
        xdp_action::XDP_DROP => increment_stat(STAT_PACKETS_DROPPED),
        xdp_action::XDP_PASS => increment_stat(STAT_PACKETS_PASSED),
        _ => {}
    }

    Ok(action)
}

fn parse_packet_safe(ctx: &XdpContext) -> Option<PacketInfo> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Security: ensure minimum packet size for Ethernet header
    if data + core::mem::size_of::<EthHdr>() > data_end {
        return None;
    }

    // Manual parsing to avoid packed struct alignment issues
    // Ethernet header: 6 bytes dst + 6 bytes src + 2 bytes ethertype
    if data + 14 > data_end {
        return None;
    }

    // Read ethertype (bytes 12-13 in network byte order)
    let ethertype_bytes = unsafe { [*((data + 12) as *const u8), *((data + 13) as *const u8)] };
    let ether_type = u16::from_be_bytes(ethertype_bytes);

    // Only process IPv4 packets (0x0800)
    if ether_type != 0x0800 {
        return None;
    }

    let ip_hdr_offset = data + 14; // Skip Ethernet header (14 bytes)

    // Security: bounds check for IP header
    if ip_hdr_offset + core::mem::size_of::<Ipv4Hdr>() > data_end {
        return None;
    }

    let ip_hdr = unsafe { &*(ip_hdr_offset as *const Ipv4Hdr) };

    // Security: validate IP header length and packet length
    let ip_hdr_len = (ip_hdr.ihl() as usize) * 4;
    if ip_hdr_len < 20 || ip_hdr_offset + ip_hdr_len > data_end {
        return None;
    }

    let mut src_port = 0u16;
    let mut dest_port = 0u16;

    // Parse transport layer headers (TCP/UDP) with bounds checking
    let transport_offset = ip_hdr_offset + ip_hdr_len;

    match ip_hdr.proto {
        IpProto::Tcp => {
            if transport_offset + core::mem::size_of::<TcpHdr>() <= data_end {
                let tcp_hdr = unsafe { &*( (data as *const u8).add(transport_offset - data) as *const TcpHdr ) };
                // TCP fields are u16 in network byte order
                src_port = u16::from_be(tcp_hdr.source);
                dest_port = u16::from_be(tcp_hdr.dest);
            }
        }
        IpProto::Udp => {
            if transport_offset + core::mem::size_of::<UdpHdr>() <= data_end {
                let udp_hdr = unsafe { &*( (data as *const u8).add(transport_offset - data) as *const UdpHdr ) };
                // UDP fields are [u8; 2] arrays
                src_port = u16::from_be_bytes(udp_hdr.source);
                dest_port = u16::from_be_bytes(udp_hdr.dest);
            }
        }
        _ => {
            // Other protocols (ICMP, etc.) - ports remain 0
        }
    }

    Some(PacketInfo {
        src_ip: u32::from_be_bytes(ip_hdr.src_addr),
        dest_ip: u32::from_be_bytes(ip_hdr.dst_addr),
        src_port,
        dest_port,
        protocol: ip_hdr.proto as u8,
        packet_size: (data_end - data) as u16,
    })
}

fn apply_rules(packet_info: &PacketInfo) -> Result<u32, ()> {
    // Default to PASS if no rules are loaded (safety measure)
    let mut matched_action = None;
    let mut i = 0u32;
    let mut rules_found = false;
    let mut _rules_processed = 0u32;

    while let Some(raw_rule) = unsafe { RULES_MAP.get(&i) } {
        rules_found = true;
        _rules_processed += 1;
        
        // Use bytemuck for safe conversion
        let rule: Rule = match bytemuck::try_from_bytes::<Rule>(raw_rule) {
            Ok(r) => *r,
            Err(_) => {
                // Corrupted rule data - skip and continue
                i += 1;
                continue;
            }
        };
        if rule.enabled == 0 {
            i += 1;
            continue;
        }
        // Match direction, protocol, IPs, ports (0 = any)
        if (rule.source_ip == 0 || rule.source_ip == packet_info.src_ip)
            && (rule.destination_ip == 0 || rule.destination_ip == packet_info.dest_ip)
            && (rule.source_port == 0 || rule.source_port == packet_info.src_port)
            && (rule.destination_port == 0 || rule.destination_port == packet_info.dest_port)
            && (rule.protocol == 0 || rule.protocol == packet_info.protocol)
        {
            // Found a matching rule
            matched_action = Some(rule.action);
            break;
        }
        i += 1;
        
        // Safety limit to prevent infinite loops
        if i > 1000 {
            break;
        }
    }

    // CRITICAL: If no rules are loaded at all, allow all traffic
    if !rules_found {
        return Ok(xdp_action::XDP_PASS);
    }

    // Apply the matched action
    match matched_action {
        Some(ACTION_BLOCK) | Some(ACTION_DROP) => Ok(xdp_action::XDP_DROP),
        Some(ACTION_ALLOW) | Some(ACTION_ACCEPT) => Ok(xdp_action::XDP_PASS),
        Some(ACTION_LOG) => Ok(xdp_action::XDP_PASS), // Log-only: allow for now
        None => Ok(xdp_action::XDP_PASS), // Explicit: no rule matched, allow
        _ => Ok(xdp_action::XDP_PASS), // Safety: unknown action, allow
    }
}

fn increment_stat(key: u32) {
    unsafe {
        if let Some(current) = STATS_MAP.get(&key) {
            let new_value = *current + 1;
            let _ = STATS_MAP.insert(&key, &new_value, 0);
        } else {
            let _ = STATS_MAP.insert(&key, &1u64, 0);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
