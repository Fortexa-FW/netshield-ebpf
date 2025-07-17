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
            // Security: increment error counter and drop packet
            increment_stat(STAT_INVALID_PACKETS);
            xdp_action::XDP_DROP
        }
    }
}

fn try_netshield_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    // Security check: validate packet size
    let packet_size = ctx.data_end() - ctx.data();
    if packet_size > MAX_PACKET_SIZE as usize {
        return Err(());
    }

    increment_stat(STAT_PACKETS_PROCESSED);

    // Parse packet headers with bounds checking
    let packet_info = match parse_packet_safe(&ctx) {
        Some(info) => info,
        None => {
            increment_stat(STAT_INVALID_PACKETS);
            return Ok(xdp_action::XDP_DROP);
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
                let tcp_hdr = unsafe { &*(transport_offset as *const TcpHdr) };
                // TCP fields are u16 in network byte order
                src_port = u16::from_be(tcp_hdr.source);
                dest_port = u16::from_be(tcp_hdr.dest);
            }
        }
        IpProto::Udp => {
            if transport_offset + core::mem::size_of::<UdpHdr>() <= data_end {
                let udp_hdr = unsafe { &*(transport_offset as *const UdpHdr) };
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
    // For now, implement a simple default policy
    // In a real implementation, you would iterate through rules from RULES_MAP

    // Security: Rate limiting check could go here
    // Security: Suspicious packet patterns could be detected here

    // Example: Drop packets from private IP ranges going to internet
    // (This is just an example - real rules would come from userspace)
    let src_ip = packet_info.src_ip;

    // Check for RFC 1918 private addresses attempting to go to public addresses
    if is_private_ip(src_ip) && !is_private_ip(packet_info.dest_ip) {
        // This might be suspicious - could add logging here if needed
        // Note: aya-log-ebpf logging in newer versions might require context
    }

    // Default policy: allow most traffic (rules would override this)
    Ok(xdp_action::XDP_PASS)
}

fn is_private_ip(ip: u32) -> bool {
    // RFC 1918 private address ranges
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    // Note: ip is already in host byte order from from_be_bytes

    (0x0A000000..=0x0AFFFFFF).contains(&ip) ||  // 10.0.0.0/8
    (0xAC100000..=0xAC1FFFFF).contains(&ip) ||  // 172.16.0.0/12
    (0xC0A80000..=0xC0A8FFFF).contains(&ip) // 192.168.0.0/16
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
