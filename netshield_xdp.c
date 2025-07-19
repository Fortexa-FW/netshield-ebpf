#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "netshield_common.h"

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct netshield_rule);
    __uint(max_entries, NETSHIELD_MAX_RULES);
} rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} stats_map SEC(".maps");

// Packet information structure
struct packet_info {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8 protocol;
    __u16 packet_size;
};

// Helper function to update statistics
static __always_inline void update_stat(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) {
        (*count)++;
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&stats_map, &key, &init_count, BPF_ANY);
    }
}

// Parse packet to extract relevant information
static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_info *info) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Initialize packet info
    __builtin_memset(info, 0, sizeof(*info));
    
    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0; // Not IPv4, allow by default
        
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
        
    info->src_ip = ip->saddr;
    info->dest_ip = ip->daddr;
    info->protocol = ip->protocol;
    info->packet_size = bpf_ntohs(ip->tot_len);
    
    // Parse transport layer ports
    void *transport_header = (void *)ip + (ip->ihl * 4);
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_header;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        info->src_port = bpf_ntohs(tcp->source);
        info->dest_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_header;
        if ((void *)(udp + 1) > data_end)
            return -1;
        info->src_port = bpf_ntohs(udp->source);
        info->dest_port = bpf_ntohs(udp->dest);
    }
    // For other protocols, ports remain 0
    
    return 1; // Valid packet
}

// Apply filtering rules to packet
static __always_inline int apply_rules(struct packet_info *info) {
    struct netshield_rule *rule;
    __u32 key;
    int matched_action = -1;
    
    // Iterate through rules (reduced limit for eBPF verifier)
    #pragma unroll
    for (key = 0; key < 10; key++) {  // Reduced from 100 to 10 to stay under instruction limit
        rule = bpf_map_lookup_elem(&rules_map, &key);
        if (!rule)
            continue;
        
        // Skip disabled rules
        if (!rule->enabled)
            continue;
            
        // Check rule matching (simplified for performance)
        if ((rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
            (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
            (rule->source_port == 0 || rule->source_port == info->src_port) &&
            (rule->destination_port == 0 || rule->destination_port == info->dest_port) &&
            (rule->protocol == 0 || rule->protocol == info->protocol)) {
            
            // Rule matches
            matched_action = rule->action;
            break;
        }
    }
    
    // Default behavior: ALLOW if no rules found or no match
    if (matched_action == -1) {
        return XDP_PASS; // Allow by default
    }
    
    // Convert action to XDP action
    switch (matched_action) {
        case NETSHIELD_ACTION_BLOCK:
        case NETSHIELD_ACTION_DROP:
            return XDP_DROP;
        case NETSHIELD_ACTION_ALLOW:
        case NETSHIELD_ACTION_ACCEPT:
        case NETSHIELD_ACTION_LOG:
        default:
            return XDP_PASS;
    }
}

// Main XDP program
SEC("xdp")
int netshield_ebpf(struct xdp_md *ctx) {
    struct packet_info info;
    int parse_result;
    int action;
    
    // Update packet processed counter
    update_stat(NETSHIELD_STAT_PACKETS_PROCESSED);
    
    // Parse packet
    parse_result = parse_packet(ctx, &info);
    if (parse_result < 0) {
        // Invalid packet
        update_stat(NETSHIELD_STAT_INVALID_PACKETS);
        return XDP_PASS; // Allow malformed packets (defensive)
    }
    
    if (parse_result == 0) {
        // Non-IPv4 packet, allow by default
        update_stat(NETSHIELD_STAT_PACKETS_PASSED);
        return XDP_PASS;
    }
    
    // Apply filtering rules
    action = apply_rules(&info);
    
    // Update statistics
    if (action == XDP_DROP) {
        update_stat(NETSHIELD_STAT_PACKETS_DROPPED);
    } else {
        update_stat(NETSHIELD_STAT_PACKETS_PASSED);
    }
    
    return action;
}

// License required for eBPF programs
char _license[] SEC("license") = "GPL";
