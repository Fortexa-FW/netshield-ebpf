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

// Security constants
#define NETSHIELD_MAGIC 0x4E455453  // "NETS"

// Packet information structure
struct packet_info {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8 protocol;
};

// Simplified secure rule structure
struct secure_rule {
    __u32 magic;           // Security magic number
    __u32 source_ip;
    __u32 destination_ip;
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
    __u8 action;           // 0 = allow, 1 = drop
    __u8 enabled;          // Rule enabled flag
    __u8 padding;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct secure_rule);
    __uint(max_entries, 3);  // Only 3 rules to minimize complexity
} secure_rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);  // Minimal stats
} security_stats SEC(".maps");

// Statistics indices
#define STAT_PACKETS_PROCESSED 0
#define STAT_PACKETS_ALLOWED   1
#define STAT_PACKETS_DROPPED   2
#define STAT_INVALID_PACKETS   3

// Helper function to increment statistics
static __always_inline void stats_inc(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&security_stats, &index);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

// Minimal packet parsing
static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_info *info) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return 0;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }
    
    info->src_ip = ip->saddr;
    info->dest_ip = ip->daddr;
    info->protocol = ip->protocol;
    info->src_port = 0;
    info->dest_port = 0;
    
    // Parse ports only for TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            info->src_port = bpf_ntohs(tcp->source);
            info->dest_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            info->src_port = bpf_ntohs(udp->source);
            info->dest_port = bpf_ntohs(udp->dest);
        }
    }
    
    return 1;
}

// Minimal rule matching with security validation
static __always_inline int apply_rules(struct packet_info *info) {
    __u32 key;
    
    // Only check 3 rules to minimize verifier complexity
    for (key = 0; key < 3; key++) {
        struct secure_rule *rule = bpf_map_lookup_elem(&secure_rules_map, &key);
        if (!rule) {
            continue;
        }
        
        // Security check: validate magic number
        if (rule->magic != NETSHIELD_MAGIC) {
            continue;
        }
        
        // Skip disabled rules
        if (!rule->enabled) {
            continue;
        }
        
        // Simple rule matching
        if ((rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
            (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
            (rule->protocol == 0 || rule->protocol == info->protocol)) {
            
            if (rule->action == 1) {  // Drop
                stats_inc(STAT_PACKETS_DROPPED);
                return XDP_DROP;
            } else {  // Allow
                stats_inc(STAT_PACKETS_ALLOWED);
                return XDP_PASS;
            }
        }
    }
    
    // Default: allow
    stats_inc(STAT_PACKETS_ALLOWED);
    return XDP_PASS;
}

SEC("xdp")
int netshield_ebpf_secure(struct xdp_md *ctx) {
    struct packet_info info = {0};
    
    // Count processed packets
    stats_inc(STAT_PACKETS_PROCESSED);
    
    // Parse packet
    if (!parse_packet(ctx, &info)) {
        stats_inc(STAT_INVALID_PACKETS);
        return XDP_DROP;
    }
    
    // Apply security rules
    return apply_rules(&info);
}

char LICENSE[] SEC("license") = "GPL";
