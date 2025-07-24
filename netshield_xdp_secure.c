#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netshield_common.h"

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Security constants
#define NETSHIELD_MAGIC 0x4E455453 // "NETS"
#define MAX_PACKET_SIZE 1514       // Max size Ethernet
#define MIN_IP_HEADER_LEN 20

// Packet information structure
struct packet_info {
    __u32 src_ip;         // → Address IPv4 in network byte order
    __u32 dest_ip;
    __u16 src_port;       // → Port TCP/UDP in network byte order
    __u16 dest_port;
    __u8 protocol;        // → Protocole IP (TCP=6, UDP=17, ICMP=1...)
    __u8 padding[3];
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
    __u8 padding;          // Always leave padding for alignment to 4/8 bytes
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

// Fonction stats optimized to avoid race conditions
static __always_inline void stats_inc_safe(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&security_stats, &index);
    if (count) {
        // Atomic operation usage
        __sync_fetch_and_add(count, 1);
    } else {
        // Initialization if absent
        __u64 initial_val = 1;
        bpf_map_update_elem(&security_stats, &index, &initial_val, BPF_NOEXIST);
    }
}

static __always_inline int parse_packet_secure(struct xdp_md *ctx, struct packet_info *info) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Verification minimal packet size
    if (data + MIN_IP_HEADER_LEN + sizeof(struct ethhdr) > data_end) {
        return 0;
    }

    struct ethhdr *eth = data;
    // Vérification bounds stricte
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    // Verification IPv4 protocol only
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return 0;
    }

    struct iphdr *ip = (void *)(eth + 1);
    // Double verification with IP length calculation
    __u8 ip_header_len = (ip->ihl & 0x0F) * 4;
    if (ip_header_len < MIN_IP_HEADER_LEN ||
        (void *)ip + ip_header_len > data_end) {
        return 0;
    }

    info->src_ip = ip->saddr;
    info->dest_ip = ip->daddr;
    info->protocol = ip->protocol;
    info->src_port = 0;
    info->dest_port = 0;

    // Parsing secure TCP/UDP ports
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_header_len;
        if ((void *)(tcp + 1) <= data_end) {
            info->src_port = bpf_ntohs(tcp->source);
            info->dest_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_header_len;
        if ((void *)(udp + 1) <= data_end) {
            info->src_port = bpf_ntohs(udp->source);
            info->dest_port = bpf_ntohs(udp->dest);
        }
    }

    return 1;
}

static __always_inline int apply_rules_optimized(struct packet_info *info) {
    struct secure_rule *rule;
    __u32 k;

    k = 0;
    rule = bpf_map_lookup_elem(&secure_rules_map, &k);
    if (rule && rule->magic == NETSHIELD_MAGIC && rule->enabled &&
        (rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
        (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
        (rule->protocol == 0 || rule->protocol == info->protocol))
    {
        if (rule->action == 1) { stats_inc_safe(STAT_PACKETS_DROPPED); return XDP_DROP; }
        else                  { stats_inc_safe(STAT_PACKETS_ALLOWED); return XDP_PASS; }
    }
    k = 1;
    rule = bpf_map_lookup_elem(&secure_rules_map, &k);
    if (rule && rule->magic == NETSHIELD_MAGIC && rule->enabled &&
        (rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
        (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
        (rule->protocol == 0 || rule->protocol == info->protocol))
    {
        if (rule->action == 1) { stats_inc_safe(STAT_PACKETS_DROPPED); return XDP_DROP; }
        else                  { stats_inc_safe(STAT_PACKETS_ALLOWED); return XDP_PASS; }
    }
    k = 2;
    rule = bpf_map_lookup_elem(&secure_rules_map, &k);
    if (rule && rule->magic == NETSHIELD_MAGIC && rule->enabled &&
        (rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
        (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
        (rule->protocol == 0 || rule->protocol == info->protocol))
    {
        if (rule->action == 1) { stats_inc_safe(STAT_PACKETS_DROPPED); return XDP_DROP; }
        else                  { stats_inc_safe(STAT_PACKETS_ALLOWED); return XDP_PASS; }
    }

    // FIXME: Default policy (should be block) : allow
    stats_inc_safe(STAT_PACKETS_ALLOWED);
    return XDP_PASS;
}

SEC("xdp")
int netshield_ebpf_secure(struct xdp_md *ctx) {
    struct packet_info info = {0};

    // Validation context size
    if (!ctx || ctx->data >= ctx->data_end) {
        stats_inc_safe(STAT_INVALID_PACKETS);
        return XDP_ABORTED; // Safer than XDP_DROP
    }

    // Immediate counting
    stats_inc_safe(STAT_PACKETS_PROCESSED);

    // Secure parsing
    if (!parse_packet_secure(ctx, &info)) {
        stats_inc_safe(STAT_INVALID_PACKETS);
        return XDP_PASS; // Allow non-IP packets
    }

    // Application of rules
    return apply_rules_optimized(&info);
}

char LICENSE[] SEC("license") = "GPL";

