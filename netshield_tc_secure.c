#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>  // Pour TC_ACT_OK/SHOT etc.
#include "netshield_common.h"

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Security constants
#define NETSHIELD_MAGIC 0x4E455453 // "NETS"
#define MAX_PACKET_SIZE 1514
#define MIN_IP_HEADER_LEN 20

// Packet information structure
struct packet_info {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8 protocol;
    __u8 padding[3];
};

struct secure_rule {
    __u32 magic;
    __u32 source_ip;
    __u32 destination_ip;
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
    __u8 action;    // 0 = allow, 1 = drop
    __u8 enabled;
    __u8 padding;
};

// Maps for secure rules and statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct secure_rule);
    __uint(max_entries, 3);
} secure_rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} security_stats SEC(".maps");

// Stats indices
#define STAT_PACKETS_PROCESSED 0
#define STAT_PACKETS_ALLOWED   1
#define STAT_PACKETS_DROPPED   2
#define STAT_INVALID_PACKETS   3

static __always_inline void stats_inc_safe(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&security_stats, &index);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_val = 1;
        bpf_map_update_elem(&security_stats, &index, &initial_val, BPF_NOEXIST);
    }
}

static __always_inline int parse_packet_secure(struct __sk_buff *skb, struct packet_info *info) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + MIN_IP_HEADER_LEN + sizeof(struct ethhdr) > data_end)
        return 0;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    __u8 ip_header_len = (ip->ihl & 0x0F) * 4;
    if (ip_header_len < MIN_IP_HEADER_LEN ||
        (void *)ip + ip_header_len > data_end)
        return 0;

    bpf_printk("Original IPs: src=%u, dest=%u", ip->saddr, ip->daddr);

    // Convert IP addresses from network byte order to host byte order to match Rust
    info->src_ip = bpf_ntohl(ip->saddr);
    info->dest_ip = bpf_ntohl(ip->daddr);
    info->protocol = ip->protocol;
    info->src_port = 0;
    info->dest_port = 0;

    bpf_printk("Packet IPs in host order: src=0x%x, dest=0x%x", info->src_ip, info->dest_ip);

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

    bpf_printk("Packet Info: src_ip=0x%x, dest_ip=0x%x", info->src_ip, info->dest_ip);

    k = 0;
    rule = bpf_map_lookup_elem(&secure_rules_map, &k);
    if (rule) {
        bpf_printk("Rule 0: magic=0x%x, enabled=%u, src=0x%x, dest=0x%x, proto=%u, action=%u",
                   rule->magic, rule->enabled, rule->source_ip, rule->destination_ip, rule->protocol, rule->action);
    }
    if (rule && rule->magic == NETSHIELD_MAGIC && rule->enabled &&
        (rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
        (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
        (rule->protocol == 0 || rule->protocol == info->protocol))
    {
        if (rule->action == 1) { stats_inc_safe(STAT_PACKETS_DROPPED); return TC_ACT_SHOT; }
        else                  { stats_inc_safe(STAT_PACKETS_ALLOWED); return TC_ACT_OK; }
    }
    k = 1;
    rule = bpf_map_lookup_elem(&secure_rules_map, &k);
    if (rule) {
        bpf_printk("Rule 1: magic=0x%x, enabled=%u, src=0x%x, dest=0x%x, proto=%u, action=%u",
                   rule->magic, rule->enabled, rule->source_ip, rule->destination_ip, rule->protocol, rule->action);
    }
    if (rule && rule->magic == NETSHIELD_MAGIC && rule->enabled &&
        (rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
        (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
        (rule->protocol == 0 || rule->protocol == info->protocol))
    {
        if (rule->action == 1) { stats_inc_safe(STAT_PACKETS_DROPPED); return TC_ACT_SHOT; }
        else                  { stats_inc_safe(STAT_PACKETS_ALLOWED); return TC_ACT_OK; }
    }
    k = 2;
    rule = bpf_map_lookup_elem(&secure_rules_map, &k);
    if (rule) {
        bpf_printk("Rule 2: magic=0x%x, enabled=%u, src=0x%x, dest=0x%x, proto=%u, action=%u",
                   rule->magic, rule->enabled, rule->source_ip, rule->destination_ip, rule->protocol, rule->action);
    }
    if (rule && rule->magic == NETSHIELD_MAGIC && rule->enabled &&
        (rule->source_ip == 0 || rule->source_ip == info->src_ip) &&
        (rule->destination_ip == 0 || rule->destination_ip == info->dest_ip) &&
        (rule->protocol == 0 || rule->protocol == info->protocol))
    {
        if (rule->action == 1) { stats_inc_safe(STAT_PACKETS_DROPPED); return TC_ACT_SHOT; }
        else                  { stats_inc_safe(STAT_PACKETS_ALLOWED); return TC_ACT_OK; }
    }

    // Default policy : allow (can change to block if preferred)
    stats_inc_safe(STAT_PACKETS_ALLOWED);
    return TC_ACT_OK;
}

// ********* TC EBPF Module *********
SEC("classifier")
int netshield_ebpf_tc(struct __sk_buff *skb)
{
    struct packet_info info = {0};

    // Pas de test sur !skb: struct __sk_buff toujours valide
    stats_inc_safe(STAT_PACKETS_PROCESSED);

    if (!parse_packet_secure(skb, &info)) {
        stats_inc_safe(STAT_INVALID_PACKETS);
        return TC_ACT_OK; // Pass non-IP
    }

    return apply_rules_optimized(&info);
}

char LICENSE[] SEC("license") = "GPL";
