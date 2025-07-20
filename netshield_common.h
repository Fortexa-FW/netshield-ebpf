#ifndef NETSHIELD_COMMON_H
#define NETSHIELD_COMMON_H

#include <linux/types.h>

// Rule structure - must match Rust NetshieldRule serialization format
struct netshield_rule {
    __u32 id;
    __u8 enabled;
    __u8 direction;         // 0 = Incoming, 1 = Outgoing  
    __u8 action;           // 0 = Block, 1 = Allow, 2 = Drop, 3 = Accept, 4 = Log
    __u8 protocol;         // IP protocol (TCP=6, UDP=17), 0 for any
    __u32 source_ip;       // IPv4 address in network byte order, 0 for any
    __u32 destination_ip;  // IPv4 address in network byte order, 0 for any
    __u16 source_port;     // Port number in host byte order, 0 for any
    __u16 destination_port; // Port number in host byte order, 0 for any
    __u32 priority;        // Rule priority (lower = higher priority)
    // Total size: 24 bytes (well within eBPF limits)
} __attribute__((packed));

// Action constants
#define NETSHIELD_ACTION_BLOCK  0
#define NETSHIELD_ACTION_ALLOW  1  
#define NETSHIELD_ACTION_DROP   2
#define NETSHIELD_ACTION_ACCEPT 3
#define NETSHIELD_ACTION_LOG    4

// Direction constants  
#define NETSHIELD_DIRECTION_INCOMING 0
#define NETSHIELD_DIRECTION_OUTGOING 1
#define NETSHIELD_DIRECTION_BOTH     2

// Protocol constants
#define NETSHIELD_PROTOCOL_ANY  0
#define NETSHIELD_PROTOCOL_TCP  6
#define NETSHIELD_PROTOCOL_UDP  17
#define NETSHIELD_PROTOCOL_ICMP 1

// Statistics constants
#define NETSHIELD_STAT_PACKETS_PROCESSED 0
#define NETSHIELD_STAT_PACKETS_DROPPED   1
#define NETSHIELD_STAT_PACKETS_PASSED    2
#define NETSHIELD_STAT_INVALID_PACKETS   3
#define NETSHIELD_STAT_RULES_MATCHED     4

// Limits
#define NETSHIELD_MAX_RULES 1000
#define NETSHIELD_MAX_PACKET_SIZE 1514

#endif // NETSHIELD_COMMON_H
