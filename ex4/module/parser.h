/*
In this module we parse a socket buffer (packet).
*/
#ifndef _PARSER_H_
#define _PARSER_H_

#include "fw.h"

#define INT_NET_DEVICE_NAME "enp0s8"
#define EXT_NET_DEVICE_NAME "enp0s9"

#define FW_INT_ADRR 167837955 // 10.1.1.3
#define FW_EXT_ADRR 167838211 // 10.1.2.3

// Classifies packet's type
typedef enum
{
    PACKET_TYPE_ICMP,
    PACKET_TYPE_UDP,
    PACKET_TYPE_TCP,
    PACKET_TYPE_FW,
    PACKET_TYPE_LOOPBACK,
    PACKET_TYPE_OTHER_PROTOCOL,
} packet_type_t;

// Holds packet's fields.
// The fields are stored in host order form.
typedef struct
{
    direction_t direction;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port; // number of port or 0 for any or port 1023 for any port number > 1023
    __be16 dst_port; // number of port or 0 for any or port 1023 for any port number > 1023
    __u8 protocol;   // values from: prot_t
    ack_t ack;       // values from: ack_t
    packet_type_t type;
    unsigned int hooknum;
    struct sk_buff *skb;
    const struct nf_hook_state *state;
} packet_t;

void parse_packet(packet_t *packet, struct sk_buff *skb, const struct nf_hook_state *state);
int is_xmas_packet(const struct sk_buff *skb);
int is_syn_packet(const struct sk_buff *skb);

char *direction_str(direction_t direction);
void print_packet(packet_t *packet);

#endif
