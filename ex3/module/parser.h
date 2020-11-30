/*
In this module we parse a socket buffer (packet).
*/
#ifndef _PARSER_H_
#define _PARSER_H_

#include "fw.h"

#define IN_NET_DEVICE_NAME "enp0s8"
#define OUT_NET_DEVICE_NAME "enp0s9"

// Classifies packet's type
typedef enum
{
    PACKET_TYPE_REG,
    PACKET_TYPE_LOOPBACK,
    PACKET_TYPE_OTHER_PROTOCOL,
    PACKET_TYPE_XMAS,
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
} packet_t;

void parse_packet(packet_t *packet, const struct sk_buff *skb, const struct nf_hook_state *state);

#endif