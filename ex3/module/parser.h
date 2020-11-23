#ifndef _PARSER_H_
#define _PARSER_H_

#include "fw.h"

// classifies packet type
typedef enum {
	PACKET_REG,
	PACKET_LOOPBACK,
	PACKET_OTHER_PROTOCOL,
	PACKET_XMAS,
} packet_type_t;

// Holds packet fields.
// The fields are maintained in host order.
typedef struct
{
	direction_t direction;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port; // number of port or 0 for any or port 1023 for any port number > 1023
	__be16 dst_port; // number of port or 0 for any or port 1023 for any port number > 1023
	__u8 protocol;   // values from: prot_t
	ack_t ack;		 // values from: ack_t
	packet_type_t type;
} packet_t;

void parse_packet(const struct sk_buff *skb, const struct nf_hook_state *state, packet_t *packet);

#endif