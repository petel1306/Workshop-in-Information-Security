/*
In this module the socket buffer (packet) is being parsed.
*/
#include "parser.h"

// Allocating struct to hold the inspected packet
static const packet_t empty_packet;

const __be32 LOOPBACK_PREFIX = 0x7F000000;
const __be32 LOOPBACK_MASK = 0xFF000000;

inline __be32 is_loopback(__be32 address)
{
    return (address & LOOPBACK_MASK) == LOOPBACK_PREFIX;
}

direction_t get_direction(const struct nf_hook_state *state)
{
    char *net_in = state->in->name;
    char *net_out = state->out->name;
    if (strcmp(net_in, IN_NET_DEVICE_NAME) && strcmp(net_out, OUT_NET_DEVICE_NAME))
    {
        return DIRECTION_OUT; // Coming from inside to outside = direction out
    }
    if (strcmp(net_in, OUT_NET_DEVICE_NAME) && strcmp(net_out, IN_NET_DEVICE_NAME))
    {
        return DIRECTION_IN; // Coming from outside to inside = direction in
    }
    return DIRECTION_NONE;
}

/**
 * Parses socket buffer (packet), and fills the required fields in packet_t structure.
 * In addition, it transfers the data (from netwwork order) to host order
 */
void parse_packet(packet_t *packet, const struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Alocating headers for network & transport layers
    struct iphdr *packet_ip_header;
    struct tcphdr *packet_tcp_header;
    struct udphdr *packet_udp_header;

    // Initialize packet
    *packet = empty_packet;
    packet->type = PACKET_TYPE_REG;

    // Get direction field
    packet->direction = get_direction(state);

    // Get IP fields
    packet_ip_header = ip_hdr(skb);
    packet->src_ip = ntohl(packet_ip_header->saddr);
    packet->dst_ip = ntohl(packet_ip_header->daddr);

    // Check for loopback packet
    if (is_loopback(packet->src_ip) || is_loopback(packet->dst_ip))
    {
        packet->type = PACKET_TYPE_LOOPBACK;
    }

    // Get transport layer protocol field, and declaring headers
    packet->protocol = packet_ip_header->protocol;

    switch (packet->protocol)
    {
    case PROT_ICMP:
        // Do nothing
        break;

    case PROT_TCP: {
        // Get TCP port fields
        packet_tcp_header = tcp_hdr(skb);
        packet->src_port = ntohs(packet_tcp_header->source);
        packet->dst_port = ntohs(packet_tcp_header->dest);

        // Get the ACK field
        packet->ack = packet_tcp_header->ack ? ACK_YES : ACK_NO;

        // Check for Christmas tree packet
        if (packet_tcp_header->fin && packet_tcp_header->urg && packet_tcp_header->psh)
        {
            packet->type = PACKET_TYPE_XMAS;
        }

        break;
    }

    case PROT_UDP: {
        // Get UDP port fields
        packet_udp_header = udp_hdr(skb);
        packet->src_port = ntohs(packet_udp_header->source);
        packet->dst_port = ntohs(packet_udp_header->dest);
        break;
    }

    default:
        // Unsupported protocol
        packet->type = PACKET_TYPE_OTHER_PROTOCOL;
        break;
    }
}