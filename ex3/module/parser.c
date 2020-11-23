/*
In this module the packet filtering is done.
*/
#include "parser.h"

// Allocating struct to hold the inspected packet
static packet_t packet;
static const packet_t empty_packet;

const __be32 LOOPBACK_SUBNET = 0x7F000000;
const __be32 LOOPBACK_MASK = 0xFFFFFF00;

inline __be32 is_loopback(__be32 address)
{
    return (address & LOOPBACK_MASK) == LOOPBACK_SUBNET;
}

direction_t get_direction(nf_hook_state *state)
{
    char *net_in = state->in->name;
    char *net_out = state->in->name;
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

/*
    Parses socket buffer (packet), fills the required fields in packet_t structure, and returns it.
    In addition, it transfers the data (from netwwork order) to host order 
*/
packet_t *parse_packet(const struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Initialize packet
    packet = empty_packet;
    packet.type = PACKET_REG;

    // Get direction field
    packet.direction = get_direction(state);

    // Get IP fields
    struct iphdr *packet_ip_header = ip_hdr(skb);
    packet.src_ip = ntohl(packet_ip_header->saddr);
    packet.dst_ip = ntohl(packet_ip_header->daddr);

    // Check for loopback packet
    if (is_loopback(packet.src_ip) || is_loopback(packet.dst_ip))
    {
        packet.type = PACKET_LOOPBACK;
    }

    // Get protocol field
    packet.protocol = packet_ip_header->protocol;

    switch (packet.protocol)
    {
    case PROT_ICMP:
        // Do nothing
        break;

    case PROT_TCP:
    {
        // Get TCP port fields
        struct tcphdr *packet_tcp_header = tcp_hdr(skb);
        packet.src_port = ntohs(packet_tcp_header->source);
        packet.dst_port = ntohs(packet_tcp_header->dest);

        // Get the ACK field
        packet.ack = packet_tcp_header->ack ? ACK_YES : ACK_NO;

        // Check for Christmas tree packet
        if (packet_tcp_header->fin && packet_tcp_header->urg && packet_tcp_header->psh)
        {
            packet.type = PACKET_XMAS;
        }

        break;
    }

    case PROT_UDP:
    {
        // Get UDP port fields
        struct udphdr *packet_udp_header = udp_hdr(skb);
        packet.src_port = ntohs(packet_udp_header.source);
        packet.dst_port = ntohs(packet_udp_header.dest);
        break;
    }

    default:
        // Unsupported protocol
        packet.type = PACKET_OTHER_PROTOCOL;
        break;
    }

    return packet;
}