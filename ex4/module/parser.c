/*
In this module the socket buffer (packet) is being parsed.
*/
#include "parser.h"

// Allocating struct to hold the inspected packet
static const packet_t empty_packet;

const __be32 LOOPBACK_PREFIX = 0x7F000000; // 127.X.X.X
const __be32 LOOPBACK_MASK = 0xFF000000; // 127.0.0.0

inline __be32 is_loopback(__be32 address)
{
    return (address & LOOPBACK_MASK) == LOOPBACK_PREFIX;
}

inline __u8 involves_fw(__be32 src_ip, __be32 dst_ip)
{
    // return (src_ip == FW_INT_ADRR) || (dst_ip == FW_INT_ADRR) || (src_ip == FW_EXT_ADRR) || (dst_ip == FW_EXT_ADRR);
    return (dst_ip == FW_INT_ADRR) || (dst_ip == FW_EXT_ADRR);
}

direction_t get_direction(const struct nf_hook_state *state)
{
    char *net_in = state->in->name;
    char *net_out = state->out->name;
    
    if ((net_out != NULL && strcmp(net_out, EXT_NET_DEVICE_NAME) == 0) || (net_in != NULL && strcmp(net_in, INT_NET_DEVICE_NAME) == 0))
    {
        return DIRECTION_OUT; // Coming from inside to outside = direction out
    }
    if ((net_out != NULL && strcmp(net_out, INT_NET_DEVICE_NAME) == 0) || (net_in != NULL && strcmp(net_in, EXT_NET_DEVICE_NAME) == 0))
    {
        return DIRECTION_IN; // Coming from outside to inside = direction in
    }
    return DIRECTION_NONE;
}

/**
 * Parses socket buffer (packet), and fills the required fields in packet_t structure.
 * In addition, it transfers the data (from netwwork order) to host order
 */
void parse_packet(packet_t *packet, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Alocating headers for network & transport layers
    struct iphdr *packet_ip_header;
    struct tcphdr *packet_tcp_header;
    struct udphdr *packet_udp_header;

    // Initialize packet
    *packet = empty_packet;

    // Set skb, state
    packet->skb = skb;
    packet->state = state;

    // Set the hook num
    packet->hooknum = state->hook;

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
        return;
    }

    // Check if packet sent from /to fw
    if (involves_fw(packet->src_ip, packet->dst_ip))
    {
        packet->type = PACKET_TYPE_FW;
        return;
    }

    // Get transport layer protocol field, and declaring headers
    packet->protocol = packet_ip_header->protocol;
    
    switch (packet->protocol)
    {
    case PROT_ICMP:
        packet->type = PACKET_TYPE_ICMP;
        // Do nothing
        break;

    case PROT_TCP: {
        packet->type = PACKET_TYPE_TCP;

        // Get TCP port fields
        packet_tcp_header = tcp_hdr(skb);
        packet->src_port = ntohs(packet_tcp_header->source);
        packet->dst_port = ntohs(packet_tcp_header->dest);

        // Get the ACK field
        packet->ack = packet_tcp_header->ack ? ACK_YES : ACK_NO;
        break;
    }

    case PROT_UDP: {
        packet->type = PACKET_TYPE_UDP;

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

int is_xmas_packet(const struct sk_buff *skb)
{
    struct tcphdr *tcp_header = tcp_hdr(skb);
    return (tcp_header->fin && tcp_header->urg && tcp_header->psh);
}

int is_syn_packet(const struct sk_buff *skb)
{
    struct tcphdr *tcp_header = tcp_hdr(skb);
    return (tcp_header->syn && !tcp_header->ack);
}

/*
 * For debug purposes
 */
char *direction_str(direction_t direction)
{
    switch (direction)
    {
    case DIRECTION_NONE:
        return "none";
    case DIRECTION_IN:
        return "in";
    case DIRECTION_OUT:
        return "out";
    case DIRECTION_ANY:
        return "any";
    }
    return "";
}

/*
 * For debug purposes
 */
void print_packet(packet_t *packet)
{
    INFO("Packet:\nhooknum = %d, type = %d, direction = %s, src_ip = %d.%d.%d.%d, src_port = % d, dst_ip = "
         "%d.%d.%d.%d, dst_port = % d, protocol = %d",
         packet->hooknum, packet->type, direction_str(packet->direction), IP_PARTS(packet->src_ip), packet->src_port,
         IP_PARTS(packet->dst_ip), packet->dst_port, packet->protocol)
}