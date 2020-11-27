/*
In this module the packet filtering is preformed.
*/

#include "filter.h"
#include "logger.h"
#include "parser.h"
#include "ruler.h"

// Boolean evaluation: returns 1 (MATCH_TRUE) <--> X is non zero
#define bool_val(X) ((X) ? 1 : 0)

// Create a boolean type.
// Zero value = MATCH_FALSE, Non zero value = MATCH_TRUE
typedef enum
{
    MATCH_FALSE = 0,
    MATCH_TRUE = 1,
} bool_t;

/**
 * Checks whether the network prefixes of 2 IPs are equal.
 * In case rule IP is "any", than prefix_size = 0. Thus the logic remains the same.
 */
inline bool_t is_ip_match(__be32 ip1, __be32 ip2, __u8 prefix_size)
{
    __be32 ip1_prefix, ip2_prefix;
    __u8 host_bits = 32 - prefix_size;

    if (prefix_size == PREFIX_IP_ANY) {
        return MATCH_TRUE;
    }
    
    ip1_prefix = ip1 >> host_bits;
    ip2_prefix = ip2 >> host_bits;
    return bool_val(ip1_prefix == ip2_prefix);
}

/**
 * Checks whether port_p (packet port), port_r (rule port) are equal
 */
inline bool_t is_port_match(__be16 port_p, __be16 port_r)
{
    return bool_val(port_r == PORT_ANY || (port_r == PORT_ABOVE_1023 && port_p > 1023) || port_r == port_p);
}

/**
 * Checks if there is a match between packet and rule
 */
bool_t is_rule_match(const packet_t *packet, const rule_t *rule)
{
    // Define the boolean for each matching factor
    bool_t direction_match;
    bool_t src_ip_match;
    bool_t dst_ip_match;
    bool_t protocol_match;
    bool_t src_port_match;
    bool_t dst_port_match;
    bool_t ack_match;

    // Checks the if direction match
    direction_match = bool_val(packet->direction & rule->direction);
    if (direction_match == MATCH_FALSE)
    {
        return MATCH_FALSE;
    }

    // Checks if the IP addresses match
    src_ip_match = is_ip_match(packet->src_ip, rule->src_ip, rule->src_prefix_size);
    dst_ip_match = is_ip_match(packet->dst_ip, rule->dst_ip, rule->dst_prefix_size);
    if (src_ip_match == MATCH_FALSE || dst_ip_match == MATCH_FALSE)
    {
        return MATCH_FALSE;
    }

    // Checks if the protocol match
    protocol_match = bool_val(rule->protocol == PROT_ANY || packet->protocol == rule->protocol);
    if (protocol_match == MATCH_FALSE)
    {
        return MATCH_FALSE;
    }

    // Different behavior for each protocol type
    if (packet->protocol == PROT_ICMP)
    {
        // There is an ICMP match!
        return MATCH_TRUE;
    }
    else
    {
        // In that case the protocol is TCP or UDP, hence it has ports.
        // Lets check if the ports match
        src_port_match = is_port_match(packet->src_port, rule->src_port);
        dst_port_match = is_port_match(packet->dst_port, rule->dst_port);
        if (src_port_match == MATCH_FALSE || dst_port_match == MATCH_FALSE)
        {
            return MATCH_FALSE;
        }

        // Different behavior for TCP, UDP protocols
        if (packet->protocol == PROT_UDP)
        {
            // There is an UDP match!
            return MATCH_TRUE;
        }
        else
        {
            // In that case the protocol is TCP, hence it has an ACK flag.
            ack_match = bool_val(packet->ack & rule->ack);
            if (ack_match == MATCH_FALSE)
            {
                return MATCH_FALSE;
            }

            // There is a TCP match!
            return MATCH_TRUE;
        }
    }
    // Should not reach here (all cases should be covered by now)
    return MATCH_FALSE;
}

/**
 * We perform here the packet filtering for each packet passing through the firewall
 */
unsigned int fw_filtering(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Get the head of the rule table, and iterate over the rules
    // Note that we aren't supposed to change the rules here, hence the const keyword
    const rule_t *const rule_table = get_rules();
    const rule_t *rule;
    __u8 rule_index;

    // Get the required packet fields. The fields should not be changed throughout the filtering.
    const packet_t *packet = parse_packet(skb, state);

    // Special actions: (depending on the packet's type)
    switch (packet->type)
    {
    case PACKET_TYPE_LOOPBACK:
        return NF_ACCEPT; // Accept any loopback (127.0.0.1/8) packet without logging it

    case PACKET_TYPE_OTHER_PROTOCOL:
        return NF_ACCEPT; // Accept any non TCP, UDP and ICMP protocol without logging it

    case PACKET_TYPE_XMAS:
        // *** Log the action here, with reason: "reason_t.REASON_XMAS_PACKET" ***
        return NF_DROP; // Drop any Christmas tree packet

    default:
        break; // This a regular packet (PACKET_REG). Let's look for a match with a rule!
    }

    // If the rule table is inactive, then accept automatically. (and log the action)
    if (!is_active())
    {
        // *** Log the action here, with reason: "reason_t.REASON_FW_INACTIVE" ***
        return NF_ACCEPT;
    }

    for (rule_index = 0; rule_index < get_rules_ammount(); rule_index++)
    {
        rule = rule_table + rule_index;

        if (is_rule_match(packet, rule))
        {
            __u8 verdict = rule->action;
            // *** Log the action here, with reason: "rule_index" ***
            return verdict;
        }
    }

    // In case no rule matched, we drop the packet
    // *** Log the action here, with reason: "reason_t.REASON_NO_MATCHING_RULE" ***
    return NF_DROP;
}