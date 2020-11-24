/*
In this module the packet filtering is preformed.
*/

#include "filter.h"
#include "parser.h"
#include "ruler.h"
#include "logger.h"

// Boolean evaluation: returns 1 (true) <--> X is non zero
#define bool_val(X) ((X) ? 1 : 0)

// Create a boolean type.
// Zero value = false, Non zero value = true
typedef enum {
    false = 0,
    true = 1,
} bool_t;

/**
 * Checks whether the network prefixes of 2 IPs are equal.
 * In case rule IP is "any", than prefix_size = 0. Thus the logic remains the same.
 */
inline bool_t is_ip_match(__be32 ip1, __be32 ip2, __u8 prefix_size)
{
    __u8 host_bits = 32 - prefix_size;
    __be32 ip1_prefix = ip1 >> host_bits;
    __be32 ip2_prefix = ip2 >> host_bits;
    return bool_val(ip1_prefix == ip2_prefix);
}

/**
 * Checks whether port_p (packet port), port_r (rule port) are equal
 */
inline bool_t is_port_match(__be16 port_p, __be16 port_r)
{
    return bool_val(port_r == PORT_ANY || port_p == port_r);
}

/**
 * Checks if there is a match between packet and rule
 */
bool_t is_rule_match(const packet_t *packet, const rule_t *rule)
{

    // Checks the if direction match
    bool_t direction_match = bool_val(packet->direction & rule->direction);
    if (direction_match == false)
    {
        return false;
    }

    // Checks if the IP addresses match
    bool_t src_ip_match = is_ip_match(packet->src_ip, rule->src_ip, rule->src_prefix_size);
    bool_t dst_ip_match = is_ip_match(packet->dst_ip, rule->dst_ip, rule->dst_prefix_size);
    if (src_ip_match == false || dst_ip_match == false)
    {
        return false;
    }

    // Checks if the protocol match
    bool_t protocol_match = bool_val(rule->protocol == PROT_ANY || packet->protocol == rule->protocol);
    if (protocol_match == false)
    {
        return false;
    }

    prot_t protocol = packet->protocol;

    // Different behavior for each protocol type
    if (protocol == PROT_ICMP)
    {
        // There is an ICMP match!
        return true;
    }
    else
    {
        // In that case the protocol is TCP or UDP, hence it has ports.
        // Lets check if the ports match
        bool_t src_port_match = is_port_match(packet->src_port, rule->src_port);
        bool_t dst_port_match = is_port_match(packet->dst_port, rule->dst_port);
        if (src_port_match == false || dst_port_match == false)
        {
            return false;
        }

        // Different behavior for TCP, UDP protocols
        if (protocol == UDP)
        {
            // There is an UDP match!
            return true;
        }
        else
        {
            // In that case the protocol is TCP, hence it has an ACK flag.
            bool_t ack_match = bool_val(packet->ack & rule->ack);
            if (ack_match == false)
            {
                return false;
            }
            
            // There is a TCP match!
            return true;
        }
    }
    // Should not reach here (all cases should be covered by now)
    return false;
}

/**
 * We perform here the packet filtering for each packet passing through the firewall
 */
static unsigned int fw_filtering(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Get the required packet fields. The fields should not be changed throughout the filtering.
    const packet_t *packet = parse_packet(skb, state);

    // Special actions: (depending on the packet's type)
    switch (packet->type)
    {
    case PACKET_LOOPBACK:
        // Accept any loopback (127.0.0.1/8) packet without logging it
        return NF_ACCEPT;

    case PACKET_OTHER_PROTOCOL:
        // Accept any non TCP, UDP and ICMP protocol without logging it
        return NF_ACCEPT;

    case PACKET_XMAS:
        // Drop any Christmas tree packet
        // *** Log the action here, with reason: "reason_t.REASON_XMAS_PACKET" ***
        return NF_DROP;

    default:
        // This a regular packet (PACKET_REG). Let's look for a match with a rule!
    }

    // Get the head of the rule table, and iterate over the rules
    // Note that we aren't supposed to change the rules here, hence the const keyword
    const rule_t *const rule_table = get_rules();
    const rule_t *rule;

    for (__u8 rule_index = 0; rule_index < get_rules_ammount(); rule_index++)
    {
        rule = rule_table + rule_index;

        bool_t rule_match = is_rule_match(packet, rule);
        if (rule_match)
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