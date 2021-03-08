/*
In this module the packet filtering is preformed.
*/
#include "filter.h"
#include "fw.h"
#include "logger.h"
#include "parser.h"
#include "proxy.h"
#include "ruler.h"
#include "tracker.h"

#include <linux/time.h>

static int debug_time = 0;

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

    if (prefix_size == PREFIX_IP_ANY)
    {
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

/*
 * Create log_row template from a packet
 * The struct (log_row_t) is returned in a statically allocated buffer,
 * which subsequent filter calls will overwrite.
 */
void get_log_row(const packet_t *packet, log_row_t *log_row)
{
    // Fill the current time
    struct timespec ts;
    getnstimeofday(&ts);
    log_row->timestamp = ts.tv_sec;

    log_row->src_ip = packet->src_ip;
    log_row->dst_ip = packet->dst_ip;
    log_row->protocol = packet->protocol;
    log_row->src_port = packet->src_port;
    log_row->dst_port = packet->dst_port;

    // Count field may be irrelevant (in case the log entry already exists)
    // *** If the packet is starting TCP connection then it dosen't counted
    log_row->count = (packet->type == PACKET_TYPE_TCP) ? 0 : 1;

    // action, reason fields will be filled according to the match
}

unsigned int stateless_filter(packet_t *packet, log_row_t *log_row)
{

    // Get the head of the rule table, and iterate over the rules
    // Note that we aren't supposed to change the rules here, hence the const keyword
    const rule_t *const rules = get_rules();
    const rule_t *rule;
    __u8 rule_index;

    // If the rule table is inactive, then accept automatically (and log the action).
    if (is_active_table() == INACTIVE)
    {
        DINFO("Rule table inactive")

        log_action(log_row, NF_ACCEPT, REASON_FW_INACTIVE);
        return NF_ACCEPT;
    }

    for (rule_index = 0; rule_index < get_rules_amount(); rule_index++)
    {
        rule = rules + rule_index;

        if (is_rule_match(packet, rules + rule_index))
        {
            // There is a match! Let's log the action
            __u8 verdict = rule->action;
            DINFO("static filter: rule_index = %d, verdict = %d", rule_index, verdict)

            log_action(log_row, verdict, rule_index);
            return verdict;
        }
    }

    // In case no rule matched, we drop the packet
    DINFO("static filter: no match")

    log_action(log_row, NF_DROP, REASON_NO_MATCHING_RULE);
    return NF_DROP;
}

/**
 * We perform here the packet inspecting (including filtering)
 */
unsigned int fw_inspect(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Allocate firewall structs
    packet_t packet;
    connection_t *conn;
    log_row_t log_row;

    // Alocate auxiliary variables
    const struct tcphdr *tcph;
    int ret;
    
    if (debug_time) {
        return NF_ACCEPT;
    }

    // Get the required packet fields. The fields should not be changed throughout the filtering.
    parse_packet(&packet, skb, state);
    
    // Get connection entry
    conn = find_connection(&packet);

    // Get the log_row fields from the packet
    get_log_row(&packet, &log_row);

    // Special actions: (depending on the packet's type)
    switch (packet.type)
    {
    case PACKET_TYPE_LOOPBACK:
        return NF_ACCEPT; // Accept any loopback (127.0.0.1/8) packet without logging it

    case PACKET_TYPE_FW:
        return NF_ACCEPT; // Accept any packet designated to the firewall

    case PACKET_TYPE_OTHER_PROTOCOL:
        return NF_ACCEPT; // Accept any non TCP, UDP and ICMP protocol without logging it

    default:
        break; // This a regular packet-> Let's look for a match with a rule!
    }
    
    // Ignoring packets from unintended interfaces
    if (packet.direction == DIRECTION_NONE) {
        return NF_ACCEPT;
    }
    
    print_packet(&packet); // Debug

    // Routing intended TCP packets for proxy connections
    if (packet.type == PACKET_TYPE_TCP && proxy_route(&packet))
    {
        log_action(&log_row, NF_ACCEPT, REASON_TCP_PROXY);        
        return NF_ACCEPT;
    }

    // Local-out hook is non-relevant anymore - accept by default
    if (packet.hooknum == NF_INET_LOCAL_OUT)
    {
        return NF_ACCEPT;
    }
    // Now we are dealing with pre-route hook !

    // If it's non TCP packet, do statless filtering
    if (packet.type != PACKET_TYPE_TCP)
    {
        return stateless_filter(&packet, &log_row);
    }
    // Now we are sure it's a TCP packet !

    // Drop any Christmas tree packet
    if (is_xmas_packet(skb))
    {
        DINFO("Verdict: xmas packet")
        log_action(&log_row, NF_DROP, REASON_XMAS_PACKET);
        return NF_DROP;
    }

    // Check if the connection exists
    if (conn == NULL)
    {
        // Check if it's a desired syn packet
        if (is_syn_packet(skb))
        {
            // Statless filtering
            __u8 verdict = stateless_filter(&packet, &log_row);

            if (verdict == NF_DROP)
            {
                return NF_DROP;
            }

            // Add the connection
            DINFO("Creates a connection")
            conn = add_connection(&packet);

            // If proxy then setup proxy connection
            if (proxy_setup(&packet, conn))
            {
                return NF_ACCEPT;
            }
        }

        else
        {
            DINFO("Verdict: connection dosen't exist")
            log_action(&log_row, NF_DROP, REASON_TCP_STREAM_ENFORCE);
            return NF_DROP;
        }
    }
    // Now we are sure the connection exists -
    // Let's perform statefull inspection
    
    tcph = tcp_hdr(skb);

    DINFO("Before enforcing: %s, Expect %s", conn_status_str(conn->state.status),
          direction_str(conn->state.expected_direction));

    DINFO("tcp filter: direction=%s, src_ip=%d.%d.%d.%d, src_port=%d, dst_ip=%d.%d.%d.%d, dst_port=%d, syn=%d, "
          "ack=%d, fin=%d",
          direction_str(packet.direction), IP_PARTS(packet.src_ip), packet.src_port, IP_PARTS(packet.dst_ip),
          packet.dst_port, tcph->syn, tcph->ack, tcph->fin)

    ret = enforce_state(tcph, packet.direction, &conn->state);

    DINFO("Enforce answer: %d", ret)

    switch (ret)
    {
    case 2:
        remove_connection(conn);
    case 0:
        if (escape_ftp_data(&packet, conn))
        {
            log_action(&log_row, NF_ACCEPT, REASON_FTP_DATA_SESSION);
        }
        else
        {
            log_action(&log_row, NF_ACCEPT, REASON_TCP_STREAM_ENFORCE);
        }
        return NF_ACCEPT;
    case 1:
        log_action(&log_row, NF_DROP, REASON_TCP_STREAM_ENFORCE);
        return NF_DROP;
    }

    return NF_DROP; // Done !
}