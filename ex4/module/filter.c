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
    log_row->count = 1;

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
            log_action(log_row, verdict, rule_index);

            INFO("static filter : direction=%s, src_ip = %d.%d.%d.%d, src_port = % d, dst_ip = %d.%d.%d.%d, dst_port = "
                 "% d, protocol = %d, rule_index = %d",
                 direction_str(packet->direction), IP_PARTS(packet->src_ip), packet->src_port, IP_PARTS(packet->dst_ip),
                 packet->dst_port, packet->protocol, rule_index)

            return verdict;
        }
    }

    // In case no rule matched, we drop the packet
    log_action(log_row, NF_DROP, REASON_NO_MATCHING_RULE);
    return NF_DROP;
}

/**
 * We perform here the packet filtering for each packet passing through the firewall
 */
unsigned int fw_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Allocate firewall vars
    packet_t packet;
    log_row_t log_row;
    id_t client_id;
    connection_t *conn;
    proxy_t *proxy;

    // Get TCP header
    struct tcphdr *tcph = tcp_hdr(skb);
    unsigned int is_syn = tcph->syn && !tcph->ack;

    // Get the required packet fields. The fields should not be changed throughout the filtering.
    parse_packet(&packet, skb, state);

    // Get connection entry
    conn = find_connection(&packet);

    // Get client id (in case proxy)
    get_client_id(&packet, &client_id);

    // Get proxy entry
    proxy = find_proxy_by_client(client_id);

    // Get the log_row fields from the packet
    get_log_row(&packet, &log_row);

    INFO("static filter : type = %d, direction = %s, src_ip = %d.%d.%d.%d, src_port = % d, dst_ip = %d.%d.%d.%d, "
         "dst_port = % d, protocol = %d",
         packet.type, direction_str(packet.direction), IP_PARTS(packet.src_ip), packet.src_port,
         IP_PARTS(packet.dst_ip), packet.dst_port, packet.protocol)

    // Special actions: (depending on the packet's type)
    switch (packet.type)
    {
    case PACKET_TYPE_LOOPBACK:
        return NF_ACCEPT; // Accept any loopback (127.0.0.1/8) packet without logging it

    case PACKET_TYPE_FW:
        return NF_ACCEPT; // Accept any packet designated to the firewall

    case PACKET_TYPE_OTHER_PROTOCOL:
        return NF_ACCEPT; // Accept any non TCP, UDP and ICMP protocol without logging it

    case PACKET_TYPE_XMAS:
        log_action(&log_row, NF_DROP, REASON_XMAS_PACKET);
        return NF_DROP; // Drop any Christmas tree packet

    default:
        break; // This a regular packet-> Let's look for a match with a rule!
    }

    // Check if the id is reserved for ftp data session
    if (is_syn && packet.direction == DIRECTION_IN && is_reserved(client_id))
    {
        log_action(&log_row, NF_ACCEPT, REASON_FTP_DATA_SESSION);
        return NF_ACCEPT;
    }

    // Do statless filter for non TCP packet
    if (packet.type != PACKET_TYPE_TCP)
    {
        return stateless_filter(&packet, &log_row);
    }

    // Stateful inspection logic
    if (is_syn)
    {
        // Ensures the connection dosen't exist
        if (conn == NULL && proxy == NULL)
        {
            __u8 verdict = stateless_filter(&packet, &log_row);

            if (verdict == NF_ACCEPT)
            {
                // Creates connection (regular or proxy)

                if (packet.direction == DIRECTION_OUT &&
                    (packet.dst_port == PROXY_HTTP || packet.dst_port == PROXY_FTP))
                {
                    DINFO("Creates proxy connection")
                    add_proxy(&packet);
                }
                else
                {
                    DINFO("Creates regular connection")
                    add_connection(&packet);
                }
            }

            return verdict;
        }

        // The connection already exists
        INFO("syn packet of existing connection")
        log_action(&log_row, NF_DROP, REASON_TCP_STREAM_ENFORCE);
        return NF_DROP;
    }

    // Now we are sure its a non-SYN, TCP packet.

    // Check if client to proxy packet
    if (packet.direction == DIRECTION_OUT && (packet.dst_port == PROXY_HTTP || packet.dst_port == PROXY_FTP) &&
        proxy != NULL)
    {
        int ret;

        DINFO("c2p packet")

        DINFO("Before enforcing: %s, Expect %s", conn_status_str(proxy->c2p_state.status),
              direction_str(proxy->c2p_state.expected_direction));

        DINFO("http filter: direction=%s, src_ip=%d.%d.%d.%d, src_port=%d, dst_ip=%d.%d.%d.%d, dst_port=%d, syn=%d, "
              "ack=%d, fin=%d",
              direction_str(packet.direction), IP_PARTS(packet.src_ip), packet.src_port, IP_PARTS(packet.dst_ip),
              packet.dst_port, tcph->syn, tcph->ack, tcph->fin)

        ret = enforce_state(tcph, packet.direction, &proxy->c2p_state);

        DINFO("Enforce answer: %d", ret)

        // Fake packet
        switch (ret)
        {
        case 2:
            remove_connection(conn);
        case 0:
            log_action(&log_row, NF_ACCEPT, REASON_TCP_STREAM_ENFORCE);
            // fake_packet()
            return NF_ACCEPT;
        case 1:
            log_action(&log_row, NF_DROP, REASON_TCP_STREAM_ENFORCE);
            return NF_DROP;
        }
    }

    // Check for regular connection
    if (conn != NULL)
    {
        // Lets enforce the states
        int ret;

        DINFO("Before enforcing: %s, Expect %s", conn_status_str(conn->state.status),
              direction_str(conn->state.expected_direction));

        DINFO("http filter: direction=%s, src_ip=%d.%d.%d.%d, src_port=%d, dst_ip=%d.%d.%d.%d, dst_port=%d, syn=%d, "
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
            log_action(&log_row, NF_ACCEPT, REASON_TCP_STREAM_ENFORCE);
            return NF_ACCEPT;
        case 1:
            log_action(&log_row, NF_DROP, REASON_TCP_STREAM_ENFORCE);
            return NF_DROP;
        }
    }

    DINFO("Didn't find the connection")
    log_action(&log_row, NF_DROP, REASON_TCP_STREAM_ENFORCE);
    return NF_DROP;
}
