#include "rules_handler.h"

#include <arpa/inet.h>

// macros for rule fiels
#define PREFIX_IP_ANY (0) // A prefix size that used to indicate, the rule allows any IP address
#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1024)

typedef enum
{
    NF_DROP = 0,
    NF_ACCEPT = 1,
} action_t;

/*
 * Copy rule struct to a char buffer
 */
void rule2buf(const rule_t *rule, char *buf)
{
    VAR2BUF(rule->rule_name);
    VAR2BUF(&rule->direction);
    VAR2BUF(&rule->src_ip);
    VAR2BUF(&rule->src_prefix_size);
    VAR2BUF(&rule->dst_ip);
    VAR2BUF(&rule->dst_prefix_size);
    VAR2BUF(&rule->src_port);
    VAR2BUF(&rule->dst_port);
    VAR2BUF(&rule->protocol);
    VAR2BUF(&rule->ack);
    VAR2BUF(&rule->action);
}

/*
 * Copy char buffer to a rule struct.
 */
void buf2rule(rule_t *rule, const char *buf)
{

    BUF2VAR(rule->rule_name);
    BUF2VAR(&rule->direction);
    BUF2VAR(&rule->src_ip);
    BUF2VAR(&rule->src_prefix_size);
    BUF2VAR(&rule->dst_ip);
    BUF2VAR(&rule->dst_prefix_size);
    BUF2VAR(&rule->src_port);
    BUF2VAR(&rule->dst_port);
    BUF2VAR(&rule->protocol);
    BUF2VAR(&rule->ack);
    BUF2VAR(&rule->action);
}

#define STR_ANY "any"
#define STR_IN "in"
#define STR_OUT "out"
#define STR_TCP "TCP"
#define STR_UDP "UDP"
#define STR_ICMP "ICMP"

char *direction2str(const direction_t direction)
{
    switch (direction)
    {
    case DIRECTION_IN:
        return STR_IN;
    case DIRECTION_OUT:
        return STR_OUT;
    default:
        return STR_ANY;
    }
}

char *protocol2str(const uint8_t protocol)
{
    switch (protocol)
    {
    case PROT_ICMP:
        return STR_ICMP;
    case PROT_UDP:
        return STR_UDP;
    case PROT_TCP:
        return STR_TCP;
    default:
        return STR_ANY;
    }
}

char *ack2str(const ack_t ack)
{
    switch (ack)
    {
    case ACK_YES:
        return "yes";
    case ACK_NO:
        return "no";
    default:
        return "any";
    }
}

char *action2str(const uint8_t action)
{
    if (action == NF_ACCEPT)
    {
        return "accept";
    }
    else
    {
        return "drop";
    }
}

/**
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2direction(const char *str, direction_t *direction)
{
    if (0 == strcmp(str, STR_IN))
    {
        *direction = DIRECTION_IN;
        return 1;
    }
    else if (0 == strcmp(str, STR_OUT))
    {
        *direction = DIRECTION_OUT;
        return 1;
    }
    else if (0 == strcmp(str, STR_ANY))
    {
        *direction = DIRECTION_ANY;
        return 1;
    }
    else
    {
        return 0;
    }
}

/**
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2protocol(const char *str, uint8_t *protocol)
{
    if (0 == strcmp(str, STR_ICMP))
    {
        *protocol = PROT_ICMP;
        return 1;
    }
    else if (0 == strcmp(str, STR_UDP))
    {
        *protocol = PROT_UDP;
        return 1;
    }
    else if (0 == strcmp(str, STR_TCP))
    {
        *protocol = PROT_TCP;
        return 1;
    }
    else if (0 == strcmp(str, STR_ANY))
    {
        *protocol = PROT_ANY;
        return 1;
    }
    else
    {
        return 0;
    }
}

/**
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2ack(const char *str, ack_t *ack)
{
    if (0 == strcmp(str, "yes"))
    {
        *ack = ACK_YES;
        return 1;
    }
    else if (0 == strcmp(str, "no"))
    {
        *ack = ACK_NO;
        return 1;
    }
    else if (0 == strcmp(str, "any"))
    {
        *ack = ACK_ANY;
        return 1;
    }
    else
    {
        return 0;
    }
}

/**
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2action(const char *str, uint8_t *action)
{
    if (0 == strcmp(str, "accept"))
    {
        *action = NF_ACCEPT;
        return 1;
    }
    else if (0 == strcmp(str, "drop"))
    {
        *action = NF_DROP;
        return 1;
    }
    else
    {
        return 0;
    }
}

/*
 * Converts ip address to string.
 */
void ip2str(char *ip_str, const uint32_t ip, const uint8_t prefix_size)
{
    struct in_addr ip_addr;
    if (prefix_size == PREFIX_IP_ANY)
    {
        strcpy(ip_str, "any");
    }
    else
    {
        ip_addr.s_addr = htonl(ip);
        sprintf(ip_str, "%s/%d", inet_ntoa(ip_addr), prefix_size);
    }
}

/**
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2ip(const char *str, uint32_t *ip, uint8_t *prefix_size)
{
    struct in_addr ip_addr;
    char ip_str[30];
    unsigned int prefix_buf;
    int check;

    if (0 == strcmp(str, "any"))
    {
        *prefix_size = PREFIX_IP_ANY;
        return 1;
    }

    check = sscanf(str, "%s/%u", ip_str, &prefix_buf);
    if (check != 2 || prefix_buf > 32)
    {
        return 0;
    }
    *prefix_size = (uint8_t)prefix_buf;

    if (inet_aton(ip_str, &ip_addr) == 0)
    {
        return 0;
    }
    *ip = ntohl(ip_addr.s_addr);

    return 1;
}

/*
 * Converts port to string.
 */
void port2str(char *str_port, const uint16_t port)
{
    if (port == PORT_ABOVE_1023)
    {
        strcpy(str_port, ">1023");
    }
    else if (port == PORT_ANY)
    {
        strcpy(str_port, "any");
    }
    else
    {
        sprintf(str_port, "%d", port);
    }
}

uint8_t str2port(const char *str_port, uint16_t *port)
{
    int check;
    unsigned int port_buf;

    if (0 == strcmp(str_port, ">1023"))
    {
        *port = PORT_ABOVE_1023;
        return 1;
    }
    if (0 == strcmp(str_port, "any"))
    {
        *port = PORT_ANY;
        return 1;
    }
    check = sscanf(str_port, "%u", &port_buf);
    if (check == 1 && port_buf <= 1023)
    {
        *port = (uint16_t)port_buf;
        return 1;
    }
    return 0;
}

/**
 * Convert rule to a human-readable string (in the agreed format)
 */
void rule2str(const rule_t *rule, char *str)
{
    char *direction, src_ip[30], dst_ip[30], *protocol, src_port[8], dst_port[8], *ack, *action;

    direction = direction2str(rule->direction);
    ip2str(src_ip, rule->src_ip, rule->src_prefix_size);
    ip2str(dst_ip, rule->dst_ip, rule->dst_prefix_size);
    protocol = protocol2str(rule->protocol);
    port2str(src_port, rule->src_port);
    port2str(dst_port, rule->dst_port);
    ack = ack2str(rule->ack);
    action = action2str(rule->action);

    // At least 2 spaces between each field
    sprintf(str, "%-20s  %-3s  %-18s  %-18s  %-4s  %-5s  %-5s  %-3s  %-6s\n", rule->rule_name, direction, src_ip,
            dst_ip, protocol, src_port, dst_port, ack, action);
}

#define STR2FIELD(field) b_##field = str2##field(str, &rule->field)

/**
 * Convert human-readable string (in the agreed format) to a rule
 */
uint8_t str2rule(rule_t *rule, const char *str)
{
    char direction[3], src_ip[30], dst_ip[30], protocol[4], src_port[5], dst_port[5], ack[3], action[6];
    uint8_t b_direction, b_src_ip, b_dst_ip, b_protocol, b_src_port, b_dst_port, b_ack, b_action;
    int check;

    check = sscanf(str, "%20s %3s %18s %18s %4s %5s %5s %3s %6s\n", rule->rule_name, direction, src_ip, dst_ip,
                   protocol, src_port, dst_port, ack, action);
    if (check != 9)
    {
        return 0;
    }

    b_direction = str2direction(str, &rule->direction);
    b_src_ip = str2ip(src_ip, &rule->src_ip, &rule->src_prefix_size);
    b_dst_ip = str2ip(dst_ip, &rule->dst_ip, &rule->dst_prefix_size);
    b_protocol = str2protocol(str, &rule->protocol);
    b_src_port = str2port(src_port, &rule->src_port);
    b_dst_port = str2port(dst_port, &rule->dst_port);
    b_ack = str2ack(str, &rule->ack);
    b_action = str2action(str, &rule->action);

    if (b_direction && b_src_ip && b_dst_ip && b_protocol && b_src_port && b_dst_port && b_ack && b_action)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}