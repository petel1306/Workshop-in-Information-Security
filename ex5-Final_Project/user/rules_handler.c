#include "rules_handler.h"

void rule2buf(const rule_t *rule, char *buf)
{
    STR2BUF(rule->rule_name, 20);
    VAR2BUF(rule->direction);
    VAR2BUF(rule->src_ip);
    VAR2BUF(rule->src_prefix_size);
    VAR2BUF(rule->dst_ip);
    VAR2BUF(rule->dst_prefix_size);
    VAR2BUF(rule->src_port);
    VAR2BUF(rule->dst_port);
    VAR2BUF(rule->protocol);
    VAR2BUF(rule->ack);
    VAR2BUF(rule->action);
}

/*
 * Copy char buffer to a rule struct.
 */
void buf2rule(rule_t *rule, const char *buf)
{
    BUF2STR(rule->rule_name, 20);
    BUF2VAR(rule->direction);
    BUF2VAR(rule->src_ip);
    BUF2VAR(rule->src_prefix_size);
    BUF2VAR(rule->dst_ip);
    BUF2VAR(rule->dst_prefix_size);
    BUF2VAR(rule->src_port);
    BUF2VAR(rule->dst_port);
    BUF2VAR(rule->protocol);
    BUF2VAR(rule->ack);
    BUF2VAR(rule->action);
}

char *direction2str(const direction_t direction)
{
    switch (direction)
    {
    case DIRECTION_IN:
        return "in";
    case DIRECTION_OUT:
        return "out";
    default:
        return "any";
    }
}

/**
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2direction(const char *str, direction_t *direction)
{
    if (0 == strcmp(str, "in"))
    {
        *direction = DIRECTION_IN;
        return 1;
    }
    else if (0 == strcmp(str, "out"))
    {
        *direction = DIRECTION_OUT;
        return 1;
    }
    else if (0 == strcmp(str, "any"))
    {
        *direction = DIRECTION_ANY;
        return 1;
    }
    else
    {
        return 0;
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

#define PREFIX_IP_ANY (0) // A prefix size that used to indicate, the rule allows any IP address

/*
 * Converts full ip address to string.
 */
void fip2str(char *fip_str, const uint32_t ip, const uint8_t prefix_size)
{
    char ip_str[20];
    if (prefix_size == PREFIX_IP_ANY)
    {
        strcpy(fip_str, "any");
    }
    else
    {
        ip2str(ip_str, ip);
        sprintf(fip_str, "%s/%d", ip_str, prefix_size);
    }
}

/**
 * Converts string to full ip
 * Returns 0 if succeed (the string is valid), -1 if failed.
 */
uint8_t str2fip(const char *fip_str, uint32_t *ip, uint8_t *prefix_size)
{
    unsigned int prefix_container;
    unsigned int ip1, ip2, ip3, ip4;
    int check;
    char ip_str[20];

    if (0 == strcmp(fip_str, "any"))
    {
        *prefix_size = PREFIX_IP_ANY;
        return 1;
    }

    check = sscanf(fip_str, "%u.%u.%u.%u/%u", &ip1, &ip2, &ip3, &ip4, &prefix_container);
    if (check != 5 || prefix_container > 32)
    {
        return 0;
    }
    *prefix_size = (uint8_t)prefix_container;

    sprintf(ip_str, "%u.%u.%u.%u", ip1, ip2, ip3, ip4);
    return str2ip(ip_str, ip);
}

/**
 * Convert rule to a human-readable string (in the agreed format)
 */
void rule2str(const rule_t *rule, char *str)
{
    // Allocate enough space
    char *direction, src_ip[30], dst_ip[30], *protocol, src_port[8], dst_port[8], *ack, *action;

    direction = direction2str(rule->direction);
    fip2str(src_ip, rule->src_ip, rule->src_prefix_size);
    fip2str(dst_ip, rule->dst_ip, rule->dst_prefix_size);
    protocol = protocol2str(rule->protocol);
    port2str(src_port, rule->src_port);
    port2str(dst_port, rule->dst_port);
    ack = ack2str(rule->ack);
    action = action2str(rule->action);

    // At least 2 spaces between each field
    sprintf(str, "%-20s  %-3s  %-18s  %-18s  %-4s  %-5s  %-5s  %-3s  %-6s\n", rule->rule_name, direction, src_ip,
            dst_ip, protocol, src_port, dst_port, ack, action);
}

/**
 * Convert human-readable string (in the agreed format) to a rule
 */
uint8_t str2rule(rule_t *rule, const char *str)
{
    // Allocate enough space
    char direction[10], src_ip[30], dst_ip[30], protocol[10], src_port[10], dst_port[10], ack[10], action[10];
    uint8_t b_direction, b_src_ip, b_dst_ip, b_protocol, b_src_port, b_dst_port, b_ack, b_action;
    int check;

    check = sscanf(str, "%20s %3s %18s %18s %4s %5s %5s %3s %6s\n", rule->rule_name, direction, src_ip, dst_ip,
                   protocol, src_port, dst_port, ack, action);
    if (check != 9)
    {
        return 0;
    }

    b_direction = str2direction(direction, &rule->direction);
    b_src_ip = str2fip(src_ip, &rule->src_ip, &rule->src_prefix_size);
    b_dst_ip = str2fip(dst_ip, &rule->dst_ip, &rule->dst_prefix_size);
    b_protocol = str2protocol(protocol, &rule->protocol);
    b_src_port = str2port(src_port, &rule->src_port);
    b_dst_port = str2port(dst_port, &rule->dst_port);
    b_ack = str2ack(ack, &rule->ack);
    b_action = str2action(action, &rule->action);

    if (b_direction && b_src_ip && b_dst_ip && b_protocol && b_src_port && b_dst_port && b_ack && b_action)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}