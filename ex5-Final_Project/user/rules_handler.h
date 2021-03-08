#ifndef _RULES_HANDLER_H
#define _RULES_HANDLER_H

#include "interface.h"

#define MAX_RULES 50

typedef enum
{
    ACK_NO = 0x01,
    ACK_YES = 0x02,
    ACK_ANY = ACK_NO | ACK_YES,
} ack_t;

typedef enum
{
    DIRECTION_IN = 0x01,
    DIRECTION_OUT = 0x02,
    DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT
} direction_t;

typedef struct
{
    char rule_name[20]; // names will be no longer than 20 chars
    direction_t direction;
    uint32_t src_ip;
    uint8_t src_prefix_size; // valid values: 0-32, e.g., /24 for the example above
                             // (the field is redundant - easier to print)
    uint32_t dst_ip;
    uint8_t dst_prefix_size; // as above
    uint16_t src_port;       // number of port or 0 for any or port 1023 for any port number > 1023
    uint16_t dst_port;       // number of port or 0 for any or port 1023 for any port number > 1023
    uint8_t protocol;        // values from: prot_t
    ack_t ack;               // values from: ack_t
    uint8_t action;          // valid values: NF_ACCEPT, NF_DROP
} rule_t;

void rule2buf(const rule_t *rule, char *buf);
void buf2rule(rule_t *rule, const char *buf);

void rule2str(const rule_t *rule, char *str);
uint8_t str2rule(rule_t *rule, const char *str);

#endif