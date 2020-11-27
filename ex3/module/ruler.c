/*
In this module is responsible for rules logic & maintaining.
*/
#include "ruler.h"

#define RULE_SIZE sizeof(rule_t)

// Aloccating array to hold the rules.
static struct
{
    rule_t rules[MAX_RULES];
    __u8 amount;
    active_t active;
} rule_table = {.active = 0};

/**
 * Returns a pointer to the head of the rule table.
 */
rule_t *get_rules(void)
{
    return rule_table.rules;
}

/**
 * Returns the current amount of rules in the rule table.
 */
__u8 get_rules_amount(void)
{
    return rule_table.amount;
}

/**
 * Tells whether the rule table is active. (0 = false) , (1 = true)
 * It can be inactive in one of the 2 cases:
 * 1. *After* loading the module and *before* recieving rules from the user for the first time.
 * 2. If the user introduced unvalid rules.
 */
active_t is_active_table(void)
{
    return rule_table.active;
}

/*
 * Copy rule struct to a char buffer
 */
void rule2buf(const rule_t *rule, char **buf_ptr)
{
    char *buf = *buf_ptr;

    VAR2BUF(rule->rule_name)
    VAR2BUF(&rule->direction)
    VAR2BUF(&rule->src_ip)
    VAR2BUF(&rule->src_prefix_size)
    VAR2BUF(&rule->dst_ip)
    VAR2BUF(&rule->dst_prefix_size)
    VAR2BUF(&rule->src_port)
    VAR2BUF(&rule->dst_port)
    VAR2BUF(&rule->protocol)
    VAR2BUF(&rule->ack)
    VAR2BUF(&rule->action)
}

/*
 * Copy char buffer to a rule struct.
 * Returns 1 if the buffer is valid, 0 if unvalid
 */
void buf2rule(rule_t *rule, const char **buf_ptr)
{
    const char *buf = *buf_ptr;

    BUF2VAR(rule->rule_name)
    BUF2VAR(&rule->direction)
    BUF2VAR(&rule->src_ip)
    BUF2VAR(&rule->src_prefix_size)
    BUF2VAR(&rule->dst_ip)
    BUF2VAR(&rule->dst_prefix_size)
    BUF2VAR(&rule->src_port)
    BUF2VAR(&rule->dst_port)
    BUF2VAR(&rule->protocol)
    BUF2VAR(&rule->ack)
    BUF2VAR(&rule->action)
}

#define BUF2RULE buf2rule(rule, &buf);
#define RULE2BUF rule2buf(rule, &buf);

ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf)
{
    rule_t *rule;

    if (rule_table.active == INACTIVE)
    {
        return 0;
    }

    // Storing the amount of rules in th buffer first
    VAR2BUF(&rule_table.amount);

    // Stroing each rule in the buffer a serial manner
    for (rule = rule_table.rules; rule < rule_table.rules + rule_table.amount; rule++)
    {
        RULE2BUF
    }

    // Return the total size we have passed
    return 1 + rule_table.amount * RULE_SIZE;
}

__u8 is_valid_rule(rule_t *rule)
{
    __u8 valid_direction = (rule->direction >> 2) == 0;
    __u8 valid_masks = rule->src_prefix_mask < 32 && rule->dst_prefix_mask < 32;
    __u8 valid_ports = rule->src_port <= 1024 && rule->dst_port <= 1024;
    __u8 valid_protocol = rule->protocol == PROT_ICMP || rule->protocol == PROT_TCP || rule->protocol == PROT_UDP ||
                          rule->protocol == PROT_ANY;
    __u8 valid_ack = rule->ack == ACK_NO || rule->ack == ACK_YES || rule->ack == ACK_ANY;
    __u8 valid_action = rule->action == NF_DROP || rule->action == NF_ACCEPT;

    return valid_direction && valid_masks && valid_ports && valid_protocol && valid_ack && valid_action;
}

ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    rule_t *rule;

    // Getting the amount of rules first
    BUF2VAR(&rule_table.amount);
    if (rule_table.amount > MAX_RULES || count != rule_table.amount * RULE_SIZE + 1)
    {
        // The buffer isn't representing valid rule table
        rule_table.active = INACTIVE;
        return count;
    }

    // Getting each rule in the buffer a serial manner
    for (rule = rule_table.rules; rule < rule_table.rules + rule_table.amount; rule++)
    {
        BUF2RULE

        if (!is_valid_rule(rule))
        {
            // The buffer isn't representing valid rule table
            rule_table.active = INACTIVE;
            return count;
        }
    }

    // The rule table is valid
    rule_table.active = ACTIVE;
    return count;
}