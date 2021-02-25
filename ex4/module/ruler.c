/*
In this module is responsible for rules logic & maintaining.
*/
#include "ruler.h"
#include "fw.h"

const __u8 RULE_SIZE =
    20 + sizeof(direction_t) + sizeof(ack_t) + 2 * sizeof(__be32) + 2 * sizeof(__be16) + 4 * sizeof(__u8);

// Aloccating array to hold the rules.
static struct
{
    rule_t rules[MAX_RULES];
    __u8 amount;
    active_t active;
} rule_table = {.active = INACTIVE};

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

ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf)
{
    rule_t *rule;
    
    if (rule_table.active == INACTIVE)
    {
        return 0;
    }
    
    DINFO("Showing %d rules", rule_table.amount)

    // Storing the amount of rules in the buffer first
    VAR2BUF(rule_table.amount);

    // Stroing each rule in the buffer a serial manner
    for (rule = rule_table.rules; rule < rule_table.rules + rule_table.amount; rule++)
    {
        rule2buf(rule, buf);
        buf += RULE_SIZE;
    }

    // Return the total size we have passed
    return 1 + rule_table.amount * RULE_SIZE;
}

/**
 * Checks if the rule fields are in the required range
 */
__u8 is_valid_rule(rule_t *rule)
{
    __u8 valid_direction =
        rule->direction == DIRECTION_IN || rule->direction == DIRECTION_OUT || rule->direction == DIRECTION_ANY;
    __u8 valid_prefix = rule->src_prefix_size <= 32 && rule->dst_prefix_size <= 32;
    __u8 valid_ports = rule->src_port <= 1024 && rule->dst_port <= 1024;
    __u8 valid_protocol = rule->protocol == PROT_ICMP || rule->protocol == PROT_TCP || rule->protocol == PROT_UDP ||
                          rule->protocol == PROT_ANY;
    __u8 valid_ack = rule->ack == ACK_NO || rule->ack == ACK_YES || rule->ack == ACK_ANY;
    __u8 valid_action = rule->action == NF_DROP || rule->action == NF_ACCEPT;

    /*
    DINFO("%s", rule->rule_name)
    DSHOW(rule->direction)
    DSHOW(rule->src_ip)
    DSHOW(rule->src_prefix_size)
    DSHOW(rule->dst_ip)
    DSHOW(rule->dst_prefix_size)
    DSHOW(rule->protocol)
    DSHOW(rule->src_port)
    DSHOW(rule->dst_port)
    DSHOW(rule->ack)
    DSHOW(rule->action)
    */

    return valid_direction && valid_prefix && valid_ports && valid_protocol && valid_ack && valid_action;
}

ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    rule_t *rule;

    // Getting the amount of rules first
    BUF2VAR(rule_table.amount);

    DINFO("Storing %d rules", rule_table.amount)

    if (rule_table.amount > MAX_RULES || count != rule_table.amount * RULE_SIZE + sizeof(rule_table.amount))
    {
        // The buffer isn't representing a valid rule table
        rule_table.active = INACTIVE;
        return count;
    }

    // Getting each rule in the buffer a serial manner
    for (rule = rule_table.rules; rule < rule_table.rules + rule_table.amount; rule++)
    {
        buf2rule(rule, buf);
        buf += RULE_SIZE;

        if (!is_valid_rule(rule))
        {
            // The buffer isn't representing a valid rule table
            rule_table.active = INACTIVE;
            return count;
        }
    }

    // The rule table is valid, and has been loaded
    rule_table.active = ACTIVE;
    return count;
}