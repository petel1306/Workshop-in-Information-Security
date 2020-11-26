/*
In this module is responsible for rules logic & maintaining.
*/
#include "ruler.h"

// Aloccating array to hold the rules.
static rule_t rule_table[MAX_RULES];
static __u8 rules_ammount;
static __u8 active = 0; 

/**
 * Returns a pointer to the head of the rule table.
 */
rule_t *get_rules(void)
{
    return rule_table;
}

/**
 * Returns the current amount of rules in the rule table.
 */
__u8 get_rules_ammount(void)
{
    return rules_ammount;
}

/**
 * Tells if the rule table is active. (0 = false) , (1 = true)
 * It can be inactive in one of the 2 cases:
 * 1. *After* loading the module and *before* recieving rules from the user for the first time.
 * 2. If the user introduced unvalid rules.
 */
__u8 is_active(void)
{
    return active;
}