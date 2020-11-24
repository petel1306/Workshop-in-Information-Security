/*
In this module is responsible for rules logic & maintaining.
*/
#include "ruler.h"

// Aloccating array to hold the rules.
static rule_t[MAX_RULES] rule_table;
static __u8 rules_ammount;

rule_t *get_rules()
{
    return rule_table;
}

__u8 get_rules_ammount() {
    return rules_ammount;
}