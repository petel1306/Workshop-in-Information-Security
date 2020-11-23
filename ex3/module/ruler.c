/*
In this module the packet ruling is done.
*/
#include "ruler.h"

// Aloccating array to hold the rules.
static rule_t[MAX_RULES] rule_table;
static unsigned int rule_ammount;

rule_t *get_rules()
{
    return rule_table;
}

unsigned int get_rule_ammount() {
    return rule_ammount;
}