#ifndef _RULER_H_
#define _RULER_H_

#include "fw.h"

#define MAX_RULES (50)

// macros for rule fiels
#define PREFIX_IP_ANY (0) // A prefix size that used to indicate, the rule allows any IP address
#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1024)

rule_t *get_rules(void);

__u8 get_rules_ammount(void);

__u8 is_active(void);

#endif