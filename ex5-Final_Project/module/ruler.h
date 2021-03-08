#ifndef _RULER_H_
#define _RULER_H_

#include "fw.h"

#define MAX_RULES (50)

// macros for rule fiels
#define PREFIX_IP_ANY (0) // A prefix size that used to indicate, the rule allows any IP address
#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1024)

typedef enum
{
    INACTIVE,
    ACTIVE
} active_t;

// Define getters
rule_t *get_rules(void);
__u8 get_rules_amount(void);
active_t is_active_table(void);

// Define device rules operations
ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

#endif