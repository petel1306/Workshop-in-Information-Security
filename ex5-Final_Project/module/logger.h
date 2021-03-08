#ifndef _LOGGER_H_
#define _LOGGER_H_

#include "fw.h"

// log a filtering action on a packet
void log_action(log_row_t *log, __u8 action, reason_t reason);

// Free all resources acquired by the logger
void free_log(void);

// Define log device operations
int open_log(struct inode *_inode, struct file *_file);
ssize_t read_log(struct file *filp, char *buf, size_t length, loff_t *offp);

ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

#endif