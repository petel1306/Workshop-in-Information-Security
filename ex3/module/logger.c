/*
In this module the packet logging is done.
*/
#include "logger.h"


void log_action(log_row_t *log, __u8 action, reason_t reason) {
    // Recording the action
    log->action = action;
    log->reason = reason;

    // Logging the action
}

const uint8_t LOG_ROW_BUF_SIZE = sizeof(unsigned long) + 2 * sizeof(__u8) + 2 * sizeof(__be32) + 2 * sizeof(__be16)
    + sizeof(reason_t) + sizeof(unsigned int);

void log2buf(const log_row_t *log, char *buf)
{
    VAR2BUF(log->timestamp);
    VAR2BUF(log->protocol);
    VAR2BUF(log->action);
    VAR2BUF(log->src_ip);
    VAR2BUF(log->dst_ip);
    VAR2BUF(log->src_port);
    VAR2BUF(log->dst_port);
    VAR2BUF(log->reason);
    VAR2BUF(log->count);
}

int open_log(struct inode *_inode, struct file *_file)
{
    return 0;
}

ssize_t read_log(struct file *filp, char *buf, size_t length, loff_t *offp)
{
    return 0;
}

ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return count;
}