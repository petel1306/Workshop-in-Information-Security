/*
In this module the packet logging is done.
*/

#include "logger.h"

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