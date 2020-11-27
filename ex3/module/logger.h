#ifndef _LOGGER_H_
#define _LOGGER_H_

#include "fw.h"

// Define device log operations
int open_log(struct inode *_inode, struct file *_file);
ssize_t read_log(struct file *filp, char *buff, size_t length, loff_t *offp);

ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

#endif