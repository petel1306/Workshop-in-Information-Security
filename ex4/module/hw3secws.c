#include "filter.h"
#include "fw.h"
#include "logger.h"
#include "ruler.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

#define CLASS_NAME "fw"
#define MAJOR_NAME_RULE "fw-chardev1"
#define MAJOR_NAME_LOG "fw-chardev2"
#define DEVICE_NAME_RULE "rules"
#define DEVICE_NAME_LOG "fw_log"

static int rules_major;
static int log_major;
static struct class *sysfs_class = NULL;
static struct device *rules_dev = NULL;
static struct device *log_dev = NULL;

// Allocating struct to hold forward hook_op
static struct nf_hook_ops nf_forward_op;

/**
 * Set the required fields of nf_hook_ops,
 * and register netfilter hook to the desirable hook point <hook_num>
 */
static int set_nf_hook(struct nf_hook_ops *my_op, enum nf_inet_hooks hook_num)
{
    int reg_error;
    // Initialize netfilter hook - this piece of code was taken from:
    // https://medium.com/bugbountywriteup/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
    my_op->hook = (nf_hookfn *)fw_filter; // hook function
    my_op->hooknum = hook_num;            // received packets
    my_op->pf = PF_INET;                  // IPv4
    my_op->priority = NF_IP_PRI_FIRST;    // max hook priority

    reg_error = nf_register_net_hook(&init_net, my_op);
    return reg_error;
}

/*
 * Rules device registartion procedure :
 */

static struct file_operations rule_ops = {.owner = THIS_MODULE};

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, show_rules, store_rules);

static int register_rules_dev(void)
{
    // create char device
    rules_major = register_chrdev(0, MAJOR_NAME_RULE, &rule_ops);
    if (rules_major < 0)
    {
        goto failed_rules_major;
    }

    // create sysfs device
    rules_dev = device_create(sysfs_class, NULL, MKDEV(rules_major, 0), NULL, DEVICE_NAME_RULE);
    if (IS_ERR(rules_dev))
    {
        goto failed_rules_device;
    }

    // create sysfs file attributes
    if (device_create_file(rules_dev, (const struct device_attribute *)&dev_attr_rules.attr))
    {

        goto failed_rules_file;
    }
    return 0;

failed_rules_file:
    device_destroy(sysfs_class, MKDEV(rules_major, 0));
failed_rules_device:
    unregister_chrdev(rules_major, MAJOR_NAME_RULE);
failed_rules_major:
    return -1;
}
static void unregister_rules_dev(void)
{
    device_remove_file(rules_dev, (const struct device_attribute *)&dev_attr_rules.attr);
    device_destroy(sysfs_class, MKDEV(rules_major, 0));
    unregister_chrdev(rules_major, MAJOR_NAME_RULE);
}

/*
 * Log device registartion procedure :
 */

static struct file_operations log_ops = {.owner = THIS_MODULE, .open = open_log, .read = read_log};

static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO, NULL, reset_log);

static int register_log_dev(void)
{
    // create char device
    log_major = register_chrdev(0, MAJOR_NAME_LOG, &log_ops);
    if (log_major < 0)
    {
        goto failed_log_major;
    }

    // create sysfs device - acced from sysfs
    log_dev = device_create(sysfs_class, NULL, MKDEV(log_major, 0), NULL, DEVICE_NAME_LOG);
    if (IS_ERR(log_dev))
    {
        goto failed_log_device;
    }

    // create sysfs file attributes
    if (device_create_file(log_dev, (const struct device_attribute *)&dev_attr_reset.attr))
    {
        goto failed_log_file;
    }

    return 0;

failed_log_file:
    device_destroy(sysfs_class, MKDEV(log_major, 0));
failed_log_device:
    unregister_chrdev(log_major, MAJOR_NAME_LOG);
failed_log_major:
    return -1;
}

static void unregister_log_dev(void)
{
    device_remove_file(log_dev, (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(sysfs_class, MKDEV(log_major, 0));
    unregister_chrdev(log_major, MAJOR_NAME_LOG);
}

/**
 * Initialize module:
 * 1. Register char devices using sysfs API.
 * 2. Reister NetFilter hook at forward point.
 */
static int __init hw3secws_init(void)
{
    // Create sysfs class
    sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sysfs_class))
    {
        INFO("Failed to create sysfs class")
        goto failed_class;
    }

    // Register rules device
    if (register_rules_dev() != 0)
    {
        INFO("Failed to register rule devices")
        goto failed_log_reg;
    }

    // Register log device
    if (register_log_dev() != 0)
    {
        INFO("Failed to register log devices")
        goto failed_rule_reg;
    }

    // Register hook at Net Filter forward point
    if (set_nf_hook(&nf_forward_op, NF_INET_FORWARD) != 0)
    {
        INFO("Failed to set netfilter FORWARD hook")
        goto failed_hook;
    }

    DINFO("Successful Initialization")

    return 0;

// Terminating in case of registration error
failed_hook:
    unregister_log_dev();
failed_log_reg:
    unregister_rules_dev();
failed_rule_reg:
    class_destroy(sysfs_class);
failed_class:
    return -1;
}

static void __exit hw3secws_exit(void)
{
    // Release resources at exiting - free acquired memory
    free_log();

    // Release resources at exiting - unregister the hook
    nf_unregister_net_hook(&init_net, &nf_forward_op);

    // Release resources at exiting - unregister char devices
    unregister_log_dev();
    unregister_rules_dev();
    class_destroy(sysfs_class);

    DINFO("Exiting")
}

module_init(hw3secws_init);
module_exit(hw3secws_exit);