#include "filter.h"
#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

#define DEVICE_NAME_RULE "fw_rule"
#define DEVICE_NAME_LOG "fw_log"
#define CLASS_NAME "fw"
#define SYS_DEVICE_NAME_RULE "rules"
#define SYS_DEVICE_NAME_LOG "log"

static int rule_major;
static int log_major;
static struct class *sysfs_class = NULL;
static struct device *rule_dev = NULL;
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
    my_op->hook = (nf_hookfn *)fw_filtering; // hook function
    my_op->hooknum = hook_num;               // received packets
    my_op->pf = PF_INET;                     // IPv4
    my_op->priority = NF_IP_PRI_FIRST;       // max hook priority

    reg_error = nf_register_net_hook(&init_net, my_op);
    return reg_error;
}

static int register_rule_device(void)
{
    return 0;
}
static void unregister_rule_device(void)
{
    return;
}

static int register_log_device(void)
{
    return 0;
}

static void unregister_log_device(void)
{
    return;
}

static int __init hw3secws_init(void)
{
    // create sysfs class
    sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if ( IS_ERR(sysfs_class)) {
        printk(KERN_INFO "Failed to set sysfs class\n");
        goto failed_class;
    }
    
    if (register_rule_device() != 0) {
        printk(KERN_INFO "Failed to set rule device\n");
        goto failed_rule_dev;
    }

    if (register_log_device() != 0){
        printk(KERN_INFO "Failed to set log device\n");
        goto failed_log_dev;
    }

    // Register hook at Net Filter forward point
    if (set_nf_hook(&nf_forward_op, NF_INET_FORWARD) != 0)
    {
        printk(KERN_INFO "Failed to set netfilter FORWARD hook\n");
        goto failed_hook;
    }

        return 0;

// Terminating in case of registration error
failed_hook:
    unregister_log_device();
failed_log_dev:
    unregister_rule_device();
failed_rule_dev:
class_destroy(sysfs_class);
failed_class:
    return -1;
}

static void __exit hw3secws_exit(void)
{
    // Cleaning resources at exiting - unregister the hook
    nf_unregister_net_hook(&init_net, &nf_forward_op);
}

module_init(hw3secws_init);
module_exit(hw3secws_exit);