#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

#define DEVICE_NAME "NF_stats"
#define SYSFS_CLASS_NAME "Top_Class"
#define UINT_SIZE sizeof(unsigned int)

// Allocating 3 structs to hold different hook_ops
static struct nf_hook_ops nf_input_op;
static struct nf_hook_ops nf_forward_op;
static struct nf_hook_ops nf_output_op;

// Allocating device info & pointers
static int major_number;
static struct file_operations fops = {.owner = THIS_MODULE};
static struct class *sysfs_class = NULL;
static struct device *sysfs_device = NULL;

// Counters for #NF_ACCEPT, #NF_DROP
static unsigned int accept_cnt = 0;
static unsigned int drop_cnt = 0;

ssize_t display_stats(struct device *dev, struct device_attribute *attr, char *buf) //sysfs show implementation
{
    // return scnprintf(buf, PAGE_SIZE, "%u,%u\n", accept_cnt, drop_cnt);
    // *** I could write the line above, but I chose a resource-efficient option! ***

    // Hardcoding the counter uint bits into string
    memcpy(buf, (char *)&accept_cnt, UINT_SIZE);
    memcpy(buf + UINT_SIZE, (char *)&drop_cnt, UINT_SIZE);

    return UINT_SIZE << 1; // return 2 * uint_size
}

ssize_t reset_stats(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) //sysfs store implementation
{
    if (*buf == '*') // Every store call starts with '*' char, will cause counters resetting
    {
        accept_cnt = 0;
        drop_cnt = 0;
    }

    return count;
}

static DEVICE_ATTR(sysfs_att, S_IWUSR | S_IRUGO, display_stats, reset_stats);

/**
 * Handle the packets at the hook points
 */
static unsigned int my_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    switch (state->hook)
    {
    // Allow local connection to the FW or from the FW
    case NF_INET_LOCAL_IN:
    case NF_INET_LOCAL_OUT:
        printk(KERN_INFO "*** Packet Accepted ***\n");
        accept_cnt++;
        return NF_ACCEPT;

    // Block connection going through the FW
    case NF_INET_FORWARD:
        printk(KERN_INFO "*** Packet Dropped ***\n");
        drop_cnt++;
        return NF_DROP;

    default:
        printk(KERN_INFO "Should not reach here\n");
        return NF_ACCEPT;
    }
}

/**
 * Set the required fields of nf_hook_ops,
 * and register netfilter hook to the desirable hook point <hook_num>
 */
static int set_nf_hook(struct nf_hook_ops *my_op, enum nf_inet_hooks hook_num)
{
    int reg_error;
    // Initialize netfilter hook - this piece of code was taken from:
    // https://medium.com/bugbountywriteup/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
    my_op->hook = (nf_hookfn *)my_hook_func; // hook function
    my_op->hooknum = hook_num;               // received packets
    my_op->pf = PF_INET;                     // IPv4
    my_op->priority = NF_IP_PRI_FIRST;       // max hook priority

    reg_error = nf_register_net_hook(&init_net, my_op);
    return reg_error;
}

static int __init hw1secws_init(void)
{
    // Register hooks at input, forward, output points
    if (set_nf_hook(&nf_input_op, NF_INET_LOCAL_IN) != 0)
    {
        printk(KERN_INFO "Failed to set netfilter INPUT hook point\n");
        goto failed_input;
    }
    if (set_nf_hook(&nf_forward_op, NF_INET_FORWARD) != 0)
    {
        printk(KERN_INFO "Failed to set netfilter FORWARD hook\n");
        goto failed_forward;
    }
    if (set_nf_hook(&nf_output_op, NF_INET_LOCAL_OUT) != 0)
    {
        printk(KERN_INFO "Failed to set netfilter OUTPUT hook\n");
        goto failed_output;
    }

    //create char device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0)
        goto failed_char_device;

    //create sysfs class
    sysfs_class = class_create(THIS_MODULE, SYSFS_CLASS_NAME);
    if (IS_ERR(sysfs_class))
    {
        goto failed_sysfs_class;
    }

    //create sysfs device
    sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, SYSFS_CLASS_NAME
                                 "_" DEVICE_NAME);
    if (IS_ERR(sysfs_device))
    {
        goto failed_sysfs_device;
    }

    //create sysfs file attributes
    if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
    {
        goto failed_sysfs_att;
    }

    return 0;

// Terminating in case of devicing error
failed_sysfs_att:
    device_destroy(sysfs_class, MKDEV(major_number, 0));
failed_sysfs_device:
    class_destroy(sysfs_class);
failed_sysfs_class:
    unregister_chrdev(major_number, DEVICE_NAME);
failed_char_device:

// Terminating in case of NF hooking error
failed_output:
    nf_unregister_net_hook(&init_net, &nf_forward_op);
failed_forward:
    nf_unregister_net_hook(&init_net, &nf_input_op);
failed_input:
    return -1;
}

static void __exit hw1secws_exit(void)
{
    // Cleaning resources at exiting - unregister devices
    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
    device_destroy(sysfs_class, MKDEV(major_number, 0));
    class_destroy(sysfs_class);
    unregister_chrdev(major_number, "Sysfs_Device");

    // Cleaning resources at exiting - unregister the hooks
    nf_unregister_net_hook(&init_net, &nf_input_op);
    nf_unregister_net_hook(&init_net, &nf_forward_op);
    nf_unregister_net_hook(&init_net, &nf_output_op);
}

module_init(hw1secws_init);
module_exit(hw1secws_exit);