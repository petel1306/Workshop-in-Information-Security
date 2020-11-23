#include "fw.h"
#include "filter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

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

static int __init hw1secws_init(void)
{
    // Register hook at Net Filter forward point
    if (set_nf_hook(&nf_forward_op, NF_INET_FORWARD) != 0)
    {
        printk(KERN_INFO "Failed to set netfilter FORWARD hook\n");
        goto failed_hook;
    }
    return 0;

// Terminating in case of NF hooking error
failed_hook:
    return -1;
