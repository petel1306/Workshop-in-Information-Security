#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

// Allocating 3 structs to hold different hook_ops
static struct nf_hook_ops nf_input_op;
static struct nf_hook_ops nf_forward_op;
static struct nf_hook_ops nf_output_op;

/**
 * Handle the packets at the hook points
 */
static unsigned int my_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    switch(state->hook) {
        // Allow local connection to the FW or from the FW
        case NF_INET_LOCAL_IN:
        case NF_INET_LOCAL_OUT:
            printk(KERN_INFO "*** Packet Accepted ***\n");
            return NF_ACCEPT;

        // Block connection going through the FW
        case NF_INET_FORWARD:
            printk(KERN_INFO "*** Packet Dropped ***\n");
            return NF_DROP;
    }
}

/**
 * Set the required fields of nf_hook_ops,
 * and register netfilter hook to the desirable hook point <hook_num>
 */
static int set_nf_hook( nf_hook_ops *my_op, nf_inet_hooks hook_num) {
    int reg_error;
    // Initialize netfilter hook - this piece of code was taken from:
    // https://medium.com/bugbountywriteup/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
    my_op->hook = (nf_hookfn*) my_hook_func;    // hook function
	my_op->hooknum = hook_num;                 // received packets
	my_op->pf = PF_INET;                      // IPv4
	my_op->priority = NF_IP_PRI_FIRST;       // max hook priority

    reg_error = nf_register_net_hook(&init_net, my_op);
    return reg_error;
}

static int __init hw1secws_init(void) {
	printk(KERN_INFO "Hello World!\n");

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
    if (set_nf_hook(&nf_output_op, NF_INET_LOCAL_OUT) != 0){
        printk(KERN_INFO "Failed to set netfilter OUTPUT hook\n");
		goto failed_output;
    }
	return 0;

    // Terminating in case of registration error
    failed_output:
        nf_unregister_net_hook(&init_net, &nf_output_op);
    failed_forward:
        nf_unregister_net_hook(&init_net, &nf_forward_op);
    failed_input:
        nf_unregister_net_hook(&init_net, &nf_input_op);
    return -1;
}

static void __exit hw1secws_exit(void) {
    // Cleaning resources at exiting - unregister the hooks
    nf_unregister_net_hook(&init_net, &nf_input_op);
    nf_unregister_net_hook(&init_net, &nf_forward_op);
    nf_unregister_net_hook(&init_net, &nf_output_op);
	printk(KERN_INFO "Goodbye World!\n");
}

module_init(hw1secws_init);
module_exit(hw1secws_exit);