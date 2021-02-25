#include "filter.h"
#include "fw.h"
#include "logger.h"
#include "proxy.h"
#include "ruler.h"
#include "tracker.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

#define CLASS_NAME "fw"
#define MAJOR_NAME_RULE "fw-chardev1"
#define MAJOR_NAME_LOG "fw-chardev2"
#define MAJOR_NAME_CONN "fw-chardev3"
#define MAJOR_NAME_PROXY "fw-chardev4"
#define DEVICE_NAME_RULE "rules"
#define DEVICE_NAME_LOG "fw_log"
#define DEVICE_NAME_CONN "conns"
#define DEVICE_NAME_PROXY "proxy"

static int rules_major;
static int log_major;
static int conn_major;
static int proxy_major;
static struct class *sysfs_class = NULL;
static struct device *rules_dev = NULL;
static struct device *log_dev = NULL;
static struct device *conn_dev = NULL;
static struct device *proxy_dev = NULL;

// Allocating struct to hold forward hook_op
static struct nf_hook_ops nf_preroute_op;
static struct nf_hook_ops nf_localout_op;

/**
 * Set the required fields of nf_hook_ops,
 * and register netfilter hook to the desirable hook point <hook_num>
 */
static int set_nf_hook(struct nf_hook_ops *my_op, enum nf_inet_hooks hook_num)
{
    int reg_error;
    // Initialize netfilter hook - this piece of code was taken from:
    // https://medium.com/bugbountywriteup/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
    my_op->hook = (nf_hookfn *)fw_inspect; // hook function
    my_op->hooknum = hook_num;             // received packets
    my_op->pf = PF_INET;                   // IPv4
    my_op->priority = NF_IP_PRI_FIRST;     // max hook priority

    reg_error = nf_register_net_hook(&init_net, my_op);
    return reg_error;
}

/*
 * Rule device registartion procedure :
 */

static struct file_operations rule_ops = {.owner = THIS_MODULE};

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, show_rules, store_rules);

static int register_rules_dev(void)
{
    // create char device
    rules_major = register_chrdev(0, MAJOR_NAME_RULE, &rule_ops);
    if (rules_major < 0)
    {
        goto failed_proxy_major;
    }

    // create sysfs device
    rules_dev = device_create(sysfs_class, NULL, MKDEV(rules_major, 0), NULL, DEVICE_NAME_RULE);
    if (IS_ERR(rules_dev))
    {
        goto failed_proxy_device;
    }

    // create sysfs file attributes
    if (device_create_file(rules_dev, (const struct device_attribute *)&dev_attr_rules.attr))
    {

        goto failed_proxy_file;
    }
    return 0;

failed_proxy_file:
    device_destroy(sysfs_class, MKDEV(rules_major, 0));
failed_proxy_device:
    unregister_chrdev(rules_major, MAJOR_NAME_RULE);
failed_proxy_major:
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

static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_log);

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

/*
 * Connections device registartion procedure :
 */

static struct file_operations conn_ops = {.owner = THIS_MODULE};

ssize_t conns(struct device *dev, struct device_attribute *attr, char *buf)
{
    ssize_t csize = ctable2buf(buf);
    buf += csize;
    return csize;
}

static DEVICE_ATTR(conns, S_IRUGO, conns, NULL);

static int register_conn_dev(void)
{
    // create char device
    conn_major = register_chrdev(0, MAJOR_NAME_CONN, &conn_ops);
    if (conn_major < 0)
    {
        goto failed_conn_major;
    }

    // create sysfs device - acced from sysfs
    conn_dev = device_create(sysfs_class, NULL, MKDEV(conn_major, 0), NULL, DEVICE_NAME_CONN);
    if (IS_ERR(conn_dev))
    {
        goto failed_conn_device;
    }

    if (device_create_file(conn_dev, (const struct device_attribute *)&dev_attr_conns.attr))
    {
        goto failed_conn_file;
    }

    return 0;

failed_conn_file:
    device_destroy(sysfs_class, MKDEV(conn_major, 0));
failed_conn_device:
    unregister_chrdev(conn_major, MAJOR_NAME_CONN);
failed_conn_major:
    return -1;
}

static void unregister_conn_dev(void)
{
    device_remove_file(conn_dev, (const struct device_attribute *)&dev_attr_conns.attr);
    device_destroy(sysfs_class, MKDEV(conn_major, 0));
    unregister_chrdev(conn_major, MAJOR_NAME_CONN);
}

/*
 * Proxy device registartion procedure :
 */

static struct file_operations proxy_ops = {.owner = THIS_MODULE};

static DEVICE_ATTR(set_port, S_IWUSR, NULL, set_proxy_port);

static DEVICE_ATTR(add_ftp, S_IWUSR, NULL, add_ftp_data);

static int register_proxy_dev(void)
{
    // create char device
    proxy_major = register_chrdev(0, MAJOR_NAME_PROXY, &proxy_ops);
    if (proxy_major < 0)
    {
        goto failed_proxy_major;
    }

    // create sysfs device
    proxy_dev = device_create(sysfs_class, NULL, MKDEV(proxy_major, 0), NULL, DEVICE_NAME_PROXY);
    if (IS_ERR(proxy_dev))
    {
        goto failed_proxy_device;
    }

    // create sysfs file attributes
    if (device_create_file(proxy_dev, (const struct device_attribute *)&dev_attr_set_port.attr))
    {
        goto failed_proxy_file;
    }
    if (device_create_file(proxy_dev, (const struct device_attribute *)&dev_attr_add_ftp.attr))
    {
        goto failed_ftp_file;
    }
    return 0;

failed_ftp_file:
    device_remove_file(proxy_dev, (const struct device_attribute *)&dev_attr_set_port.attr);
failed_proxy_file:
    device_destroy(sysfs_class, MKDEV(proxy_major, 0));
failed_proxy_device:
    unregister_chrdev(proxy_major, MAJOR_NAME_PROXY);
failed_proxy_major:
    return -1;
}

static void unregister_proxy_dev(void)
{
    device_remove_file(proxy_dev, (const struct device_attribute *)&dev_attr_add_ftp.attr);
    device_remove_file(proxy_dev, (const struct device_attribute *)&dev_attr_set_port.attr);
    device_destroy(sysfs_class, MKDEV(proxy_major, 0));
    unregister_chrdev(proxy_major, MAJOR_NAME_PROXY);
}

/**
 * Initialize module:
 * 1. Register char devices using sysfs API.
 * 2. Reister NetFilter hook at forward point.
 */
static int __init hw4secws_init(void)
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
        goto failed_rule_reg;
    }

    // Register log device
    if (register_log_dev() != 0)
    {
        INFO("Failed to register log devices")
        goto failed_log_reg;
    }

    // Register connections device
    if (register_conn_dev() != 0)
    {
        INFO("Failed to register connections devices")
        goto failed_conn_reg;
    }

    // Register proxy device
    if (register_proxy_dev() != 0)
    {
        INFO("Failed to register proxy devices");
        goto failed_proxy_reg;
    }

    // Register hook at Net Filter forward point
    if (set_nf_hook(&nf_preroute_op, NF_INET_PRE_ROUTING) != 0)
    {
        INFO("Failed to set netfilter FORWARD hook")
        goto failed_hook1;
    }

    // Register hook at Net Filter forward point
    if (set_nf_hook(&nf_localout_op, NF_INET_LOCAL_OUT) != 0)
    {
        INFO("Failed to set netfilter FORWARD hook")
        goto failed_hook2;
    }

    DINFO("Successful Initialization")

    return 0;

// Terminating in case of registration error
failed_hook2:
    nf_unregister_net_hook(&init_net, &nf_preroute_op);
failed_hook1:
    unregister_proxy_dev();
failed_proxy_reg:
    unregister_conn_dev();
failed_conn_reg:
    unregister_log_dev();
failed_log_reg:
    unregister_rules_dev();
failed_rule_reg:
    class_destroy(sysfs_class);
failed_class:
    return -1;
}

static void __exit hw4secws_exit(void)
{
    // Release resources at exiting - free acquired memory
    free_log();
    free_connections();

    // Release resources at exiting - unregister the hooks
    nf_unregister_net_hook(&init_net, &nf_localout_op);
    nf_unregister_net_hook(&init_net, &nf_preroute_op);

    // Release resources at exiting - unregister char devices
    unregister_proxy_dev();
    unregister_conn_dev();
    unregister_log_dev();
    unregister_rules_dev();
    class_destroy(sysfs_class);

    DINFO("Exiting")
}

module_init(hw4secws_init);
module_exit(hw4secws_exit);
