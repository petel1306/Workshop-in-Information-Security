/*
In this module the packet logging is done.
*/
#include "logger.h"
#include "fw.h"

#define MAX_POOL 100

typedef struct
{
    log_row_t log_row;

    // This is used to link players together in the players list
    struct list_head list_node;
} log_entry_t;

LIST_HEAD(log);        // The head of log linked list
__u32 rows_amount = 0; // The amount of log rows/ entries

// Implement a pool of free memory instead allocate each time
static log_entry_t *log_pool;
static __u8 pool_amount = 0;

/**
 * Obtain an allocated log_entry_t from the pool
 */
static log_entry_t *allocate_entry(void)
{
    if (pool_amount == 0)
    {
        log_pool = (log_entry_t *)kcalloc(MAX_POOL, sizeof(log_entry_t), GFP_KERNEL);
        pool_amount = MAX_POOL;
    }
    pool_amount--;
    return log_pool + pool_amount; // Same as &log_pool[pool_amount]
}

/**
 * Checks if two log_row are match
 * Returns 1 if true, 0 if false
 */
__u8 log_match(log_row_t *lr1, log_row_t *lr2)
{
    return lr1->src_ip == lr2->src_ip && lr1->dst_ip == lr2->dst_ip && lr1->protocol == lr2->protocol &&
           lr1->src_port == lr2->src_port && lr1->dst_port == lr2->dst_port && lr1->reason == lr2->reason;
}

/**
 * log a filtering action on a packet
 */
void log_action(log_row_t *log_row, __u8 action, reason_t reason)
{
    struct list_head *pos;
    log_entry_t *entry = NULL;

    // Recording the action
    log_row->action = action;
    log_row->reason = reason;

    // Searching for a similar log entry
    list_for_each(pos, &log) // In here pos will be the list_head item in the corresponding log_entry_t struct
    {
        // Extract get a reference to the log_entry_t for this iteration
        entry = list_entry(pos, log_entry_t, list_node);

        if (log_match(log_row, &entry->log_row))
        {
            entry->log_row.timestamp = log_row->timestamp;
            entry->log_row.count++;
            return;
        }
    }

    // No entry match. Adding a new log entry
    entry = allocate_entry();
    entry->log_row = *log_row;
    list_add_tail(&entry->list_node, &log);
    rows_amount++;
}

/*
 * Free all resources and initialize the log
 */
void log_cleanup(void)
{
    log_entry_t *the_entry;
    log_entry_t *temp_entry;
    list_for_each_entry_safe(the_entry, temp_entry, &log, list_node)
    {
        list_del(&the_entry->list_node);
        kfree(the_entry);
    }
    rows_amount = 0;
}

// Implementing log device operations

const __u8 LOG_ROW_BUF_SIZE = sizeof(unsigned long) + 2 * sizeof(__u8) + 2 * sizeof(__be32) + 2 * sizeof(__be16) +
                              sizeof(reason_t) + sizeof(unsigned int);

const __u8 AMOUNT_BUF_SIZE = sizeof(rows_amount);

log_entry_t *read_entry;
static __u8 is_ammount_passed;

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
    read_entry = NULL;
    is_ammount_passed = 0;
    return 0;
}

ssize_t read_log(struct file *filp, char *buf, size_t length, loff_t *offp)
{
    char my_buf[LOG_ROW_BUF_SIZE];
    int count = 0;

    if (!is_ammount_passed)
    {
        if (length < AMOUNT_BUF_SIZE)
        {
            return 0;
        }

        if (copy_to_user(buf, &rows_amount, AMOUNT_BUF_SIZE))
        {
            return -EFAULT;
        }

        count += AMOUNT_BUF_SIZE;
        length -= AMOUNT_BUF_SIZE;
        is_ammount_passed = 1;
    }

    if (read_entry == NULL)
    {
        list_for_each_entry(read_entry, &log, list_node)
        {
            if (length < LOG_ROW_BUF_SIZE)
            {
                break;
            }

            log2buf(&read_entry->log_row, my_buf);
            if (copy_to_user(buf + count, my_buf, LOG_ROW_BUF_SIZE))
            {
                return -EFAULT;
            }
            count += LOG_ROW_BUF_SIZE;
            length -= LOG_ROW_BUF_SIZE;
        }
    }
    else
    {
        list_for_each_entry_continue(read_entry, &log, list_node)
        {
            if (length < LOG_ROW_BUF_SIZE)
            {
                break;
            }

            log2buf(&read_entry->log_row, my_buf);
            if (copy_to_user(buf + count, my_buf, LOG_ROW_BUF_SIZE))
            {
                return -EFAULT;
            }
            count += LOG_ROW_BUF_SIZE;
            length -= LOG_ROW_BUF_SIZE;
        }
    }
    return count;
}

ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    log_cleanup();
    return count;
}