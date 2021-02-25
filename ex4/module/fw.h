#ifndef _FW_H_
#define _FW_H_

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/udp.h>
#include <net/tcp.h>

unsigned int get_info_counter(void);

/*
 * Print messgas to the user
 */
#define INFO(message, ...) printk(KERN_INFO "\n\nFirewall-%d: " message "\n\n", get_info_counter(), ##__VA_ARGS__);

/*
 * Print debug messages to the user (in case DEBUG is defined)
 */
#define DEBUG

#ifdef DEBUG
#define DCOM(command) command // Debug command
#define DINFO(message, ...)                                                                                            \
    printk(KERN_INFO "\n\nFirewall-%d debug: " message "\n\n", get_info_counter(), ##__VA_ARGS__);
#define DSHOW(var) DINFO(#var " = %d", var);
#else
#define DCOM(command)
#define DINFO(...)
#define DSHOW(var)
#endif

#define IP_PARTS(ip) (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF

/**
 * Copy var to buffer, and increment the pointer of the bufer
 */
void var2buf(char **buf_ptr, const void *var, size_t n);

/**
 * Copy buffer to var, and increment the pointer of the bufer
 */
void buf2var(const char **buf_ptr, void *var, size_t n);

#define VAR2BUF(var) var2buf(&buf, &var, sizeof(var))
#define BUF2VAR(var) buf2var(&buf, &var, sizeof(var))

#define STR2BUF(str, n) var2buf(&buf, str, n)
#define BUF2STR(str, n) buf2var(&buf, str, n)

// the protocols we will work with
typedef enum
{
    PROT_ICMP = 1,
    PROT_TCP = 6,
    PROT_UDP = 17,
    PROT_ANY = 143,
} prot_t;

typedef enum
{
    ACK_NO = 0x01,
    ACK_YES = 0x02,
    ACK_ANY = ACK_NO | ACK_YES,
} ack_t;

typedef enum
{
    DIRECTION_IN = 0x01,
    DIRECTION_OUT = 0x02,
    DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT,
    DIRECTION_NONE = DIRECTION_IN & DIRECTION_OUT,
} direction_t;

// rule base
typedef struct
{
    char rule_name[20]; // names will be no longer than 20 chars
    direction_t direction;
    __be32 src_ip;
    __u8 src_prefix_size; // valid values: 0-32, e.g., /24 for the example above
    __be32 dst_ip;
    __u8 dst_prefix_size; // as above
    __be16 src_port;      // number of port or 0 for any or port 1023 for any port number > 1023
    __be16 dst_port;      // number of port or 0 for any or port 1023 for any port number > 1023
    __u8 protocol;        // values from: prot_t
    ack_t ack;            // values from: ack_t
    __u8 action;          // valid values: NF_ACCEPT, NF_DROP
} rule_t;

// various reasons to be registered in each log entry
typedef enum
{
    REASON_FW_INACTIVE = -1,
    REASON_NO_MATCHING_RULE = -2,
    REASON_XMAS_PACKET = -4,
    REASON_TCP_STREAM_ENFORCE = -8,
    REASON_FTP_DATA_SESSION = -16,
    REASON_TCP_PROXY = -32
} reason_t;

// logging
typedef struct
{
    unsigned long timestamp; // time of creation/update
    __u8 protocol;           // values from: prot_t
    __u8 action;             // valid values: NF_ACCEPT, NF_DROP
    __be32 src_ip;           // if you use this struct in userspace, change the type to unsigned int
    __be32 dst_ip;           // if you use this struct in userspace, change the type to unsigned int
    __be16 src_port;         // if you use this struct in userspace, change the type to unsigned short
    __be16 dst_port;         // if you use this struct in userspace, change the type to unsigned short
    reason_t reason;         // rule#index, or values from: reason_t
    unsigned int count;      // counts this line's hits
} log_row_t;

#endif // _FW_H_