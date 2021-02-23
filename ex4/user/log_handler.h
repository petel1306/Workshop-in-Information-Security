#ifndef _LOG_HANDLER_H_
#define _LOG_HANDLER_H_

#include "interface.h"

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
    uint8_t protocol;        // values from: prot_t
    uint8_t action;          // valid values: NF_ACCEPT, NF_DROP
    uint32_t src_ip;         // if you use this struct in userspace, change the type to unsigned int
    uint32_t dst_ip;         // if you use this struct in userspace, change the type to unsigned int
    uint16_t src_port;       // if you use this struct in userspace, change the type to unsigned short
    uint16_t dst_port;       // if you use this struct in userspace, change the type to unsigned short
    reason_t reason;         // rule#index, or values from: reason_t
    unsigned int count;      // counts this line's hits
} log_row_t;

void buf2log_row(log_row_t *log_row, const char *buf);
void log_row2str(const log_row_t *log_row, char *str);
void log_headline(char *str);

#endif