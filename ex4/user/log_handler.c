#include "log_handler.h"

#include <time.h>

/*
 * Copy char buffer to a log struct.
 */
void buf2log_row(log_row_t *log_row, const char *buf)
{
    BUF2VAR(log_row->timestamp);
    BUF2VAR(log_row->protocol);
    BUF2VAR(log_row->action);
    BUF2VAR(log_row->src_ip);
    BUF2VAR(log_row->dst_ip);
    BUF2VAR(log_row->src_port);
    BUF2VAR(log_row->dst_port);
    BUF2VAR(log_row->reason);
    BUF2VAR(log_row->count);
}

#define REASON_CASE(reason)                                                                                            \
    case reason:                                                                                                       \
        strcpy(str, #reason);                                                                                          \
        break;

void reason2str(char *str, const reason_t reason)
{
    switch (reason)
    {
        REASON_CASE(REASON_FW_INACTIVE)
        REASON_CASE(REASON_NO_MATCHING_RULE)
        REASON_CASE(REASON_XMAS_PACKET)
        REASON_CASE(REASON_TCP_STREAM_ENFORCE)
        REASON_CASE(REASON_FTP_DATA_SESSION)
        REASON_CASE(REASON_TCP_PROXY)
    default:
        sprintf(str, "%d", reason);
    }
}

void time2str(char *str, const unsigned long timestamp)
{
    time_t time = timestamp; // type adaptation
    struct tm *time_s = localtime(&time);

    // Testing logic
    if (mktime(time_s) != time)
    {
        DINFO("Time logic isn't working")
    }

    strftime(str, 20, "%m/%d/%Y %T", time_s);
}

const char *log_format = "%-19s  %-15s  %-15s  %-8s  %-8s  %-8s  %-6s  %-25s %s\n";

void log_row2str(const log_row_t *log_row, char *str)
{
    // Allocate enough space
    char timestamp[30], src_ip[30], dst_ip[30], src_port[8], dst_port[8], *protocol, *action, reason[30], count[25];

    time2str(timestamp, log_row->timestamp);
    ip2str(src_ip, log_row->src_ip);
    ip2str(dst_ip, log_row->dst_ip);
    sprintf(src_port, "%u", log_row->src_port);
    sprintf(dst_port, "%u", log_row->dst_port);
    protocol = protocol2str(log_row->protocol);
    action = action2str(log_row->action);
    reason2str(reason, log_row->reason);
    sprintf(count, "%u", log_row->count);

    // At least 2 spaces between each field
    sprintf(str, log_format, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, reason, count);
}

void log_headline(char *str)
{
    sprintf(str, log_format, "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "reason",
            "count");
}
