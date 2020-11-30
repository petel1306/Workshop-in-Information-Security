#include "log_handler.h"

/*
 * Copy char buffer to a log struct.
 */
void buf2log(log_row_t *log, const char *buf)
{
    BUF2VAR(log->timestamp);
    BUF2VAR(log->protocol);
    BUF2VAR(log->action);
    BUF2VAR(log->src_ip);
    BUF2VAR(log->dst_ip);
    BUF2VAR(log->src_port);
    BUF2VAR(log->dst_port);
    BUF2VAR(log->reason);
    BUF2VAR(log->count);
}

void reason2str(char *str, reason_t reason)
{
}

void time2str(const char *str, reason_t *reason)
{
}
