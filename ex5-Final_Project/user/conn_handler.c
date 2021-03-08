#include "conn_handler.h"
#include "interface.h"

void buf2conn(connection_t *conn, const char *buf)
{
    BUF2VAR(conn->internal_ip);
    BUF2VAR(conn->internal_port);
    BUF2VAR(conn->external_ip);
    BUF2VAR(conn->external_port);
    BUF2VAR(conn->state);
}

#define STATE_CASE(state)                                                                                              \
    case STATE_##state:                                                                                                \
        strcpy(str, #state);                                                                                           \
        break;

void state2str(char *str, const tcp_state_t state)
{
    switch (state)
    {
        STATE_CASE(EXPECTING)
        STATE_CASE(INITIATING)
        STATE_CASE(ONGOING)
        STATE_CASE(CLOSING)
        STATE_CASE(PROXY)
    default:
        strcpy(str, "");
    }
}

const char *conn_format = "%-15s  %-15s  %-8s  %-8s  %-10s\n";

void conn2str(const connection_t *conn, char *str)
{
    char src_ip[30], dst_ip[30], src_port[8], dst_port[8], state[15];

    ip2str(src_ip, conn->internal_ip);
    ip2str(dst_ip, conn->external_ip);
    sprintf(src_port, "%u", conn->internal_port);
    sprintf(dst_port, "%u", conn->external_port);
    state2str(state, conn->state);

    sprintf(str, conn_format, src_ip, dst_ip, src_port, dst_port, state);
}

void conn_headline(char *str)
{
    sprintf(str, conn_format, "in_ip", "out_ip", "in_port", "out_port", "state");
}
