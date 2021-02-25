#ifndef _CONN_HANDLER_H_
#define _CONN_HANDLER_H_

#include "interface.h"

typedef enum
{
    STATE_EXPECTING,
    STATE_INITIATING,
    STATE_ONGOING,
    STATE_CLOSING,
    STATE_PROXY
} tcp_state_t;

typedef struct
{
    uint32_t internal_ip;
    uint16_t internal_port;
    uint32_t external_ip;
    uint16_t external_port;
    tcp_state_t state;
} connection_t;

void buf2conn(connection_t *conn, const char *buf);
void conn2str(const connection_t *conn, char *str);
void conn_headline(char *str);

#endif