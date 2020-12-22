/*
In this module we track the state of TCP connections.
*/
#ifndef _TRACKER_H_
#define _TRACKER_H_

#include "fw.h"
#include "parser.h"

typedef enum
{
    SYN,
    SYN_ACK,
    ESTABLISHED,
    FIN1,
    A_ACK,
    A_FIN2,
    B_FIN2,
    B_ACK,
} status_t;

typedef struct
{
    status_t status;
    direction_t expected_direction;
} state_t;

typedef struct
{
    __be32 ip;
    __be16 port;
} id_t;

typedef struct
{
    id_t internal_id; // internal id
    id_t external_id; // external id
    state_t state;

    struct list_head list_node;
} connection_t;

void add_connection(packet_t *packet);
connection_t *get_connection(packet_t *packet);
void remove_connection(connection_t *connection);
void free_connections(void);

int enforce_state(const struct tcphdr *tcph, direction_t packet_direction, state_t *state);

#endif