/*
In this module we track the state of TCP connections.
*/
#ifndef _TRACKER_H_
#define _TRACKER_H_

#include "fw.h"
#include "parser.h"

typedef enum
{
    PRESYN,
    SYN,
    SYN_ACK,
    ESTABLISHED,
    FIN1,
    A_ACK,
    A_FIN2,
    B_FIN2,
    B_ACK,
} tcp_status_t;

typedef struct
{
    tcp_status_t status;
    direction_t expected_direction;
} tcp_state_t;

typedef struct
{
    __be32 ip;
    __be16 port;
} id_t;

typedef enum
{
    PROXY_NONE,
    PROXY_HTTP,
    PROXY_FTP_CONTROL,
    PROXY_FTP_DATA
} proxy_type_t;

typedef struct
{
    proxy_type_t type;
    __be16 port;

} proxy_t;

typedef struct
{
    id_t internal_id; // internal id
    id_t external_id; // external id
    tcp_state_t state;
    proxy_t proxy;

    struct list_head list_node;
} connection_t;

// Auxiliary functions
direction_t flip_direction(direction_t direction);

// Connection functions
void add_connection(const packet_t *packet);
connection_t *find_connection(packet_t *packet);
void remove_connection(connection_t *connection);
void free_connections(void);

// For debug purposes
const char *conn_status_str(tcp_status_t status);
const char *direction_str(direction_t direction);

// Enforcing TCP states' validity
void pre_state(tcp_state_t *state);
void init_state(tcp_state_t *state, const packet_t *packet);
int enforce_state(const struct tcphdr *tcph, direction_t packet_direction, tcp_state_t *state);

/*
 * Status to be shown to the user
 */
typedef enum
{
    STATE_INITIATING,
    STATE_ONGOING,
    STATE_CLOSING
} public_state_t;

// Define connections device operations
public_state_t state2public(tcp_state_t state);
ssize_t ctable2buf(char *buf);

#endif