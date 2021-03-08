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
    NONE_PROXY,
    PROXY_HTTP,
    PROXY_FTP_CONTROL,
    FTP_DATA
} connection_type_t;

typedef struct
{
    id_t internal_id;
    id_t external_id;
    tcp_state_t state;
    connection_type_t type;
    __be16 proxy_port;

    struct list_head list_node;
} connection_t;

// Auxiliary functions
direction_t flip_direction(direction_t direction);
void get_ids(const packet_t *packet, id_t *int_id, id_t *ext_id);
int is_id_match(const id_t id1, const id_t id2);

// Connection functions
connection_t *add_blank_connection(void);
connection_t *add_connection(const packet_t *packet);
connection_t *find_connection(packet_t *packet);
void remove_connection(connection_t *connection);
void free_connections(void);

// For debug purposes
const char *conn_status_str(tcp_status_t status);

// Identify proxy
int is_proxy_connection(const connection_t *conn);

// Enforcing TCP states' validity
int enforce_state(const struct tcphdr *tcph, direction_t packet_direction, tcp_state_t *state);

/*
 * Status to be shown to the user
 */
typedef enum
{
    STATE_EXPECTING,
    STATE_INITIATING,
    STATE_ONGOING,
    STATE_CLOSING,
    STATE_PROXY
} public_state_t;

// Define connections device operations
public_state_t state2public(tcp_state_t state);
ssize_t ctable2buf(char *buf);

#endif