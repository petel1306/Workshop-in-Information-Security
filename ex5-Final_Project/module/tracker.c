#include "tracker.h"
#include "fw.h"

#define ID_PORT_ANY 0

LIST_HEAD(ctable);
__u32 connections_amount = 0;

direction_t flip_direction(direction_t direction)
{
    if (direction == DIRECTION_IN)
    {
        return DIRECTION_OUT;
    }
    if (direction == DIRECTION_OUT)
    {
        return DIRECTION_IN;
    }
    return direction;
}

void get_ids(const packet_t *packet, id_t *int_id, id_t *ext_id)
{
    if (packet->direction == DIRECTION_OUT)
    {
        int_id->ip = packet->src_ip;
        int_id->port = packet->src_port;
        ext_id->ip = packet->dst_ip;
        ext_id->port = packet->dst_port;
    }
    if (packet->direction == DIRECTION_IN)
    {
        int_id->ip = packet->dst_ip;
        int_id->port = packet->dst_port;
        ext_id->ip = packet->src_ip;
        ext_id->port = packet->src_port;
    }
}

/**
 * Checks if two connection id matches.
 * Port 0 is a wildcard (i.e. match to any port)
 */
int is_id_match(const id_t id1, const id_t id2)
{
    int ip_match = (id1.ip == id2.ip);
    int port_match = (id1.port == id2.port) || id1.port == ID_PORT_ANY || id2.port == ID_PORT_ANY;
    return ip_match && port_match;
}

/**
 * Add a blank connection
 */
connection_t *add_blank_connection(void)
{

    // Allocate connection
    connection_t *conn = (connection_t *)kmalloc(sizeof(connection_t), GFP_KERNEL);

    // Add connection to the table
    list_add_tail(&conn->list_node, &ctable);
    connections_amount++;

    return conn;
}

/**
 * Add a new connection
 */
connection_t *add_connection(const packet_t *packet)
{
    connection_t *conn = add_blank_connection();

    // Get ids from the packet
    get_ids(packet, &conn->internal_id, &conn->external_id);

    // Initialize connection state
    conn->state.status = PRESYN;
    conn->state.expected_direction = DIRECTION_ANY;

    // Non-proxy connection
    conn->type = NONE_PROXY;
    conn->proxy_port = 1;

    return conn;
}

connection_t *find_connection(packet_t *packet)
{
    connection_t *conn;
    id_t packet_int_id, packet_ext_id;
    get_ids(packet, &packet_int_id, &packet_ext_id);

    list_for_each_entry(conn, &ctable, list_node)
    {

        if (is_id_match(conn->internal_id, packet_int_id) && is_id_match(conn->external_id, packet_ext_id))
        {
            return conn;
        }
    }
    return NULL;
}

void remove_connection(connection_t *connection)
{
    list_del(&connection->list_node);
    connections_amount--;
}

void free_connections(void)
{
    connection_t *the_connection;
    connection_t *temp_connection;

    list_for_each_entry_safe(the_connection, temp_connection, &ctable, list_node)
    {
        list_del(&the_connection->list_node);
        kfree(the_connection);
    }

    connections_amount = 0;
}

/**
 * Tells if proxy connection
 */
int is_proxy_connection(const connection_t *conn)
{
    connection_type_t type = conn->type;
    return (type == PROXY_HTTP) || (type == PROXY_FTP_CONTROL);
}

/**
 * returns 0 and updates the state if the tcp packet state is valid
 * returns 1 if the tcp packet state is unvalid
 * returns 2 if the connection has ended
 */
int enforce_state(const struct tcphdr *tcph, direction_t packet_direction, tcp_state_t *state)
{
    if (tcph->rst)
    {
        return 2;
    }
    if (packet_direction & state->expected_direction)
    {
        switch (state->status)
        {
        case PRESYN:
            if (tcph->syn && !tcph->ack) // syn
            {
                state->status = SYN;
                state->expected_direction = flip_direction(packet_direction);
                return 0;
            }
            return 1;

        case SYN:
            if (tcph->syn && tcph->ack) // syn ack
            {
                state->status = SYN_ACK;
                state->expected_direction = flip_direction(packet_direction);
                return 0;
            }
            return 1;

        case SYN_ACK:
            if (tcph->ack) // ack
            {
                state->status = ESTABLISHED;
                state->expected_direction = DIRECTION_ANY;
                return 0;
            }
            return 1;

        case ESTABLISHED:
            if (tcph->fin)
            {
                state->status = FIN1;
                state->expected_direction = flip_direction(packet_direction);
            }
            return 0;

        case FIN1:
            if (tcph->fin && tcph->ack)
            {
                state->status = A_FIN2;
                state->expected_direction = flip_direction(packet_direction);
                return 0;
            }
            if (tcph->ack)
            {
                state->status = A_ACK;
                state->expected_direction = packet_direction;
                return 0;
            }
            if (tcph->fin)
            {
                state->status = B_FIN2;
                state->expected_direction = DIRECTION_ANY;
                return 0;
            }
            return 1;

        case A_ACK:
            if (tcph->fin)
            {
                state->status = A_FIN2;
                state->expected_direction = flip_direction(packet_direction);
                return 0;
            }
            return 1;

        case A_FIN2:
            if (tcph->ack)
            { // End of connection
                return 2;
            }
            return 1;

        case B_FIN2:
            if (tcph->ack)
            {
                state->status = B_ACK;
                state->expected_direction = flip_direction(packet_direction);
                return 0;
            }
            return 1;

        case B_ACK:
            if (tcph->ack)
            { // End of connection
                return 2;
            }
            return 1;
        }
    }
    return 1;
}

/*
 * For debug purposes
 */
const char *conn_status_str(tcp_status_t status)
{
    switch (status)
    {
    case PRESYN:
        return "pre-SYN";
    case SYN:
        return "SYN sent";
    case SYN_ACK:
        return "SYN ACK sent";
    case ESTABLISHED:
        return "ACK sent, conn ESTABLISHED";
    case FIN1:
        return "fin1 sent";
    case A_ACK:
        return "case A - ack for fin1 sent";
    case A_FIN2:
        return "case A - fin2 sent";
    case B_FIN2:
        return "case B - fin2 sent";
    case B_ACK:
        return "case B - ack some fin";
    }
    return "";
}

public_state_t state2public(tcp_state_t state)
{
    switch (state.status)
    {
    case PRESYN:
        return STATE_EXPECTING;
    case SYN:
    case SYN_ACK:
        return STATE_INITIATING;
    case ESTABLISHED:
        return STATE_ONGOING;
    default:
        return STATE_CLOSING;
    }
}

const __u8 CONN_BUF_SIZE = 2 * sizeof(__be32) + 2 * sizeof(__be16) + sizeof(public_state_t);
const __u8 CAMOUNT_SIZE = sizeof(connections_amount);

void conn2buf(const connection_t *conn, char *buf)
{
    public_state_t pub_state;
    
    if (is_proxy_connection(conn))
    {
        pub_state = STATE_PROXY;
    }
    else
    {
        pub_state = state2public(conn->state);
    }
    
    VAR2BUF(conn->internal_id.ip);
    VAR2BUF(conn->internal_id.port);
    VAR2BUF(conn->external_id.ip);
    VAR2BUF(conn->external_id.port);
    VAR2BUF(pub_state);
}

ssize_t ctable2buf(char *buf)
{
    connection_t *conn;

    VAR2BUF(connections_amount);

    list_for_each_entry(conn, &ctable, list_node)
    {
        conn2buf(conn, buf);
        buf += CONN_BUF_SIZE;
    }

    return CAMOUNT_SIZE + connections_amount * CONN_BUF_SIZE;
}
