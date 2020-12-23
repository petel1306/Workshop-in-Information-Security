#include "tracker.h"
#include "fw.h"

LIST_HEAD(ctable);
static unsigned int connections_amount;

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

void add_connection(packet_t *packet)
{
    connection_t *new_connection = (connection_t *)kmalloc(sizeof(connection_t), GFP_KERNEL);
    new_connection->state.status = SYN;
    new_connection->state.expected_direction = flip_direction(packet->direction);
    if (packet->direction == DIRECTION_OUT)
    {
        new_connection->internal_id.ip = packet->src_ip;
        new_connection->internal_id.port = packet->src_port;
        new_connection->external_id.ip = packet->dst_ip;
        new_connection->external_id.port = packet->dst_port;
    }
    if (packet->direction == DIRECTION_IN)
    {
        new_connection->internal_id.ip = packet->dst_ip;
        new_connection->internal_id.port = packet->dst_port;
        new_connection->external_id.ip = packet->src_ip;
        new_connection->external_id.port = packet->src_port;
    }

    list_add_tail(&new_connection->list_node, &ctable);
    connections_amount++;
}

connection_t *find_connection(packet_t *packet)
{
    connection_t *conn;
    list_for_each_entry(conn, &ctable, list_node)
    {
        if (packet->direction == DIRECTION_OUT && conn->internal_id.ip == packet->src_ip &&
            conn->internal_id.port == packet->src_port && conn->external_id.ip == packet->dst_ip &&
            conn->external_id.port == packet->dst_port)
        {
            return conn;
        }
        if (packet->direction == DIRECTION_IN && conn->internal_id.ip == packet->dst_ip &&
            conn->internal_id.port == packet->dst_port && conn->external_id.ip == packet->src_ip &&
            conn->external_id.port == packet->src_port)
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

/*
 * returns 0 and updates the state if the tcp packet state is valid
 * returns 1 if the tcp packet state is unvalid
 * returns 2 if the connection has ended
 */
int enforce_state(const struct tcphdr *tcph, direction_t packet_direction, tcp_state_t *state)
{
    if (packet_direction & state->expected_direction)
    {
        switch (state->status)
        {
        case SYN:
            if (tcph->syn && tcph->ack) // syn ack
            {
                state->status = SYN_ACK;
                state->expected_direction = flip_direction(packet_direction);
                return 0;
            }
            return 1;

        case SYN_ACK:
            if (tcph->ack)
            { // ack
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

static const char *conn_status_str(tcp_status_t status)
{
    /* For debug logs, return state as string */
    switch (status)
    {
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
}

/*
 * For debug purposes
 */
static const char *conn_direction_str(direction_t direction)
{
    switch (direction)
    {
    case DIRECTION_NONE:
        return "none";
    case DIRECTION_IN:
        return "in";
    case DIRECTION_OUT:
        return "out";
    case DIRECTION_ANY:
        return "any";
    }
}

/*
 * Status to be shown to the user
 */
typedef enum
{
    STATE_INITIATING,
    STATE_ONGOING,
    STATE_CLOSING
} public_state_t;

public_state_t state2public(tcp_state_t state)
{
    switch (state.status)
    {
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
const __u8 AMOUNT_BUF_SIZE = sizeof(connections_amount);

void conn2buf(const connection_t *conn, char *buf)
{
    public_state_t pub_state = state2public(conn->state);
    VAR2BUF(conn->internal_id.ip);
    VAR2BUF(conn->internal_id.port);
    VAR2BUF(conn->external_id.ip);
    VAR2BUF(conn->external_id.port);
    VAR2BUF(pub_state);
}

static __u8 is_ammount_passed;
static connection_t *read_conn;

int open_ctable(struct inode *_inode, struct file *_file)
{
    read_conn = list_first_entry(&ctable, connection_t, list_node);
    is_ammount_passed = 0;
    return 0;
}

ssize_t read_ctable(struct file *filp, char *buf, size_t length, loff_t *offp)
{
    char my_buf[CONN_BUF_SIZE];
    int count = 0;

    if (!is_ammount_passed)
    {
        if (length < AMOUNT_BUF_SIZE)
        {
            return 0;
        }

        if (copy_to_user(buf, &connections_amount, AMOUNT_BUF_SIZE))
        {
            return -EFAULT;
        }

        count += AMOUNT_BUF_SIZE;
        length -= AMOUNT_BUF_SIZE;
        is_ammount_passed = 1;
    }

    list_for_each_entry_continue(read_conn, &ctable, list_node)
    {
        if (length < CONN_BUF_SIZE)
        {
            break;
        }

        conn2buf(read_conn, my_buf);
        if (copy_to_user(buf + count, my_buf, CONN_BUF_SIZE))
        {
            return -EFAULT;
        }

        count += CONN_BUF_SIZE;
        length -= CONN_BUF_SIZE;
    }
    return count;
}