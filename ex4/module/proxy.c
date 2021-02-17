#include "proxy.h"
#include "fw.h"
#include "tracker.h"

extern struct list_head ctable;
extern __u32 connections_amount;

connection_t *proxy_ports[1 << 16]; // 2^16 possible ports

/**
 * Tells if proxy connection
 */
int is_proxy_connection(connection_t *conn)
{
    connection_type_t type = conn->type;
    return (type == PROXY_HTTP) || (type == PROXY_FTP_CONTROL);
}

/**
 * Finds proxy by client id (ip + port)
 */
connection_t *find_proxy_by_client(id_t client_id)
{
    connection_t *conn;

    list_for_each_entry(conn, &ctable, list_node)
    {
        if (is_proxy_connection(conn) && is_id_match(client_id, conn->internal_id))
        {
            return conn;
        }
    }
    return NULL;
}

/**
 * Finds proxy by user proxy port
 */
connection_t *find_proxy_by_port(__be16 proxy_port)
{
    return proxy_ports[proxy_port];
}