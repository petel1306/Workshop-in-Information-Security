#include "proxy.h"
#include "fw.h"
#include "tracker.h"

static LIST_HEAD(ptable); // proxy table
static __u32 proxy_amount = 0;

proxy_t *proxy_ports[1 << 16]; // 2^16 possible ports

/**
 * Reserved connections for FTP data sessions
 */
static LIST_HEAD(reserved_connections);

void add_proxy(packet_t *packet)
{
    proxy_t *new_proxy = (proxy_t *)kmalloc(sizeof(proxy_t), GFP_KERNEL);

    init_state(&new_proxy->c2p_state, packet);
    pre_state(&new_proxy->s2p_state);

    new_proxy->client_id.ip = packet->src_ip;
    new_proxy->client_id.port = packet->src_port;
    new_proxy->server_id.ip = packet->dst_ip;
    new_proxy->server_id.port = packet->dst_port;

    list_add_tail(&new_proxy->list_node, &ptable);
    proxy_amount++;
}

static int id_match(const id_t id1, const id_t id2)
{
    return (id1.ip == id2.ip && id1.port == id2.port);
}

void get_client_id(const packet_t *packet, id_t *client_id)
{

    if (packet->direction == DIRECTION_OUT)
    {
        client_id->ip = packet->src_ip;
        client_id->port = packet->src_port;
    }

    if (packet->direction == DIRECTION_IN)
    {
        client_id->ip = packet->dst_ip;
        client_id->port = packet->dst_port;
    }
}

/**
 * Finds proxy by client ip, port
 */
proxy_t *find_proxy_by_client(id_t client_id)
{
    proxy_t *proxy;

    list_for_each_entry(proxy, &ptable, list_node)
    {
        if (id_match(client_id, proxy->client_id))
        {
            return proxy;
        }
    }
    return NULL;
}

void remove_proxy(proxy_t *proxy)
{
    list_del(&proxy->list_node);
    proxy_amount--;
}

void free_proxy()
{
    proxy_t *the_proxy;
    proxy_t *temp_proxy;

    reservation_t *the_resv;
    reservation_t *temp_resv;

    // proxy cleanup
    list_for_each_entry_safe(the_proxy, temp_proxy, &ptable, list_node)
    {
        list_del(&the_proxy->list_node);
        kfree(the_proxy);
    }
    proxy_amount = 0;

    // reservations cleanup
    list_for_each_entry_safe(the_resv, temp_resv, &reserved_connections, list_node)
    {
        list_del(&the_resv->list_node);
        kfree(the_resv);
    }
}

/**
 * Functions for converting ptable to buffer
 * A litlle bit code duplication (of the ctable functions), but it should be OK :)
 */

const __u8 PROXY_BUF_SIZE = 2 * sizeof(__be32) + 2 * sizeof(__be16) + sizeof(public_state_t);
const __u8 PAMOUNT_SIZE = sizeof(proxy_amount);

void proxy2buf(const proxy_t *proxy, char *buf)
{
    public_state_t pub_state = state2public(proxy->c2p_state);
    VAR2BUF(proxy->client_id.ip);
    VAR2BUF(proxy->client_id.port);
    VAR2BUF(proxy->server_id.ip);
    VAR2BUF(proxy->server_id.port);
    VAR2BUF(pub_state);
}

ssize_t ptable2buf(char *buf)
{
    proxy_t *proxy;

    VAR2BUF(proxy_amount);

    list_for_each_entry(proxy, &ptable, list_node)
    {
        proxy2buf(proxy, buf);
        buf += PROXY_BUF_SIZE;
    }

    return PAMOUNT_SIZE + proxy_amount * PROXY_BUF_SIZE;
}

// ==================== proxy functions serving the user =====================

/**
 * Finds proxy by user proxy port
 */
static proxy_t *find_proxy_by_port(__be16 proxy_port)
{
    return proxy_ports[proxy_port];
}

/**
 * Set proxy by user port
 */
static proxy_t *set_proxy_port(__be16 proxy_port, proxy_t *proxy)
{
    proxy_ports[proxy_port] = proxy;
}

__u8 is_reserved(id_t client_id)
{
    reservation_t *resv;
    reservation_t *temp;
    list_for_each_entry_safe(resv, temp, &reserved_connections, list_node)
    {
        if (id_match(client_id, resv->client_id))
        {
            list_del(&resv->list_node);
            kfree(resv);
            return 1;
        }
    }
    return 0;
}

void reserve(id_t client_id)
{
    reservation_t *resv = (reservation_t *)kmalloc(sizeof(reservation_t), GFP_KERNEL);
    resv->client_id = client_id;
    list_add_tail(&resv->list_node, &reserved_connections);
}
