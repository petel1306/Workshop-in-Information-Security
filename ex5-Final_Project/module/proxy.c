#include "proxy.h"
#include "fw.h"
#include "parser.h"
#include "tracker.h"

extern struct list_head ctable;
extern __u32 connections_amount;

connection_t *proxy_ports[1 << 16]; // 2^16 possible ports

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

/**
 * Fix packet checksum
 */
static void fix_checksum(struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    // Fix TCP header checksum
    int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check =
        tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));

    // Fix IP header checksum
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    skb->ip_summed = CHECKSUM_NONE;

    // Fix packet linearization
    // skb->csum_valid = 0;
    // if (skb_linearize(skb) < 0)
    // {
    //     /* Handle error
    // }
}

/**
 * Setup proxy connection (if it's of internal client -> external client form)
 * Returns 1 for proxy connection, otherwise 0.
 */
int proxy_setup(packet_t *packet, connection_t *conn)
{
    int is_proxy = 0;
    if (packet->direction == DIRECTION_OUT)
    {
        if (packet->dst_port == HTTP_PORT)
        {
            conn->type = PROXY_HTTP;
            is_proxy = 1;
        }
        if (packet->dst_port == FTP_PORT)
        {
            conn->type = PROXY_FTP_CONTROL;
            is_proxy = 1;
        }

        if (is_proxy)
        {
            proxy_route(packet);
        }
    }
    return is_proxy;
}

/**
 * Routing proxy connections.
 * Returns 1 if the packet is rounted for proxy, otherwise 0
 */
int proxy_route(packet_t *packet)
{
    struct sk_buff *skb = packet->skb;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);

    if (packet->hooknum == NF_INET_PRE_ROUTING)
    {
        if (packet->direction == DIRECTION_OUT)
        {
            // Check if c2p (client to proxy) packet

            id_t int_id, ext_id;
            connection_t *proxy;

            get_ids(packet, &int_id, &ext_id);
            proxy = find_proxy_by_client(int_id);

            if (proxy != NULL)
            {
                __be16 redirect_port;

                DINFO("c2p packet")

                // Change the routing
                iph->daddr = htonl(FW_INT_ADRR);
                redirect_port = (proxy->type == PROXY_HTTP) ? HTTP_PROXY_PORT : FTP_PROXY_PORT;
                tcph->dest = htons(redirect_port);

                // Fix the checksum
                fix_checksum(packet->skb);

                return 1;
            }
        }
        else
        {
            // Check if s2p (server to proxy) packet type

            connection_t *proxy = find_proxy_by_port(packet->dst_port);
            if (proxy != NULL)
            {
                id_t int_id, ext_id;
                get_ids(packet, &int_id, &ext_id);

                // Check if the result is consistent (server id matches)
                if (is_id_match(ext_id, proxy->external_id))
                {
                    DINFO("s2p packet")

                    // Change the routing
                    iph->daddr = htonl(FW_EXT_ADRR);

                    // Fix the checksum
                    fix_checksum(packet->skb);

                    return 1;
                }
            }
        }
    }
    else
    {
        if (packet->direction == DIRECTION_OUT)
        {
            // Check if p2s (proxy to server) packet type

            connection_t *proxy = find_proxy_by_port(packet->src_port);
            if (proxy != NULL)
            {
                id_t int_id, ext_id;
                get_ids(packet, &int_id, &ext_id);

                // Check if the result is consistent (server id matches)
                if (is_id_match(ext_id, proxy->external_id))
                {
                    DINFO("p2s packet")

                    // Fake source
                    iph->saddr = htonl(proxy->internal_id.ip);

                    // Fix the checksum
                    fix_checksum(packet->skb);

                    return 1;
                }
            }
        }
        else
        {
            // Check if p2c (proxy to client) packet type

            id_t int_id, ext_id;
            connection_t *proxy;

            get_ids(packet, &int_id, &ext_id);
            proxy = find_proxy_by_client(int_id);

            if (proxy != NULL)
            {
                DINFO("p2c packet")

                // Fake source
                iph->saddr = htonl(proxy->external_id.ip);
                tcph->source = htons(proxy->external_id.port);

                // Fix the checksum
                fix_checksum(packet->skb);

                return 1;
            }
        }
    }
    
    return 0;
}

int escape_ftp_data(packet_t *packet, connection_t *conn)
{
    if (conn->type == FTP_DATA && conn->state.status == SYN) // Wild card port is a sign for FTP data session
    {
        conn->external_id.port = packet->src_port;
        return 1;
    }
    return 0;
}

// ========================== Proxy device operations ===========================
const __u16 PROXY_SET_SIZE = sizeof(__be32) + 2 * sizeof(__be16);
const __u16 FTP_ADD_SIZE = 2 * sizeof(__be32) + sizeof(__be16);

ssize_t set_proxy_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    id_t client_id;
    __be32 client_ip;
    __be16 client_port;
    __be16 proxy_port;
    connection_t *proxy;

    if (count < PROXY_SET_SIZE)
    {
        return 0;
    }

    // Should get (client_ip, client_port, proxy_port)
    BUF2VAR(client_ip);
    BUF2VAR(client_port);
    BUF2VAR(proxy_port);
    
    client_id.ip = ntohl(client_ip);
    client_id.port = client_port;

    DINFO("set_proxy_port: client_ip=%d.%d.%d.%d, client_port=%d, proxy_port=%d", IP_PARTS(client_id.ip), client_id.port, proxy_port)

    proxy = find_proxy_by_client(client_id);
    if (proxy == NULL)
    {
        DINFO("set_proxy_port: can't find proxy")
    }

    proxy->proxy_port = proxy_port;
    proxy_ports[proxy_port] = proxy;

    return PROXY_SET_SIZE;
}

ssize_t add_ftp_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    __be32 ftp_ip, server_ip;
    __be16 ftp_port;
    connection_t *conn;

    if (count < FTP_ADD_SIZE)
    {
        return 0;
    }

    // Should get (client_ip, server_ip, ftp_data_port)
    BUF2VAR(ftp_ip);
    BUF2VAR(server_ip);
    BUF2VAR(ftp_port);

    // Add an FTP data connection
    conn = add_blank_connection();

    // Set identifiers
    conn->internal_id.ip = ntohl(ftp_ip);
    conn->internal_id.port = ftp_port;
    conn->external_id.ip = ntohl(server_ip);
    conn->external_id.port = 0; // Wildcard - match to any port
    
    DINFO("Add_ftp_data: client_ip=%d.%d.%d.%d,  client_port=%d, server_ip=%d.%d.%d.%d, server_port=%d",
        IP_PARTS(conn->internal_id.ip), conn->internal_id.port, IP_PARTS(conn->external_id.ip), conn->external_id.port);

    // Initialize connection state
    conn->state.status = PRESYN;
    conn->state.expected_direction = DIRECTION_IN; // Now the client becomes the server

    // Non-proxy connection
    conn->type = FTP_DATA;
    conn->proxy_port = 1;

    return FTP_ADD_SIZE;
}