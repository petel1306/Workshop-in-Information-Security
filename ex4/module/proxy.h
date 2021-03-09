/*
In this module we manage the proxy connections.
*/

#include "fw.h"
#include "tracker.h"

#define HTTP_PORT 80
#define FTP_PORT 21
#define HTTP_PROXY_PORT 800
#define FTP_PROXY_PORT 210

// Proxy kernel operations
connection_t *find_proxy_by_client(id_t client_id);
connection_t *find_proxy_by_port(__be16 proxy_port);

// Proxy inspecting operations
int proxy_setup(packet_t *packet, connection_t *conn);
int proxy_route(packet_t *packet);
int escape_ftp_data(packet_t *packet, connection_t *conn);

// Proxy devices operations

ssize_t set_proxy_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t add_ftp_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);