#include "fw.h"
#include "tracker.h"

#define HTTP_PORT 80
#define FTP_PORT 21
#define HTTP_PROXY_PORT 800
#define FTP_PROXY_PORT 210

// Proxy kernel operations
int is_proxy_connection(connection_t *conn);
void setup_proxy(packet_t *packet);
connection_t *find_proxy_by_port(__be16 proxy_port);

// Proxy inspecting operations
int proxy_setup(packet_t *packet, connection_t *conn);
int proxy_route(packet_t *packet);
int escape_ftp_data(packet_t *packet, connection_t *conn);

// Proxy devices operations

// *** After setting a proxy port immediately read from the device to get it's destination ***
ssize_t set_proxy_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t get_proxy_server(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t add_ftp_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);