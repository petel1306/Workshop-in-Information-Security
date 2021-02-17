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

// Proxy manipulating packets
void c2p(packet_t *packet, connection_t *conn);
void s2p(packet_t *packet, connection_t *conn);
void p2c(packet_t *packet, connection_t *conn);
void p2s(packet_t *packet, connection_t *conn);