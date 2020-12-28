#include "fw.h"
#include "tracker.h"

typedef enum
{
    PROXY_HTTP = 80,
    PROXY_FTP = 21
} proxy_type_t;

typedef struct
{
    id_t client_id;
    id_t server_id;
    tcp_state_t c2p_state; // client to proxy state
    proxy_type_t type;

    struct list_head list_node;
} proxy_t;

typedef struct
{
    id_t client_id;

    struct list_head list_node;
} reservation_t;

// Proxy kernel operations
void add_proxy(packet_t *packet);
void get_client_id(const packet_t *packet, id_t *client_id);
proxy_t *find_proxy_by_client(id_t client_id);
void remove_proxy(proxy_t *proxy);
void free_proxy(void);

// Advanced proxy operations
__u8 is_reserved(id_t client_id);
void reserve(id_t client_id);

// Define connections device operations
ssize_t ptable2buf(char *buf);

typedef enum
{
    KIND_C2P, // Client to proxy
    KIND_S2P, // Server to proxy
    KIND_P2C, // Proxy to client
    KIND_P2S, // Proxy to server
    KIND_NONE
} proxy_kind_t;