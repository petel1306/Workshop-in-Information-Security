#include "interface.h"

// Counts the messages to the user
static unsigned int info_counter = 0;

unsigned int get_info_counter(void)
{
    return ++info_counter;
}

/**
 * Copy var to buffer, and increment the pointer of the bufer
 */
void var2buf(char **buf_ptr, const void *var, size_t n)
{
    memcpy(*buf_ptr, var, n);
    *buf_ptr += n;
}

/**
 * Copy buffer to var, and increment the pointer of the bufer
 */
void buf2var(const char **buf_ptr, void *var, size_t n)
{
    memcpy(var, *buf_ptr, n);
    *buf_ptr += n;
}

#define NF_DROP 0
#define NF_ACCEPT 1

char *action2str(const uint8_t action)
{
    if (action == NF_ACCEPT)
    {
        return "accept";
    }
    else
    {
        return "drop";
    }
}

/**
 * Returns 1 if succeed (the string is valid), 0 if failed.
 */
uint8_t str2action(const char *str, uint8_t *action)
{
    if (0 == strcmp(str, "accept"))
    {
        *action = NF_ACCEPT;
        return 1;
    }
    else if (0 == strcmp(str, "drop"))
    {
        *action = NF_DROP;
        return 1;
    }
    else
    {
        return 0;
    }
}

// the protocols we will work with
typedef enum
{
    PROT_ICMP = 1,
    PROT_TCP = 6,
    PROT_UDP = 17,
    PROT_ANY = 143,
} prot_t;

char *protocol2str(const uint8_t protocol)
{
    switch (protocol)
    {
    case PROT_ICMP:
        return "ICMP";
    case PROT_UDP:
        return "UDP";
    case PROT_TCP:
        return "TCP";
    default:
        return "any";
    }
}

/**
 * Returns 1 if succeed (the string is valid), 0 if failed.
 */
uint8_t str2protocol(const char *str, uint8_t *protocol)
{
    if (0 == strcmp(str, "ICMP"))
    {
        *protocol = PROT_ICMP;
        return 1;
    }
    else if (0 == strcmp(str, "UDP"))
    {
        *protocol = PROT_UDP;
        return 1;
    }
    else if (0 == strcmp(str, "TCP"))
    {
        *protocol = PROT_TCP;
        return 1;
    }
    else if (0 == strcmp(str, "any"))
    {
        *protocol = PROT_ANY;
        return 1;
    }
    else
    {
        return 0;
    }
}

// macros for rule fiels
#define PORT_ANY (0)
#define PORT_ABOVE_1023 (1024)

/*
 * Converts port to string.
 */
void port2str(char *port_str, const uint16_t port)
{
    if (port == PORT_ABOVE_1023)
    {
        strcpy(port_str, ">1023");
    }
    else if (port == PORT_ANY)
    {
        strcpy(port_str, "any");
    }
    else
    {
        sprintf(port_str, "%d", port);
    }
}

/**
 * Returns 1 if succeed (the string is valid), 0 if failed.
 */
uint8_t str2port(const char *port_str, uint16_t *port)
{
    int check;
    unsigned int port_container;

    if (0 == strcmp(port_str, ">1023"))
    {
        *port = PORT_ABOVE_1023;
        return 1;
    }
    if (0 == strcmp(port_str, "any"))
    {
        *port = PORT_ANY;
        return 1;
    }
    check = sscanf(port_str, "%u", &port_container);
    if (check == 1 && port_container <= 1023)
    {
        *port = (uint16_t)port_container;
        return 1;
    }
    return 0;
}

#include <arpa/inet.h>
// Declarations of the functions we will use from inet
int inet_aton(const char *cp, struct in_addr *inp);
char *inet_ntoa(struct in_addr in);

/*
 * Converts full ip address to string.
 */
void ip2str(char *ip_str, const uint32_t ip)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ip);
    strcpy(ip_str, inet_ntoa(ip_addr));
}

/**
 * Returns 1 if succeed (the string is valid), 0 if failed.
 */
uint8_t str2ip(const char *ip_str, uint32_t *ip)
{
    struct in_addr ip_addr;
    int valid_adress = inet_aton(ip_str, &ip_addr);
    *ip = valid_adress ? ntohl(ip_addr.s_addr) : 0;
    return valid_adress ? 1 : 0;
}